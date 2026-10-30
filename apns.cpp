#include <fmt/chrono.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <CLI/Validators.hpp>
#include <chrono>
#include <exception>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/log/level.hpp>
#include <oxen/log/type.hpp>
#include <stdexcept>

#include "apns_auth.hpp"
#include "http2_notifier.hpp"
#include "notifiers.hpp"

static auto cat = oxen::log::Cat("apns");

namespace spns::notifier::apns {

namespace log = oxen::log;
using namespace log::literals;

int run(int argc, char* argv[]) {

    CLI::App app{"SPNS APNs notifier"};

    NotifierBase nb{app, "apns"};

    std::string team_id;
    std::string key_id;
    std::filesystem::path key_file;
    std::string app_id;
    bool sandbox = false;

    app.add_option("--team-id", team_id, "Apple team identifier (10 characters)")->required();
    app.add_option("--key-id", key_id, "Apple key id for authentication (10 characters)")
            ->required();
    app.add_option(
               "--privkey",
               key_file,
               "PEM file containing the Apple secret key associed with --key-id used for request "
               "authentication")
            ->required()
            ->check(CLI::ExistingFile);
    app.add_option("--app-id", app_id, "Apple application/bundle ID")->required();
    app.add_flag(
            "--sandbox",
            sandbox,
            "Run in sandbox mode with pushes to the sandbox APNs; requires a sandbox key");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    std::optional<AuthSigner> tokensigner;
    try {
        tokensigner.emplace(std::move(key_id), std::move(team_id), std::move(key_file));
    } catch (const std::exception& e) {
        throw std::runtime_error{"Unable to initialize auth signer: {}"_format(e.what())};
    }

    auto& omq = nb.init();

    auto [token, expires] = tokensigner->new_auth_token();

    auto hn = std::make_optional<APNSHTTP>(app_id, token, sandbox);

    nb.add_endpoints(
            *hn,
            // An APNs device token is 64 hex digits.
            [](std::string_view token) -> std::optional<std::string> {
                if (token.size() != 64 || !oxenc::is_hex(token))
                    return "Invalid APNs device token (expected 64 hex, got {}B)"_format(
                            token.size());
                return std::nullopt;
            },
            [](const notification& n, int code, const std::string& resp_body) {
                // Error codes: see
                // https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
                if (code == 200)
                    return Outcome::success;

                // Otherwise, for an error, there is supposed to be a json body with a "reason" key
                // to figure out exactly what happened:
                std::string reason;
                try {
                    reason = nlohmann::json::parse(resp_body)["reason"].get<std::string>();
                } catch (...) {
                    log::warning(
                            cat,
                            "Unable to parse error {} response; will retry soon.  Response:\n{}",
                            code,
                            resp_body);
                }

                log::debug(
                        cat, "Received non-success response {} (with reason: {})", code, reason);

                if (code == 400 &&
                    (reason == "BadDeviceToken"sv || reason == "DeviceTokenNotForTopic"sv)) {
                    // This means the token we were given is invalid, and so we should drop it.
                    log::warning(cat, "{} '{}'; dropping device subscription(s)", reason, n.token);
                    return Outcome::invalid_token;
                }
                if (code == 410) {
                    if (reason == "ExpiredToken")
                        log::warning(
                                cat,
                                "Token '{}' is expired; dropping device subscription(s)",
                                n.token);
                    else if (reason == "Unregistered")
                        log::warning(
                                cat,
                                "Token '{}' is no longer active; dropping device subscription(s)",
                                n.token);
                    else
                        log::warning(
                                cat,
                                "Unknown 410 reason '{}'; dropping device subscription(s)",
                                reason);
                    return Outcome::invalid_token;
                }
                if (code == 429 && reason == "TooManyRequests") {
                    log::warning(
                            cat,
                            "Too many requests to token '{}'; cooldown down that device for ~1min",
                            n.token);
                    return Outcome::quota;
                }
                log::error(
                        cat,
                        "Error submitting PN for '{}': {} ({}).  Will retry soon",
                        n.token,
                        code,
                        reason);
                return Outcome::retry;
            });

    log::info(cat, "SPNS APNs Notifier initialized, starting up");

    nb.start(hn->loop);

    // Run this timer every 50m to refresh the token.  (There's no errors to worry about retrying
    // anything if it fails, because the token is simply a self-signed value.)
    omq.add_timer(
            [&expires, &token, &tokensigner, &hn] {
                try {
                    std::tie(token, expires) = tokensigner->new_auth_token();
                } catch (const std::exception& e) {
                    log::critical(cat, "Token signing FAILED: {}", e.what());
                    return;
                }
                hn->update_auth_token(token);
            },
            50min);

    nb.run();

    log::info(cat, "Stopping HTTP2 notification client...");
    hn->stop();
    hn.reset();
    log::info(cat, "Shutdown complete.");

    return 0;
}

}  // namespace spns::notifier::apns

int main(int argc, char* argv[]) {

    try {
        return spns::notifier::apns::run(argc, argv);
    } catch (const std::exception& e) {
        oxen::log::error(cat, "{}", e.what());
        return 1;
    }
}
