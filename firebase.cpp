#include <fmt/chrono.h>
#include <oxenmq/oxenmq.h>

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <CLI/Validators.hpp>
#include <exception>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/log/level.hpp>
#include <oxen/log/type.hpp>

#include "google_auth.hpp"
#include "http2_notifier.hpp"
#include "notifiers.hpp"
#include "util.hpp"

static auto cat = oxen::log::Cat("firebase");

namespace spns::notifier::firebase {

int run(int argc, char* argv[]) {

    CLI::App app{"SPNS firebase notifier"};

    NotifierBase nb{app, "firebase"};

    std::filesystem::path auth_file;

    app.add_option(
               "--auth",
               auth_file,
               "JSON file containing google 'service_account' authentication details")
            ->required()
            ->check(CLI::ExistingFile);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    std::optional<AuthRequestor> authreq;
    try {
        authreq.emplace(std::move(auth_file));
    } catch (const std::exception& e) {
        log::error(cat, "Unable to initialize auth requester: {}", e.what());
        return 1;
    }

    log::debug(cat, "SPNS Firebase Notifier initialized; requesting initial auth token");

    auto [token, expires] = authreq->new_auth_token();

    log::info(cat, "SPNS Firebase Notifier initialized and authenticated with Google");

    auto hn = std::make_optional<FirebaseHTTP>(authreq->project_id(), token);

    auto& omq = nb.init();

    nb.add_endpoints(
            *hn,
            // A Firebase device token is an opaque non-empty string.
            [](std::string_view token) -> std::optional<std::string> {
                if (token.empty())
                    return "Firebase device token cannot be empty";
                return std::nullopt;
            },
            [](const notification& n, int code, const std::string& resp_body) {
                // Error codes: see https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
                switch (code) {
                    case 200: return Outcome::success;
                    case 400:
                        // This is a generic "INVALID_ARGUMENT".  This could be a malformed request,
                        // or an invalid token.  There's a deeply nested value in the body that
                        // helps us distinguish:
                        try {
                            auto err_det0 = nlohmann::json::parse(resp_body)["error"]["details"][0];
                            if (err_det0["@type"].get<std::string_view>() ==
                                        "type.googleapis.com/google.firebase.fcm.v1.FcmError" &&
                                err_det0["errorCode"].get<std::string_view>() ==
                                        "INVALID_ARGUMENT") {
                                log::warning(
                                        cat,
                                        "Device token {} is no longer valid; deleting it",
                                        n.token);
                                return Outcome::invalid_token;
                            }
                        } catch (...) {
                        }

                        // Otherwise this is some other sort of error so log it and schedule a retry
                        log::warning(
                                cat,
                                "Notification request returned 400 error with body:\n{}",
                                resp_body);
                        return Outcome::retry;
                    case 401:
                        // THIRD_PARTY_AUTH_ERROR.  This seems to be for when you are deeply truely
                        // cursed by having decided to use Firebase to send notifications to APNS to
                        // make sure that both Google and Apple get to see all your notifications.
                        log::warning(
                                cat,
                                "Notification request returned 401, this is unexpected!  Body:\n{}",
                                resp_body);
                        return Outcome::retry;
                    case 403:
                        // SENDER_ID_MISMATCH -- the client app registered for FCM but
                        // apparently didn't include us as an allowed sender.
                        log::warning(
                                cat,
                                "Device token {} has not authorized us to send "
                                "notifications; deleting it",
                                n.token);
                        return Outcome::invalid_token;
                    case 404:
                        // UNREGISTERED -- the token is not registered, perhaps because the token
                        // got refreshed, the app got uninstalled, etc.
                        log::warning(
                                cat, "Device token {} unregistered from FCM; deleting it", n.token);
                        return Outcome::invalid_token;
                    case 429:
                        // QUOTA_EXCEEDED -- we hit some sort of quota, but it could be
                        // either for this token specifically or for the project overall.
                        log::warning(
                                cat,
                                "Exceeded quota sending to token {}; will retry in 60s",
                                n.token);
                        return Outcome::quota;
                    default:
                        log::warning(
                                cat,
                                "Error code {} while sending to token {}; will retry soon",
                                code,
                                n.token);
                        return Outcome::retry;
                }
            });

    log::info(cat, "SPNS Firebase Notifier initialized, starting up");

    nb.start(hn->loop);

    // Run this timer once a minute, refreshing if we have less than 20min validity left for the
    // token.  That way even if we get a failure, we can still retry 19 times before the token
    // actually becomes invalid, and if Google starts returning tokens with less than 20min
    // validity, at least we rate limit ourselves to one per minute.
    omq.add_timer(
            [&expires, &token, &authreq, &hn] {
                auto now = std::chrono::system_clock::now();
                if (expires > now + 20min)
                    return;

                try {
                    std::tie(token, expires) = authreq->new_auth_token();
                } catch (const std::exception&) {
                    // Already logged, but log if it's failing and we're nearly expired:
                    if (expires < now)
                        log::error(
                                cat,
                                "Current OAuth2 token expired {} ago!",
                                friendly_duration(now - expires));
                    else if (expires < now + 10min)
                        log::warning(
                                cat,
                                "Current OAuth2 token expires in {}!",
                                friendly_duration(expires - now));
                    return;
                }
                hn->update_auth_token(token);
            },
            1min);

    nb.run();

    log::info(cat, "Stopping HTTP2 notification client...");
    hn->stop();
    hn.reset();
    log::info(cat, "Shutdown complete.");

    return 0;
}

}  // namespace spns::notifier::firebase

int main(int argc, char* argv[]) {
    try {
        return spns::notifier::firebase::run(argc, argv);
    } catch (const std::exception& e) {
        oxen::log::error(cat, "{}", e.what());
        return 1;
    }
}
