#include "apns_auth.hpp"

#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "auth_common.hpp"
#include "util.hpp"

namespace spns::notifier::apns {

namespace {
    void put_half(std::span<const unsigned char> v, std::span<unsigned char, 32> out, char name) {
        auto first = std::ranges::find_if(v, [](unsigned char c) { return c != 0; });
        v = v.subspan(first - v.begin());
        if (v.size() > out.size())
            throw std::runtime_error{"Invalid ES256 signature: {} is {} bytes ({})"_format(
                    name, v.size(), oxenc::to_hex(v.begin(), v.end()))};
        auto pad = out.size() - v.size();
        std::fill_n(out.begin(), pad, 0);
        std::ranges::copy(v, out.begin() + pad);
    }
}  // namespace

std::array<unsigned char, 64> es256_signature(
        std::span<const unsigned char> r, std::span<const unsigned char> s) {
    std::array<unsigned char, 64> rs;
    put_half(r, std::span{rs}.first<32>(), 'R');
    put_half(s, std::span{rs}.last<32>(), 'S');
    return rs;
}

AuthSigner::AuthSigner(
        std::string key_id_, std::string team_id_, const std::filesystem::path& privkey) :
        key_id{std::move(key_id_)},
        team_id{std::move(team_id_)},
        priv{load_privkey(file::slurp(privkey))} {

    if (key_id.size() != 10)
        throw std::invalid_argument{"Invalid key_id: expected 10-digit identifier"};
    if (team_id.size() != 10)
        throw std::invalid_argument{"Invalid team_id: expected 10-digit identifier"};
}

std::pair<std::string, std::chrono::sys_seconds> AuthSigner::new_auth_token() {
    std::pair<std::string, std::chrono::sys_seconds> result;
    auto& [token, now] = result;

    now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());

    token = "{}.{}"_format(
            b64_url(nlohmann::json{{"alg", "ES256"}, {"kid", key_id}}.dump()),
            b64_url(nlohmann::json{{"iss", team_id}, {"iat", now.time_since_epoch().count()}}
                            .dump()));

    const gnutls_datum_t to_sign{
            .data = reinterpret_cast<unsigned char*>(token.data()),
            .size = static_cast<unsigned int>(token.size())};
    gnutls_datum_t sig{};

    int rc = gnutls_privkey_sign_data(priv.get(), GNUTLS_DIG_SHA256, 0, &to_sign, &sig);
    if (rc < 0)
        throw std::runtime_error{"Failed to sign JWT: {}"_format(gnutls_strerror(rc))};
    gnutls_bytes sig_data{sig.data};

    gnutls_datum_t r{}, s{};
    rc = gnutls_decode_rs_value(&sig, &r, &s);
    if (rc < 0)
        throw std::runtime_error{
                "Failed to decode signature for JWT: {}"_format(gnutls_strerror(rc))};
    gnutls_bytes r_data{r.data}, s_data{s.data};

    auto rs = es256_signature({r.data, r.size}, {s.data, s.size});

    token += '.';
    token += b64_url(std::string_view{reinterpret_cast<const char*>(rs.data()), rs.size()});

    return result;
}

}  // namespace spns::notifier::apns
