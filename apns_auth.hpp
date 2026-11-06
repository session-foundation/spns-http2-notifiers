#pragma once

#include <array>
#include <chrono>
#include <filesystem>
#include <span>
#include <string>

#include "auth_common.hpp"

namespace spns::notifier::apns {

// Converts the R and S integers of a P-256 ECDSA signature, as decoded from its DER encoding, to
// the 64-byte R || S that JWS requires for ES256, each value left-padded with zeros to 32 bytes.
// DER integers are minimal and signed, so a value may be shorter than 32 bytes, or 33 with a
// leading 0x00 when its top bit is set.  Throws std::runtime_error if a value, without its leading
// zeros, is longer than 32 bytes.
std::array<unsigned char, 64> es256_signature(
        std::span<const unsigned char> r, std::span<const unsigned char> s);

class AuthSigner {
  private:
    std::string key_id;
    std::string team_id;
    privkey_ptr priv;

  public:
    // Takes the 10-digit "key id", 10-digit team id, and path to an Apple ".p8" private key
    // associated with that key_id, which is just a PEM file containing a private key (see Apple
    // docs about token-based connection to APNs for info on how to generate this).
    explicit AuthSigner(
            std::string key_id, std::string team_id, const std::filesystem::path& privkey);

    // Creates a new JWT to be sent in a "Authorization: bearer <TOKEN>" header to authenticate HTTP
    // requests.  The token includes the current time, and will be good for 1h; rotation is required
    // before that (e.g.  50min).  Apple docs explain that Apple may or may not possibly get mad and
    // do something or nothing if this is regenerated more frequently than once per 20min.
    //
    // Returns the token and the expiry (i.e. current time + 1h) before which the value should be
    // regenerated.
    std::pair<std::string, std::chrono::sys_seconds> new_auth_token();
};

}  // namespace spns::notifier::apns
