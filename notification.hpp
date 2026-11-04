#pragma once
#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace spns::notifier {

struct notification {
    std::string token;
    std::vector<std::byte> nonce_ciphertext;
    bool high_priority;
    int attempts = 0;

    // Constructs a notification by encrypting the given payload with the given encryption key and
    // storing the nonce + ciphertext into the nonce_ciphertext member.
    notification(
            std::string token,
            std::string_view payload,
            std::span<const unsigned char, 32> enc_key,
            bool high_prio);

    // Takes the body of a SPNS hivemind push request, parses it and builds an encrypted
    // notification object out of the data.  `notifier_id` is the expected notifier id that the main
    // spns server should have indicated in the request.
    static notification parse_spns(std::string_view data, std::string_view notifier_id);
};

}  // namespace firebase
