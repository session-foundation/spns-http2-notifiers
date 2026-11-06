#include "apns_auth.hpp"

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <oxenc/base64.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "auth_common.hpp"

using namespace spns::notifier;
using bytes = std::vector<unsigned char>;

namespace {

int failures = 0;

void check(bool ok, std::string_view what) {
    if (!ok) {
        ++failures;
        std::cerr << "FAIL: " << what << "\n";
    }
}

bytes concat(const bytes& a, const bytes& b) {
    auto r = a;
    r.insert(r.end(), b.begin(), b.end());
    return r;
}

bool rs_equals(const std::array<unsigned char, 64>& rs, const bytes& expected) {
    return std::ranges::equal(rs, expected);
}

void test_normalisation() {
    bytes v32(32), v31(31);
    for (int i = 0; i < 32; ++i)
        v32[i] = 0x80 + i;
    for (int i = 0; i < 31; ++i)
        v31[i] = 0x01 + i;
    auto v33 = concat({0x00}, v32);
    auto v31_padded = concat({0x00}, v31);

    check(rs_equals(apns::es256_signature(v32, v32), concat(v32, v32)), "32-byte R and S");
    check(rs_equals(apns::es256_signature(v33, v31), concat(v32, v31_padded)),
          "33-byte R, 31-byte S");
    check(rs_equals(apns::es256_signature(v31, v33), concat(v31_padded, v32)),
          "31-byte R, 33-byte S");

    bytes v30(v31.begin() + 1, v31.end());
    check(rs_equals(
                  apns::es256_signature(v30, concat({0x00, 0x00}, v32)),
                  concat(concat({0x00, 0x00}, v30), v32)),
          "30-byte R, 34-byte S with two leading zeros");

    auto throws = [](const bytes& r, const bytes& s) {
        try {
            apns::es256_signature(r, s);
        } catch (const std::runtime_error&) {
            return true;
        }
        return false;
    };
    check(throws(concat({0x01}, v32), v32), "33-byte R without a leading zero throws");
    check(throws(v32, concat({0x01}, v32)), "33-byte S without a leading zero throws");
}

std::string from_b64url(std::string s) {
    std::ranges::replace(s, '-', '+');
    std::ranges::replace(s, '_', '/');
    return oxenc::from_base64(s);
}

void test_signing(int count) {
    gnutls_x509_privkey_t xkey;
    gnutls_x509_privkey_init(&xkey);
    if (gnutls_x509_privkey_generate2(
                xkey,
                GNUTLS_PK_ECDSA,
                GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1),
                0,
                nullptr,
                0) < 0)
        throw std::runtime_error{"key generation failed"};
    gnutls_datum_t pem_datum{};
    gnutls_x509_privkey_export2(xkey, GNUTLS_X509_FMT_PEM, &pem_datum);
    gnutls_bytes pem_owner{pem_datum.data};
    gnutls_x509_privkey_deinit(xkey);
    std::string pem{reinterpret_cast<const char*>(pem_datum.data), pem_datum.size};

    auto path = std::filesystem::temp_directory_path() /
                ("apns-auth-test-" + std::to_string(getpid()) + ".pem");
    std::ofstream{path} << pem;
    apns::AuthSigner signer{"ABCDEFGHIJ", "KLMNOPQRST", path};
    std::filesystem::remove(path);

    auto priv = load_privkey(pem);
    gnutls_pubkey_t pub;
    gnutls_pubkey_init(&pub);
    gnutls_pubkey_import_privkey(pub, priv.get(), 0, 0);

    int signed_ok = 0, short_halves = 0, verified = 0;
    for (int i = 0; i < count; ++i) {
        std::string token;
        try {
            token = signer.new_auth_token().first;
        } catch (const std::exception& e) {
            check(false, std::string{"signing threw: "} + e.what());
            continue;
        }
        ++signed_ok;
        auto dot = token.rfind('.');
        auto sig = from_b64url(token.substr(dot + 1));
        if (sig.size() != 64) {
            check(false, "signature is not 64 bytes");
            continue;
        }
        if (sig[0] == 0 || sig[32] == 0)
            ++short_halves;

        auto* raw = reinterpret_cast<unsigned char*>(sig.data());
        gnutls_datum_t r{raw, 32}, s{raw + 32, 32}, der{};
        gnutls_encode_rs_value(&der, &r, &s);
        gnutls_bytes der_owner{der.data};
        gnutls_datum_t data{
                reinterpret_cast<unsigned char*>(token.data()), static_cast<unsigned int>(dot)};
        if (gnutls_pubkey_verify_data2(pub, GNUTLS_SIGN_ECDSA_SHA256, 0, &data, &der) >= 0)
            ++verified;
        else
            check(false, "signature does not verify");
    }
    gnutls_pubkey_deinit(pub);

    check(signed_ok == count, "every token signed");
    check(verified == count, "every signature verified");
    std::cout << "signed " << signed_ok << "/" << count << " tokens (" << short_halves
              << " with an R or S under 32 bytes), " << verified << " verified\n";
}

}  // namespace

int main() {
    test_normalisation();
    test_signing(5000);
    if (failures) {
        std::cerr << failures << " failure(s)\n";
        return 1;
    }
    std::cout << "all passed\n";
}
