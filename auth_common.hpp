#pragma once
#include <gnutls/abstract.h>

#include <memory>

namespace spns::notifier {

struct privkey_deleter {
    void operator()(gnutls_privkey_t priv) const noexcept;
};
using privkey_ptr = std::unique_ptr<std::remove_pointer_t<gnutls_privkey_t>, privkey_deleter>;

struct gnutls_free_deleter {
    void operator()(void* p) const noexcept;
};
// Owns a buffer that gnutls allocated for us, such as a gnutls_datum_t's data.
using gnutls_bytes = std::unique_ptr<unsigned char[], gnutls_free_deleter>;

privkey_ptr load_privkey(std::string_view content);

std::string b64_url(std::string_view in);

}  // namespace spns::notifier
