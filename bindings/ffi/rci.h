/* C ABI for rust-curl-impersonate.
 *
 * Link against librust_curl_impersonate_ffi.so (or the platform equivalent).
 * Every request call is synchronous; errors are JSON objects with an "error"
 * key. Strings returned by this library must be released with rci_string_free.
 */
#ifndef RUST_CURL_IMPERSONATE_FFI_H
#define RUST_CURL_IMPERSONATE_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RciClient RciClient;

/* ABI version. */
uint32_t rci_version(void);

/* Create a client for a profile name. Returns NULL and sets rci_last_error()
 * when the name is unknown. */
RciClient *rci_client_new(const char *profile);

/* Free a handle; NULL is a no-op. */
void rci_client_free(RciClient *handle);

/* Send a request. `method` is "GET", "POST", ...; `body` may be NULL when
 * `body_len` is 0. Returns {"status":<u16>,"body":"<utf-8>"} or
 * {"error":"..."} — free it with rci_string_free. */
char *rci_request(RciClient *handle,
                  const char *method,
                  const char *url,
                  const uint8_t *body,
                  size_t body_len);

/* One-shot GET: creates a client, sends the request, and frees the client. */
char *rci_get(const char *profile, const char *url);

/* Last client-construction error on this thread. The pointer stays valid
 * until the next call on the same thread. */
const char *rci_last_error(void);

/* Release a string returned by this library; NULL is a no-op. */
void rci_string_free(char *text);

#ifdef __cplusplus
}
#endif

#endif /* RUST_CURL_IMPERSONATE_FFI_H */
