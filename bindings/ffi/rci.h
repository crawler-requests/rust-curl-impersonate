/* C ABI for rust-curl-impersonate.
 *
 * Link against librust_curl_impersonate_ffi.so (or the platform equivalent).
 * Every request call is synchronous; the calling thread blocks until the
 * response arrives. Strings returned by this library are owned by it and must
 * be released with rci_string_free.
 *
 * ABI version 2. `rci_version()` returns it. Every function present in
 * version 1 keeps its signature and its JSON shape, so a version-1 caller
 * keeps working.
 */
#ifndef RUST_CURL_IMPERSONATE_FFI_H
#define RUST_CURL_IMPERSONATE_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RciClient RciClient;

/* ====================================================================== */
/* Version and library                                                     */
/* ====================================================================== */

/* ABI version. */
uint32_t rci_version(void);

/* Names of the 48 curl-impersonate presets, as a JSON array of strings.
 * Release with rci_string_free. */
char *rci_targets(void);

/* Names selectable with rci_client_new: the 48 presets plus every record in
 * the built-in fingerprint library. JSON array of strings. */
char *rci_profiles(void);

/* Metadata for one profile as a JSON object:
 *   {"name":"...","wire":"...","family":"...","platform":"...",
 *    "fidelity":"exact"|"close"|"partial"|null,
 *    "deviation":null|"...","http1_only":true|false,
 *    "has_http3":true|false,"source":"..."}
 * Unknown profile: {"error":"unknown profile <name>"}. */
char *rci_profile_info(const char *profile);

/* ====================================================================== */
/* Client construction                                                     */
/* ====================================================================== */

/* Create a client for a profile name with default settings (30 s timeout).
 * Returns NULL and sets rci_last_error() when the name is unknown. */
RciClient *rci_client_new(const char *profile);

/* Create a client with settings read from a JSON object. Unknown keys are
 * rejected with an error. Every key is optional:
 *   {
 *     "timeout_ms": 30000,          total request timeout,
 *     "proxy": "http://h:8080",     http://, https://, socks5://, socks5h://,
 *     "follow_redirects": true,     false stops at the first response,
 *     "follow_safe": false,         reject redirects to private addresses,
 *     "pool_max_idle_per_host": 4,
 *     "headers": [["name","value"], ...],   added to every request,
 *     "split_cookies": false,
 *     "http1_only": false
 *   }
 * Pass NULL or "{}" for defaults. Returns NULL and sets rci_last_error() on
 * an unknown profile or invalid settings. */
RciClient *rci_client_new_with_options(const char *profile, const char *options_json);

/* Free a handle; NULL is a no-op. */
void rci_client_free(RciClient *handle);

/* The preset whose bytes this handle sends. Stable for the handle's life.
 * Free with rci_string_free. */
char *rci_client_profile(RciClient *handle);

/* ====================================================================== */
/* Requests                                                                */
/* ====================================================================== */

/* Send a request. `method` is "GET", "POST", ...; `body` may be NULL when
 * `body_len` is 0.
 *
 * Returns a JSON object:
 *   {"status":200,"version":"HTTP/1.1"|"HTTP/2.0"|"HTTP/3",
 *    "url":"<final url>","headers":[["name","value"], ...],
 *    "body":"<utf-8 text>","body_is_text":true}
 * A body that is not valid UTF-8 is returned as lowercase hex with
 * "body_is_text":false. On failure the object is {"error":"..."}.
 * Free the returned string with rci_string_free. */
char *rci_request(RciClient *handle,
                  const char *method,
                  const char *url,
                  const uint8_t *body,
                  size_t body_len);

/* Like rci_request, with extra headers for this one request.
 * `headers_json` is a JSON array of [name, value] pairs, NULL or "" for none.
 * `body` is a NUL-terminated UTF-8 string, NULL for no body. */
char *rci_request_with(RciClient *handle,
                       const char *method,
                       const char *url,
                       const char *headers_json,
                       const char *body);

/* One-shot GET: creates a client, sends the request, and frees the client. */
char *rci_get(const char *profile, const char *url);

/* Send the same GET over HTTP/3. The profile must carry an HTTP/3 record;
 * rci_profile_info reports "has_http3".
 *
 * `addr` is "ip:port" the QUIC socket connects to, `host` is the SNI and
 * :authority value, `path` is the request target. A `addr` host that is a
 * name (not an IP) is resolved first.
 *
 * Returns {"status":<u16>,"headers":[["name","value"], ...],
 * "body":"...","body_is_text":true|false}. The body follows the same rule as
 * rci_request: UTF-8 text inline, anything else as lowercase hex.
 * Failure: {"error":"..."}. */
char *rci_http3_get(const char *profile,
                    const char *addr,
                    const char *host,
                    const char *path);

/* ====================================================================== */
/* Handle introspection                                                    */
/* ====================================================================== */

/* Headers of the most recent request on this handle, as a JSON array of
 * [name, value] pairs, or "[]" before any request. */
char *rci_client_last_headers(RciClient *handle);

/* Cookie changes and redirect history recorded by the handle:
 * {"cookies":["SET\t..."], "redirects":["302\t..."]}. */
char *rci_client_activity(RciClient *handle);

/* ====================================================================== */
/* Errors and memory                                                       */
/* ====================================================================== */

/* Last client-construction error on this thread. The pointer stays valid
 * until the next call on the same thread. */
const char *rci_last_error(void);

/* Append a JSON document to the process's fingerprint library. `json` is a
 * document in the library schema (docs/provider-protocol.md): a bare record,
 * an array of records, or {"fingerprints":[...]}. Records become selectable
 * with rci_client_new immediately; a name they share with a built-in record
 * resolves to the document's version for this process. The document is
 * validated before anything is kept.
 * Returns "{}" on success or {"error":"..."}. */
char *rci_load_fingerprints(const char *json);

/* Release a string returned by this library; NULL is a no-op. */
void rci_string_free(char *text);

#ifdef __cplusplus
}
#endif

#endif /* RUST_CURL_IMPERSONATE_FFI_H */
