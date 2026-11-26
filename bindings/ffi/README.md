# rust-curl-impersonate C ABI

The C ABI exposing `rust-curl-impersonate` to other languages, in both a
shared library (`cdylib`) and a static one (`staticlib`). It is the entry
point for Python/Node/Go/Java/C++/C#/Swift bindings; the Rust crate stays the
single source of fingerprint logic.

## Build

```sh
cargo build -p rust-curl-impersonate-ffi --release
```

The artifacts are, per platform:

- shared: `librust_curl_impersonate_ffi.so` / `.dylib` / `.dll` (with a
  `.lib` import library on MSVC)
- static: `librust_curl_impersonate_ffi.a` / `rust_curl_impersonate_ffi.lib`

`rci.h` is the matching C header. The static archive bundles BoringSSL, which
is C++, so link it with a C++ driver or add `-lstdc++` (details in
`USING_THIS_ARCHIVE.md`).

## Prebuilt platforms

Every `v*` tag publishes one archive per target, each with `rci.h`, both
library forms, `SHA256SUMS`, and a `USING_THIS_ARCHIVE.md`:

| OS | Architectures |
|---|---|
| Linux (glibc) | x86_64, aarch64, armv7 (hard-float), i686 |
| Linux (musl) | x86_64, aarch64 |
| macOS | x86_64, arm64 |
| Windows | x86_64, arm64, i686 |
| Android | arm64-v8a, armeabi-v7a, x86_64, x86 |
| iOS | arm64 (device), arm64 + x86_64 (simulator) |

Two gaps are deliberate: armv7-musl and i686-musl. The `btls` crate passes
an `i64` where `time_t` is expected, and musl on 32-bit targets has a 32-bit
`time_t`, so it does not compile there. armv7 and i686 are covered by their
glibc builds. Linux musl builds are dynamically linked against musl
(Alpine-compatible); the Android builds expect `libc++_shared.so` from the
NDK at runtime when the shared form is used (the static form does not).

## Use from C

```c
#include "rci.h"

RciClient *client = rci_client_new("chrome150");
char *reply = rci_request(client, "GET", "https://tls.peet.ws/api/all", NULL, 0);
puts(reply);              /* {"status":200,"version":"HTTP/2.0",...,"body":"..."} */
rci_string_free(reply);
rci_client_free(client);
```

## Use from Python

```sh
python3 bindings/ffi/python/demo.py chrome150 https://tls.peet.ws/api/all
```

`python/demo.py` uses `ctypes`; copy its wrapper into your project rather than
shelling out. `python/smoke.py` exercises every function and is what CI runs.

## API (ABI version 2)

| Function | Purpose |
|---|---|
| `rci_version()` | ABI version (2) |
| `rci_targets()` | the 48 preset names, JSON array |
| `rci_profiles()` | every selectable name (presets + library records) |
| `rci_profile_info(profile)` | family/platform/fidelity/http1_only/has_http3/deviation for one name |
| `rci_client_new(profile)` | create a handle (runtime + client, 30 s timeout) |
| `rci_client_new_with_options(profile, json)` | same, with timeout/proxy/headers/redirect/split-cookie settings |
| `rci_request(handle, method, url, body, len)` | send one request |
| `rci_request_with(handle, method, url, headers_json, body)` | send one request with per-request headers |
| `rci_get(profile, url)` | one-shot GET |
| `rci_http3_get(profile, addr, host, path)` | GET over HTTP/3 with a profile that carries an H3 record |
| `rci_client_profile(handle)` | the preset whose bytes the handle sends |
| `rci_client_last_headers(handle)` | headers of the most recent response |
| `rci_client_activity(handle)` | cookie changes and redirect history |
| `rci_load_fingerprints(json)` | add records to the library at runtime (a provider) |
| `rci_client_free(handle)` | release a handle |
| `rci_last_error()` | last handle-construction error on this thread |
| `rci_string_free(text)` | release a returned string |

Responses are JSON objects:

```json
{
  "status": 200,
  "version": "HTTP/2.0",
  "url": "https://example.com/",
  "headers": [["content-type", "text/html"], ...],
  "body": "...",
  "body_is_text": true
}
```

A body that is not valid UTF-8 comes back as lowercase **hex** with
`body_is_text: false`, so no byte is lost through a `char *`. Errors are
`{"error":"..."}`.

## Notes for binding authors

- Every call blocks on the calling thread. Reuse one `RciClient` per
  thread/task; do not call `rci_get` in a hot loop.
- All returned strings are owned by the library; free them with
  `rci_string_free`. A handle must be freed with `rci_client_free`.
- Settings that are not in `rci_client_new_with_options` (TLS overrides,
  HTTP/2 tuning, HTTP/3 parameters) live on the Rust `ClientBuilder`; use the
  Rust API directly when a profile preset is not enough. Widening the C ABI is
  a field here worth doing when a binding needs it.
- `rci_load_fingerprints` registers a user-priority provider, so a record it
  adds can shadow a built-in one of the same name for the life of the process,
  without waiting for a new release.
- No registry patch is needed. `rust-curl-impersonate` depends on the modified
  `wreq`/`quinn`/`quinn-proto` sources inside this repository, so a binding crate
  in a separate project can use a plain path or git dependency.
- HTTP/3 is available only for profiles whose record carries an `http3`
  block (currently the QUIC-era Chrome/Firefox/Safari presets and `chrome160`).
  A profile without one returns `{"error":"HTTP/3 is unavailable"}` from
  `rci_http3_get`.

## Embedding guide

`docs/embedding.md` is the per-language walkthrough: the full function table,
the response shapes, and working examples for C, C++, Python, Node, Go,
Java/Kotlin, PHP, C# and Swift. This file keeps the function list; that one
shows how to call it from each language.
