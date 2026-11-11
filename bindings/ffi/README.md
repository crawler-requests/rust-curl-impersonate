# rust-curl-impersonate C ABI

Shared library (`cdylib`) exposing `rust-curl-impersonate` to other languages.
It is the starting point for Python/Node/Go/Java/C++ bindings; the Rust crate
stays the single source of fingerprint logic.

## Build

```sh
cargo build -p rust-curl-impersonate-ffi --release
```

The artifact is `target/release/librust_curl_impersonate_ffi.so` on Linux,
`.dylib` on macOS, `.dll` on Windows. `rci.h` is the matching C header.

## Use from C

```c
#include "rci.h"

RciClient *client = rci_client_new("chrome150");
char *reply = rci_request(client, "GET", "https://tls.peet.ws/api/all", NULL, 0);
puts(reply);              /* {"status":200,"body":"..."} */
rci_string_free(reply);
rci_client_free(client);
```

## Use from Python

```sh
python3 bindings/ffi/python/demo.py chrome150 https://tls.peet.ws/api/all
```

`python/demo.py` uses `ctypes`; copy its wrapper into your project rather than
shelling out.

## API

| Function | Purpose |
|---|---|
| `rci_version()` | ABI version |
| `rci_client_new(profile)` | create a handle (runtime + client) |
| `rci_request(handle, method, url, body, len)` | send one request |
| `rci_get(profile, url)` | one-shot GET |
| `rci_client_free(handle)` | release a handle |
| `rci_last_error()` | last handle-creation error on this thread |
| `rci_string_free(text)` | release a returned string |

Responses are JSON: `{"status":<u16>,"body":"<utf-8>"}` or
`{"error":"..."}`. `body` is always UTF-8 text; binary downloads need a future
streaming API (see below).

## Notes for binding authors

- The calls block. Reuse one `RciClient` per thread/task rather than calling
  `rci_get` in a loop.
- All returned strings are owned by the library; free them with
  `rci_string_free`.
- No registry patch is needed. `rust-curl-impersonate` depends directly on the
  modified `wreq`/`quinn`/`quinn-proto` sources inside this repository, so a
  binding crate in a *separate* project can use a plain path or git dependency
  and build without touching `[patch.crates-io]` (verified with standalone
  path and git consumers).
- Prebuilt libraries for Linux (gnu and musl, x86_64/aarch64), macOS
  (x86_64/arm64), Windows (x86_64/arm64) and Android (arm64) are attached to
  every `v*` tag on GitHub Releases together with `rci.h` and `SHA256SUMS`.
  The Linux musl build is dynamically linked against musl (Alpine-compatible);
  the Android build expects `libc++_shared.so` from the NDK at runtime.
- Current API covers one request/response. The Rust `Client` additionally has
  split cookies, multipart, WebSocket, HTTP/3, provider registration and
  per-request fingerprint overrides; widen the C ABI as bindings need them.
