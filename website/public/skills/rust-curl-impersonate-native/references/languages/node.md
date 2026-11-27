# Node.js (koffi)

Verified working with koffi 3.x — returns HTTP/1.1 200.

```js
import koffi from "koffi";

const lib = koffi.load("./rci/lib/librust_curl_impersonate_ffi.so");
const rci_get = lib.func("void *rci_get(const char *profile, const char *url)");
const rci_string_free = lib.func("void rci_string_free(void *p)");

const pointer = rci_get("chrome150", "https://example.com");
const reply = JSON.parse(koffi.decode(pointer, "char", -1));
rci_string_free(pointer);
console.log(reply.status, reply.version, reply.headers.length);
```

## The one rule that matters

Declare the return type as **`void *`**, not `str`. If you declare it `str`,
koffi takes ownership of the string and frees it itself; the explicit
`rci_string_free` then double-frees and the process aborts. `ffi-napi` has the
same trap — take the raw pointer.

## Full declarations

```js
const lib = koffi.load(path);
const rci_version = lib.func("uint32 rci_version()");
const rci_profiles = lib.func("void *rci_profiles()");
const rci_client_new = lib.func("void *rci_client_new(const char *profile)");
const rci_client_new_with_options =
  lib.func("void *rci_client_new_with_options(const char *profile, const char *options)");
const rci_client_free = lib.func("void rci_client_free(void *handle)");
const rci_request = lib.func(
  "void *rci_request(void *h, const char *method, const char *url, const uint8_t *body, size_t len)");
const rci_string_free = lib.func("void rci_string_free(void *p)");
```

`rci_last_error` can be declared `str` (it is borrowed and must not be freed).

## Binary bodies

`Buffer` handles the hex form; decode with `Buffer.from(reply.body, "hex")`
when `reply.body_is_text` is false.

## Library path

Node loads by absolute path or by name; if you ship the `.so` beside your app,
pass its path explicitly, or set `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH`.

## Test

```sh
python3 scripts/local_echo_server.py 8765 &
node -e '...'   # or point rci_get at http://127.0.0.1:8765/index.html
```
