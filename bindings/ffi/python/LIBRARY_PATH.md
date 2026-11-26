# Using this archive

This archive contains the `rust-curl-impersonate` C ABI library, in both
forms an embedder needs.

```
include/rci.h   C header for every language that binds to the C ABI
lib/            the shared library and the static library
python/demo.py  a ctypes binding you can copy into a project
bin/echo        a host-tool smoke binary (desktop/server targets only)
```

## Shared or static

Pick the form that matches how your program is built:

| Form | File | When |
|---|---|---|
| Shared | `librust_curl_impersonate_ffi.so` / `.dylib` / `.dll` | The library ships beside your binary and the loader finds it at runtime. This is what Python, Node, Java and most FFI layers load. |
| Static | `librust_curl_impersonate_ffi.a` / `.lib` | You link it into your own binary, so there is nothing to find at runtime. This is the normal choice for a mobile app, a single-file CLI, or anything that must not ship a loose `.so`. |

The static library contains BoringSSL, which is C++. **Link it with a C++
driver**, or add the C++ runtime:

```sh
# C source, C++ linker:
g++ -x c main.c -x none -L lib -l:librust_curl_impersonate_ffi.a \
    -lpthread -ldl -lm -o app

# Or keep your C driver and add the C++ runtime explicitly:
cc main.c -L lib -l:librust_curl_impersonate_ffi.a -lstdc++ -lpthread -ldl -lm
```

On iOS and Android the static form is the one to use: a dynamic library
inside an app bundle is either restricted (iOS) or awkward to package
(Android), while a static archive links straight into the app.

## Python

`python/demo.py` finds the library through `RCI_LIB`, so point it at this
archive's `lib/` directory:

```sh
RCI_LIB=/path/to/lib/librust_curl_impersonate_ffi.so \
  python3 python/demo.py chrome150 https://tls.peet.ws/api/all
```

`RCI_LIST=1` prints the selectable profiles instead of sending a request.

## Other languages

- **C / C++**: `#include "rci.h"`, link `lib/`, set a runtime search path
  (rpath) to the shared library, or link the static one directly.
- **Go**: cgo with `#cgo LDFLAGS: -L${SRCDIR}/lib -lrust_curl_impersonate_ffi`.
- **Java**: JNA or Panama against `rci.h`.
- **Node**: `koffi` or `ffi-napi` against the shared library.
- **Swift / Objective-C**: link the static `.a` (iOS) or the `.dylib` (macOS).

Every call blocks on the calling thread; reuse one client handle per
thread/task. Strings this library returns must be freed with
`rci_string_free`. See `README.md` for the full function list.
