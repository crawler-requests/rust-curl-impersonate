# Using this archive

This archive contains the `rust-curl-impersonate` C ABI shared library.

```
include/rci.h   C header for every language that binds to the C ABI
lib/            the shared library (and, on Windows, its import library)
python/demo.py  a ctypes binding you can copy into a project
bin/echo        a host-tool smoke binary (desktop/server targets only)
```

The library name is `librust_curl_impersonate_ffi.so` on Linux,
`librust_curl_impersonate_ffi.dylib` on macOS, and
`rust_curl_impersonate_ffi.dll` on Windows.

## Python

`python/demo.py` finds the library through `RCI_LIB`, so point it at this
archive's `lib/` directory:

```sh
RCI_LIB=/path/to/lib/librust_curl_impersonate_ffi.so \
  python3 python/demo.py chrome150 https://tls.peet.ws/api/all
```

`RCI_LIST=1` prints the selectable profiles instead of sending a request.

## Other languages

- **C / C++**: `#include "rci.h"`, link the library in `lib/`, set a runtime
  search path (rpath) to it.
- **Go**: cgo with `#cgo LDFLAGS: -L${SRCDIR}/lib -lrust_curl_impersonate_ffi`.
- **Java**: JNA or Panama against `rci.h`.
- **Node**: `koffi` or `ffi-napi` against the shared library.

Every call blocks on the calling thread; reuse one client handle per
thread/task. Strings this library returns must be freed with
`rci_string_free`. See `README.md` for the full function list.
