# Go (cgo)

Verified working — returns 200 through the C ABI.

```go
package main

/*
#cgo LDFLAGS: -L${SRCDIR}/rci/lib -lrust_curl_impersonate_ffi -Wl,-rpath,${SRCDIR}/rci/lib
#include <stdint.h>
#include <stdlib.h>
extern uint32_t rci_version(void);
extern char *rci_get(const char *profile, const char *url);
extern void rci_string_free(char *text);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

func main() {
	fmt.Println("abi", uint32(C.rci_version()))

	profile := C.CString("chrome150")
	url := C.CString("https://tls.peet.ws/api/all")
	defer C.free(unsafe.Pointer(profile))
	defer C.free(unsafe.Pointer(url))

	out := C.rci_get(profile, url)
	defer C.rci_string_free(out)              // the library owns this string

	var reply map[string]any
	json.Unmarshal([]byte(C.GoString(out)), &reply)
	fmt.Println(reply["status"], reply["version"])
}
```

Generate the full extern block from the header instead of typing it:

```sh
python3 scripts/gen_declarations.py --header rci/include/rci.h --go
```

## Ownership

- `C.CString(...)` you create → free with `C.free`.
- Strings the library returns → `C.rci_string_free`. `defer` it right after the
  call so a panic cannot leak.
- Handles → `C.rci_client_free(unsafe.Pointer(handle))`.

## Linking notes

- `-Wl,-rpath,${SRCDIR}/rci/lib` makes the binary find the shared library
  without `LD_LIBRARY_PATH`. A relative rpath is fine for a `go run .` in place.
- For a single static binary, link `rci/lib/librust_curl_impersonate_ffi.a`
  with the C++ runtime: add `-lstdc++ -lpthread -ldl -lm` and prefer `CXX`
  set to `g++`. Go's external linker must be a C++ driver.
- Go modules: the library path in `LDFLAGS` is absolute at build time; ship the
  `.so` next to the binary for anything you distribute.
