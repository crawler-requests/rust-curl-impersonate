# Go binding

A Go wrapper for the rust-curl-impersonate C ABI (ABI v2), used through cgo.

```sh
# against a release archive
CGO_LDFLAGS="-L/path/to/lib -lrust_curl_impersonate_ffi -Wl,-rpath,/path/to/lib" go build
```

```go
import rci "github.com/crawler-requests/rust-curl-impersonate/bindings/ffi/go"

info, _ := rci.LookupProfile("chrome150")
client, err := rci.NewClient("chrome150", nil)
if err != nil { log.Fatal(err) }
defer client.Close()

reply, err := client.Get("https://tls.peet.ws/api/all")
if err != nil { log.Fatal(err) }
text, _ := reply.Text()
fmt.Println(reply.Status, reply.Version, len(text))
```

## What it adds over the raw ABI

- **Handle lifetime**: `Client.Close()` is idempotent and the type is usable
  with `defer`; a closed client refuses requests instead of passing a dangling
  pointer.
- **Error replies**: every `{"error": ...}` becomes a Go `error`, so callers check
  `err` and never look at an error payload by hand. `rci_last_error` is only read
  where the ABI actually writes it (handle construction).
- **Binary bodies**: `Response.Content()` hex-decodes when `BodyIsText` is false.
- **Typed options**: `Options` is a struct, so an unknown option key cannot be
  composed by accident; the library would refuse it anyway.
- **Same library discovery**: `RCI_LIB`, `RCI_LIB_DIR`, and the archive/`cargo
  build` layouts, so the same code works from an archive and from this repo.

## Tests

`go test ./...` needs the offline server (the same one the other bindings use):

```sh
python3 python/testserver.py 8765 &          # archive layout
CGO_LDFLAGS="-L$PWD/lib -lrust_curl_impersonate_ffi -Wl,-rpath,$PWD/lib" go test ./...
```

`TestHTTP1OnlyForcesHTTP1` needs the public internet and skips without it.
