# Running the Go binding's tests

The tests talk to a local HTTP server so they need no network.

```sh
# 1. a library to link against (release archive, or the repository build)
ARCH=/path/to/rust-curl-impersonate-ffi-<version>-<target>

# 2. the offline test server (same one the other bindings use)
python3 "$ARCH/python/testserver.py" 8765 &

# 3. build and test, pointing cgo at the archive
cd bindings/ffi/go
CGO_LDFLAGS="-L$ARCH/lib -lrust_curl_impersonate_ffi -Wl,-rpath,$ARCH/lib" \
  go test ./...
```

`RCI_BASE` overrides the server base URL (default `http://127.0.0.1:8765`).
`TestHTTP1OnlyForcesHTTP1` needs the public internet to prove the negotiation
and skips when it is unreachable.
