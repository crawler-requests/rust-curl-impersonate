# Python (ctypes)

Verified working. The archive ships `python/rci_bindings.py`, a full binding
(and a copy is in this skill's `assets/python/`). Copy it into the project
rather than writing a new ctypes layer.

## Use the shipped binding

```python
from rci_bindings import Client            # rci_bindings.py in the project

with Client("chrome150", timeout_ms=10_000) as client:
    reply = client.get("https://tls.peet.ws/api/all")
    print(reply.status, reply.version, reply.header("server"))
    print(reply.text[:200] if reply.body_is_text else len(reply.content))
```

Point it at the library with `Library(path=...)` or `RCI_LIB`; otherwise it
looks in `../lib`, `./lib`, and `target/release`.

What it does for you:

- parses `rci.h` at load time and applies all 17 ctypes signatures, so a new
  function in the header appears without touching the binding;
- `restype = c_void_p` for every `char *` result, and `c_char_p` for the
  borrowed `rci_last_error`;
- `Response.content` decodes the lowercase-hex binary body;
- `Client.request` picks `rci_request` vs `rci_request_with`; it raises
  `ValueError` for per-request headers + binary body, a combination the ABI
  does not have;
- raises `RciError` carrying the library's `{"error": ...}` text.

## Minimal hand-written ctypes (when you do not want the class)

```python
import ctypes, json

lib = ctypes.CDLL("./rci/lib/librust_curl_impersonate_ffi.so")
lib.rci_get.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.rci_get.restype = ctypes.c_void_p          # NOT c_char_p
lib.rci_string_free.argtypes = [ctypes.c_void_p]

pointer = lib.rci_get(b"chrome150", b"https://example.com")
reply = json.loads(ctypes.string_at(pointer).decode())
lib.rci_string_free(pointer)
print(reply["status"], reply["version"])
```

`restype = c_char_p` copies the string and discards the original pointer; the
`rci_string_free` that follows then frees memory the library never handed out.
This is the single most common ctypes crash with this ABI.

## Generate every declaration from the header

```sh
python3 scripts/gen_declarations.py --header rci/include/rci.h --ctypes
```

## Binary bodies

```python
body = bytes.fromhex(reply["body"]) if not reply["body_is_text"] else reply["body"].encode()
```

## Test

```sh
python3 scripts/local_echo_server.py 8765 &
python3 -m pytest python/tests -q          # from the binding's directory
```

The tests cover status, hex decoding, POST + per-request headers, header
suppression, unknown option/profile rejection, redirect policy, `last_headers`,
`rci_load_fingerprints`, and an optional HTTP/3 case.
