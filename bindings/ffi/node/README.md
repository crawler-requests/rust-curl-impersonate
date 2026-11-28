# Node binding

A Node wrapper for the rust-curl-impersonate C ABI (ABI v2) on top of
[koffi](https://koffi.dev) (a prebuilt FFI, so no native build tools are needed).

```sh
npm install
RCI_LIB=/path/to/librust_curl_impersonate_ffi.so node --test
```

```js
const { Rci } = require('./rci');

const rci = Rci.load();                       // RCI_LIB, then lib/
const client = rci.client('chrome150', { timeoutMs: 10_000 });
const reply = client.get('https://tls.peet.ws/api/all');
console.log(reply.status, reply.version, reply.body.length);
client.close();
```

## What it adds over the raw ABI

- **Ownership**: `char *` returns are declared `void *` and freed with
  `rci_string_free` inside `decode`; declaring them `char *` would let koffi
  copy and drop the pointer.
- **Errors**: `{"error": ...}` becomes a thrown `Error`.
- **Typed options**: the option names are checked before the ABI sees them, and
  the mapping is `timeoutMs` → `timeout_ms` rather than string assembly.
- **Library discovery**: `RCI_LIB`, `RCI_LIB_DIR`, and both the archive and the
  repository layout.

`Rci.load({ ffi: require('ffi-napi') })` swaps the FFI layer if a project
already uses one; the declarations are the same shape.

## Tests

`node --test` needs the offline server:

```sh
python3 python/testserver.py 8765 &
RCI_LIB=./lib/librust_curl_impersonate_ffi.so node --test
```

The `http1_only` check needs the public internet (`RCI_NETWORK=1`).
