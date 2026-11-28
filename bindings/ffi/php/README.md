# PHP binding

A PHP 7.4+ binding for the rust-curl-impersonate C ABI (ABI v2), using the FFI
extension (`php -m | grep ffi`).

```php
require 'rci.php';
$rci = new Rci('/path/to/librust_curl_impersonate_ffi.so');
$client = $rci->client('chrome150', ['timeout_ms' => 10000]);
$reply = $client->get('https://tls.peet.ws/api/all');
echo $reply->status, ' ', $reply->version, "\n";
$client->close();
```

## What it adds over the raw ABI

- **Declarations**: PHP's `FFI::cdef` cannot read `rci.h` (comments, `#include`),
  so the 17 prototypes are written once inside `rci.php`. `tests.php` compares
  those names against `rci.h`, which is the gate that keeps the copy honest.
- **Ownership**: `Rci::text()` frees every library string; `rci_last_error` is
  read (never freed) in one place.
- **Errors**: `{"error": ...}` becomes an `RciError`, and a `__destruct` closes
  the handle so an exception cannot leak it.
- **Binary bodies**: `RciResponse::content()` hex-decodes when the library
  reports a non-UTF-8 body.

## Tests

Plain PHP, no PHPUnit:

```sh
python3 python/testserver.py 8765 &
RCI_LIB=./lib/librust_curl_impersonate_ffi.so RCI_HEADER=./include/rci.h php tests.php
```

Set `PHP_NETWORK=1` to include the `http1_only` negotiation check, which needs
the public internet.
