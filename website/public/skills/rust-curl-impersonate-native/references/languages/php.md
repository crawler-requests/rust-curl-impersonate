# PHP (FFI, 7.4+)

Verified working — returns HTTP/1.1 200. Requires the `ffi` extension
(`php -m | grep ffi`).

```php
<?php
$lib = FFI::cdef("
typedef struct RciClient RciClient;
uint32_t rci_version(void);
char *rci_profile_info(const char *profile);
char *rci_get(const char *profile, const char *url);
void rci_string_free(char *text);
", "/path/to/rci/lib/librust_curl_impersonate_ffi.so");

echo "abi ", $lib->rci_version(), "\n";
$pointer = $lib->rci_get("chrome150", "https://example.com");
echo substr(FFI::string($pointer), 0, 200), "\n";
$lib->rci_string_free($pointer);
```

## Why the declarations are inlined

`FFI::cdef` parses C declarations but not `#include` or comments, so you cannot
point it at `rci.h` directly — inline the prototypes. Keep the names and types
identical to the header; generate them with:

```sh
python3 scripts/gen_declarations.py --header rci/include/rci.h --list
```

## Ownership

- `char *` results → `FFI::string($p)` copies the bytes, then
  `rci_string_free($p)`.
- Declare `char *` results as `char *` (FFI keeps the pointer); `FFI::string()`
  does not free.

## Binary bodies

```php
$body = $reply['body_is_text'] ? $reply['body'] : hex2bin($reply['body']);
```

## Loading

`FFI::cdef` needs an absolute path (or a library found on the loader path).
For a PHP-FPM deployment, set `LD_LIBRARY_PATH` for the pool, or place the
library where the loader searches.
