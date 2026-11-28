# C and C++ bindings

`rci.h` is the complete C API; nothing else is needed to call it. `rci.hpp` is
an optional header-only C++17 convenience layer.

```c
#include "rci.h"

RciClient *client = rci_client_new("chrome150");
char *reply = rci_request(client, "GET", "https://example.com", NULL, 0);
puts(reply);                     /* {"status":200,...} or {"error":"..."} */
rci_string_free(reply);
rci_client_free(client);
```

```cpp
#include "rci.hpp"

rci::Library lib;
auto client = lib.client("chrome150");
const rci::Reply reply = client.get("https://example.com");
std::printf("%ld %s\n", reply.status, reply.version.c_str());
```

## What the C++ header adds

- **Ownership**: `rci::Owned` frees every library string in its destructor;
  `Client` is move-only so one handle is never freed twice.
- **Errors**: a NULL handle and an `{"error": ...}` reply both throw
  `rci::Error`; a closed `Client` throws instead of using a dangling pointer.
- **No JSON dependency**: it reads the flat keys the ABI returns (`status`,
  `version`, `url`, `body`, `body_is_text`) and exposes the raw JSON as
  `Reply::json` for the nested arrays, so a project keeps whichever JSON library
  it already has.

## Build and test

```sh
# C
gcc -I include main.c -L lib -lrust_curl_impersonate_ffi -Wl,-rpath,'$ORIGIN/lib'

# C++ (the library contains BoringSSL, which is C++, so use a C++ driver)
g++ -std=c++17 -Wall -Wextra -Werror -I include tests.cpp \
    -L lib -lrust_curl_impersonate_ffi -Wl,-rpath,$PWD/lib -o tests
python3 python/testserver.py 8765 &
./tests
```

The static library needs the same C++ runtime; see `USING_THIS_ARCHIVE.md`.
