# C and C++

Verified working: dynamic link with `gcc`, static link with both
`g++ -x c` and `cc … -lstdc++`.

## C

```c
#include <stdio.h>
#include "rci.h"

int main(void) {
    printf("abi %u\n", rci_version());

    RciClient *client = rci_client_new("chrome150");
    if (!client) { printf("err: %s\n", rci_last_error()); return 1; }

    char *reply = rci_request_with(client, "GET", "https://example.com",
                                   "[[\"accept-language\",\"zh-CN\"]]", NULL);
    printf("%.200s\n", reply);          /* {"status":200,...} */
    rci_string_free(reply);
    rci_client_free(client);
    return 0;
}
```

## C++

```cpp
#include <cstdio>
#include "rci.h"

int main() {
    char *profiles = rci_profiles();
    std::printf("%.60s...\n", profiles);
    rci_string_free(profiles);
}
```

## Linking

Dynamic:

```sh
gcc -I rci/include main.c -L rci/lib -lrust_curl_impersonate_ffi \
    -Wl,-rpath,'$ORIGIN/rci/lib' -o app
```

Static — **the static archive bundles BoringSSL, which is C++**, so it must be
linked by a C++ driver:

```sh
g++ -x c main.c -x none -I rci/include -L rci/lib \
    -l:librust_curl_impersonate_ffi.a -lpthread -ldl -lm -o app
```

Or keep the C compiler and add the C++ runtime explicitly:

```sh
cc main.c -I rci/include -L rci/lib \
   -l:librust_curl_impersonate_ffi.a -lstdc++ -lpthread -ldl -lm -o app
```

MSVC: `cl main.c rust_curl_impersonate_ffi.lib` (MSVC brings the C++ runtime).

## Notes

- The dynamic library also needs `libstdc++` / `libgcc_s` on Linux. A `scratch`
  or C++-less Alpine image needs `libstdc++`, or use the static form.
- `body_len` is `size_t`; pass `0` and a `NULL` body for "no body".
- Compile-check the header exactly as a consumer would:

```sh
printf '#include "rci.h"\nint main(void){return 0;}\n' > /tmp/h.c
cc  -Wall -Wextra -Werror -I rci/include -o /tmp/h-c   /tmp/h.c
c++ -Wall -Wextra -Werror -I rci/include -x c++ -o /tmp/h-cxx /tmp/h.c
```
