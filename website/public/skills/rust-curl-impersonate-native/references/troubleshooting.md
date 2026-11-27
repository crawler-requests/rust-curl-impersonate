# Troubleshooting a native integration

Symptom → cause → fix. Every entry comes from a real failure seen while
integrating this ABI.

## The library is not found at runtime

```
java.lang.UnsatisfiedLinkError: librust_curl_impersonate_ffi.so: cannot open shared object file
OSError: ... cannot open shared object file: No such file or directory
System.DllNotFoundException
```

Linux: set an rpath when linking (`-Wl,-rpath,'$ORIGIN/rci/lib'`) or
`LD_LIBRARY_PATH`. macOS: `@rpath` or `DYLD_LIBRARY_PATH`. Windows: the `.dll`
must sit beside the `.exe`. Java/Python/Node can also be given the absolute
path (`rci.lib`, `RCI_LIB`, `app.func(...)`) — prefer that over guessing.

**Do not** copy random system libraries into the build; that hides a missing
`libstdc++` today and breaks on another machine tomorrow.

## Crash on free, or garbage in the returned string

- ctypes: the `char *` result was declared `c_char_p`. ctypes copied the string
  and dropped the original pointer; `rci_string_free` then freed memory the
  library never handed out. Declare `c_void_p`.
- JNA: the result was declared `String`. Same problem. Declare `Pointer`.
- Node/koffi: the result was declared `str` instead of `void *`; koffi frees it,
  and the explicit `rci_string_free` double-frees.
- You freed `rci_last_error()` — it is borrowed. Never free it.

## "unknown profile …"

The name is not in `rci_profiles()`. Print that list instead of guessing.
Presets are the 48 curl-impersonate targets (`chrome150`, `firefox147`, …);
library records are additional names (`go1.26`, `python3.12_requests`, …).

## Client is `NULL` and the error is "invalid options: unknown field …"

`rci_client_new_with_options` uses `deny_unknown_fields`: a typo in a key is an
error, not ignored. The valid keys are `timeout_ms`, `proxy`,
`follow_redirects`, `follow_safe`, `pool_max_idle_per_host`, `headers`,
`split_cookies`, `http1_only`.

## The request "succeeds" but the server answers 302

Redirects are **not followed by default**. Pass `follow_safe: true` (refuses
loopback/private targets) or `follow_safe: false` (follows without the filter).
`follow_redirects` does not currently change behaviour.

## `{"error":"HTTP/3 is unavailable"}`

The profile has no QUIC record. Check `rci_profile_info(name).has_http3` first.
There is no silent fallback to HTTP/2 by design.

## Body looks like gibberish

`body_is_text` is false → the body is **lowercase hex**. Decode it. A text
parser on the hex string produces nonsense, not an error.

## Static link: undefined references to C++ symbols

The static archive contains BoringSSL (C++). Link with a C++ driver:

```sh
g++ -x c main.c -x none -L rci/lib -l:librust_curl_impersonate_ffi.a \
    -lpthread -ldl -lm -o app
# or
cc main.c -L rci/lib -l:librust_curl_impersonate_ffi.a -lstdc++ -lpthread -ldl -lm
```

Go: the external linker must be a C++ driver (`CXX=g++`) when linking the `.a`.

## Android: `libc++_shared.so` not found

The **shared** Android build needs the NDK's `libc++_shared.so`. Either ship it
in `jniLibs`, set `ANDROID_STL=c++_shared`, or switch to the static `.a` (which
does not need it).

## `verify_abi.py` reports a fingerprint mismatch

`--echo` asserts JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd` and Akamai h2
`1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p` for `chrome150`. A mismatch
means the profile's bytes did not go out: wrong profile name, or a proxy in
front rewriting TLS. Fix that before writing more wrapper code — everything
downstream depends on it.

## `armv7-musl` / `i686-musl` archive missing

They are not built: the upstream `btls` crate does not compile its i64→time_t
call on 32-bit musl. Use the glibc build of the same architecture.
