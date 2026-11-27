---
name: rust-curl-impersonate-native
description: Use when integrating rust-curl-impersonate as a native library from a non-Rust language (Python, Java/Kotlin, Go, Node, PHP, C#, Swift, C/C++, Android), or when asked which functions and signatures the C ABI exposes or how to load the .so/.dll/.dylib/.a. Covers downloading the right release archive for the host or mobile target, verifying the ABI before writing code, generating a binding from rci.h, and proving the fingerprint reaches the wire.
---

# Integrate rust-curl-impersonate as a native library

The fingerprint logic exists once, in Rust. Every other language talks to it
through **one C ABI**: a shared library (`.so` / `.dylib` / `.dll`) or a static
one (`.a` / `.lib`) plus `rci.h`, with **17 exported functions in ABI v2**.

This skill is the working procedure. It exists because a C ABI has no
reflection: an agent that guesses at signatures, ownership, or the JSON shapes
produces code that compiles and then crashes or silently loses bytes. Do not
guess — read `references/api.md`, then verify with the scripts.

## Decision: which form and which language

| The caller is | Use | Reference |
|---|---|---|
| Python | `ctypes` binding that ships in the archive | `references/languages/python.md` |
| Java / Kotlin (JVM) | JNA project that ships in the archive | `references/languages/java.md` |
| Android (Kotlin/Java) | `.so` into `jniLibs`, or NDK + JNI; static `.a` avoids `libc++_shared.so` | `references/languages/android.md` |
| Go | cgo over the shared library | `references/languages/go.md` |
| Node.js | `koffi` (or `ffi-napi`) | `references/languages/node.md` |
| PHP | `FFI::cdef` (PHP 7.4+) | `references/languages/php.md` |
| C# / .NET | `DllImport` + `IntPtr` | `references/languages/csharp.md` |
| Swift / iOS / macOS | static `.a` (iOS must not ship a dylib) | `references/languages/swift.md` |
| C / C++ | `#include "rci.h"` | `references/languages/c.md` |
| Rust | skip this ABI; depend on the crate | `references/languages/rust.md` |

**Dynamic vs static.** Runtime-loaded languages (Python, Java, Node, PHP, C#)
need the shared library beside the app or on the loader path (rpath /
`LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` / same dir as the `.exe`). Anything that
ships as a single binary or an app bundle (iOS, Android app, CLI) should link
the **static** library — and then it **must be linked with a C++ linker**,
because BoringSSL is C++ (see `references/languages/c.md`).

## Step 1 — get the library for the right target

```sh
python3 scripts/fetch_library.py                 # newest release, this host → ./rci
python3 scripts/fetch_library.py --dest vendor/rci
python3 scripts/fetch_library.py --target aarch64-linux-android   # Android
python3 scripts/fetch_library.py --target aarch64-apple-ios       # iOS
```

It picks the target from the host (including musl vs glibc), resolves the
release through the GitHub API, downloads with resume, checks the SHA-256
against `SHA256SUMS`, and unpacks to `rci/`:

```
rci/include/rci.h        authoritative C declarations
rci/lib/                 shared + static library
rci/python/              rci_bindings.py (full ctypes binding) + tests
rci/java/                standalone Maven project (JNA) + JUnit tests
rci/EMBEDDING.md         the per-language guide
```

18 targets: Linux glibc/musl x86_64+aarch64, Linux armv7hf and i686 (glibc
only), macOS x86_64/arm64, Windows x86_64/arm64/i686, Android 4 ABIs, iOS
device + 2 simulators. `armv7-musl` and `i686-musl` do not exist: the upstream
`btls` crate does not compile on 32-bit musl.

**Do not invent a target name.** If the user's platform is not in the table,
say so and name the closest published one instead of downloading the wrong
library.

## Step 2 — verify the ABI before writing any code

```sh
python3 scripts/verify_abi.py --lib rci/lib            # 15 offline checks
python3 scripts/verify_abi.py --lib rci/lib --echo     # + a live request
```

It proves what wrappers otherwise find out at runtime: all 17 exports present,
`rci_version() >= 2`, 48 presets, `NULL` handle/string handling, unknown
profile and unknown option errors, and — with `--echo` — that the JA4 and
Akamai h2 fingerprints on `tls.peet.ws` match the `chrome150` capture. If the
fingerprints do not match, the profile's bytes are not going out; stop and fix
that before integrating anything.

## Step 3 — learn the real contract (do not guess)

Read `references/api.md` before writing a binding. The five things that break
wrappers most often:

1. **`char *` results are owned by the library** — free them with
   `rci_string_free`. In ctypes that means `restype = c_void_p` (never
   `c_char_p`); in JNA `Pointer` (never `String`). `const char *rci_last_error()`
   is the opposite: borrowed, never free it.
2. **`rci_client_new*` is the only function that returns `NULL`.** Every query
   and request returns a JSON object, errors included (`{"error": "..."}`).
3. **Binary bodies come back as lowercase hex** with `body_is_text: false` —
   decode it, never treat it as text.
4. **Redirects are not followed by default.** `follow_safe: true` follows and
   refuses loopback/private targets; `follow_safe: false` follows without the
   filter. `follow_redirects` does not currently change behaviour.
5. **One handle per thread.** Every call blocks. Reuse one handle; do not call
   `rci_get` in a loop.

## Step 4 — integrate with the shipped binding when one exists

Do not write a new ctypes/JNA layer from scratch if the archive already has one:

- **Python**: copy `rci/python/rci_bindings.py` into the project (it parses
  `rci.h` at load time and applies all 17 signatures). Its `Client`,
  `Profile`, `Response` types already decode hex bodies and raise on errors.
- **Java**: copy `rci/java/` (or run `mvn package` there) and depend on JNA.

For every other language, generate the declarations from the header instead of
typing them from memory:

```sh
python3 scripts/gen_declarations.py --java       # Java interface methods
python3 scripts/gen_declarations.py --go         # a compilable cgo extern block
python3 scripts/gen_declarations.py --list       # the full signature table
```

`--header` defaults to `rci/include/rci.h`, so the commands work straight
after `fetch_library.py`. Point it elsewhere with
`--header /path/to/rci.h`.

Then follow the language reference for the ownership rules that language needs.

## Step 5 — prove the integration

A binding that compiles is not an integration. Run the language's own test
against a local echo endpoint first, then against the public echo service:

```sh
python3 scripts/local_echo_server.py 8766 &          # offline smoke, any port works
# Python (tests default to 8765; pass the port you started)
RCI_BASE=http://127.0.0.1:8766 python3 -m pytest rci/python/tests -q
# Java (same: the tests default to 8765, so RCI_BASE is part of the command)
cd rci/java && RCI_LIB=$PWD/../lib/librust_curl_impersonate_ffi.so \
  RCI_BASE=http://127.0.0.1:8766 mvn -q test
```

The server serves `/`, `/index.html`, `/echo`, `/redirect`, `/binary` and
`/rci-smoke.bin` on whatever port you give it; 8766 is just the example.
`RCI_BASE` is required whenever the port is not 8765 (the tests' default).
`mvn package` runs the tests too: add `-DskipTests` if no server is running.

Success for a Java/Python/Go/Node wrapper means: status 200, a `version`
field, and — against `https://tls.peet.ws/api/all` with `chrome150` — JA4
`t13d1516h2_8daaf6152771_d8a2da3f94cd` and Akamai h2
`1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p`.

## When something fails

`references/troubleshooting.md` maps the usual symptoms to causes: library not
found at runtime, crash on free, `unknown profile`, HTTP/3 unavailable, a
static link that fails to resolve C++ symbols, Android `libc++_shared.so`
missing. Do not work around a loader error by copying random system libraries;
fix the rpath/loader path or switch to the static form.

## Hard rules

- Never fabricate a function name, signature, or JSON field. The authoritative
  list is `rci/include/rci.h` and `references/api.md`.
- Never hand-write a "close enough" ctypes/JNA declaration from memory when
  `scripts/gen_declarations.py` can produce it from the header.
- Never claim the integration works without running it; a successful compile is
  not evidence, a 200 with the reference fingerprints is.
