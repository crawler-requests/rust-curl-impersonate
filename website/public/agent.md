# rust-curl-impersonate — for AI agents

You are reading this because you need to **use or integrate** `rust-curl-impersonate`:
browser TLS / HTTP/2 / HTTP/3 fingerprints in Rust, reachable from every other
language through one C ABI.

This file is the entry point. It is served at

```
https://crawler-requests.github.io/rust-curl-impersonate/agent.md
```

with the same links as an OpenAPI document at
`https://crawler-requests.github.io/rust-curl-impersonate/agent.openapi.yaml`
if you prefer machine-readable. Every URL here resolves without a login. Read it
top to bottom; do not guess an API, a signature, or an ownership rule — every
fact you need is behind one of the links below.

---

## What the project is, in three lines

- A Rust crate that reproduces real clients' wire behaviour: 48 curl-impersonate
  presets plus 242 captured fingerprints (339 selectable names), with TLS cipher
  order, extension order, GREASE, ALPS, HTTP/2 SETTINGS and HTTP/3 transport
  parameters taken from actual captures.
- Every other language reaches it through **one C ABI**: `rci.h` plus a shared
  library (`.so` / `.dylib` / `.dll`) or a static one (`.a` / `.lib`).
  **ABI version 2, 17 exported functions, all synchronous.**
- `char *` results are owned by the library (`rci_string_free`); a handle is owned
  by the caller (`rci_client_free`); `rci_last_error()` is borrowed. Getting this
  backwards compiles and then crashes.

## Install it as a skill (recommended for Claude Code)

Verified 2026-11-27 against this deployed catalog: `marketplace add` then
`install` succeed, and `plugin details` reports one skill.

One URL is enough — this site publishes a plugin marketplace manifest, and
the plugin archive it points at is a static file next to it:

```sh
claude plugin marketplace add https://crawler-requests.github.io/rust-curl-impersonate/.claude-plugin/marketplace.json
claude plugin install rust-curl-impersonate-native@rust-curl-impersonate
```

The same plugin is also on the skills repository, if you prefer a git source:

```sh
claude plugin marketplace add crawler-requests/rust-curl-impersonate-skills
claude plugin install rust-curl-impersonate-native@rust-curl-impersonate-skills
```

The plugin ships the procedure, the C ABI contract, four scripts and two working
bindings (ctypes and JNA). After it is installed, a request like *"use
rust-curl-impersonate from Java"* triggers it. The plugin registry is read at
session start, so the skill appears in the session after the install.

No plugin support (another agent runtime, or git is unreachable)? The same
skill is published as plain files on this site, so fetch the procedure and
the contract directly:

```sh
$ mkdir -p rci-skill
$ curl -fsSL https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/SKILL.md \
    -o rci-skill/SKILL.md
$ curl -fsSL https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/references/api.md \
    -o rci-skill/api.md
```

Read `SKILL.md`, follow its five steps, and pull any script or binding it names
from the table below with the same `curl`. Nothing in that path needs a git
checkout or a login.

## The contract, without the skill

Read these in order. Each is plain text or markdown served by this site, so a
network that blocks raw.githubusercontent.com or github.com still works.

| What | URL |
|---|---|
| The marketplace manifest (for `plugin marketplace add`) | `https://crawler-requests.github.io/rust-curl-impersonate/.claude-plugin/marketplace.json` |
| The plugin archive the manifest installs (static file) | `https://crawler-requests.github.io/rust-curl-impersonate/rust-curl-impersonate-native.zip` |
| The plugin manifest | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/.claude-plugin/plugin.json` |
| The procedure (5 steps, decisions, hard rules) | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/SKILL.md` |
| The C ABI contract: 17 functions, JSON shapes, ownership | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/references/api.md` |
| Symptom → cause | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/references/troubleshooting.md` |
| Per-language notes (python, java, go, node, php, csharp, swift, android, c, rust) | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/references/languages/<language>.md` |
| Authoritative C header | `https://crawler-requests.github.io/rust-curl-impersonate/rci.h` |
| Full per-language walkthrough (C, C++, Python, Node, Go, Java, PHP, C#, Swift) | `https://crawler-requests.github.io/rust-curl-impersonate/docs/embedding.md` |
| Building a wrapper library on top of this one | `https://crawler-requests.github.io/rust-curl-impersonate/docs/wrapper-guide.md` |
| Rust API overview | `https://crawler-requests.github.io/rust-curl-impersonate/README.md` |

Ready-made bindings, downloadable as single files:

| What | URL |
|---|---|
| ctypes binding (reads `rci.h` at load, applies all 17 signatures) | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/assets/python/rci_bindings.py` |
| The binding's test suite | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/assets/python/tests/test_rci_bindings.py` |
| Offline test server | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/assets/python/testserver.py` |
| JNA binding, entry point (standalone Maven project) | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/assets/java/README.md` |
| JNA binding, declarations | `https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/assets/java/src/main/java/io/github/crawlerrequests/impersonate/RciLibrary.java` |

## Get the library

Prebuilt for 18 targets, each archive carrying `include/rci.h`, the shared and the
static library, the Python binding, the Java project and `EMBEDDING.md`:

```
https://github.com/crawler-requests/rust-curl-impersonate/releases
```

The skill's `fetch_library.py` resolves the newest release through the GitHub API,
picks the target from the host (musl vs glibc included), resumes the download,
checks it against `SHA256SUMS`, and unpacks to `rci/`:

```sh
$ curl -fsSLO https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/scripts/fetch_library.py
$ python3 fetch_library.py                    # this host, newest release
$ python3 fetch_library.py --target aarch64-linux-android
$ python3 fetch_library.py --target aarch64-apple-ios
```

Do not invent a target name. The 18 targets are listed in `SKILL.md`; armv7-musl
and i686-musl do not exist upstream.

Rust callers skip the ABI entirely:

```toml
[dependencies]
rust-curl-impersonate = { git = "https://github.com/crawler-requests/rust-curl-impersonate" }
```

No registry patch is needed: the modified `wreq` / `quinn` sources live inside
that repository.

## Prove it worked (do not skip this)

A binding that compiles is not an integration. Offline first:

```sh
$ curl -fsSLO https://crawler-requests.github.io/rust-curl-impersonate/skills/rust-curl-impersonate-native/scripts/verify_abi.py
$ python3 rci/python/testserver.py 8765 &
$ python3 verify_abi.py --lib rci/lib            # 15 checks: 17 exports, ABI >= 2, 48 presets, error paths
$ python3 -m pytest rci/python/tests -q          # the shipped binding
```

Then against the public echo service, with the `chrome150` preset:

```sh
$ python3 verify_abi.py --lib rci/lib --echo
```

```text
ja4:    t13d1516h2_8daaf6152771_d8a2da3f94cd
akamai: 1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p
```

If those two values do not match, the profile's bytes are not leaving the
machine. Fix that before writing any wrapper code.

## Five behaviours that break wrappers

1. `char *` results are library-owned (`rci_string_free`); only
   `rci_client_new*` returns `NULL`; every other call returns JSON, errors as
   `{"error": "..."}`.
2. Non-UTF-8 bodies come back as **lowercase hex** with `body_is_text: false`.
   Decode them; never treat them as text.
3. Redirects are **not** followed by default (a 302 comes back as a 302). Only
   `follow_safe` follows; `follow_redirects` currently changes nothing.
4. Reuse a handle. It owns the connection pool and the cookie jar;
   `rci_get` builds and frees one per call, so it keeps nothing. HTTPS with a
   fresh handle per request medians ~582 ms against ~149 ms reused.
5. `version` in the response is what the server negotiated, not what the profile
   can do. A profile's HTTP/3 capability is
   `rci_profile_info(name).has_http3`.

## If you are writing an SDK on top of this

Read
[`docs/wrapper-guide.md`](https://crawler-requests.github.io/rust-curl-impersonate/docs/wrapper-guide.md)
before choosing a design: it covers which path to take, what a wrapper has to
add (handle lifetime, binary-safe bodies, one error model, ownership), where
cross-request state lives, how to widen the ABI, and an acceptance checklist.
