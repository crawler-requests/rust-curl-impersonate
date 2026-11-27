# The C ABI — authoritative contract (ABI version 2)

Derived from `rci.h`; every statement here was verified against a built library.
17 functions, all `extern "C"`. Version 1 signatures and JSON shapes are unchanged in v2.

## Ownership rules (read these first — they are what crash wrappers)

| Return | Owner | Release |
|---|---|---|
| `char *` from any query/request function | the **library** | `rci_string_free(ptr)` |
| `const char *rci_last_error()` | **borrowed**, never free | — |
| `RciClient *` handle | the **caller** | `rci_client_free(handle)` |
| `NULL` passed to either free function | no-op, always safe | — |

Consequences per language:

- ctypes: declare `char *` results as **`c_void_p`**, never `c_char_p` (the
  latter copies and drops the original pointer, so freeing it releases memory
  the library never handed out). `rci_last_error` stays `c_char_p`.
- JNA: declare `char *` results as **`Pointer`**, never `String`. `rci_last_error`
  may be `String` because it is borrowed.
- Anything else: keep the raw pointer, read the bytes, then free.

## The 17 functions

```c
uint32_t      rci_version(void);                                    /* 2 */
char         *rci_targets(void);                                    /* 48 preset names, JSON array */
char         *rci_profiles(void);                                   /* presets + library records, JSON array */
char         *rci_profile_info(const char *profile);                /* JSON object or {"error":...} */
RciClient    *rci_client_new(const char *profile);                  /* NULL on unknown profile */
RciClient    *rci_client_new_with_options(const char *profile, const char *options_json);
void          rci_client_free(RciClient *handle);                   /* NULL is a no-op */
char         *rci_client_profile(RciClient *handle);                /* bare preset name, not JSON */
char         *rci_request(RciClient *h, const char *method, const char *url,
                          const uint8_t *body, size_t body_len);    /* body NULL when len 0 */
char         *rci_request_with(RciClient *h, const char *method, const char *url,
                               const char *headers_json, const char *body); /* body NUL-terminated string */
char         *rci_get(const char *profile, const char *url);        /* builds, sends, frees a client */
char         *rci_http3_get(const char *profile, const char *addr,
                            const char *host, const char *path);
char         *rci_client_last_headers(RciClient *handle);           /* JSON [name,value] pairs */
char         *rci_client_activity(RciClient *handle);               /* {"cookies":[..],"redirects":[..]} */
const char   *rci_last_error(void);                                 /* thread-local, do not free */
char         *rci_load_fingerprints(const char *json);              /* "{}" or {"error":...} */
void          rci_string_free(char *text);
```

**Only `rci_client_new*` returns `NULL`.** Every query and request function
returns a JSON object, including on failure (`{"error": "..."}`).

`rci_last_error()` records **client-construction failures only**. A failed
request does not update it — read the `error` field of the reply instead.

## Errors, exactly as they come back

Real strings from a built library:

```
rci_client_new("not-a-profile")                -> NULL, rci_last_error() = "unknown profile not-a-profile"
{"nonesuch":true} options                       -> NULL, "invalid options: unknown field `nonesuch`, expected one of `timeout_ms`, `proxy`, `follow_redirects`, `follow_safe`, `pool_max_idle_per_host`, `headers`, `split_cookies`, `http1_only`"
{"timeout_ms":"x"}                              -> NULL, "invalid options: invalid type: string \"x\", expected u64"
rci_profile_info("not-a-profile")               -> {"error":"unknown profile not-a-profile"}
rci_request(h, "BOG US", url, ...)              -> {"error":"invalid HTTP method"}
rci_request(h, "GET", "http://127.0.0.1:1/", ..)-> {"error":"...client error (Connect)"}
rci_http3_get("go1.26", ...)                    -> {"error":"HTTP/3 is unavailable"}
rci_http3_get(profile, "bad-addr", ...)         -> {"error":"resolve bad-addr: invalid socket address"}
rci_client_profile(NULL)                        -> {"error":"null client handle"}
```

## Response JSON

```json
{
  "status": 200,
  "version": "HTTP/2.0",
  "url": "https://example.com/",
  "headers": [["content-type","text/html"], ["server","nginx"]],
  "body": "...",
  "body_is_text": true
}
```

- `version`: `HTTP/0.9` / `HTTP/1.0` / `HTTP/1.1` / `HTTP/2.0` / `HTTP/3.0` / `unknown`.
- `url`: the final URL after redirects (unchanged when none were followed).
- `headers`: `[name, value]` pairs in arrival order; repeats appear as separate entries.
- `body_is_text: false` → `body` is **lowercase hex**; decode it, never parse as text.
- `rci_http3_get` returns `{status, headers, body, body_is_text}` — **no `version`
  and no `url`** (it is always HTTP/3). Do not index those fields.

## `options_json` keys (all optional; unknown keys are rejected)

| Key | Type | Default | Behaviour |
|---|---|---|---|
| `timeout_ms` | int | 30000 | total request timeout |
| `proxy` | string | — | `http://`, `https://`, `socks5://`, `socks5h://` |
| `follow_redirects` | bool | true | **currently does not change behaviour** (see below) |
| `follow_safe` | bool | — | `true` follows redirects and refuses loopback/private targets; `false` follows without the filter |
| `pool_max_idle_per_host` | int | — | idle connection cap |
| `headers` | `[["n","v"],…]` | `[]` | added to every request; same name replaces the preset's header, empty value suppresses it |
| `split_cookies` | bool | — | one `Cookie` header per cookie in HTTP/2 |
| `http1_only` | bool | — | force HTTP/1.1 |

`NULL`, `""`, `"{}"` and whitespace all mean "use defaults".

**Redirects are not followed by default.** A client built without options
returns the 302 itself. Setting `follow_safe` to `true` **or** `false` enables
following; the difference is the address filter, not whether to follow.
`follow_redirects` is accepted but currently has no effect — do not document it
to users as the way to follow redirects.

Verified header behaviour:

```
{"headers":[["accept-language","zh-CN"]]}   replaces only the preset's accept-language
{"headers":[["user-agent",""]]}             suppresses user-agent; other preset headers remain
{"headers":[["x-test","1"],["x-test","2"]]} last value wins (x-test: 2)
```

## `rci_profile_info` object

```json
{
  "name": "go1.26", "wire": "go1.26", "family": "go", "platform": "linux",
  "fidelity": "close",
  "deviation": "BoringSSL always sends the TLS 1.3 cipher suites before …",
  "http1_only": false, "has_http3": false,
  "source": "tls.peet.ws capture, tools/capture/raw/go1.26.json"
}
```

- `wire`: the preset whose bytes are actually sent (aliases point at their base).
- `fidelity`: `"exact"` / `"close"` / `"partial"` / `null` (built-in presets are `null`).
- `deviation`: one `; `-joined string describing fields that cannot be sent, or `null`.
- `has_http3`: whether `rci_http3_get` can work for this profile.
- Unknown names → `{"error":"unknown profile <name>"}`.

Verified values: `chrome150` → `family: chrome`, `has_http3: true`, `fidelity: null`.
`go1.26` → `family: go`, `fidelity: "close"`, `has_http3: false`.

## `rci_load_fingerprints`

Takes a library-schema document — one record `{...}`, a list `[...]`, or
`{"fingerprints":[…]}`. Validates the whole document before keeping anything;
a bad document is rejected entirely. A record whose name matches a built-in
one **overrides it for the life of the process** (user priority 100 beats builtin 0).
Returns `"{}"` on success.

Verified:

```
before: go1.26 source = "tls.peet.ws capture, tools/capture/raw/go1.26.json"
after : go1.26 source = "cloud.acme.example/fingerprints, overrides built-in go1.26 until unregistered"
new   : cloud_premium -> wire=chrome150, fidelity=exact
```

The record schema (fields for TLS, HTTP/2, HTTP/3, headers, multipart boundary,
cookie splitting) is in the upstream repository's `docs/provider-protocol.md`.

## Threading and blocking

- Every call blocks the calling thread until the response arrives.
- A handle is **not thread-safe**: one handle per thread.
- `rci_last_error` is thread-local.
- Reuse a handle; `rci_get` builds a runtime and connection pool each call.

## Reference fingerprints (chrome150, from a real capture)

Against `https://tls.peet.ws/api/all`:

```
JA4        t13d1516h2_8daaf6152771_d8a2da3f94cd
Akamai h2  1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p
```

A wrapper that reproduces these has the profile's bytes going out. One that
does not has not integrated the library, whatever it compiled.
