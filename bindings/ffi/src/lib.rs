//! C ABI over `rust-curl-impersonate`.
//!
//! Every function is synchronous from the caller's point of view: the handle
//! owns a Tokio runtime and blocks on the request. Errors are reported as a
//! JSON object with an `error` key, so a binding never has to translate Rust
//! error types. Strings returned by this library are owned by it; release them
//! with [`rci_string_free`].
//!
//! Build with `cargo build -p rust-curl-impersonate-ffi --release`; the shared
//! library lands in `target/release/librust_curl_impersonate_ffi.so` (or the
//! platform equivalent). `rci.h` is the matching header and
//! `python/demo.py` a ctypes consumer.

// The exported functions take raw pointers by contract: the ABI is fixed by
// `rci.h`, so they cannot be marked `unsafe fn` without changing what a C
// caller sees. Every dereference is inside a `SAFETY:` comment stating the
// caller obligation, same as libc.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr, CString};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use rust_curl_impersonate::fingerprint;
use rust_curl_impersonate::{redirect, Method, Profile, Version};

/// ABI version reported by [`rci_version`]. Bump when a signature or an
/// ownership rule changes.
const ABI_VERSION: u32 = 2;

/// Per-request timeout for a handle made without an explicit `timeout_ms`.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Opaque client handle. Created by [`rci_client_new`], freed by
/// [`rci_client_free`].
pub struct RciClient {
    client: rust_curl_impersonate::Client,
    runtime: tokio::runtime::Runtime,
    /// `false` makes every request stop at the first response.
    follow_redirects: bool,
    /// Headers of the most recent response, for [`rci_client_last_headers`].
    last_headers: Mutex<Vec<(String, String)>>,
}

fn json_error(message: impl Into<String>) -> String {
    serde_json::json!({ "error": message.into() }).to_string()
}

/// Convert a Rust `String` into a caller-owned C string.
fn into_c_string(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(text) => text.into_raw(),
        // A NUL in the payload cannot travel through a `char *`. Report that
        // as an error string rather than returning a silently truncated one.
        Err(_) => CString::new(json_error("response contains a NUL byte"))
            .map(CString::into_raw)
            .unwrap_or(std::ptr::null_mut()),
    }
}

/// Borrow a C string as `&str`; null and invalid UTF-8 become errors.
unsafe fn opt_str<'a>(pointer: *const c_char) -> Result<&'a str, String> {
    if pointer.is_null() {
        return Err("null argument".to_string());
    }
    // SAFETY: the caller guarantees a valid NUL-terminated string.
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map_err(|error| error.to_string())
}

/// Borrow a byte buffer; an empty slice is valid and means "no body".
unsafe fn opt_bytes<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], String> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err("null body pointer".to_string());
    }
    // SAFETY: the caller guarantees `pointer` covers `length` bytes.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

/// Run `body` and turn a Rust panic into a JSON error, so a panic never
/// crosses the C boundary.
fn guarded(body: impl FnOnce() -> Result<String, String> + std::panic::UnwindSafe) -> String {
    match std::panic::catch_unwind(body) {
        Ok(Ok(text)) => text,
        Ok(Err(message)) => json_error(message),
        Err(_) => json_error("panic in rust-curl-impersonate"),
    }
}

fn version_name(version: Version) -> &'static str {
    if version == Version::HTTP_09 {
        "HTTP/0.9"
    } else if version == Version::HTTP_10 {
        "HTTP/1.0"
    } else if version == Version::HTTP_11 {
        "HTTP/1.1"
    } else if version == Version::HTTP_2 {
        "HTTP/2.0"
    } else if version == Version::HTTP_3 {
        "HTTP/3.0"
    } else {
        "unknown"
    }
}

/// Lowercase hex, so a binary body travels through a `char *` unchanged and
/// without adding a codec dependency.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("high nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("low nibble"));
    }
    out
}

/// A body is text when it decodes as UTF-8 without loss; anything else goes
/// out as hex so no byte is dropped.
fn body_fields(bytes: &[u8]) -> serde_json::Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => serde_json::json!({ "body": text, "body_is_text": true }),
        Err(_) => serde_json::json!({ "body": hex(bytes), "body_is_text": false }),
    }
}

fn collect_headers(headers: &rust_curl_impersonate::header::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Settings read from the `options_json` argument of
/// [`rci_client_new_with_options`]. Unknown keys are rejected so a typo is an
/// error rather than a silently ignored setting.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    proxy: Option<String>,
    #[serde(default)]
    follow_redirects: Option<bool>,
    #[serde(default)]
    follow_safe: Option<bool>,
    #[serde(default)]
    pool_max_idle_per_host: Option<usize>,
    #[serde(default)]
    headers: Option<Vec<(String, String)>>,
    #[serde(default)]
    split_cookies: Option<bool>,
    #[serde(default)]
    http1_only: Option<bool>,
}

/// Build a handle from a profile name and parsed options.
fn build_handle(name: &str, options: Options) -> Result<Box<RciClient>, String> {
    let profile = Profile::find(name).ok_or_else(|| format!("unknown profile {name}"))?;
    let mut builder = rust_curl_impersonate::Client::builder(profile)
        .timeout(options.timeout_ms.map_or(DEFAULT_TIMEOUT, Duration::from_millis));
    if let Some(proxy) = options.proxy.as_deref() {
        builder = builder.proxy_url(proxy).map_err(|error| error.to_string())?;
    }
    if let Some(safe) = options.follow_safe {
        builder = builder.follow_safe(safe);
    }
    if let Some(split) = options.split_cookies {
        builder = builder.split_cookies(split);
    }
    if let Some(http1_only) = options.http1_only {
        builder = builder.http1_only(http1_only);
    }
    if let Some(max) = options.pool_max_idle_per_host {
        builder = builder.pool_max_idle_per_host(max);
    }
    for (name, value) in options.headers.unwrap_or_default() {
        builder = builder.header(name, value);
    }
    let client = builder.build().map_err(|error| error.to_string())?;
    // A current-thread runtime, not a multi-thread one: every ABI call blocks
    // the caller, so extra worker threads would only sit idle. A multi-thread
    // runtime spawns one worker per core per handle, which made ten handles
    // cost 320 threads.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    Ok(Box::new(RciClient {
        client,
        runtime,
        follow_redirects: options.follow_redirects.unwrap_or(true),
        last_headers: Mutex::new(Vec::new()),
    }))
}

/// Run `body` somewhere that is not driving async tasks.
///
/// The ABI is synchronous: it builds a runtime, calls `block_on` on it, and
/// drops it. All three are illegal on a thread that is itself inside a tokio
/// runtime, and the panic they raise cannot unwind out of `extern "C"`, so the
/// whole process aborts. A Rust caller that wraps this library from an async
/// service hits that on its first request. When a runtime is already entered,
/// the work therefore moves to a fresh thread that owns none.
fn off_runtime<R: Send>(body: impl FnOnce() -> R + Send) -> R {
    if tokio::runtime::Handle::try_current().is_err() {
        return body();
    }
    match std::thread::scope(|scope| scope.spawn(body).join()) {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Resolve `ip:port` or `host:port` to a socket address.
fn resolve_addr(runtime: &tokio::runtime::Runtime, addr: &str) -> Result<SocketAddr, String> {
    if let Ok(parsed) = addr.parse::<SocketAddr>() {
        return Ok(parsed);
    }
    runtime
        .block_on(tokio::net::lookup_host(addr))
        .map_err(|error| format!("resolve {addr}: {error}"))?
        .next()
        .ok_or_else(|| format!("{addr} resolved to no address"))
}

fn finish_handle(result: Result<Box<RciClient>, String>) -> *mut RciClient {
    match result {
        Ok(handle) => Box::into_raw(handle),
        Err(message) => {
            set_last_error(message);
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Version and library
// ---------------------------------------------------------------------------

/// ABI version. Bump when a function signature or ownership rule changes.
#[no_mangle]
pub extern "C" fn rci_version() -> u32 {
    ABI_VERSION
}

/// The 48 preset names as a JSON array of strings.
#[no_mangle]
pub extern "C" fn rci_targets() -> *mut c_char {
    into_c_string(
        serde_json::to_string(rust_curl_impersonate::profile::TARGETS)
            .unwrap_or_else(|_| "[]".to_string()),
    )
}

/// Every selectable profile name: the 48 presets plus every fingerprint record.
#[no_mangle]
pub extern "C" fn rci_profiles() -> *mut c_char {
    let mut names: Vec<&str> = rust_curl_impersonate::profile::TARGETS.to_vec();
    names.extend(fingerprint::names());
    into_c_string(serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_string()))
}

/// Metadata for one profile as a JSON object, or `{"error":"..."}`.
#[no_mangle]
pub extern "C" fn rci_profile_info(profile: *const c_char) -> *mut c_char {
    let text = guarded(std::panic::AssertUnwindSafe(|| {
        let name = unsafe { opt_str(profile) }?;
        let profile = Profile::find(name).ok_or_else(|| format!("unknown profile {name}"))?;
        let record = profile.fingerprint();
        let fidelity = profile.fidelity().map(|fidelity| match fidelity {
            fingerprint::Fidelity::Exact => "exact",
            fingerprint::Fidelity::Close => "close",
            fingerprint::Fidelity::Partial => "partial",
        });
        let source = record.map(|record| record.source.clone()).unwrap_or_default();
        Ok(serde_json::json!({
            "name": profile.name(),
            "wire": profile.target(),
            "family": profile.family(),
            "platform": profile.platform(),
            "fidelity": fidelity,
            "deviation": profile.deviation_note(),
            "http1_only": profile.http1_only(),
            "has_http3": record.is_some_and(|record| record.http3.is_some())
                || (record.is_none() && rust_curl_impersonate::profile::http3(profile.target()).is_some()),
            "source": source,
        })
        .to_string())
    }));
    into_c_string(text)
}

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

/// Create a client for a profile name with a 30 s timeout.
#[no_mangle]
pub extern "C" fn rci_client_new(profile: *const c_char) -> *mut RciClient {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let name = unsafe { opt_str(profile) }?;
        off_runtime(|| build_handle(name, Options::default()))
    }))
    .unwrap_or_else(|_| Err("panic in rust-curl-impersonate".to_string()));
    finish_handle(result)
}

/// Create a client from a JSON options object (see `rci.h`). NULL means
/// defaults.
#[no_mangle]
pub extern "C" fn rci_client_new_with_options(
    profile: *const c_char,
    options_json: *const c_char,
) -> *mut RciClient {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let name = unsafe { opt_str(profile) }?;
        let options = match options_json {
            pointer if pointer.is_null() => Options::default(),
            pointer => {
                let text = unsafe { opt_str(pointer) }?;
                if text.trim().is_empty() {
                    Options::default()
                } else {
                    serde_json::from_str::<Options>(text)
                        .map_err(|error| format!("invalid options: {error}"))?
                }
            }
        };
        off_runtime(|| build_handle(name, options))
    }))
    .unwrap_or_else(|_| Err("panic in rust-curl-impersonate".to_string()));
    finish_handle(result)
}

/// Free a handle created by [`rci_client_new`]. Passing null is a no-op.
#[no_mangle]
pub extern "C" fn rci_client_free(handle: *mut RciClient) {
    if !handle.is_null() {
        // SAFETY: the pointer came from `Box::into_raw` in this library.
        // The drop releases the handle's runtime, and dropping a runtime
        // blocks, so it cannot happen on a thread that drives async tasks.
        unsafe {
            let boxed = Box::from_raw(handle);
            off_runtime(move || drop(boxed));
        }
    }
}

/// The preset whose bytes this handle sends.
#[no_mangle]
pub extern "C" fn rci_client_profile(handle: *mut RciClient) -> *mut c_char {
    if handle.is_null() {
        return into_c_string(json_error("null client handle"));
    }
    // SAFETY: the handle is valid for the duration of the call by contract.
    let handle = unsafe { &*handle };
    into_c_string(handle.client.profile().target().to_string())
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Send a request through a handle.
#[no_mangle]
pub extern "C" fn rci_request(
    handle: *mut RciClient,
    method: *const c_char,
    url: *const c_char,
    body: *const u8,
    body_len: usize,
) -> *mut c_char {
    let payload = unsafe { opt_bytes(body, body_len) }.map(<[u8]>::to_vec);
    into_c_string(request_core(handle, method, url, Vec::new(), payload))
}

/// Like [`rci_request`], with extra headers and a NUL-terminated body.
#[no_mangle]
pub extern "C" fn rci_request_with(
    handle: *mut RciClient,
    method: *const c_char,
    url: *const c_char,
    headers_json: *const c_char,
    body: *const c_char,
) -> *mut c_char {
    let headers: Result<Vec<(String, String)>, String> = match headers_json {
        pointer if pointer.is_null() => Ok(Vec::new()),
        pointer => (|| {
            let text = unsafe { opt_str(pointer) }?;
            if text.trim().is_empty() {
                return Ok(Vec::new());
            }
            serde_json::from_str::<Vec<(String, String)>>(text)
                .map_err(|error| format!("invalid headers_json: {error}"))
        })(),
    };
    let payload = match body {
        pointer if pointer.is_null() => Ok(Vec::new()),
        // SAFETY: the caller guarantees a valid NUL-terminated string.
        pointer => Ok(unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec()),
    };
    match (headers, payload) {
        (Ok(headers), Ok(payload)) => {
            into_c_string(request_core(handle, method, url, headers, Ok(payload)))
        }
        (Err(message), _) | (_, Err(message)) => into_c_string(json_error(message)),
    }
}

/// Shared body of [`rci_request`] and [`rci_request_with`].
fn request_core(
    handle: *mut RciClient,
    method: *const c_char,
    url: *const c_char,
    extra_headers: Vec<(String, String)>,
    payload: Result<Vec<u8>, String>,
) -> String {
    if handle.is_null() {
        return json_error("null client handle");
    }
    // SAFETY: the handle is valid for the duration of the call by contract.
    let handle = unsafe { &*handle };
    guarded(std::panic::AssertUnwindSafe(|| {
        let method = unsafe { opt_str(method) }?;
        let url = unsafe { opt_str(url) }?;
        let payload = payload?;
        let method = Method::from_bytes(method.as_bytes()).map_err(|error| error.to_string())?;
        off_runtime(|| handle.runtime.block_on(async {
            let mut request = handle.client.request(method, url);
            if !handle.follow_redirects {
                request = request.redirect(redirect::Policy::none());
            }
            for (name, value) in extra_headers {
                request = request.header(name, value);
            }
            if !payload.is_empty() {
                request = request.body(payload);
            }
            let response = request.send().await.map_err(|error| error.to_string())?;
            let status = response.status().as_u16();
            let version = response.version();
            let final_url = response.uri().to_string();
            let headers = collect_headers(response.headers());
            let bytes = response.bytes().await.map_err(|error| error.to_string())?;
            *handle.last_headers.lock().expect("last headers") = headers.clone();
            let mut object = serde_json::json!({
                "status": status,
                "version": version_name(version),
                "url": final_url,
                "headers": headers,
            });
            if let (Some(object), Some(fields)) = (object.as_object_mut(), body_fields(&bytes).as_object()) {
                for (key, value) in fields {
                    object.insert(key.clone(), value.clone());
                }
            }
            Ok(object.to_string())
        }))
    }))
}

/// Convenience: create a client, send one GET, and free the client.
#[no_mangle]
pub extern "C" fn rci_get(profile: *const c_char, url: *const c_char) -> *mut c_char {
    let handle = rci_client_new(profile);
    if handle.is_null() {
        return into_c_string(json_error(last_error()));
    }
    let result = rci_request(handle, c"GET".as_ptr(), url, std::ptr::null(), 0);
    rci_client_free(handle);
    result
}

/// Send a GET over HTTP/3. The profile must carry an HTTP/3 record.
#[no_mangle]
pub extern "C" fn rci_http3_get(
    profile: *const c_char,
    addr: *const c_char,
    host: *const c_char,
    path: *const c_char,
) -> *mut c_char {
    let text = guarded(std::panic::AssertUnwindSafe(|| {
        let name = unsafe { opt_str(profile) }?;
        let addr = unsafe { opt_str(addr) }?;
        let host = unsafe { opt_str(host) }?;
        let path = unsafe { opt_str(path) }?;
        off_runtime(|| {
            let handle = build_handle(name, Options::default())?;
            let runtime = &handle.runtime;
            let socket_addr = resolve_addr(runtime, addr)?;
            let response = runtime.block_on(handle.client.http3_get(socket_addr, host, path))?;
            http3_json(&response.headers, &response.body)
        })
    }));
    into_c_string(text)
}

/// Turn an HTTP/3 header list and body into the ABI's JSON shape. Pseudo-headers
/// leave `headers`; `:status` becomes the `status` field.
pub fn http3_json(headers: &[(String, String)], body: &[u8]) -> Result<String, String> {
    let mut status: u16 = 0;
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (name, value) in headers {
        if let Some(name) = name.strip_prefix(':') {
            if name == "status" {
                status = value
                    .parse()
                    .map_err(|_| format!("HTTP/3 :status {value:?} is not a number"))?;
            }
            continue;
        }
        pairs.push((name.clone(), value.clone()));
    }
    let mut object = serde_json::json!({ "status": status, "headers": pairs });
    if let (Some(object), Some(fields)) = (object.as_object_mut(), body_fields(body).as_object()) {
        for (key, value) in fields {
            object.insert(key.clone(), value.clone());
        }
    }
    Ok(object.to_string())
}

// ---------------------------------------------------------------------------
// Handle introspection
// ---------------------------------------------------------------------------

/// Headers of the most recent response on this handle.
#[no_mangle]
pub extern "C" fn rci_client_last_headers(handle: *mut RciClient) -> *mut c_char {
    if handle.is_null() {
        return into_c_string(json_error("null client handle"));
    }
    // SAFETY: the handle is valid for the duration of the call by contract.
    let handle = unsafe { &*handle };
    let headers = handle
        .last_headers
        .lock()
        .map(|headers| headers.clone())
        .unwrap_or_default();
    into_c_string(serde_json::to_string(&headers).unwrap_or_else(|_| "[]".to_string()))
}

/// Cookie changes and redirect history recorded by the handle.
#[no_mangle]
pub extern "C" fn rci_client_activity(handle: *mut RciClient) -> *mut c_char {
    if handle.is_null() {
        return into_c_string(json_error("null client handle"));
    }
    // SAFETY: the handle is valid for the duration of the call by contract.
    let handle = unsafe { &*handle };
    into_c_string(
        serde_json::json!({
            "cookies": handle.client.cookie_changes(),
            "redirects": handle.client.redirect_history(),
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Errors and memory
// ---------------------------------------------------------------------------

static PROVIDER_SEQ: AtomicU64 = AtomicU64::new(1);

/// Append a JSON document to the process's fingerprint library. Records land
/// in a user-priority provider, so a name they share with a built-in record
/// resolves to the document's version for this process.
#[no_mangle]
pub extern "C" fn rci_load_fingerprints(json: *const c_char) -> *mut c_char {
    let text = guarded(std::panic::AssertUnwindSafe(|| {
        let json = unsafe { opt_str(json) }?;
        let id = format!("user-{}", PROVIDER_SEQ.fetch_add(1, Ordering::SeqCst));
        let provider = fingerprint::JsonProvider::new(id, json);
        fingerprint::register_provider(provider)?;
        Ok("{}".to_string())
    }));
    into_c_string(text)
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

fn set_last_error(message: String) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = message);
}

fn last_error() -> String {
    LAST_ERROR.with(|slot| slot.borrow().clone())
}

/// Return the last construction error on this thread as a stable C string.
/// The pointer stays valid until the next call on the same thread.
#[no_mangle]
pub extern "C" fn rci_last_error() -> *const c_char {
    thread_local! {
        static BUFFER: std::cell::RefCell<CString> =
            std::cell::RefCell::new(CString::new("").unwrap());
    }
    BUFFER.with(|slot| {
        let mut slot = slot.borrow_mut();
        *slot = CString::new(last_error()).unwrap_or_default();
        slot.as_ptr()
    })
}

/// Release a string returned by this library. Passing null is a no-op.
#[no_mangle]
pub extern "C" fn rci_string_free(pointer: *mut c_char) {
    if !pointer.is_null() {
        // SAFETY: the pointer came from `CString::into_raw` in this library.
        unsafe { drop(CString::from_raw(pointer)) };
    }
}
