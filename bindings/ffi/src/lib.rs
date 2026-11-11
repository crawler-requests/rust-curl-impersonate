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
//! platform equivalent). See `python/demo.py` for a ctypes consumer.

use std::ffi::{c_char, CStr, CString};
use std::time::Duration;

use rust_curl_impersonate::{Client, Method, Profile};

const TIMEOUT: Duration = Duration::from_secs(30);

/// Opaque client handle. Created by [`rci_client_new`], freed by
/// [`rci_client_free`].
pub struct RciClient {
    client: Client,
    runtime: tokio::runtime::Runtime,
}

fn json_error(message: impl Into<String>) -> String {
    serde_json::json!({ "error": message.into() }).to_string()
}

/// Convert a Rust `String` into a caller-owned C string.
fn into_c_string(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(text) => text.into_raw(),
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

/// ABI version. Bump when a function signature or ownership rule changes.
#[no_mangle]
pub extern "C" fn rci_version() -> u32 {
    1
}

/// Create a client for a profile name (`chrome150`, `firefox147`, any of the
/// 48 presets, or any name from the fingerprint library).
///
/// Returns null when the profile is unknown; use [`rci_last_error`] for the
/// reason.
#[no_mangle]
pub extern "C" fn rci_client_new(profile: *const c_char) -> *mut RciClient {
    let result: Result<Box<RciClient>, String> =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let name = unsafe { opt_str(profile) }?;
            let profile = Profile::find(name).ok_or_else(|| format!("unknown profile {name}"))?;
            let client = Client::builder(profile)
                .timeout(TIMEOUT)
                .build()
                .map_err(|error| error.to_string())?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            Ok(Box::new(RciClient { client, runtime }))
        }))
        .unwrap_or_else(|_| Err("panic in rust-curl-impersonate".to_string()));
    match result {
        Ok(handle) => Box::into_raw(handle),
        Err(message) => {
            set_last_error(message);
            std::ptr::null_mut()
        }
    }
}

/// Free a handle created by [`rci_client_new`]. Passing null is a no-op.
#[no_mangle]
pub extern "C" fn rci_client_free(handle: *mut RciClient) {
    if !handle.is_null() {
        // SAFETY: the pointer came from `Box::into_raw` in this library.
        unsafe { drop(Box::from_raw(handle)) };
    }
}

/// Send a request through a handle.
///
/// `method` is an HTTP method name (`GET`, `POST`, ...); `url` is the target;
/// `body` may be null with `body_len == 0`. Returns a JSON object
/// `{"status":<u16>,"body":"<utf-8 text>"}`, or `{"error":"..."}`.
#[no_mangle]
pub extern "C" fn rci_request(
    handle: *mut RciClient,
    method: *const c_char,
    url: *const c_char,
    body: *const u8,
    body_len: usize,
) -> *mut c_char {
    if handle.is_null() {
        return into_c_string(json_error("null client handle"));
    }
    // SAFETY: the handle is valid for the duration of the call by contract.
    let handle = unsafe { &*handle };
    let result: Result<String, String> =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let method = unsafe { opt_str(method) }?;
            let url = unsafe { opt_str(url) }?;
            let body = unsafe { opt_bytes(body, body_len) }?;
            let method =
                Method::from_bytes(method.as_bytes()).map_err(|error| error.to_string())?;
            handle.runtime.block_on(async {
                let mut request = handle.client.request(method, url);
                if !body.is_empty() {
                    request = request.body(body.to_vec());
                }
                let response = request.send().await.map_err(|error| error.to_string())?;
                let status = response.status().as_u16();
                let text = response.text().await.map_err(|error| error.to_string())?;
                Ok(serde_json::json!({ "status": status, "body": text }).to_string())
            })
        }))
        .unwrap_or_else(|_| Err("panic in rust-curl-impersonate".to_string()));
    match result {
        Ok(value) => into_c_string(value),
        Err(message) => into_c_string(json_error(message)),
    }
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
