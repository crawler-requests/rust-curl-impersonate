//! Checks for the C ABI (`bindings/ffi`).
//!
//! These run the library the way a binding does: through the exported C
//! functions, with the same JSON shapes documented in `rci.h`. They catch an
//! ABI that still compiles but returns the wrong shape.

use std::ffi::CStr;

use rust_curl_impersonate_ffi::*;

/// Read a string the library returned, then release it.
unsafe fn take(pointer: *mut i8) -> serde_json::Value {
    assert!(!pointer.is_null(), "library returned null");
    // SAFETY: the pointer came from the library and is NUL-terminated.
    let text = unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .expect("valid utf-8");
    let value = serde_json::from_str(text).unwrap_or_else(|_| panic!("not json: {text}"));
    // The library owns the allocation; this releases it.
    rci_string_free(pointer);
    value
}

unsafe fn take_raw(pointer: *mut i8) -> String {
    assert!(!pointer.is_null(), "library returned null");
    // SAFETY: the pointer came from the library and is NUL-terminated.
    let text = unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .expect("valid utf-8")
        .to_string();
    // The library owns the allocation; this releases it.
    rci_string_free(pointer);
    text
}

#[test]
fn abi_version_is_two() {
    assert_eq!(rci_version(), 2);
}

#[test]
fn targets_and_profiles_are_json_arrays() {
    let targets = unsafe { take(rci_targets()) };
    let list = targets.as_array().expect("targets is an array");
    assert_eq!(list.len(), 48);
    assert_eq!(list[0].as_str(), Some("chrome100"));

    let profiles = unsafe { take(rci_profiles()) };
    let list = profiles.as_array().expect("profiles is an array");
    assert!(list.len() > 48, "library records are listed too");
    for target in rust_curl_impersonate::profile::TARGETS {
        assert!(list.iter().any(|name| name.as_str() == Some(target)));
    }
}

#[test]
fn profile_info_reports_metadata() {
    let info = unsafe { take(rci_profile_info(c"chrome150".as_ptr())) };
    assert_eq!(info["name"], "chrome150");
    assert_eq!(info["wire"], "chrome150");
    assert_eq!(info["has_http3"], true);
    assert_eq!(info["http1_only"], false);
    assert!(info["fidelity"].is_null(), "a preset has no fidelity note");

    // A library record carries a family and possibly a fidelity.
    let go = unsafe { take(rci_profile_info(c"go1.23".as_ptr())) };
    assert_eq!(go["family"], "go");
    assert!(go["fidelity"].is_string(), "a capture records its fidelity");

    let missing = unsafe { take(rci_profile_info(c"nope".as_ptr())) };
    assert!(missing["error"].as_str().unwrap().contains("unknown profile"));
}

#[test]
fn options_reject_unknown_keys() {
    let pointer = rci_client_new_with_options(c"chrome150".as_ptr(), c"{\"nope\":1}".as_ptr());
    assert!(pointer.is_null(), "an unknown key is an error");
    // SAFETY: the pointer is valid until the next call on this thread.
    let error = unsafe { CStr::from_ptr(rci_last_error()) }.to_str().unwrap();
    assert!(error.contains("invalid options"), "{error}");
}

#[test]
fn unknown_profile_sets_last_error() {
    let pointer = rci_client_new(c"nope".as_ptr());
    assert!(pointer.is_null());
    // SAFETY: the pointer is valid until the next call on this thread.
    let error = unsafe { CStr::from_ptr(rci_last_error()) }.to_str().unwrap();
    assert!(error.contains("unknown profile"), "{error}");
}

#[test]
fn null_handle_answers_with_an_error_object() {
    let reply = unsafe { take(rci_request(std::ptr::null_mut(), c"GET".as_ptr(), c"http://x".as_ptr(), std::ptr::null(), 0)) };
    assert!(reply["error"].as_str().unwrap().contains("null client handle"));

    let headers = unsafe { take(rci_client_last_headers(std::ptr::null_mut())) };
    assert!(headers["error"].as_str().unwrap().contains("null client handle"));
}

#[test]
fn client_can_be_created_and_freed() {
    let handle = rci_client_new(c"chrome150".as_ptr());
    assert!(!handle.is_null());
    let name = unsafe { take_raw(rci_client_profile(handle)) };
    assert_eq!(name, "chrome150");
    // Before any request the header list is empty, not an error.
    let headers = unsafe { take(rci_client_last_headers(handle)) };
    assert_eq!(headers.as_array().map(Vec::len), Some(0));
    let activity = unsafe { take(rci_client_activity(handle)) };
    assert!(activity["cookies"].is_array());
    assert!(activity["redirects"].is_array());
    rci_client_free(handle);
    // Freeing null is a no-op.
    rci_client_free(std::ptr::null_mut());
}

#[test]
fn http3_response_maps_status_and_pseudo_headers() {
    // A binding parses this shape; a regression here is silent. The mapping
    // runs without a server, so it gates the HTTP/3 response format even where
    // CI cannot reach a QUIC peer.
    let headers = vec![
        (":status".to_string(), "200".to_string()),
        ("content-type".to_string(), "text/html".to_string()),
        ("x-quic".to_string(), "h3".to_string()),
    ];
    let json: serde_json::Value =
        serde_json::from_str(&http3_json(&headers, b"<body>").expect("valid")).expect("json");
    assert_eq!(json["status"], 200);
    assert_eq!(json["body"], "<body>");
    assert_eq!(json["body_is_text"], true);
    let reported = json["headers"].as_array().expect("headers");
    assert_eq!(reported.len(), 2, "pseudo-headers leave the header list");
    assert!(!reported.iter().any(|pair| pair[0].as_str() == Some(":status")));

    // A binary body still uses the same hex rule as rci_request.
    let binary = http3_json(&headers, &[0x00, 0xff]).expect("valid");
    let json: serde_json::Value = serde_json::from_str(&binary).expect("json");
    assert_eq!(json["body"], "00ff");
    assert_eq!(json["body_is_text"], false);

    // A malformed :status is an error, not a silent zero.
    let bad = vec![(":status".to_string(), "OK".to_string())];
    assert!(http3_json(&bad, b"").is_err());
}

#[test]
fn loading_a_document_registers_a_record() {
    let document = serde_json::json!({
        "fingerprints": [
            {
                "name": "abi_test_record",
                "family": "test",
                "platform": "linux",
                "extends": "chrome150",
                "source": "abi test"
            }
        ]
    })
    .to_string();
    let reply = unsafe { take(rci_load_fingerprints(document.as_ptr() as *const i8)) };
    assert_eq!(
        reply.as_object().map(|object| object.len()),
        Some(0),
        "empty object on success"
    );

    let info = unsafe { take(rci_profile_info(c"abi_test_record".as_ptr())) };
    assert_eq!(info["wire"], "chrome150");
    assert_eq!(info["family"], "test");

    // A malformed document is rejected and changes nothing.
    let bad = unsafe { take(rci_load_fingerprints(c"[{\"name\":\"\"}]".as_ptr())) };
    assert!(bad["error"].is_string());
}
