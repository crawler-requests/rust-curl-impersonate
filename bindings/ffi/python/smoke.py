"""Exercise every function of the C ABI v2 with ctypes.

Run against a locally built library and a local HTTP server:

    cargo build -p rust-curl-impersonate-ffi --release
    python3 bindings/ffi/python/testserver.py 8765 &
    python3 bindings/ffi/python/smoke.py

Set RCI_LIB to load the library from a release archive; RCI_BASE is the local
server base URL (default http://127.0.0.1:8765). Set RCI_H3_ADDR=host:port to
include the HTTP/3 path (against a public QUIC server), with RCI_H3_PROFILE
choosing the QUIC preset (default chrome152).

The script fails loudly (exit 1) when an assertion does not hold, so CI uses
it as a gate.
"""

import ctypes
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

if sys.platform == "darwin":
    LIB_NAME = "librust_curl_impersonate_ffi.dylib"
elif os.name == "nt":
    LIB_NAME = "rust_curl_impersonate_ffi.dll"
else:
    LIB_NAME = "librust_curl_impersonate_ffi.so"

LIB = os.environ.get("RCI_LIB") or os.path.join(ROOT, "target", "release", LIB_NAME)
BASE = os.environ.get("RCI_BASE", "http://127.0.0.1:8765")

if not os.path.exists(LIB):
    sys.exit(f"build the library first: {LIB} is missing")

lib = ctypes.CDLL(LIB)

P = ctypes.c_void_p

lib.rci_version.restype = ctypes.c_uint32
lib.rci_targets.restype = P
lib.rci_profiles.restype = P
lib.rci_profile_info.argtypes = [ctypes.c_char_p]
lib.rci_profile_info.restype = P
lib.rci_client_new.argtypes = [ctypes.c_char_p]
lib.rci_client_new.restype = P
lib.rci_client_new_with_options.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.rci_client_new_with_options.restype = P
lib.rci_client_free.argtypes = [P]
lib.rci_client_profile.argtypes = [P]
lib.rci_client_profile.restype = P
lib.rci_request.argtypes = [P, ctypes.c_char_p, ctypes.c_char_p, P, ctypes.c_size_t]
lib.rci_request.restype = P
lib.rci_request_with.argtypes = [P, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.rci_request_with.restype = P
lib.rci_get.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.rci_get.restype = P
lib.rci_http3_get.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.rci_http3_get.restype = P
lib.rci_client_last_headers.argtypes = [P]
lib.rci_client_last_headers.restype = P
lib.rci_client_activity.argtypes = [P]
lib.rci_client_activity.restype = P
lib.rci_load_fingerprints.argtypes = [ctypes.c_char_p]
lib.rci_load_fingerprints.restype = P
lib.rci_last_error.restype = ctypes.c_char_p
lib.rci_string_free.argtypes = [P]
lib.rci_string_free.restype = None


def take(pointer):
    """Read a JSON string the library returned, then release it."""
    if not pointer:
        return {"error": "null pointer"}
    try:
        return json.loads(ctypes.string_at(pointer).decode())
    finally:
        lib.rci_string_free(pointer)


failures = []


def take_raw(pointer):
    """Read a bare string the library returned, then release it."""
    if not pointer:
        return None
    try:
        return ctypes.string_at(pointer).decode()
    finally:
        lib.rci_string_free(pointer)


def check(label, condition):
    if condition:
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}")
        failures.append(label)


def expect(label, value):
    check(label, bool(value))


print("abi version:", lib.rci_version())
check("abi version is 2", lib.rci_version() == 2)

targets = take(lib.rci_targets())
expect("48 targets", len(targets) == 48)
profiles = take(lib.rci_profiles())
expect("profiles exceed presets", len(profiles) > 48)
check("every target is a profile", all(t in profiles for t in targets))

info = take(lib.rci_profile_info(b"chrome150"))
check("chrome150 has http3", info.get("has_http3") is True)
check("chrome150 fidelity is null", info.get("fidelity") is None)
info_go = take(lib.rci_profile_info(b"go1.23"))
check("a library record reports a family", bool(info_go.get("family")))
expect("unknown profile errors", take(lib.rci_profile_info(b"nope")).get("error"))

# Syscall-level default client.
handle = lib.rci_client_new(b"chrome150")
check("client_new returns a handle", bool(handle))
expect("client_new profile", take_raw(lib.rci_client_profile(handle)) == "chrome150")
reply = take(lib.rci_request(handle, b"GET", BASE.encode() + b"/index.html", None, 0))
check("GET status 200", reply.get("status") == 200)
check("GET body is text", reply.get("body_is_text") is True)
check("GET reports a version", reply.get("version") in ("HTTP/1.1", "HTTP/2.0"))
check("GET headers captured", isinstance(reply.get("headers"), list) and reply["headers"])
last = take(lib.rci_client_last_headers(handle))
check("last_headers matches", last == reply.get("headers"))

binary = os.path.join(ROOT, "target", "rci-smoke.bin")
with open(binary, "wb") as handle_out:
    handle_out.write(b"\x00\x01\x02\xff\xfe binary")
try:
    reply = take(lib.rci_request(handle, b"GET", BASE.encode() + b"/rci-smoke.bin", None, 0))
    check("non-utf8 body is hex", reply.get("body_is_text") is False)
    check("hex decodes back", bytes.fromhex(reply["body"]) == b"\x00\x01\x02\xff\xfe binary")
finally:
    os.unlink(binary)

reply = take(
    lib.rci_request_with(
        handle,
        b"POST",
        BASE.encode() + b"/echo",
        json.dumps([["content-type", "text/plain"], ["x-rci", "1"]]).encode(),
        b"hello-body",
    )
)
check("POST status 200", reply.get("status") == 200)
activity = take(lib.rci_client_activity(handle))
check("activity has cookies/redirects", "cookies" in activity and "redirects" in activity)
lib.rci_client_free(handle)

# Options-driven client: custom headers, no redirects, short timeout.
options = json.dumps(
    {
        "timeout_ms": 5000,
        "follow_redirects": False,
        "headers": [["x-rci-client", "options"]],
    }
)
handle = lib.rci_client_new_with_options(b"chrome150", options.encode())
check("options client created", bool(handle))
reply = take(lib.rci_request(handle, b"GET", BASE.encode() + b"/redirect", None, 0))
check("follow_redirects=false stops at 302", reply.get("status") == 302)
lib.rci_client_free(handle)

check("bad options rejected", not lib.rci_client_new_with_options(b"chrome150", b'{"nope":1}'))
check("bad profile rejected", not lib.rci_client_new(b"nope"))
error = lib.rci_last_error()
check("last_error is set", bool(error))

# One-shot helper.
reply = take(lib.rci_get(b"chrome150", BASE.encode() + b"/index.html"))
check("rci_get status 200", reply.get("status") == 200)

# HTTP/3 against a QUIC server when RCI_H3_ADDR is provided.
# RCI_H3_PROFILE defaults to chrome152: chrome160 is captured but its ML-DSA
# signature algorithms are a recorded deviation, so some servers reject it.
h3_addr = os.environ.get("RCI_H3_ADDR")
if h3_addr:
    profile = os.environ.get("RCI_H3_PROFILE", "chrome152")
    reply = take(lib.rci_http3_get(profile.encode(), h3_addr.encode(), b"quic.nginx.org", b"/"))
    check("http3 status 200", reply.get("status") == 200)
    check("http3 returns headers", bool(reply.get("headers")))
    check("http3 returns a body", bool(reply.get("body")))
    # The error text lets a CI step tell "peer unreachable" from a real
    # transport bug, so it is printed even on success.
    print(f"     http3 profile={profile} status={reply.get('status')} "
          f"headers={len(reply.get('headers') or [])} error={reply.get('error')}")
else:
    print("skip http3 (set RCI_H3_ADDR=ip:port to include it)")

# Provider registration.
document = json.dumps(
    {
        "fingerprints": [
            {
                "name": "rci_smoke",
                "family": "test",
                "platform": "linux",
                "extends": "chrome150",
                "source": "smoke",
            }
        ]
    }
)
registry = take(lib.rci_load_fingerprints(document.encode()))
check("load_fingerprints ok", registry == {})
info = take(lib.rci_profile_info(b"rci_smoke"))
check("loaded record resolves", info.get("wire") == "chrome150")
bad = take(lib.rci_load_fingerprints(b'[{"name":""}]'))
check("bad document rejected", bool(bad.get("error")))

if failures:
    print(f"\n{len(failures)} failure(s):")
    for label in failures:
        print(" -", label)
    sys.exit(1)
print("\nall C ABI v2 checks passed")
