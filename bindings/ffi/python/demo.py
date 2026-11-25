"""Call the C ABI library from Python with ctypes.

This is the smallest useful binding, and a starting point for a real client:
copy the wrapper class into your project rather than shelling out.

Build first:

    cargo build -p rust-curl-impersonate-ffi --release

Then:

    python3 bindings/ffi/python/demo.py chrome150 https://tls.peet.ws/api/all

Set RCI_LIB to load a library from another directory (CI, release archives).
Set RCI_LIST=1 to print the selectable profiles instead of sending a request.
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
lib.rci_request_with.argtypes = [
    P,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.rci_request_with.restype = P
lib.rci_client_last_headers.argtypes = [P]
lib.rci_client_last_headers.restype = P
lib.rci_client_activity.argtypes = [P]
lib.rci_client_activity.restype = P
lib.rci_http3_get.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.rci_http3_get.restype = P
lib.rci_load_fingerprints.argtypes = [ctypes.c_char_p]
lib.rci_load_fingerprints.restype = P
lib.rci_last_error.restype = ctypes.c_char_p
lib.rci_string_free.argtypes = [P]
lib.rci_string_free.restype = None


def _take(pointer):
    """Read a JSON document the library returned and release it."""
    if not pointer:
        raise RuntimeError(lib.rci_last_error().decode())
    try:
        return json.loads(ctypes.string_at(pointer).decode())
    finally:
        lib.rci_string_free(pointer)


def _take_raw(pointer):
    if not pointer:
        raise RuntimeError(lib.rci_last_error().decode())
    try:
        return ctypes.string_at(pointer).decode()
    finally:
        lib.rci_string_free(pointer)


class Client:
    """One profile's client handle. Use as a context manager."""

    def __init__(self, profile, **options):
        encoded = json.dumps(options).encode() if options else None
        handle = lib.rci_client_new_with_options(profile.encode(), encoded)
        if not handle:
            raise RuntimeError(lib.rci_last_error().decode())
        self._handle = handle
        self.profile = profile

    def send(self, method, url, headers=None, body=None):
        headers_json = json.dumps(headers).encode() if headers else None
        pointer = lib.rci_request_with(
            self._handle,
            method.encode(),
            url.encode(),
            headers_json,
            body.encode() if body else None,
        )
        reply = _take(pointer)
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply

    def get(self, url, headers=None):
        return self.send("GET", url, headers=headers)

    def last_headers(self):
        return _take(lib.rci_client_last_headers(self._handle))

    def activity(self):
        return _take(lib.rci_client_activity(self._handle))

    def close(self):
        if self._handle:
            lib.rci_client_free(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def body_text(reply):
    """A response body as text, decoding the hex form when it is binary."""
    if reply.get("body_is_text", True):
        return reply["body"]
    return bytes.fromhex(reply["body"])


if __name__ == "__main__":
    print("abi version:", lib.rci_version())

    if os.environ.get("RCI_LIST"):
        targets = _take(lib.rci_targets())
        profiles = _take(lib.rci_profiles())
        print(f"{len(targets)} presets, {len(profiles)} selectable profiles")
        for name in profiles[:15]:
            print(" ", name, _take(lib.rci_profile_info(name.encode())).get("family"))
        sys.exit(0)

    profile = sys.argv[1] if len(sys.argv) > 1 else "chrome150"
    url = sys.argv[2] if len(sys.argv) > 2 else "https://tls.peet.ws/api/all"

    with Client(profile) as client:
        payload = client.get(url)
        print("http status:", payload["status"], payload["version"])
        text = body_text(payload)
        try:
            echo = json.loads(text)
        except ValueError:
            echo = None
        if echo is None:
            print("body:", text[:200])
        else:
            print("user agent:", echo.get("user_agent"))
            print("ja4:", echo.get("tls", {}).get("ja4"))
            print("akamai h2:", echo.get("http2", {}).get("akamai_fingerprint"))
