"""Call the C ABI library from Python with ctypes.

Build first:

    cargo build -p rust-curl-impersonate-ffi --release

Then:

    python3 bindings/ffi/python/demo.py chrome150 https://tls.peet.ws/api/all

Set RCI_LIB to load a library from another directory (CI, release archives).
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
lib.rci_version.restype = ctypes.c_uint32
lib.rci_get.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.rci_get.restype = ctypes.c_void_p
lib.rci_last_error.restype = ctypes.c_char_p
lib.rci_string_free.argtypes = [ctypes.c_void_p]
lib.rci_string_free.restype = None


def get(profile, url):
    pointer = lib.rci_get(profile.encode(), url.encode())
    if not pointer:
        raise RuntimeError(lib.rci_last_error().decode())
    try:
        return json.loads(ctypes.string_at(pointer).decode())
    finally:
        lib.rci_string_free(pointer)


if __name__ == "__main__":
    profile = sys.argv[1] if len(sys.argv) > 1 else "chrome150"
    url = sys.argv[2] if len(sys.argv) > 2 else "https://tls.peet.ws/api/all"
    print("abi version:", lib.rci_version())
    payload = get(profile, url)
    if "error" in payload:
        sys.exit(payload["error"])
    print("http status:", payload["status"])
    try:
        echo = json.loads(payload["body"])
    except ValueError:
        echo = None
    if echo is None:
        print("body:", payload["body"][:200])
    else:
        print("http version:", echo.get("http_version"))
        print("user agent:", echo.get("user_agent"))
        print("ja4:", echo.get("tls", {}).get("ja4"))
        print("akamai h2:", echo.get("http2", {}).get("akamai_fingerprint"))
