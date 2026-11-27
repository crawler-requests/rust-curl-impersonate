#!/usr/bin/env python3
"""Prove an installed library really is rust-curl-impersonate, and that it works.

    python3 verify_abi.py --lib ./rci/lib                   # offline checks
    python3 verify_abi.py --lib ./rci/lib --echo            # also a live request
    python3 verify_abi.py --lib ./rci/lib --profile chrome150 --echo-url https://tls.peet.ws/api/all

Every check is something a wrapper author would otherwise discover late: an
ABI version that is too old, a function the header declares but the library
does not export, a crash on a null handle, a body that loses bytes.

Exit status is 0 only when every check passed.
"""

import argparse
import ctypes
import json
import os
import sys

# The 17 exports of ABI v2, grouped by what a check needs them for.
EXPECTED_EXPORTS = {
    "rci_version", "rci_targets", "rci_profiles", "rci_profile_info",
    "rci_client_new", "rci_client_new_with_options", "rci_client_free",
    "rci_client_profile", "rci_request", "rci_request_with", "rci_get",
    "rci_http3_get", "rci_client_last_headers", "rci_client_activity",
    "rci_last_error", "rci_load_fingerprints", "rci_string_free",
}

# Reference fingerprints for chrome150, from a capture; a wrapper whose profile
# does not take effect will not reproduce them.
JA4_CHROME150 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
H2_CHROME150 = "1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p"

failures = []


def check(label, condition, detail=""):
    if condition:
        print(f"ok   {label}")
    else:
        print(f"FAIL {label}" + (f" — {detail}" if detail else ""))
        failures.append(label)


def library_name():
    if sys.platform == "darwin":
        return "librust_curl_impersonate_ffi.dylib"
    if os.name == "nt":
        return "rust_curl_impersonate_ffi.dll"
    return "librust_curl_impersonate_ffi.so"


def load(path):
    if os.path.isdir(path):
        path = os.path.join(path, library_name())
    if not os.path.exists(path):
        sys.exit(f"no library at {path}")
    lib = ctypes.CDLL(os.path.abspath(path))
    P = ctypes.c_void_p
    signatures = {
        "rci_version": ([], ctypes.c_uint32),
        "rci_targets": ([], P),
        "rci_profiles": ([], P),
        "rci_profile_info": ([ctypes.c_char_p], P),
        "rci_client_new": ([ctypes.c_char_p], P),
        "rci_client_new_with_options": ([ctypes.c_char_p, ctypes.c_char_p], P),
        "rci_client_free": ([P], None),
        "rci_client_profile": ([P], P),
        "rci_request": ([P, ctypes.c_char_p, ctypes.c_char_p, P, ctypes.c_size_t], P),
        "rci_request_with": ([P, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_char_p], P),
        "rci_get": ([ctypes.c_char_p, ctypes.c_char_p], P),
        "rci_http3_get": ([ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_char_p], P),
        "rci_client_last_headers": ([P], P),
        "rci_client_activity": ([P], P),
        "rci_last_error": ([], ctypes.c_char_p),
        "rci_load_fingerprints": ([ctypes.c_char_p], P),
        "rci_string_free": ([P], None),
    }
    missing = []
    for name, (argtypes, restype) in signatures.items():
        try:
            function = getattr(lib, name)
        except AttributeError:
            missing.append(name)
            continue
        function.argtypes = argtypes
        function.restype = restype
    return lib, missing


def take(lib, pointer):
    """Read a JSON string the library returned, then release it."""
    if not pointer:
        return None
    try:
        return json.loads(ctypes.string_at(pointer).decode("utf-8"))
    finally:
        lib.rci_string_free(pointer)


def take_text(lib, pointer):
    if not pointer:
        return None
    try:
        return ctypes.string_at(pointer).decode("utf-8")
    finally:
        lib.rci_string_free(pointer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", required=True,
                        help="a library file, or any directory that contains "
                             "librust_curl_impersonate_ffi.so/.dylib/.dll")
    parser.add_argument("--echo", action="store_true",
                        help="send a live request (default target is the public "
                             "tls.peet.ws, so this needs network access; "
                             "--echo-url http://127.0.0.1:8766/index.html for offline)")
    parser.add_argument("--echo-url", default="https://tls.peet.ws/api/all")
    parser.add_argument("--profile", default="chrome150")
    args = parser.parse_args()

    lib, missing = load(args.lib)
    # A library that lacks most exports is not worth 15 lines of failures.
    if missing:
        print(f"FAIL all 17 exports present — missing: {', '.join(sorted(missing))}")
        sys.exit(1)
    check("library loads", True)
    check("all 17 exports present", True)

    # ABI generation.
    version = lib.rci_version()
    check("rci_version >= 2", version >= 2, f"got {version}")
    if version < 2:
        sys.exit("this library predates the v2 ABI; fetch a newer release")

    # Profile queries.
    targets = take(lib, lib.rci_targets())
    check("48 curl-impersonate presets", isinstance(targets, list) and len(targets) == 48,
          f"got {len(targets) if isinstance(targets, list) else targets}")
    profiles = take(lib, lib.rci_profiles())
    check("profiles include the presets",
          isinstance(profiles, list) and set(targets) <= set(profiles))
    info = take(lib, lib.rci_profile_info(b"chrome150"))
    check("chrome150 metadata",
          isinstance(info, dict) and info.get("family") == "chrome"
          and "has_http3" in info, str(info)[:120])
    unknown = take(lib, lib.rci_profile_info(b"not-a-profile"))
    check("unknown profile reports an error",
          isinstance(unknown, dict) and "error" in unknown, str(unknown)[:80])

    # Ownership and null handling: these are the two errors that crash a wrapper.
    null_string = lib.rci_string_free(None)
    check("rci_string_free(NULL) is a no-op", True)
    lib.rci_client_free(None)
    check("rci_client_free(NULL) is a no-op", True)
    null_reply = take(lib, lib.rci_client_profile(None))
    check("null handle returns an error object, not a crash",
          isinstance(null_reply, dict) and "error" in null_reply, str(null_reply)[:80])

    # Client construction, including the two failure paths.
    handle = lib.rci_client_new(b"chrome150")
    check("client handle created", bool(handle))
    check("rci_client_profile is a bare string",
          bool(handle) and take_text(lib, lib.rci_client_profile(handle)) == "chrome150")
    bad = lib.rci_client_new(b"not-a-profile")
    check("unknown profile returns NULL", not bad)
    error = lib.rci_last_error()
    check("rci_last_error explains why", bool(error) and b"unknown profile" in error,
          (error or b"").decode())
    bad_options = lib.rci_client_new_with_options(b"chrome150", b'{"nonesuch":true}')
    check("unknown option is rejected", not bad_options)
    lib.rci_client_free(handle)

    # A live request proves the profile's bytes really go out.
    if args.echo:
        reply = take(lib, lib.rci_get(args.profile.encode(), args.echo_url.encode()))
        check("live request returns 200",
              isinstance(reply, dict) and reply.get("status") == 200,
              str(reply)[:200])
        # The library turns a network failure into {"error":...}, so a broken
        # route looks the same as a broken library. Say which is more likely.
        if isinstance(reply, dict) and "error" in reply:
            print("     note: a network failure also arrives as an {\"error\"} object. "
                  "Re-run with --echo-url http://127.0.0.1:8766/index.html (and "
                  "scripts/local_echo_server.py 8766) to tell library from network.")
        body = None
        if isinstance(reply, dict) and reply.get("body_is_text"):
            try:
                body = json.loads(reply["body"])
            except ValueError:
                pass
        elif isinstance(reply, dict) and "body" in reply:
            try:
                body = json.loads(bytes.fromhex(reply["body"]).decode())
            except ValueError:
                pass
        ja4 = (body or {}).get("tls", {}).get("ja4")
        h2 = (body or {}).get("http2", {}).get("akamai_fingerprint")
        if args.echo_url.endswith("tls.peet.ws/api/all"):
            check("JA4 matches the chrome150 capture", ja4 == JA4_CHROME150, f"got {ja4}")
            check("Akamai h2 matches the capture", h2 == H2_CHROME150, f"got {h2}")
        check("response reports a version",
              isinstance(reply, dict) and reply.get("version") in
              ("HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"),
              str(reply.get("version") if isinstance(reply, dict) else reply))

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
