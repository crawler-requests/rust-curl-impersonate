"""Tests for rci_bindings, run against a locally built library and test server.

    cargo build -p rust-curl-impersonate-ffi --release
    python3 bindings/ffi/python/testserver.py 8765 &
    python3 -m pytest bindings/ffi/python/tests -q

Set RCI_LIB to test a release archive instead of the build output; RCI_BASE
points at the server (default http://127.0.0.1:8765).
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import rci_bindings  # noqa: E402

BASE = os.environ.get("RCI_BASE", "http://127.0.0.1:8765")


@pytest.fixture(scope="module")
def lib():
    return rci_bindings.Library()


def test_signatures_match_the_header(lib):
    """The fallback table and the parsed rci.h cannot drift apart."""
    if not lib.header:
        pytest.skip("no rci.h next to the library")
    parsed = rci_bindings.parse_header(open(lib.header, encoding="utf-8").read())
    builtin = rci_bindings._BUILTIN_SIGNATURES
    assert set(parsed) == set(builtin), "header gained or lost a function"
    for name, (restype, argtypes, owned) in parsed.items():
        expected = builtin[name]
        assert restype is expected[0], name
        assert argtypes == expected[1], name
        assert owned == expected[2], name


def test_abi_version(lib):
    assert lib.version == rci_bindings.ABI_VERSION


def test_targets_and_profiles(lib):
    targets = lib.targets()
    profiles = lib.profiles()
    assert len(targets) == 48
    assert set(targets) <= set(profiles)
    assert len(profiles) > len(targets)


def test_profile_info(lib):
    info = lib.profile_info("chrome150")
    assert info["family"] == "chrome"
    assert info["has_http3"] is True
    assert info["fidelity"] is None

    record = lib.profile_info("go1.26")
    assert record["family"] == "go"
    assert record["fidelity"] == "close"
    assert "BoringSSL" in record["deviation"]


def test_profile_missing(lib):
    with pytest.raises(rci_bindings.RciError, match="unknown profile"):
        lib.profile_info("definitely-not-a-profile")


def test_get_and_response_helpers(lib):
    reply = lib.get("chrome150", BASE + "/index.html")
    assert reply.status == 200
    assert reply.ok
    assert reply.body_is_text
    assert reply.text == "hello from rust-curl-impersonate"
    assert reply.content.startswith(b"hello")
    assert reply.header("Content-Type").startswith("text/plain")


def test_binary_body_is_decoded(lib):
    reply = lib.get("chrome150", BASE + "/rci-smoke.bin")
    assert not reply.body_is_text
    assert reply.content == b"\x00\x01\x02\xff\xfe binary"
    with pytest.raises(ValueError):
        reply.text


def test_client_post_and_headers(lib):
    with rci_bindings.Client("chrome150", headers=[("accept-language", "zh-CN")]) as client:
        reply = client.post(BASE + "/echo", '{"a":1}', headers=[("x-test", "yes")])
    echo = reply.json()
    assert echo["method"] == "POST"
    assert echo["body"] == '{"a":1}'
    assert echo["headers"]["accept-language"] == "zh-CN"
    assert echo["headers"]["x-test"] == "yes"
    assert "user-agent" in echo["headers"]  # the preset's own header survives


def test_client_blocks_default_headers(lib):
    with rci_bindings.Client("chrome150", headers=[("user-agent", "")]) as client:
        echo = client.post(BASE + "/echo", "x").json()
    assert "user-agent" not in echo["headers"]
    assert "accept-language" in echo["headers"]


def test_unknown_option_is_rejected(lib):
    with pytest.raises(rci_bindings.RciError, match="unknown field"):
        rci_bindings.Client("chrome150", nonesuch=True)


def test_unknown_profile_is_rejected(lib):
    with pytest.raises(rci_bindings.RciError, match="unknown profile"):
        rci_bindings.Client("definitely-not-a-profile")


def test_request_error_is_an_exception(lib):
    with rci_bindings.Client("chrome150", timeout_ms=2000) as client:
        with pytest.raises(rci_bindings.RciError):
            client.get("http://127.0.0.1:1/")


def test_no_redirect_by_default(lib):
    reply = lib.get("chrome150", BASE + "/redirect")
    assert reply.status == 302
    assert reply.url.endswith("/redirect")


def test_follow_safe_refuses_loopback(lib):
    with rci_bindings.Client("chrome150", follow_safe=True) as client:
        with pytest.raises(rci_bindings.RciError, match="redirect address is blocked"):
            client.get(BASE + "/redirect")
        assert client.activity()["redirects"], "the redirect was recorded"


def test_follow_safe_false_follows(lib):
    with rci_bindings.Client("chrome150", follow_safe=False) as client:
        reply = client.get(BASE + "/redirect")
    assert reply.status == 200
    assert reply.url.endswith("/index.html")


def test_last_headers_and_wire_profile(lib):
    with rci_bindings.Client("chrome150") as client:
        assert client.last_headers() == []
        assert client.activity() == {"cookies": [], "redirects": []}
        assert client.wire_profile() == "chrome150"
        client.get(BASE + "/index.html")
        headers = dict(client.last_headers())
        assert headers["content-type"].startswith("text/plain")


def test_load_fingerprints_overrides_a_builtin(lib):
    document = {
        "fingerprints": [
            {
                "name": "rci_pytest_record",
                "family": "test",
                "platform": "linux",
                "extends": "chrome150",
                "source": "pytest",
            }
        ]
    }
    lib.load_fingerprints(document)
    info = lib.profile_info("rci_pytest_record")
    assert info["wire"] == "chrome150"
    assert info["family"] == "test"

    with pytest.raises(rci_bindings.RciError):
        lib.load_fingerprints([{"name": ""}])


def test_http3_unavailable_reports_error(lib):
    with pytest.raises(rci_bindings.RciError, match="HTTP/3 is unavailable"):
        lib.http3_get("go1.26", "quic.nginx.org:443", "quic.nginx.org", "/")


@pytest.mark.skipif(
    os.environ.get("RCI_H3") != "1", reason="needs outbound UDP; set RCI_H3=1"
)
def test_http3_against_a_public_peer(lib):
    # quic.nginx.org rate-limits by source IP and closes streams intermittently
    # (error_code 260), so a single attempt fails often. Retry until one
    # succeeds; the point is that the HTTP/3 path yields a response at all.
    last = None
    for _ in range(6):
        try:
            reply = lib.http3_get("chrome152", "quic.nginx.org:443", "quic.nginx.org", "/")
        except rci_bindings.RciError as error:
            last = error
            continue
        assert reply.status == 200
        assert reply.header("x-quic") == "h3"
        return
    pytest.skip(f"no successful HTTP/3 exchange from this network: {last}")



def test_every_declared_function_is_reachable(lib):
    """Parsing rci.h and loading the library must agree on the same 17 names."""
    imported = {name for name in dir(lib.dll) if name.startswith("rci_")}
    assert imported == set(lib.signatures)
