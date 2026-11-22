#!/usr/bin/env python3
"""Record the ClientHello a Cronet client sends, off the wire.

Cronet is Chromium's network stack, shipped to Android and iOS apps that do not
want the platform client. Its ClientHello is Chrome's, but the app chooses the
version, so it is a stack of its own next to CFNetwork and WebKit.

Cronet's Java layer requires an Android Context (its network-change monitor
calls ConnectivityManager), so a bare app_process aborts. The way that works is
a small APK installed on the device; see the `capture` section below for the
harness. This script is the host side: it listens, the app connects to it, and
the raw TLS record is written out.

Usage:
    sudo python3 -I tools/capture/cronet_capture.py <out.json> [--port 443]
        [--seconds 240]

Requires root for port 443. Point the device's /etc/hosts at the host first:

    adb shell 'echo "192.168.1.83 tls.peet.ws" >> /etc/hosts'
    adb shell 'am force-stop io.capture.cronet && am start -n io.capture.cronet/.Main'

Output is a tls.peet.ws-shaped document with the `tls` block filled in. Only the
ClientHello is captured - the listener never answers the handshake - so the
document says so instead of recording HTTP/2 frames nobody observed.
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import firefox_hello as hello  # noqa: E402  (path is set above)


def is_grease(value):
    return (value & 0x0F0F) == 0x0A0A


def sigalgs_of(extensions):
    """Signature algorithm codes from extension 13, in wire order."""
    for kind, payload in extensions:
        if kind == 13 and len(payload) >= 2:
            size = struct.unpack(">H", payload[:2])[0]
            return [struct.unpack(">H", payload[2 + i:4 + i])[0]
                    for i in range(0, min(size, len(payload) - 2), 2)]
    return []


def ja4(ciphers, extensions):
    """The full JA4: a-segment from the shape, b/c from the sorted lists."""
    head = hello.ja4(ciphers, extensions).split("_")[0]
    cipher_list = sorted(f"{c:04x}" for c in ciphers if not is_grease(c))
    # JA4 excludes SNI and ALPN from the extension hash; those carry no
    # fingerprint value of their own. The signature algorithms follow the
    # extension list in wire order (not sorted) - leaving them out changes
    # the hash for every hello that carries extension 13.
    ext_list = sorted(
        f"{kind:04x}"
        for kind, _ in extensions
        if not is_grease(kind) and kind not in (0, 16)
    )
    text = ",".join(ext_list)
    sigalgs = sigalgs_of(extensions)
    if sigalgs:
        text += "_" + ",".join(f"{code:04x}" for code in sigalgs)

    def digest(values):
        return hashlib.sha256(values.encode()).hexdigest()[:12]

    return f"{head}_{digest(','.join(cipher_list))}_{digest(text)}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--seconds", type=int, default=240)
    parser.add_argument("--user-agent", default="Cronet/100.0.4891.0 (Android 13)")
    args = parser.parse_args()

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", args.port))
    server.listen(5)
    server.settimeout(args.seconds)
    print(f"listening on {args.port}; launch the Cronet app now", flush=True)

    conn, peer = server.accept()
    print(f"connection from {peer[0]}", flush=True)
    conn.settimeout(25)
    head = conn.recv(5)
    if len(head) < 5 or head[0] != 0x16:
        raise SystemExit(f"not a TLS handshake record: {head!r}")
    length = int.from_bytes(head[3:5], "big")
    body = b""
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    conn.close()
    server.close()

    record = head + body
    ciphers, extensions = hello.parse(record)
    document = {
        "tls": {
            "ja4": ja4(ciphers, extensions),
            "ciphers": [
                "TLS_GREASE (0x%04X)" % c
                if is_grease(c)
                else hello.CIPHER_NAMES.get(c, f"TLS_UNKNOWN_{c:#06x}")
                for c in ciphers
            ],
            "extensions": [hello.describe(k, p) for k, p in extensions],
        },
        "http_version": "",
        "method": "",
        "user_agent": args.user_agent,
        "captured": "ClientHello only (a local listener recorded it and closed)",
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1)

    names = [entry["name"] for entry in document["tls"]["extensions"]]
    print(f"wrote {args.output}: {len(ciphers)} ciphers, {len(names)} extensions")
    print(f"  ja4 {document['tls']['ja4']}")
    print("  " + ", ".join(names))


if __name__ == "__main__":
    sys.exit(main())
