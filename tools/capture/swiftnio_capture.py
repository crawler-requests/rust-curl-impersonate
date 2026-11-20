#!/usr/bin/env python3
"""Record the ClientHello a swift-nio-ssl (NIOSSL) client sends.

swift-nio-ssl is what AsyncHTTPClient and other TLS-using Swift packages ride
on. On iOS it is a stack of its own: it links CNIOBoringSSL, so its
ClientHello is BoringSSL's shape rather than CFNetwork's, and no record in the
library covers it.

Usage:
    python3 -I tools/capture/swiftnio_capture.py <niocap-binary> <out.json>
        [--port 8447] [--host tls.peet.ws] [--alpn "h2,http/1.1"] [--timeout 30]

Output has the shape `tools/gen_fingerprints.py` reads from `tools/capture/raw/`,
i.e. a `tls` block with ciphers, extensions and a JA4 a-segment.
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import firefox_hello as hello  # noqa: E402  (path is set above)


def read_record(conn):
    conn.settimeout(15)
    data = conn.recv(5)
    if len(data) < 5 or data[0] != 0x16:
        return None
    length = struct.unpack(">H", data[3:5])[0]
    chunks = [data]
    remaining = length
    while remaining > 0:
        chunk = conn.recv(min(remaining, 4096))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("output")
    parser.add_argument("--port", type=int, default=8447)
    parser.add_argument("--host", default="tls.peet.ws")
    parser.add_argument("--alpn", default="h2,http/1.1")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--user-agent", default="")
    args = parser.parse_args()

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    server.settimeout(args.timeout)

    client = subprocess.Popen(
        [args.binary, args.host, str(args.port), args.alpn, "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    record = None
    try:
        conn, _ = server.accept()
        with conn:
            record = read_record(conn)
    finally:
        try:
            client.terminate()
            client.wait(timeout=10)
        except subprocess.TimeoutExpired:
            client.kill()

    if record is None:
        stderr = client.stderr.read().decode("utf-8", "replace") if client.stderr else ""
        raise SystemExit(f"no TLS ClientHello arrived; client said: {stderr.strip()}")

    ciphers, extensions = hello.parse(record)
    document = {
        "tls": {
            "ja4": hello.ja4(ciphers, extensions),
            "ciphers": [hello.CIPHER_NAMES.get(c, f"TLS_UNKNOWN_{c:#06x}") for c in ciphers],
            "extensions": [hello.describe(kind, payload) for kind, payload in extensions],
        },
        "http_version": "",
        "user_agent": args.user_agent,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1)

    names = [entry["name"] for entry in document["tls"]["extensions"]]
    print(f"wrote {args.output}: {len(ciphers)} ciphers, {len(names)} extensions")
    print("  " + ", ".join(names))


if __name__ == "__main__":
    sys.exit(main())
