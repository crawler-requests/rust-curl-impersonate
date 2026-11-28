#!/usr/bin/env python3
"""A tiny HTTP server for testing a native binding offline.

    python3 local_echo_server.py 8765

Routes:
  /            200 "hello from rust-curl-impersonate" (text/plain)
  /index.html  the same
  /redirect   302 to /index.html
  /echo       echoes method, request headers and body as JSON (GET and POST)
  /cookie     two Set-Cookie headers, for a handle's cookie jar to carry
  /binary     raw bytes (0x00 0x01 0x02 0xff 0xfe) to check hex decoding
              (/rci-smoke.bin is accepted too: that is the name the shipped
              binding tests use)

Use it to prove a wrapper's request path, header merging, redirect policy and
binary-body decoding without depending on the network:

    curl -s http://127.0.0.1:8765/echo -d '{"a":1}'
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BINARY = b"\x00\x01\x02\xff\xfe binary"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, content_type="text/plain; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or []):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _paths(self):
        return self.path.split("?", 1)[0]

    def do_GET(self):
        path = self._paths()
        if path == "/redirect":
            self._send(302, b"", extra=[("Location", "/index.html")])
        elif path in ("/binary", "/rci-smoke.bin"):
            # /rci-smoke.bin is the name the upstream binding tests use, so the
            # shipped tests run unchanged against this server.
            self._send(200, BINARY, content_type="application/octet-stream")
        elif path in ("/", "/index.html"):
            self._send(200, b"hello from rust-curl-impersonate")
        elif path == "/echo":
            self._echo(b"")
        elif path == "/cookie":
            # Two Set-Cookie headers, so a binding's cookie-jar test has
            # something to carry to the next request on the same handle.
            self._send(200, b"set", extra=[
                ("Set-Cookie", "sid=abc123; Path=/"),
                ("Set-Cookie", "theme=dark; Path=/"),
            ])
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self._paths() == "/echo":
            self._echo(body)
        else:
            self._send(404, b"not found")

    def _echo(self, body):
        payload = json.dumps({
            "method": self.command,
            "path": self.path,
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
        }).encode()
        self._send(200, payload, content_type="application/json")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
