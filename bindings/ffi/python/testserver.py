"""A tiny HTTP server for the C ABI smoke test.

    python3 bindings/ffi/python/testserver.py 8765

Routes:
  /            "hello from rust-curl-impersonate"
  /index.html  the same
  /redirect    302 to /index.html
  /echo        echoes method, request headers and body as JSON
  anything else under /          served as text; binary paths return raw bytes
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

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/redirect":
            self._send(302, b"", extra=[("Location", "/index.html")])
        elif path.startswith("/rci-smoke.bin"):
            self._send(200, BINARY, content_type="application/octet-stream")
        elif path in ("/", "/index.html"):
            self._send(200, b"hello from rust-curl-impersonate")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        payload = json.dumps(
            {
                "method": "POST",
                "path": self.path,
                "headers": {name.lower(): value for name, value in self.headers.items()},
                "body": body.decode("utf-8", "replace"),
            }
        ).encode()
        self._send(200, payload, content_type="application/json")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
