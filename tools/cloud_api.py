#!/usr/bin/env python3
"""A stand-in for a licensed fingerprint service.

Serves one JSON library document with ETag / If-None-Match revalidation and an
optional bearer token, so that `examples/cloud_provider.rs` runs end to end
without a real backend. A real service would assemble the document per
subscription, sign it and rotate it; the provider side of that contract
(`RemoteProvider`) is what this mock exercises.

Start it:

    python3 tools/cloud_api.py goal-evidence/cloud-library.json \
        --port 8747 --bearer-token demo-token

Then, in another shell:

    FINGERPRINT_CLOUD_URL=http://127.0.0.1:8747/fingerprints.json \
    FINGERPRINT_CLOUD_TOKEN=demo-token \
    cargo run --example cloud_provider

Every request is logged: the first fetch carries no `If-None-Match` and gets
`200`, a refresh sends it back and gets `304`.
"""

import argparse
import hashlib
import http.server
import sys


def make_handler(document: bytes, etag: str, bearer: str | None):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # silence the default logger
            pass

        def do_GET(self):
            authorization = self.headers.get("Authorization")
            if_none_match = self.headers.get("If-None-Match")
            if self.path != "/fingerprints.json":
                code, body, headers = 404, b'{"error":"not found"}', {}
            elif bearer is not None and authorization != f"Bearer {bearer}":
                code, body, headers = 401, b'{"error":"unauthorized"}', {}
            elif if_none_match == etag:
                code, body, headers = 304, b"", {"ETag": etag}
            else:
                code, body, headers = 200, document, {"ETag": etag}
            print(
                "[cloud-api] {} {} if-none-match={!r} authorization={!r} -> {}".format(
                    self.command,
                    self.path,
                    if_none_match,
                    "Bearer ***" if authorization else None,
                    code,
                ),
                flush=True,
            )
            self.send_response(code)
            if code == 200:
                self.send_header("Content-Type", "application/json")
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "library", help="JSON document in the fingerprint library schema"
    )
    parser.add_argument(
        "--port", type=int, default=8747, help="port to listen on (default 8747)"
    )
    parser.add_argument(
        "--bearer-token",
        default=None,
        help="require this bearer token; omit the flag to serve openly",
    )
    args = parser.parse_args()

    document = open(args.library, "rb").read()
    etag = '"' + hashlib.sha256(document).hexdigest()[:16] + '"'
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", args.port), make_handler(document, etag, args.bearer_token)
    )
    print(
        "[cloud-api] serving {} at http://127.0.0.1:{}/fingerprints.json "
        "etag={} bearer={}".format(
            args.library,
            args.port,
            etag,
            "required" if args.bearer_token else "none",
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())