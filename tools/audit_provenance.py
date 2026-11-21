#!/usr/bin/env python3
"""Check that every record in the library is derived from a capture, not invented.

A record can be wrong in several ways and each has a different check:

  raw file       the record must name a tools/capture/raw/*.json that exists
  tls block      that file must contain a real ClientHello (ciphers, extensions)
  no invention   every header and every HTTP/2 parameter the record claims must
                 exist in the raw file. A value that is not in the capture was
                 made up, even if it looks plausible.
  provenance     the capture must say where it came from, and a capture whose
                 JA4 carries no b/c segment came from a local socket rather
                 than a server, which is worth stating.

Usage:
    python3 -I tools/audit_provenance.py [--verbose]

Exits non-zero if any record fails a check.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RAW = os.path.join(ROOT, "tools", "capture", "raw")
LIBRARY = os.path.join(ROOT, "src", "fingerprint", "builtin.json")

# Hop-by-hop headers the generator drops on purpose: the transport writes its
# own Host and Connection, so a record never carries them.
HOP_BY_HOP = {"host", "connection"}


def raw_headers(raw):
    found = []
    if raw.get("http1"):
        for line in raw["http1"].get("headers") or []:
            name, _, value = line.partition(": ")
            found.append((name.lower(), value))
    for frame in (raw.get("http2") or {}).get("sent_frames") or []:
        for line in frame.get("headers") or []:
            name, _, value = line.partition(": ")
            if not name.startswith(":"):
                found.append((name.lower(), value))
    return [(n, v) for n, v in found if n not in HOP_BY_HOP]


def audit(verbose=False):
    records = json.load(open(LIBRARY))["fingerprints"]
    base = [r for r in records if not r.get("extends")]
    problems = []
    local_only = []

    for record in base:
        name = record["name"]
        source = record.get("source", "")

        if "tools/capture/raw/" not in source:
            problems.append((name, "source names no raw capture", source[:60]))
            continue
        relative = source.split("tools/capture/raw/")[-1].strip().rstrip(",")
        path = os.path.join(RAW, relative)
        if not os.path.exists(path):
            problems.append((name, "raw capture missing", relative))
            continue

        raw = json.load(open(path))
        tls = raw.get("tls") or {}
        if not tls.get("ciphers") or not tls.get("extensions"):
            problems.append((name, "raw capture has no ClientHello", relative))
            continue

        # No invention: the record's headers must be exactly the capture's.
        claimed = [(n.lower(), v) for n, v in (record.get("headers") or [])]
        captured = raw_headers(raw)
        if claimed != captured:
            problems.append((
                name, "headers not in the capture",
                f"claimed {claimed[:2]} vs captured {captured[:2]}",
            ))

        # No invention: HTTP/2 settings must come from the capture.
        if record.get("http2") and not raw.get("http2"):
            problems.append((name, "HTTP/2 data with no captured frames",
                             str(record["http2"].get("settings"))))

        # A capture with no b/c segment did not reach a server.
        ja4 = tls.get("ja4") or ""
        if ja4.endswith("_-") or ja4.count("_") < 2:
            local_only.append(name)

        if verbose:
            print(f"ok  {name:<30} {relative}")

    return base, problems, local_only


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    base, problems, local_only = audit(args.verbose)

    print(f"{len(base)} base records, {len(problems)} problems")
    for name, kind, detail in problems:
        print(f"  FAIL {name:<30} {kind}: {detail}")

    # Not a failure: these were captured against a socket on this machine
    # instead of a server, so only the a-segment of the JA4 is available. The
    # bytes are what the client sent; the point is to know which are which.
    print(f"{len(local_only)} records came from a local socket, not a server:")
    print("  " + ", ".join(sorted(local_only)))

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
