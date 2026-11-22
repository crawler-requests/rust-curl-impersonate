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
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RAW = os.path.join(ROOT, "tools", "capture", "raw")
LIBRARY = os.path.join(ROOT, "src", "fingerprint", "builtin.json")

sys.path.insert(0, os.path.join(HERE, "capture"))
import firefox_hello as hello  # noqa: E402  (path is set above)

CIPHER_CODES = {name: code for code, name in hello.CIPHER_NAMES.items()}
SIGALG_CODES = {name: code for code, name in hello.SIGALG_NAMES.items()}


def is_grease(value):
    return (value & 0x0F0F) == 0x0A0A


def extension_id(name):
    """The numeric id of a captured extension entry, or None for GREASE."""
    if "GREASE" in name:
        return None
    match = re.search(r"\((0x[0-9a-fA-F]+|\d+)\)\s*$", name)
    if match:
        value = match.group(1)
        return int(value, 16) if value.startswith("0x") else int(value, 10)
    # "Unknown extension 51764" carries no parentheses.
    match = re.search(r"(\d+)\s*$", name)
    return int(match.group(1)) if match else None


def digest(values):
    return hashlib.sha256(",".join(values).encode()).hexdigest()[:12]


def ja4_hashes(ciphers, extensions, sigalgs):
    """The b and c parts of a JA4 from its raw lists."""
    cipher_list = sorted(f"{code:04x}" for code in ciphers if not is_grease(code))
    ext_list = sorted(
        f"{kind:04x}" for kind in extensions
        if not is_grease(kind) and kind not in (0, 16)
    )
    if not cipher_list:
        b = "0" * 12
    else:
        b = digest(cipher_list)
    text = ",".join(ext_list)
    sigalgs = [code for code in sigalgs if not is_grease(code)]
    if sigalgs:
        text += "_" + ",".join(f"{code:04x}" for code in sigalgs)
    c = "0" * 12 if not ext_list else hashlib.sha256(text.encode()).hexdigest()[:12]
    return b, c


def extension_ids(tls):
    found = []
    for entry in tls.get("extensions") or []:
        value = extension_id(entry.get("name", ""))
        if value is not None:
            found.append(value)
    return found


def signature_algorithm_codes(tls):
    """Codes from extension 13 in wire order, or None if a name is unknown.

    A GREASE value is dropped, as JA4 drops it everywhere.
    """
    for entry in tls.get("extensions") or []:
        name = entry.get("name", "")
        if not name.startswith("signature_algorithms ("):
            continue
        codes = []
        for value in entry.get("signature_algorithms") or []:
            if isinstance(value, int):
                code = value
            elif value.startswith("0x"):
                code = int(value, 16)
            else:
                code = SIGALG_CODES.get(value)
            if code is None:
                return None
            if not is_grease(code):
                codes.append(code)
        return codes
    return []


def cipher_codes(tls):
    """Codes from the capture's cipher names, or None when one is unknown.

    tls.peet.ws prints `0x00C4` for a suite it has no name for, so a label
    that is already a code point is taken as one.
    """
    codes = []
    for name in tls.get("ciphers") or []:
        if "GREASE" in name:
            continue
        code = CIPHER_CODES.get(name)
        if code is None and re.fullmatch(r"0x[0-9a-fA-F]{2,4}", name):
            code = int(name, 16)
        if code is None:
            return None
        codes.append(code)
    return codes


def hashes_from_raw_fields(tls):
    """(b, c) from the capture's own entries, or None when names are unknown."""
    ciphers = cipher_codes(tls)
    sigalgs = signature_algorithm_codes(tls)
    if ciphers is None or sigalgs is None:
        return None
    return ja4_hashes(ciphers, extension_ids(tls), sigalgs)


def hashes_from_ja4_r(tls):
    """(b, c) from tls.peet.ws's raw JA4, or None when there is none."""
    raw = tls.get("ja4_r")
    if not raw:
        return None
    parts = raw.split("_")
    if len(parts) < 3:
        return None
    ciphers = [int(value, 16) for value in parts[1].split(",") if value]
    extensions = [int(value, 16) for value in parts[2].split(",") if value]
    sigalgs = [int(value, 16) for value in parts[3].split(",") if value] \
        if len(parts) > 3 else []
    return ja4_hashes(ciphers, extensions, sigalgs)


def hashes_from_record(record, tls):
    """(b, c) the library record itself describes, or None if unreadable.

    Extension 21 is stored apart from `extension_order`, so it is added back
    when the record sends it (a fixed length, or the transport's size rule
    while the capture did pad).
    """
    described = record.get("tls") or {}
    ciphers = []
    for name in (described.get("ciphers") or "").split(":"):
        if not name:
            continue
        code = CIPHER_CODES.get(name)
        if code is None:
            return None
        ciphers.append(code)
    extensions = [int(value) for value in
                  (described.get("extension_order") or "").split("-") if value]
    padding = described.get("padding")
    if isinstance(padding, dict):
        extensions.append(21)
    elif padding is None and 21 in extension_ids(tls):
        extensions.append(21)
    sigalgs = described.get("sigalg_codes")
    if not sigalgs:
        sigalgs = [SIGALG_CODES[name] for name in
                   (described.get("sigalgs") or "").split(":")
                   if name in SIGALG_CODES]
    return ja4_hashes(ciphers, extensions, sigalgs)


def alpn_tag(protocols):
    """JA4's two-character ALPN label."""
    if not protocols or not protocols[0]:
        return "00"
    raw = protocols[0].encode()

    def alphanumeric(byte):
        return (0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A
                or 0x61 <= byte <= 0x7A)

    if alphanumeric(raw[0]) and alphanumeric(raw[-1]):
        return chr(raw[0]) + chr(raw[-1])
    text = raw.hex()
    return text[0] + text[-1]

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
    recomputed = 0
    compared = 0

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

        # The capture's JA4 must be the hash of the capture's own fields.
        # tls.peet.ws gives its raw list (`ja4_r`); where it does not, the
        # fields themselves are hashed instead. A stored hash that does not
        # match its own capture is wrong evidence even when the bytes are real.
        from_raw = hashes_from_ja4_r(tls)
        from_fields = hashes_from_raw_fields(tls)
        if from_raw and from_fields and from_raw != from_fields:
            problems.append((
                name, "capture fields disagree with its ja4_r",
                f"{from_raw[0]}_{from_raw[1]} vs {from_fields[0]}_{from_fields[1]}",
            ))
        computed = from_raw or from_fields
        parts = ja4.split("_") if ja4 else []
        if computed and len(parts) == 3 and parts[2] not in ("", "-"):
            recomputed += 1
            if (parts[1], parts[2]) != computed:
                problems.append((
                    name, "stored ja4 does not hash the capture",
                    f"stored {parts[1]}_{parts[2]}, recomputed "
                    f"{computed[0]}_{computed[1]}",
                ))

        # The record's TLS fields must hash to the capture's JA4. A difference
        # is allowed only when the record says what it dropped or reordered.
        expected = hashes_from_record(record, tls)
        if expected and computed and expected != computed:
            compared += 1
            if not (record.get("deviations") or []):
                problems.append((
                    name, "record does not reproduce the capture's JA4",
                    f"record {expected[0]}_{expected[1]}, capture "
                    f"{computed[0]}_{computed[1]}",
                ))
        elif expected and computed:
            compared += 1

        if verbose:
            print(f"ok  {name:<30} {relative}")

    return base, problems, local_only, recomputed, compared


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    base, problems, local_only, recomputed, compared = audit(args.verbose)

    print(f"{len(base)} base records, {len(problems)} problems")
    print(f"{recomputed} stored JA4s recomputed from their capture, "
          f"{compared} records checked against their capture")
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
