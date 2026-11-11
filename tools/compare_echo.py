#!/usr/bin/env python3
"""Compare an `examples/echo` response with the raw capture it was built from.

Usage: compare_echo.py <capture-dir> <echo-dir> [prefix]

Both directories hold one JSON document per record: the capture as saved by
tools/capture, the echo log prefixed with a `status:` line. The report lists
the TLS fields that reached the wire unchanged and the ones that differ, so a
deviation in the embedded record can be checked against a real handshake.
"""

import json
import os
import re
import sys


def load_capture(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_echo(path):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    start = text.index("{")
    return json.loads(text[start:])


def extension_id(name):
    """Return the numeric id of an extension label, or None for GREASE."""
    if "GREASE" in name:
        return None
    match = re.search(r"\((0x[0-9a-fA-F]+|\d+)\)\s*$", name)
    if not match:
        match = re.search(r"extension (\d+)$", name)
    if not match:
        return None
    value = match.group(1)
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def extension_ids(tls):
    return [extension_id(entry.get("name", "")) for entry in tls.get("extensions") or []]


def payload(tls, wanted):
    for entry in tls.get("extensions") or []:
        if extension_id(entry.get("name", "")) == wanted:
            return entry
    return {}


def names(values):
    return [value for value in values or []]


def strip_grease(values):
    return [value for value in values if "GREASE" not in str(value)]


def compare(raw, live):
    raw_tls, live_tls = raw["tls"], live["tls"]
    diffs = []
    raw_exts = strip_grease(extension_ids(raw_tls))
    live_exts = strip_grease(extension_ids(live_tls))
    if raw_exts != live_exts:
        if set(raw_exts) == set(live_exts):
            diffs.append("extension order")
        else:
            diffs.append(
                "extensions missing="
                + str(sorted(set(raw_exts) - set(live_exts)))
                + " extra="
                + str(sorted(set(live_exts) - set(raw_exts)))
            )
    raw_ciphers = strip_grease(names(raw_tls.get("ciphers")))
    live_ciphers = strip_grease(names(live_tls.get("ciphers")))
    if raw_ciphers != live_ciphers:
        diffs.append("ciphers")
    for label, wanted in (("groups", 10), ("sigalgs", 13)):
        raw_values = strip_grease(names(payload(raw_tls, wanted).get(
            "supported_groups" if wanted == 10 else "signature_algorithms")))
        live_values = strip_grease(names(payload(live_tls, wanted).get(
            "supported_groups" if wanted == 10 else "signature_algorithms")))
        if raw_values != live_values:
            diffs.append(label)
    raw_alpn = payload(raw_tls, 16).get("protocols")
    live_alpn = payload(live_tls, 16).get("protocols")
    if raw_alpn != live_alpn:
        diffs.append("alpn " + str(raw_alpn) + " -> " + str(live_alpn))
    if raw.get("ja4") != live.get("ja4"):
        diffs.append("ja4")
    return diffs


def main():
    capture_dir, echo_dir = sys.argv[1], sys.argv[2]
    prefix = sys.argv[3] if len(sys.argv) > 3 else "utls_"
    same = 0
    for name in sorted(os.listdir(capture_dir)):
        stem = name[:-5] if name.endswith(".json") else name
        if not stem.startswith(prefix):
            continue
        echo_path = os.path.join(echo_dir, stem + ".log")
        if not os.path.exists(echo_path):
            echo_path = os.path.join(echo_dir, stem + ".json")
        if not os.path.exists(echo_path):
            print(f"{stem}: missing echo")
            continue
        try:
            diffs = compare(
                load_capture(os.path.join(capture_dir, name)), load_echo(echo_path)
            )
        except Exception as error:  # noqa: BLE001 - report and keep going
            print(f"{stem}: parse error: {error}")
            continue
        if diffs:
            print(f"{stem}: {', '.join(diffs)}")
        else:
            same += 1
    print(f"identical (TLS structure, JA4): {same}")


if __name__ == "__main__":
    main()
