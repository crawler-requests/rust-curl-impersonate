#!/usr/bin/env python3
"""Detect new TLS extension ids worth adding to the Chrome profiles.

Two sources are cheap and stable enough to poll:

  1. IANA's TLS extension type registry. It carries a `updated` date on every
     record, so a new codepoint or a newly split entry shows up as a new id
     with a fresh date. This is the standard body Chrome has to follow for
     IANA-registered extensions.

  2. The vendored BoringSSL's `tls1.h`, compared against the copy the crate
     was last synced with. An extension Chromium adds outside IANA (4832,
     30032) appears here first, because Chrome implements it in BoringSSL.

Output is a report of what is new since the last recorded snapshot; nothing is
committed automatically. Run it on a schedule (cron, CI, or a `/loop`) and act
on the ids it names.

Usage:
  python3 -I tools/watch_extensions.py            # report
  python3 -I tools/watch_extensions.py --update   # also rewrite the snapshot

The snapshot lives at goal-evidence/extension-watch-baseline.json.
"""

import argparse
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASELINE = os.path.join(ROOT, "goal-evidence", "extension-watch-baseline.json")
IANA_URL = (
    "https://www.iana.org/assignments/tls-extensiontype-values/"
    "tls-extensiontype-values.xml"
)


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8", "replace")


def iana_records(xml):
    """(id, name, updated) for every record in the extension-type registry.

    The document holds several registries (extension types, certificate
    status types, ALPN ids, ...) whose ids overlap, so only the
    `tls-extensiontype-values-*` sections are read.
    """
    records = []
    for section in re.findall(
        r'<registry id="tls-extensiontype-values-1"[^>]*>(.*?)</registry>',
        xml,
        re.S,
    ):
        for line in section.split("<record"):
            updated = re.search(r'^\s*updated="([^"]*)"', line)
            value = re.search(r"<value>(.*?)</value>", line, re.S)
            name = re.search(r"<name>(.*?)</name>", line, re.S)
            if not value:
                continue
            try:
                ident = parse_value(value.group(1).strip())
            except ValueError:
                continue
            if ident is None:
                continue
            records.append(
                {
                    "id": ident,
                    "name": name.group(1).strip() if name else "",
                    "updated": updated.group(1) if updated else "",
                }
            )
    return records


def parse_value(raw):
    """IANA writes ids as `5`, `0-255`, `0xff00-0xffff`, or `N/A`."""
    raw = raw.replace(" ", "")
    if not raw or raw.upper() == "N/A":
        return None
    first = raw.split("-")[0]
    if first.startswith("0x") or first.startswith("0X"):
        return int(first, 16)
    return int(first)


def boringssl_ids():
    """Extension ids named in the vendored BoringSSL header."""
    import glob

    pattern = os.path.expanduser(
        "~/.cargo/registry/src/*/btls-sys-0.5.6/deps/boringssl/"
        "include/openssl/tls1.h"
    )
    candidates = glob.glob(pattern)
    if not candidates:
        return {}
    with open(candidates[0], encoding="utf-8") as handle:
        text = handle.read()
    out = {}
    for name, value in re.findall(
        r"#define TLSEXT_TYPE_([a-z0-9_]+) (0x[0-9a-fA-F]+|\d+)", text
    ):
        out[int(value, 0)] = name
    return out


def load_baseline():
    try:
        with open(BASELINE, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {"iana": {}, "boringssl": {}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()

    baseline = load_baseline()

    try:
        xml = fetch(IANA_URL)
    except Exception as error:  # noqa: BLE001 - the point is to report it
        print(f"IANA registry unreachable: {error}", file=sys.stderr)
        xml = None

    new_ids = []
    if xml is not None:
        records = iana_records(xml)
        known = baseline.get("iana", {})
        for record in records:
            ident = record["id"]
            if str(ident) not in known:
                # A codepoint that appears for the first time.
                new_ids.append(("iana", ident, record["name"], record["updated"]))
            elif known[str(ident)].get("name") != record["name"]:
                # Same codepoint, newly named or reassigned.
                new_ids.append(
                    (
                        "iana-renamed",
                        ident,
                        f"{known[str(ident)].get('name')} -> {record['name']}",
                        record["updated"],
                    )
                )
        print(f"IANA: {len(records)} records, {len(new_ids)} new or changed")

    bssl = boringssl_ids()
    if bssl:
        known_bssl = baseline.get("boringssl", {})
        fresh = [i for i in bssl if str(i) not in known_bssl]
        print(f"BoringSSL: {len(bssl)} ids, {len(fresh)} not in the baseline")
        for ident in sorted(fresh):
            new_ids.append(("boring", ident, bssl[ident], ""))

    if new_ids:
        print()
        print("New or changed extension ids:")
        for source, ident, name, updated in new_ids:
            print(f"  {ident:<7} {source:<13} {name:<34} {updated}")
        print()
        print(
            "For each id: capture a current Chrome ClientHello, decide whether it "
            "can be expressed by BoringSSL, and add a switch to "
            "scripts/boringssl/chrome4832.patch if it cannot."
        )
    else:
        print("\nNothing new since the baseline.")

    if args.update:
        payload = {
            "iana": {
                str(record["id"]): {"name": record["name"], "updated": record["updated"]}
                for record in (iana_records(xml) if xml is not None else [])
            },
            "boringssl": {str(ident): name for ident, name in bssl.items()},
        }
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=1, sort_keys=True)
            handle.write("\n")
        print(f"baseline written: {BASELINE}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
