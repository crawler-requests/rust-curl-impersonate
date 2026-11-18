#!/usr/bin/env python3
"""Build the ClientHello extension registry Chrome can send.

Three inputs, merged:

  1. Every extension id seen in the library's Chrome captures
     (tools/capture/raw/*.json) - what Chrome actually sends.
  2. Every extension id the vendored BoringSSL knows
     (btls-sys .../include/openssl/tls1.h plus ssl/extensions.cc), which
     tells us what the transport can express natively.
  3. A hand-written list of ids the vendored patch adds, plus the ones no
     BoringSSL build has (Chromium-only extensions).

Output: goal-evidence/extension-registry.md, a table saying for each id:
  - the name and what it is,
  - how many Chrome captures carry it,
  - whether this crate can emit it, and how.

Run: python3 -I tools/extension_registry.py
"""

import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RAW = os.path.join(HERE, "capture", "raw")
BTLS = os.path.expanduser("~/.cargo/registry/src")

# Names and meanings for ids a reader will meet in a Chrome ClientHello.
# Anything not listed here is still reported, just without prose.
KNOWN = {
    0: ("server_name", "SNI; the hostname Chrome is asking for"),
    5: ("status_request", "OCSP stapling request"),
    10: ("supported_groups", "named groups, in Chrome's preference order"),
    11: ("ec_point_formats", "legacy uncompressed-point marker"),
    13: ("signature_algorithms", "sigalg list; Chrome 156+ leads with GREASE and ML-DSA"),
    16: ("alpn", "application protocol negotiation (h2, http/1.1, sometimes h3)"),
    18: ("signed_certificate_timestamp", "SCT request"),
    21: ("padding", "RFC 7685 padding; Chromium sends it with a fixed length"),
    23: ("extended_master_secret", "TLS 1.2 EMS marker"),
    27: ("compress_certificate", "certificate compression (brotli/zstd/zlib)"),
    34: ("delegated_credentials", "RFC 9345 delegated credentials"),
    35: ("session_ticket", "ticket-based resumption marker"),
    41: ("pre_shared_key", "TLS 1.3 resumption; only on a resumed session"),
    43: ("supported_versions", "TLS version list"),
    44: ("cookie", "DTLS cookie; not used by Chrome over TCP/QUIC"),
    45: ("psk_key_exchange_modes", "psk_dhe_ke marker"),
    47: ("certificate_authorities", "CA name list for post-handshake auth"),
    50: ("signature_algorithms_cert", "sigalg list for certificates"),
    51: ("key_share", "ephemeral key shares (X25519MLKEM768 first on 131+)"),
    57: ("quic_transport_parameters", "QUIC only; never in a TCP ClientHello"),
    62: ("tls_flags", "BoringSSL extension, not sent by Chrome"),
    17513: ("application_settings_old", "ALPS, older code point (Chrome <124)"),
    17613: ("application_settings", "ALPS, current code point (Chrome 124+)"),
    30032: ("channel_id", "deprecated ChannelID; Chrome 58-70 send it empty"),
    4832: ("server_padding_request", "Chromium-only; asks the server to pad its response"),
    51764: ("trust_anchors", "draft-ietf-tls-trust-anchors; Chrome 156+ with an id list"),
    65037: ("ech_grease", "ECH GREASE when no ECHConfig was found"),
    65281: ("renegotiation_info", "legacy renegotiation marker"),
    13172: ("next_proto_neg", "deprecated NPN; uTLS iOS captures only"),
}

# Ids the vendored patch adds a switch for
# (scripts/boringssl/chrome4832.patch).
PATCHED = {
    4832: "SSL_CTX_set_server_padding_request",
    30032: "SSL_CTX_set_channel_id_offer",
    21: "SSL_CTX_set_force_padding_len",
}

# Ids BoringSSL knows and can emit without any patch.
NATIVE_OVERRIDES = {}


def extension_id(entry):
    """The numeric id of one captured extension entry."""
    name = entry.get("name") if isinstance(entry, dict) else str(entry)
    if not name or "GREASE" in name:
        return None
    match = re.search(r"\((\d+)\)", name)
    if match:
        return int(match.group(1))
    match = re.search(r"Unknown extension (\d+)", name)
    if match:
        return int(match.group(1))
    match = re.search(r"Unknown extension (0x[0-9a-fA-F]+)", name)
    if match:
        return int(match.group(1), 16)
    return None


def chrome_captures():
    """(id -> set of record names) across the Chrome-family captures."""
    ids = {}
    for path in sorted(glob.glob(os.path.join(RAW, "*.json"))):
        stem = os.path.basename(path)[:-5]
        if not (
            stem.startswith("chrome")
            or stem.startswith("chromium")
            or stem.startswith("tlsclient_chrome")
            or stem.startswith("utls_chrome")
        ):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            continue
        for entry in document.get("tls", {}).get("extensions", []):
            ident = extension_id(entry)
            if ident is not None:
                ids.setdefault(ident, set()).add(stem)
    return ids


def boringssl_known():
    """Extension ids the vendored BoringSSL headers name."""
    pattern = os.path.join(
        BTLS, "*", "btls-sys-0.5.6", "deps", "boringssl", "include", "openssl", "tls1.h"
    )
    candidates = glob.glob(pattern)
    if not candidates:
        return {}
    known = {}
    with open(candidates[0], encoding="utf-8") as handle:
        text = handle.read()
    for name, value in re.findall(
        r"#define TLSEXT_TYPE_([a-z0-9_]+) (0x[0-9a-fA-F]+|\d+)", text
    ):
        known.setdefault(int(value, 0), name)
    return known


def classify(ident, seen_in, bssl):
    """How this crate sends the extension, or why it cannot."""
    if ident == 4832:
        return "patch", "SSL_CTX_set_server_padding_request"
    if ident == 30032:
        return "patch", "SSL_CTX_set_channel_id_offer (empty payload)"
    if ident == 21:
        return "patch", "SSL_CTX_set_force_padding_len (exact length)"
    if ident == 41:
        return "cache", "session cache; appears on the resumed connection"
    if ident == 51764:
        return "native", "SSL_CTX_set1_requested_trust_anchors"
    if ident in bssl:
        return "native", bssl[ident]
    if ident in seen_in:
        return "unsupported", "BoringSSL has no writer for it"
    return "unknown", ""


def main():
    seen = chrome_captures()
    bssl = boringssl_known()
    rows = []
    for ident in sorted(set(seen) | set(bssl)):
        state, how = classify(ident, seen, bssl)
        name, meaning = KNOWN.get(ident, ("", ""))
        rows.append(
            {
                "id": ident,
                "name": name,
                "meaning": meaning,
                "captures": len(seen.get(ident, ())),
                "state": state,
                "how": how,
            }
        )

    out = []
    out.append("# Chrome ClientHello extension registry")
    out.append("")
    out.append("Generated by `tools/extension_registry.py` - do not edit by hand.")
    out.append("")
    out.append(
        "Covers every extension id seen in the library's Chrome captures plus every "
        "id the vendored BoringSSL names. `state` says how this crate emits it:"
    )
    out.append("")
    out.append("- `native` - BoringSSL writes it with an existing API")
    out.append("- `patch` - needs `scripts/boringssl/chrome4832.patch`")
    out.append("- `cache` - needs the session cache (resumed connection)")
    out.append("- `unsupported` - comes from a capture but BoringSSL cannot write it")
    out.append("- `unknown` - known to BoringSSL but never seen in a Chrome capture")
    out.append("")
    out.append("| id | name | captures | state | how | meaning |")
    out.append("|---|---|---|---|---|---|")
    for row in rows:
        out.append(
            f"| {row['id']} | {row['name'] or '-'} | {row['captures'] or '-'} | "
            f"{row['state']} | {row['how'] or '-'} | {row['meaning'] or '-'} |"
        )
    out.append("")

    counts = {}
    for row in rows:
        counts[row["state"]] = counts.get(row["state"], 0) + 1
    out.append("## Summary")
    out.append("")
    for state in ("native", "patch", "cache", "unsupported", "unknown"):
        if state in counts:
            out.append(f"- {state}: {counts[state]}")
    unsupported = [r for r in rows if r["state"] == "unsupported"]
    out.append("")
    if unsupported:
        out.append("### Unsupported ids")
        out.append("")
        for row in unsupported:
            out.append(
                f"- {row['id']} ({row['name'] or 'unnamed'}) in {row['captures']} "
                f"capture(s) - {row['meaning'] or 'no description'}"
            )
    else:
        out.append("No captured Chrome extension is unsupported.")

    target = os.path.join(ROOT, "goal-evidence", "extension-registry.md")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")
    print("\n".join(out[:12]))
    print(f"\n... wrote {target}")


if __name__ == "__main__":
    sys.exit(main())
