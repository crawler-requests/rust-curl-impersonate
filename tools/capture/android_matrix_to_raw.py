#!/usr/bin/env python3
"""Turn matrix captures into the raw files the library generator reads.

One file per distinct shape, not per device: OkHttp 4.12 sends the same
hello on Android 8.1 through 14 because the TLS provider, not the OS
release, shapes it. The file records every Android release that produced
that shape, so the grouping is evidence rather than an assumption.

    python3 -I tools/capture/android_matrix_to_raw.py \
        --matrix /tmp/matrix,/tmp/matrix-cronet [--dry-run]

A cell is (android SDK, variant). The variant says what stack and version:
`okhttp-4.12.0`, `conscrypt-2.5.2`, `cronet-119.6045.31`, or `platform`
(the OS's own HttpsURLConnection and WebView).
"""

import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")


def slug(variant):
    return variant.replace(".", "_").replace("-", "_")


def name_for(variant, kind, ja4):
    # The shape's own hash is in the name: two builds of the same library
    # that send different hellos cannot collide.
    suffix = ja4.split("_", 2)[-1]
    base = "android_" + slug(variant)
    if kind == "webview":
        base += "_webview"
    return "%s_%s" % (base, suffix)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True,
                        help="comma-separated matrix output directories")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # (name, ja4) -> list of (sdk, device, document)
    shapes = {}
    for root in args.matrix.split(","):
        for cell in sorted(glob.glob(os.path.join(root, "a*"))):
            label = os.path.basename(cell)
            sdk = int(label[1:3])
            variant = label.split("-", 1)[1]
            for path in sorted(glob.glob(os.path.join(cell, "*.json"))):
                document = json.load(open(path))
                sni = document.get("sni", "")
                kind = "webview" if "webview" in sni else "client"
                if variant == "platform" and kind == "client":
                    # The bare URLConnection hello on each release differs
                    # (h1 vs h2, TLS 1.2 vs 1.3) and is already covered by
                    # android_conscrypt13 for the phone; keep WebView here.
                    continue
                if variant.startswith("okhttp-") and kind != "client":
                    continue
                tls = document["tls"]
                name = name_for(variant, kind, tls["ja4"])
                key = (name, tls["ja4"])
                shapes.setdefault(key, []).append((sdk, document))

    written = []
    for (name, ja4), entries in sorted(shapes.items()):
        sdks = sorted({sdk for sdk, _ in entries})
        first = entries[0][1]
        # A device section names every release this exact hello came from.
        devices = sorted({d.get("device", "") for _, d in entries})
        record = {
            "tls": first["tls"],
            "sni": first.get("sni"),
            "captured": "ClientHello only, recorded off the wire by a "
                        "listener the client connected to; the handshake "
                        "was never answered",
            "captured_at": first.get("captured_at"),
            "device": devices[0],
            "android_sdks": sdks,
            "all_devices": devices,
            "harness": "tools/capture/phone_capture.py + "
                       "tools/capture/android_phone, driven by "
                       "tools/capture/android_matrix.py",
            "build_label": first.get("build_label"),
        }
        target = os.path.join(RAW, name + ".json")
        written.append((name, ja4, sdks, target))
        if args.dry_run:
            continue
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=1)
            handle.write("\n")

    for name, ja4, sdks, target in written:
        print("%-52s %s sdks=%s" % (name, ja4, sdks))
    print("%d shapes from %d cells" % (len(written), len(shapes)))


if __name__ == "__main__":
    sys.exit(main())
