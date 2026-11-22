#!/usr/bin/env python3
"""Capture every library version on every Android device that can run it.

Each (device, variant) pair gets its own capture directory, and the SNI
labels carry both: `a12-okhttp-4-12-0-okhttp.<base>`. A variant whose APK
refuses to start on an old Android version logs why, and that reason is kept
in the result file - "OkHttp 3.14.4 rejects API 33" is a fact about the
client, not a failed run.

    python3 -I tools/capture/android_matrix.py --out DIR \
        [--devices 5560,5561,...] [--variants okhttp-4.12.0,...] \
        [--seconds N] [--echo]

Without --devices it uses every adb transport that says `device`.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURE = os.path.join(HERE, "phone_capture.py")
PHONE = os.path.join(HERE, "android_phone")
ROOT = os.path.dirname(os.path.dirname(HERE))


def adb(serial, *args, timeout=180):
    command = ["adb"]
    if serial:
        command += ["-s", serial]
    command += list(args)
    return subprocess.run(command, capture_output=True, text=True,
                          timeout=timeout)


def devices():
    found = []
    listing = subprocess.run(["adb", "devices"], capture_output=True,
                             text=True, timeout=30).stdout
    for line in listing.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            found.append(parts[0])
    return found


def device_info(serial):
    def prop(name):
        return adb(serial, "shell", "getprop", name, timeout=30).stdout.strip()

    return {
        "serial": serial,
        "release": prop("ro.build.version.release"),
        "sdk": prop("ro.build.version.sdk"),
        "model": prop("ro.product.model"),
        "abi": prop("ro.product.cpu.abi"),
    }


def variants(selected):
    """`platform` is app.apk: the system stack and WebView, no library."""
    found = ["platform"]
    base = os.path.join(PHONE, "out")
    for name in sorted(os.listdir(base)):
        if not name.endswith(".apk"):
            continue
        stem = name[:-4]
        if selected and stem not in selected:
            continue
        found.append(stem)
    return [name for name in found if not selected or name in selected]


def run_one(serial, label, variant, outdir, seconds, echo):
    if variant == "platform":
        apk = os.path.join(PHONE, "app.apk")
        mode = "urlconn,webview"
    else:
        apk = os.path.join(PHONE, "out", variant + ".apk")
        mode = "okhttp" if variant.startswith("okhttp") else \
            "conscrypt" if variant.startswith("conscrypt") else \
            "cronet" if variant.startswith("cronet") else "urlconn"
    command = [sys.executable, "-I", CAPTURE, "--serial", serial,
               "--out", outdir, "--reverse", "--port", "39130",
               "--proxy-port", "39131", "--seconds", str(seconds),
               "--apk", apk, "--label", label, "--mode", mode]
    if echo:
        command.append("--echo")
    result = subprocess.run(command, capture_output=True, text=True,
                            timeout=seconds + 300)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--devices")
    parser.add_argument("--variants")
    parser.add_argument("--seconds", type=int, default=40)
    parser.add_argument("--echo", action="store_true")
    parser.add_argument("--record", help="also check each capture against a "
                                         "record of the same name")
    args = parser.parse_args()

    serials = args.devices.split(",") if args.devices else devices()
    picked = args.variants.split(",") if args.variants else None
    names = variants(picked)
    os.makedirs(args.out, exist_ok=True)

    results = []
    for serial in serials:
        info = device_info(serial)
        short = "a%s" % info["sdk"]
        for variant in names:
            label = "%s-%s" % (short, variant)
            outdir = os.path.join(args.out, label)
            print("\n== %s on %s (SDK %s)" % (variant, serial, info["sdk"]),
                  flush=True)
            os.makedirs(outdir, exist_ok=False)
            started = time.time()
            result = run_one(serial, label, variant, outdir, args.seconds,
                             args.echo)
            entry = {
                "device": info,
                "variant": variant,
                "label": label,
                "captures": [],
                "error": "",
                "seconds": round(time.time() - started, 1),
            }
            for item in sorted(os.listdir(outdir)):
                if item.endswith(".json"):
                    with open(os.path.join(outdir, item)) as handle:
                        document = json.load(handle)
                    entry["captures"].append({
                        "sni": document.get("sni"),
                        "ja4": (document.get("tls") or {}).get("ja4"),
                        "file": item,
                    })
            log = os.path.join(outdir, "app.log")
            if os.path.exists(log):
                text = open(log, errors="ignore").read()
                failures = re.findall(r"PhoneCap: (\S+) failed: ([^\n]+)", text)
                entry["failures"] = [[name, why] for name, why in failures]
            if result.returncode != 0:
                entry["error"] = (result.stderr or result.stdout)[-400:]
            results.append(entry)
            print("  %d captures, %s" % (len(entry["captures"]),
                                         entry.get("failures") or "no failure"),
                  flush=True)

    with open(os.path.join(args.out, "matrix.json"), "w") as handle:
        json.dump(results, handle, indent=1)
    print("\nwrote %s" % os.path.join(args.out, "matrix.json"))


if __name__ == "__main__":
    main()
