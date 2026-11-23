#!/usr/bin/env python3
"""Capture every library version on whatever device adb is attached to.

This runs on the machine the device is plugged into, so it is the same grid
as tools/capture/android_matrix.py but pointed at one phone instead of the
redroid containers. Each variant APK is installed in turn, the listener
reads the hello, and the result is one directory per variant plus a
matrix.json that names any client that refused to start.

    python3 -I tools/capture/device_matrix.py --out DIR \
        [--serial SERIAL] [--apk-dir tools/capture/android_phone/out] \
        [--variants okhttp-4.12.0,...] [--seconds N] [--echo]
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURE = os.path.join(HERE, "phone_capture.py")
PHONE = os.path.join(HERE, "android_phone")


def adb(serial, *args, timeout=300):
    command = ["adb"]
    if serial:
        command += ["-s", serial]
    command += list(args)
    return subprocess.run(command, capture_output=True, text=True,
                          timeout=timeout)


def device_facts(serial):
    def prop(name):
        return adb(serial, "shell", "getprop", name, timeout=30).stdout.strip()

    webview = adb(serial, "shell", "dumpsys", "webviewupdate", timeout=60)
    match = re.search(r"Current WebView package \(name, version\): \((\S+), (\S+)\)",
                      webview.stdout)
    return {
        "serial": serial,
        "release": prop("ro.build.version.release"),
        "sdk": prop("ro.build.version.sdk"),
        "model": prop("ro.product.model"),
        "abi": prop("ro.product.cpu.abi"),
        "fingerprint": prop("ro.build.fingerprint"),
        "webview": match.group(2) if match else "",
    }


def modes_for(variant):
    if variant == "platform":
        return "urlconn,webview"
    if variant.startswith("okhttp"):
        return "okhttp"
    if variant.startswith("conscrypt"):
        return "conscrypt"
    if variant.startswith("cronet"):
        return "cronet"
    return "urlconn"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"))
    parser.add_argument("--apk-dir", default=os.path.join(PHONE, "out"))
    parser.add_argument("--variants", default="")
    # The device resolves the sslip.io name before connecting, and on a
    # cold DNS cache that takes 20-30 seconds; a shorter window captures
    # nothing and looks like a hang.
    parser.add_argument("--seconds", type=int, default=75)
    parser.add_argument("--port", type=int, default=39280)
    parser.add_argument("--echo", action="store_true")
    args = parser.parse_args()

    serials = adb(None, "devices", timeout=30).stdout.splitlines()[1:]
    serials = [s.split()[0] for s in serials
               if len(s.split()) >= 2 and s.split()[1] == "device"]
    serial = args.serial or (serials[0] if serials else None)
    if serial is None:
        sys.exit("no device attached; start adb or pass --serial")

    facts = device_facts(serial)
    print("device: %s %s (SDK %s, %s, WebView %s)" % (
        facts["model"], facts["release"], facts["sdk"], facts["abi"],
        facts["webview"]), flush=True)

    wanted = [v for v in args.variants.split(",") if v]
    apks = ["platform"] + sorted(
        os.path.basename(p)[:-4] for p in glob.glob(os.path.join(args.apk_dir, "*.apk")))
    if wanted:
        apks = [a for a in apks if a in wanted]

    os.makedirs(args.out, exist_ok=True)
    results = []
    for variant in apks:
        apk = os.path.join(PHONE, "app.apk") if variant == "platform" \
            else os.path.join(args.apk_dir, variant + ".apk")
        # The SNI is part of the hello: a long label pushes the ClientHello
        # past the 511-byte padding window and the capture gets flaky on
        # some devices, so the wire name stays short. The directory keeps
        # the full name, and matrix.json maps one to the other.
        label = "v%02d" % apks.index(variant)
        outdir = os.path.join(args.out, "%s-%s" % (variant, facts["sdk"]))
        if os.path.exists(outdir):
            shutil.rmtree(outdir)
        print("\n== %s" % variant, flush=True)

        install = adb(serial, "install", "-r", "-t", apk)
        if install.returncode != 0 or "Success" not in install.stdout:
            why = (install.stdout + install.stderr).strip().splitlines()[-1:]
            results.append({"variant": variant, "device": facts,
                            "captures": [], "error": " ".join(why)})
            print("  install failed: %s" % why, flush=True)
            continue
        # A stale install of another ABI reports Success and then cannot
        # load its native library, which looks like "0 captures" later.
        updated = adb(serial, "shell", "dumpsys", "package", "io.capture.phone")
        print("  installed %s" % apk.rsplit("/", 1)[-1], flush=True)

        command = [sys.executable, "-I", CAPTURE, "--serial", serial,
                   "--out", outdir, "--reverse", "--port", str(args.port),
                   "--proxy-port", str(args.port + 1),
                   "--seconds", str(args.seconds), "--no-install",
                   "--label", label, "--mode", modes_for(variant)]
        if args.echo:
            command.append("--echo")
        proc = subprocess.run(command, capture_output=True, text=True,
                              timeout=args.seconds + 240)
        entry = {"variant": variant, "label": label, "device": facts,
                 "captures": [], "error": ""}
        for item in sorted(glob.glob(os.path.join(outdir, "*.json"))):
            document = json.load(open(item))
            entry["captures"].append({"sni": document.get("sni"),
                                      "ja4": (document.get("tls") or {}).get("ja4"),
                                      "file": os.path.basename(item)})
        log = os.path.join(outdir, "app.log")
        if os.path.exists(log):
            text = open(log, errors="ignore").read()
            entry["failures"] = re.findall(r"PhoneCap: (\S+) failed: ([^\n]+)", text)
        if proc.returncode != 0:
            entry["error"] = (proc.stderr or proc.stdout)[-400:]
        results.append(entry)
        print("  %d captures %s" % (len(entry["captures"]),
                                    entry.get("failures") or ""), flush=True)
        # Let the previous cell's listener and reverse forward go away.
        time.sleep(2)

    with open(os.path.join(args.out, "matrix.json"), "w") as handle:
        json.dump(results, handle, indent=1)
    print("\nwrote %s" % os.path.join(args.out, "matrix.json"))


if __name__ == "__main__":
    sys.exit(main())
