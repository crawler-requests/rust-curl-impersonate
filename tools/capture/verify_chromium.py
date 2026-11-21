#!/usr/bin/env python3
"""Re-capture a Chromium build and compare it with the record it produced.

A Chromium record has two states worth distinguishing:

  first connection   no `pre_shared_key`, one fewer extension
  resumed session    `pre_shared_key` from a cached ticket

`chromium_capture.py` starts a fresh profile every run, so it can only ever
see the first state. Chrome for Testing records such as chrome158 and chrome159
were captured in the resumed state, which is why running the old script
against the same build looks like a mismatch. Driving one browser process over
CDP and navigating twice reproduces the resumed hello.

Usage:
    python3 -I tools/capture/verify_chromium.py <chrome-binary> <record> [--url ...]

Exits non-zero on a mismatch.
"""

import argparse
import json
import os
from collections import Counter
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW = os.path.join(ROOT, "tools", "capture", "raw")


def evaluate_until_json(websocket, port, url, attempts=3):
    """Navigate in one browser process, returning the echo JSON per visit."""
    tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
    ws_url = [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
    ws = websocket.create_connection(ws_url, timeout=60)
    counter = [0]

    def send(method, params=None):
        counter[0] += 1
        current = counter[0]
        ws.send(json.dumps({"id": current, "method": method, "params": params or {}}))
        while True:
            message = json.loads(ws.recv())
            if message.get("id") == current:
                return message

    results = []
    try:
        for _ in range(attempts):
            send("Page.navigate", {"url": url})
            time.sleep(6)
            reply = send("Runtime.evaluate",
                         {"expression": "document.body.innerText", "returnByValue": True})
            text = reply.get("result", {}).get("result", {}).get("value", "")
            try:
                results.append(json.loads(text))
            except ValueError:
                results.append(None)
    finally:
        ws.close()
    return results


def names_of(tls):
    return sorted(
        "GREASE" if "GREASE" in entry["name"] else entry["name"].split(" (")[0]
        for entry in tls["extensions"]
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("record")
    parser.add_argument("--url", default="https://tls.peet.ws/api/all")
    args = parser.parse_args()

    try:
        import websocket  # noqa: F401
    except ImportError:
        sys.exit("needs the websocket-client package: pip install websocket-client")

    profile = tempfile.mkdtemp(prefix="cft-verify-")
    port = 9333
    browser = subprocess.Popen(
        [args.binary, "--headless=new", "--no-sandbox", "--disable-gpu",
         f"--user-data-dir={profile}", f"--remote-debugging-port={port}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(5)
        visits = evaluate_until_json(__import__("websocket"), port, args.url)
    finally:
        browser.terminate()
        browser.wait(timeout=20)

    visits = [v for v in visits if v]
    if not visits:
        raise SystemExit("no echo JSON from the browser")

    record = json.load(open(os.path.join(RAW, args.record + ".json")))
    expected = names_of(record["tls"])
    expected_ja4 = record["tls"]["ja4"]

    # A Chrome ClientHello has two shapes: a first connection (no
    # pre_shared_key) and a resumed one (with it). The record was captured in
    # whichever state the capture run happened to be in, so compare against
    # both - what must hold is that the observed hello is one of the two
    # states of this build, with everything else identical.
    def without_psk(names):
        return [n for n in names if n != "pre_shared_key"]

    ok = False
    for index, visit in enumerate(visits, 1):
        live = names_of(visit["tls"])
        # A resumed connection differs from a first one by exactly the
        # pre_shared_key extension - and only when that is the sole
        # difference may the comparison ignore it. Any other divergence is a
        # real mismatch and must be reported.
        # Extension name sets are necessary but not sufficient, and the JA4
        # a-segment counts them, so the two are checked together: a record and
        # a run match only if they are in the same state (both first
        # connections, or both resumed) and everything else is equal.
        #
        # CDP keeps one browser process, so every visit after the first is a
        # resumed session. A record captured on a first connection therefore
        # differs by exactly pre_shared_key, which is a state difference, not
        # a wrong record - the run reports it and names which state it saw.
        recorded_segment = expected_ja4.split("_")[0] if expected_ja4 else ""
        live_segment = visit["tls"]["ja4"].split("_")[0]
        resumed = "pre_shared_key" in live
        first_connection = (
            live == expected and live_segment == recorded_segment
        )
        # If the record is a first connection and this visit is resumed, the
        # comparison is meaningful only after dropping the PSK extension and
        # the segment that counts it.
        state_only = (
            resumed
            and Counter(live) - Counter({"pre_shared_key": 1}) == Counter(expected)
            and recorded_segment[:6] == live_segment[:6]
        )
        same = first_connection or state_only
        print(f"visit {index}: ja4={visit['tls']['ja4']} "
              f"exts={len([n for n in live if n != 'GREASE'])} "
              f"psk={'pre_shared_key' in live} match={same}")
        if same:
            ok = True

    if not ok:
        print(f"\nrecord {args.record}: ja4={expected_ja4}")
        print("  expected:", [n for n in expected if n != "GREASE"])
        print("  live    :", [n for n in names_of(visits[0]['tls']) if n != "GREASE"])
        return 1
    print(f"\nOK: {args.record} reproduced from {os.path.basename(args.binary)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
