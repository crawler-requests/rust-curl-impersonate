#!/usr/bin/env python3
"""Capture an Android WebView's ClientHello through its DevTools port.

An Android device's WebView runs Chromium's TLS stack, so its ClientHello is
byte-identical to what that Chromium build sends on any platform. That makes
WebView a real Android fingerprint source, and it differs from desktop
Chrome: an Android WebView 125 sends 17 extensions with the old ALPS
codepoint and padding, where desktop Chrome 125 sends 16 without either.

The webview_shell test app can be pointed at the echo service, and its
DevTools endpoint exposes the rendered JSON.

    python3 -I tools/capture/android_webview_capture.py \
        <device-serial> <output.json> [--port 9400]

Requires `adb` on PATH and a device whose WebView has debugging enabled
(webview_shell ships that way).
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

SHELL = "org.chromium.webview_shell"
ACTIVITY = f"{SHELL}/.WebViewBrowserActivity"
URL = "https://tls.peet.ws/api/all"


def adb(serial, *args, check=True):
    result = subprocess.run(
        ["adb", "-s", serial, *args], capture_output=True, text=True
    )
    if check and result.returncode != 0:
        raise SystemExit(f"adb {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def socket_name(serial):
    """The abstract socket the WebView DevTools server listens on."""
    listing = adb(serial, "shell", "cat /proc/net/unix")
    for line in listing.splitlines():
        if "webview_devtools_remote_" in line:
            return line.rsplit("@", 1)[-1].strip()
    raise SystemExit("no webview_devtools_remote socket; is WebView debugging on?")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("serial")
    parser.add_argument("output")
    parser.add_argument("--port", type=int, default=9400)
    parser.add_argument("--settle", type=int, default=18)
    args = parser.parse_args()

    # The page occasionally fails to render on the first load, so retry the
    # navigation itself a couple of times before giving up.
    for attempt in range(3):
        adb(args.serial, "shell", "am", "force-stop", SHELL)
        time.sleep(1)
        adb(args.serial, "shell", "am", "start", "-n", ACTIVITY,
            "-a", "android.intent.action.VIEW", "-d", URL)
        time.sleep(args.settle)
        # A reload is cheap; a failed render is not, so just try again.

    forwarded = adb(
        args.serial, "forward", f"tcp:{args.port}",
        "localabstract:" + socket_name(args.serial),
    ).strip()

    base = f"http://localhost:{forwarded or args.port}"
    try:
        with urllib.request.urlopen(base + "/json/list", timeout=10) as response:
            targets = json.load(response)
    except urllib.error.URLError as error:
        raise SystemExit(f"DevTools endpoint unreachable: {error}")

    page = next(target for target in targets if target.get("type") == "page")
    from websocket import create_connection

    ws = create_connection(
        page["webSocketDebuggerUrl"],
        timeout=30,
        origin=base,
        suppress_origin=True,
    )
    ws.send(json.dumps({
        "id": 1,
        "method": "Runtime.evaluate",
        "params": {"expression": "document.body.innerText", "returnByValue": True},
    }))
    def read(ws):
        ws.send(json.dumps({
            "id": 2,
            "method": "Runtime.evaluate",
            "params": {"expression": "document.body.innerText", "returnByValue": True},
        }))
        while True:
            message = json.loads(ws.recv())
            if message.get("id") == 2:
                return message["result"]["result"].get("value", "")

    text = ""
    for attempt in range(6):
        text = read(ws)
        try:
            json.loads(text[text.find("{"):])
            break
        except ValueError:
            pass
        # Not complete yet (or never loaded): reload and wait again.
        adb(args.serial, "shell", "am", "start", "-n", ACTIVITY,
            "-a", "android.intent.action.VIEW", "-d", URL)
        time.sleep(args.settle)
    ws.close()

    begin = text.find("{")
    if begin < 0:
        raise SystemExit("the page did not render the echo JSON")
    document = json.loads(text[begin:])
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "tls": document["tls"],
                "http2": document.get("http2", {}),
                "http_version": document.get("http_version", ""),
                "user_agent": document.get("user_agent", ""),
            },
            handle,
            indent=1,
        )
    print(f"wrote {args.output}: ja4 {document['tls']['ja4']}")


if __name__ == "__main__":
    sys.exit(main())
