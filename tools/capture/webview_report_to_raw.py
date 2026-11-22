#!/usr/bin/env python3
"""Turn a WebView page report into a raw library file.

The WebView cannot use a CONNECT proxy, so it is pointed straight at
tls.peet.ws and reads the report back out of the page: the page's title
carries the fields this project records, and the app logs it. This script
takes that logged report, adds the ClientHello the listener captured from
the same WebView earlier, and writes the raw file.

    python3 -I tools/capture/webview_report_to_raw.py --log LOG \
        --hello RAW_HELLO.json --name NAME [--device TEXT] [--dry-run]
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
MARKER = re.compile(r" I PhoneCap: webview report (\{.*)$")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True,
                        help="captured logcat text with 'webview report' lines")
    parser.add_argument("--hello", required=True,
                        help="raw file holding the ClientHello from the matrix")
    parser.add_argument("--name", required=True)
    parser.add_argument("--device", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    report = None
    for line in open(args.log, errors="ignore"):
        match = MARKER.search(line)
        if match:
            report = json.loads(match.group(1))
            break
    if report is None:
        sys.exit("no webview report in " + args.log)

    hello = json.load(open(os.path.join(RAW, args.hello)))

    record = {
        "tls": hello["tls"],
        "http2": report.get("http2"),
        "http_version": report.get("http_version"),
        "sni": hello.get("sni"),
        "captured": "ClientHello from the listener in this run; HTTP/2 "
                    "fingerprint from tls.peet.ws's report of the same "
                    "WebView build, read out of the page",
        "device": args.device or hello.get("device"),
        "android_sdks": hello.get("android_sdks"),
        "harness": "tools/capture/android_phone (webview-url mode) + "
                   "tools/capture/phone_capture.py",
        "via": "https://tls.peet.ws/api/all loaded in the system WebView",
    }
    print(json.dumps({"ja4": record["tls"]["ja4"],
                      "akamai": (record.get("http2") or {}).get(
                          "akamai_fingerprint")}, indent=1))
    target = os.path.join(RAW, args.name + ".json")
    if args.dry_run:
        print("would write", target)
        return
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=1)
        handle.write("\n")
    print("wrote", target)


if __name__ == "__main__":
    sys.exit(main())
