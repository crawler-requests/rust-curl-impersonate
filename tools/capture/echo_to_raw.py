#!/usr/bin/env python3
"""Turn a `--echo` capture's tls.peet.ws report into a raw library file.

The listener records the ClientHello; the relay hands the same connection to
the real service, whose report comes back in the app log. This script takes
that report (the server's own ja4, ja4_r, HTTP/2 frames and Akamai
fingerprint) and writes it as a raw file, so the record is built from what a
server saw rather than from our parser.

    python3 -I tools/capture/echo_to_raw.py --log DIR/app.log --name NAME \
        [--device TEXT] [--dry-run]
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")

PREFIX = re.compile(r"^\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+\s+\d+\s+\d+ I PhoneCap: ")


def reports(log_text):
    """Every JSON object the app logged as a request body."""
    # Collect the JSON by brace matching rather than by log boundaries: the
    # body may be the last thing a run logs, and a logcat line prefix breaks
    # any line-oriented rule.
    found = []
    text = "\n".join(
        line[PREFIX.match(line).end():] if PREFIX.match(line) else ""
        for line in log_text.splitlines())
    for marker in (" status ", "cronet body ", " body "):
        at = text.find(marker)
        if at < 0:
            continue
        brace = text.find("{", at)
        if brace < 0:
            continue
        depth = 0
        for position in range(brace, len(text)):
            if text[position] == "{":
                depth += 1
            elif text[position] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        found.append(json.loads(text[brace:position + 1]))
                    except json.JSONDecodeError:
                        pass
                    break
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--device", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    text = open(args.log, errors="ignore").read()
    found = reports(text)
    if not found:
        sys.exit("no JSON report in " + args.log)
    report = next((r for r in found if r.get("http2")), found[0])
    raw = {
        "tls": report["tls"],
        "http2": report.get("http2"),
        "http_version": report.get("http_version"),
        "method": report.get("method"),
        "user_agent": report.get("user_agent"),
        "captured": "ClientHello recorded by the listener, then the same "
                    "connection was relayed to tls.peet.ws, whose report "
                    "(ja4, ja4_r, HTTP/2 frames) is stored here",
        "device": args.device,
        "via": "tls.peet.ws echo through tools/capture/phone_capture.py "
               "--echo",
    }
    target = os.path.join(RAW, args.name + ".json")
    print(json.dumps({"ja4": raw["tls"].get("ja4"),
                      "akamai": (raw.get("http2") or {}).get(
                          "akamai_fingerprint")}, indent=1))
    if args.dry_run:
        print("would write", target)
        return
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(raw, handle, indent=1)
        handle.write("\n")
    print("wrote", target)


if __name__ == "__main__":
    sys.exit(main())
