#!/usr/bin/env python3
"""Capture Firefox through geckodriver.

Firefox renders ``application/json`` with its internal JSON viewer, so neither
``body.innerText`` nor the WebDriver page source contains the raw document.
The viewer's "Raw Data" tab does; this script opens it and reads the text.

    python3 tools/capture/firefox_capture.py tools/capture/raw/firefox158.json

Set ``GECKODRIVER`` to the binary and ``GECKODRIVER_PORT`` to change the port;
the script starts geckodriver itself.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

URL = "https://tls.peet.ws/api/all"
PORT = int(os.environ.get("GECKODRIVER_PORT", "4444"))
GECKODRIVER = os.environ.get("GECKODRIVER", "geckodriver")


def wait_for(status_url, seconds=30):
    for _ in range(seconds * 2):
        try:
            with urllib.request.urlopen(status_url, timeout=2):
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"{status_url} did not become ready")


def request(base, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        base + path, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{method} {path}: {error.read().decode()[:400]}") from error


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: firefox_capture.py <output>")
    process = subprocess.Popen(
        [GECKODRIVER, "--port", str(PORT), "--log", "error"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{PORT}"
    try:
        wait_for(base + "/status")
        session = request(
            base,
            "POST",
            "/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "firefox",
                        "moz:firefoxOptions": {"args": ["-headless"]},
                    }
                }
            },
        )["value"]["sessionId"]
        try:
            request(base, "POST", f"/session/{session}/url", {"url": URL})
            time.sleep(2)
            # The viewer tab is a <button>; only the xpath finds it by text.
            element = request(
                base,
                "POST",
                f"/session/{session}/element",
                {"using": "xpath", "value": '//*[normalize-space(text())="Raw Data"]'},
            )["value"]["element-6066-11e4-a52e-4f735466cecf"]
            request(base, "POST", f"/session/{session}/element/{element}/click", {})
            time.sleep(1)
            text = request(
                base,
                "POST",
                f"/session/{session}/execute/sync",
                {"script": "return document.body.textContent", "args": []},
            )["value"]
            match = re.search(r'\{.*"tls"\s*:', text, re.S)
            if match is None:
                raise RuntimeError("the Raw Data tab did not contain the JSON document")
            body = text[match.start() :]
            _, end = json.JSONDecoder().raw_decode(body)
            with open(sys.argv[1], "w", encoding="utf-8") as handle:
                handle.write(body[:end])
            print("firefox: saved", end, "bytes")
        finally:
            try:
                request(base, "DELETE", f"/session/{session}")
            except Exception:
                pass
    finally:
        process.terminate()


if __name__ == "__main__":
    main()
