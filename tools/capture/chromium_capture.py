#!/usr/bin/env python3
"""Capture headless Chromium by dumping the JSON viewer page and unwrapping it.

Chromium wraps the response in ``<html><pre>`` when it renders JSON, so the
text is unescaped and saved as the raw document. Run from anywhere:

    python3 tools/capture/chromium_capture.py tools/capture/raw/chromium156.json
"""

import html
import re
import shutil
import subprocess
import sys

URL = "https://tls.peet.ws/api/all"


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: chromium_capture.py <output> [browser-binary]")
    browser = None
    if len(sys.argv) == 3:
        browser = sys.argv[2]
    else:
        for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
            browser = shutil.which(name)
            if browser:
                break
    if browser is None:
        sys.exit("chromium is not installed")
    version = subprocess.run(
        [browser, "--version"], capture_output=True, text=True, timeout=30
    ).stdout
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", version)
    if match is None:
        sys.exit(f"cannot read the Chromium version from {version!r}")
    ua = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{match.group(1)} Safari/537.36"
    )
    result = subprocess.run(
        [
            browser,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            f"--user-agent={ua}",
            "--dump-dom",
            URL,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        sys.exit(f"chromium failed: {result.stderr[-400:]}")
    source = result.stdout
    match = re.search(r"<pre[^>]*>(.*)</pre>", source, re.S)
    body = html.unescape(match.group(1) if match else source)
    with open(sys.argv[1], "w", encoding="utf-8") as handle:
        handle.write(body)
    print("chromium: saved", len(body), "bytes")


if __name__ == "__main__":
    main()
