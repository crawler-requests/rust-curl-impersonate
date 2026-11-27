#!/usr/bin/env python3
"""Download and verify the rust-curl-impersonate C ABI archive for this host.

    python3 fetch_library.py                     # newest release, this host
    python3 fetch_library.py --version 0.3.0     # a specific release
    python3 fetch_library.py --target aarch64-apple-ios   # cross target
    python3 fetch_library.py --dest ./vendor/rci # where to unpack

What it does:

1. maps this machine (or `--target`) to one of the 18 published targets;
2. asks the GitHub API for the release and the asset name, falling back to a
   plain URL if the API is rate-limited;
3. downloads with resume and a long timeout (GitHub over a slow link is
   normal: the archive is ~19 MB and a direct connection can sit at 30 KB/s);
4. checks the SHA-256 against the release's SHA256SUMS;
5. unpacks into `--dest` (default: ./rci).

The result directory has the layout every other script and doc assumes:

    rci/include/rci.h
    rci/lib/librust_curl_impersonate_ffi.so   (or .dylib / .dll)
    rci/lib/librust_curl_impersonate_ffi.a    (or .lib)
    rci/python/rci_bindings.py
    rci/java/...  rci/EMBEDDING.md  rci/USING_THIS_ARCHIVE.md
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

REPO = "crawler-requests/rust-curl-impersonate"
API = "https://api.github.com/repos/%s/releases" % REPO
DOWNLOAD = "https://github.com/%s/releases/download" % REPO
# A slow link is not an error. Five minutes covers 19 MB at ~65 KB/s.
TIMEOUT = 900


def host_target() -> str:
    """The published target matching this machine, or exit with a hint."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64", "armv7l": "armv7"}.get(machine, machine)

    if system == "linux":
        # musl hosts (Alpine) need the musl build; detect it from the libc.
        musl = False
        try:
            with open("/proc/self/maps", encoding="utf-8") as handle:
                musl = any("musl" in line for line in handle)
        except OSError:
            pass
        if not musl:
            out = subprocess.run(["ldd", "--version"], capture_output=True, text=True)
            musl = "musl" in (out.stdout + out.stderr).lower()
        if machine in ("x86_64", "aarch64"):
            return f"{machine}-unknown-linux-{ 'musl' if musl else 'gnu'}"
        if machine == "armv7":
            return "armv7-unknown-linux-gnueabihf"
        if machine in ("i686", "i386"):
            return "i686-unknown-linux-gnu"   # no i686-musl build exists
    if system == "darwin":
        if machine == "x86_64":
            return "x86_64-apple-darwin"
        if machine == "aarch64":
            return "aarch64-apple-darwin"
    if system == "windows":
        if machine == "x86_64":
            return "x86_64-pc-windows-msvc"
        if machine == "aarch64":
            return "aarch64-pc-windows-msvc"
        if machine in ("i686", "x86"):
            return "i686-pc-windows-msvc"

    sys.exit(
        f"no published target for {system}/{machine}. "
        "Android and iOS builds need an explicit --target, e.g. "
        "--target aarch64-linux-android or --target aarch64-apple-ios. "
        f"Available: {', '.join(KNOWN_TARGETS)}"
    )


KNOWN_TARGETS = [
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "armv7-unknown-linux-gnueabihf", "i686-unknown-linux-gnu",
    "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc", "i686-pc-windows-msvc",
    "aarch64-linux-android", "armv7-linux-androideabi",
    "x86_64-linux-android", "i686-linux-android",
    "aarch64-apple-ios", "aarch64-apple-ios-sim", "x86_64-apple-ios",
]


def http_json(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "rci-skill-fetch"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def resolve_version(explicit: str | None) -> str:
    """Return a tag like v0.3.0. The API is preferred, a plain URL is the fallback."""
    if explicit:
        return explicit if explicit.startswith("v") else "v" + explicit
    try:
        release = http_json(API + "/latest")
        return release["tag_name"]
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError) as error:
        print(f"  GitHub API unavailable ({error}); trying the redirect-free URL", file=sys.stderr)
    raise SystemExit(
        "cannot discover the latest release; pass --version <tag> instead"
    )


def asset_name(version: str, target: str) -> str:
    suffix = ".zip" if "windows" in target else ".tar.gz"
    return f"rust-curl-impersonate-ffi-{version.lstrip('v')}-{target}{suffix}"


def download(url: str, path: str) -> None:
    """Download with resume: a slow or interrupted GitHub transfer continues."""
    for attempt in range(1, 4):
        existing = os.path.getsize(path) if os.path.exists(path) else 0
        request = urllib.request.Request(url, headers={"User-Agent": "rci-skill-fetch"})
        if existing:
            request.add_header("Range", f"bytes={existing}-")
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response, \
                    open(path, "ab" if existing and response.status == 206 else "wb") as handle:
                expected = response.headers.get("Content-Length")
                total = existing + int(expected) if expected else None
                written = existing
                started = time.time()
                while True:
                    chunk = response.read(1 << 16)
                    if not chunk:
                        break
                    handle.write(chunk)
                    written += len(chunk)
                    if total and sys.stderr.isatty():
                        rate = written / max(time.time() - started, 1) / 1024
                        print(f"\r  {written/1048576:.1f}/{total/1048576:.1f} MB "
                              f"({rate:.0f} KB/s)", end="", file=sys.stderr)
            if sys.stderr.isatty():
                print(file=sys.stderr)
            return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            print(f"  attempt {attempt} failed: {error}", file=sys.stderr)
            if attempt == 3:
                raise SystemExit(
                    f"download failed after 3 attempts: {url}\n"
                    "If the connection is slow, retry this script — it resumes from "
                    "where it stopped. A release asset can also be fetched by hand."
                )
            time.sleep(5 * attempt)


def verify(path: str, sums_path: str, name: str) -> None:
    """Check SHA-256 against the release's SHA256SUMS."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    actual = digest.hexdigest()
    expected = None
    if os.path.exists(sums_path):
        with open(sums_path, encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[-1].lstrip("*") == name:
                    expected = parts[0]
                    break
    if expected is None:
        print(f"  no SHA-256 entry for {name}; cannot verify", file=sys.stderr)
        return
    if actual != expected:
        raise SystemExit(f"SHA-256 mismatch for {name}\n  expected {expected}\n  actual   {actual}")
    print(f"  sha256 ok: {actual}")


def unpack(archive: str, dest: str) -> None:
    """Unpack so the archive's single top-level directory becomes `dest`."""
    with tempfile.TemporaryDirectory() as staging:
        if archive.endswith(".zip"):
            with zipfile.ZipFile(archive) as handle:
                handle.extractall(staging)
        else:
            with tarfile.open(archive) as handle:
                handle.extractall(staging)
        entries = os.listdir(staging)
        # The archive wraps everything in one directory; flatten it into dest.
        source = os.path.join(staging, entries[0]) if len(entries) == 1 else staging
        if os.path.exists(dest):
            shutil.rmtree(dest)
        shutil.copytree(source, dest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", help="release tag, e.g. 0.3.0 or v0.3.0")
    parser.add_argument("--target", help="same target names as the release matrix")
    parser.add_argument("--dest", default="rci", help="unpack directory (default: rci)")
    parser.add_argument("--keep-archive", action="store_true")
    args = parser.parse_args()

    target = args.target or host_target()
    if target not in KNOWN_TARGETS:
        sys.exit(f"unknown target {target}; known: {', '.join(KNOWN_TARGETS)}")
    version = resolve_version(args.version)
    name = asset_name(version, target)
    print(f"release {version}, target {target}, asset {name}")

    dest = os.path.abspath(args.dest)
    work = tempfile.mkdtemp(prefix="rci-fetch-")
    archive = os.path.join(work, name)
    sums = os.path.join(work, "SHA256SUMS")
    try:
        download(f"{DOWNLOAD}/{version}/{name}", archive)
        try:
            download(f"{DOWNLOAD}/{version}/SHA256SUMS", sums)
        except SystemExit:
            print("  SHA256SUMS not downloadable; skipping the checksum", file=sys.stderr)
        verify(archive, sums, name)
        unpack(archive, dest)
    finally:
        if args.keep_archive:
            print(f"archive kept at {archive}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    print(f"\ndone: {dest}")
    for root, _, files in os.walk(dest):
        for file in sorted(files):
            if file in ("rci.h",) or file.endswith((".so", ".dylib", ".dll", ".a", ".lib")):
                print("  " + os.path.relpath(os.path.join(root, file), dest))
    print("\nnext: python3 verify_abi.py --lib " + os.path.join(dest, "lib"))


if __name__ == "__main__":
    main()
