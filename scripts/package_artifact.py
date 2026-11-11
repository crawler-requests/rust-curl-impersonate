#!/usr/bin/env python3
"""Package one platform's C ABI library for a GitHub release.

Usage:
    python3 scripts/package_artifact.py --target x86_64-unknown-linux-gnu \
        --version 0.1.0 --out dist

The archive contains the cdylib, its import library on Windows, rci.h, the
`echo` smoke-test binary, LICENSE and the binding README.
"""

import argparse
import os
import shutil
import sys
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LIBRARIES = (
    "librust_curl_impersonate_ffi.so",
    "librust_curl_impersonate_ffi.dylib",
    "rust_curl_impersonate_ffi.dll",
)
# MSVC writes `<name>.dll.lib`, GNU writes `lib<name>.dll.a`; `.pdb` carries
# Windows debug symbols.
EXTRA_LIBRARY_SUFFIXES = (".dll.lib", ".dll.a", ".pdb")


def find_library(release_dir):
    for name in LIBRARIES:
        path = os.path.join(release_dir, name)
        if os.path.exists(path):
            return path
    sys.exit(f"no cdylib found in {release_dir}")


def release_dir_for(target_dir, target):
    """Cross builds write to <target-dir>/<target>/release; a native build
    without `--target` writes to <target-dir>/release."""
    for candidate in (
        os.path.join(target_dir, target, "release"),
        os.path.join(target_dir, "release"),
    ):
        if any(os.path.exists(os.path.join(candidate, name)) for name in LIBRARIES):
            return candidate
    return os.path.join(target_dir, target, "release")


def stage(target, version, target_dir, out_dir):
    release_dir = release_dir_for(target_dir, target)
    library = find_library(release_dir)
    stem = f"rust-curl-impersonate-ffi-{version}-{target}"
    stage_dir = os.path.join(out_dir, stem)
    os.makedirs(os.path.join(stage_dir, "lib"), exist_ok=True)
    os.makedirs(os.path.join(stage_dir, "include"), exist_ok=True)

    shutil.copy2(library, os.path.join(stage_dir, "lib", os.path.basename(library)))
    for name in sorted(os.listdir(release_dir)):
        if name.endswith(EXTRA_LIBRARY_SUFFIXES) and "rust_curl_impersonate_ffi" in name:
            shutil.copy2(os.path.join(release_dir, name), os.path.join(stage_dir, "lib", name))

    shutil.copy2(os.path.join(ROOT, "bindings", "ffi", "rci.h"),
                 os.path.join(stage_dir, "include", "rci.h"))
    shutil.copy2(os.path.join(ROOT, "LICENSE"), os.path.join(stage_dir, "LICENSE"))
    shutil.copy2(os.path.join(ROOT, "bindings", "ffi", "README.md"),
                 os.path.join(stage_dir, "README.md"))

    # Android artifacts are consumed as a shared library, not as a host binary.
    echo = os.path.join(release_dir, "examples", "echo" + (".exe" if "windows" in target else ""))
    if "android" not in target and os.path.exists(echo):
        os.makedirs(os.path.join(stage_dir, "bin"), exist_ok=True)
        shutil.copy2(echo, os.path.join(stage_dir, "bin", os.path.basename(echo)))

    if "windows" in target:
        archive = os.path.join(out_dir, stem + ".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
            for base, _, files in os.walk(stage_dir):
                for name in files:
                    path = os.path.join(base, name)
                    handle.write(path, os.path.relpath(path, out_dir))
    else:
        archive = os.path.join(out_dir, stem + ".tar.gz")
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(stage_dir, arcname=stem)
    return archive


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target-dir", default=os.path.join(ROOT, "target"))
    parser.add_argument("--out", default=os.path.join(ROOT, "dist"))
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    archive = stage(args.target, args.version, args.target_dir, args.out)
    print(archive, os.path.getsize(archive), "bytes")


if __name__ == "__main__":
    main()
