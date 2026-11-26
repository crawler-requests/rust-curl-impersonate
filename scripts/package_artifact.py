#!/usr/bin/env python3
"""Package one platform's C ABI library for a GitHub release.

Usage:
    python3 scripts/package_artifact.py --target x86_64-unknown-linux-gnu \
        --version 0.1.0 --out dist

The archive contains the cdylib, its import library on Windows, rci.h, the
`echo` smoke-test binary, LICENSE, the binding README, and the Python
binding (`python/demo.py` plus a usage note).
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
# The static library is what an app embeds into its own binary. Its name
# follows the platform's convention, not the cdylib's.
STATIC_LIBRARIES = (
    "librust_curl_impersonate_ffi.a",
    "rust_curl_impersonate_ffi.lib",
)
# MSVC writes `<name>.dll.lib`, GNU writes `lib<name>.dll.a`; `.pdb` carries
# Windows debug symbols. `rust_curl_impersonate_ffi.lib` is the static
# library, so it is copied by STATIC_LIBRARIES, not here.
EXTRA_LIBRARY_SUFFIXES = (".dll.lib", ".dll.a", ".pdb")


def find_library(release_dir):
    for name in LIBRARIES:
        path = os.path.join(release_dir, name)
        if os.path.exists(path):
            return path
    sys.exit(f"no cdylib found in {release_dir}")


def _strip_static(path):
    """Drop debug info from a static library in place.

    Rust's staticlib keeps every object file's DWARF, which makes the archive
    over 100 MB. `strip` works on a .a by removing the debug sections from
    each member; the exported symbols stay. A host without `strip` keeps the
    unstripped archive rather than failing the whole build.
    """
    import shutil as _shutil
    import subprocess

    strip = _shutil.which("strip") or _shutil.which("llvm-strip")
    if strip is None:
        print(f"warning: no strip binary; {path} keeps debug info", file=sys.stderr)
        return
    result = subprocess.run(
        [strip, "--strip-debug", path], capture_output=True, text=True
    )
    if result.returncode != 0:
        print(
            f"warning: strip failed on {path}: {result.stderr.strip()}",
            file=sys.stderr,
        )


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
    for name in STATIC_LIBRARIES:
        source = os.path.join(release_dir, name)
        if os.path.exists(source):
            staged = os.path.join(stage_dir, "lib", name)
            shutil.copy2(source, staged)
            # The archive ships the final form; debug info in a static library
            # is hundreds of megabytes and useless to a consumer.
            _strip_static(staged)

    shutil.copy2(os.path.join(ROOT, "bindings", "ffi", "rci.h"),
                 os.path.join(stage_dir, "include", "rci.h"))
    shutil.copy2(os.path.join(ROOT, "LICENSE"), os.path.join(stage_dir, "LICENSE"))
    shutil.copy2(os.path.join(ROOT, "bindings", "ffi", "README.md"),
                 os.path.join(stage_dir, "README.md"))

    # Ship the Python binding so a downloader can use the library without
    # cloning the repository. The usage note goes to the archive root, since
    # it covers the shared/static choice for every language, not just Python.
    python_dir = os.path.join(stage_dir, "python")
    os.makedirs(python_dir, exist_ok=True)
    demo = os.path.join(ROOT, "bindings", "ffi", "python", "demo.py")
    if os.path.exists(demo):
        shutil.copy2(demo, os.path.join(python_dir, "demo.py"))
    note = os.path.join(ROOT, "bindings", "ffi", "python", "LIBRARY_PATH.md")
    if os.path.exists(note):
        shutil.copy2(note, os.path.join(stage_dir, "USING_THIS_ARCHIVE.md"))

    # Android artifacts are consumed as a shared library, not as a host binary.
    echo = os.path.join(release_dir, "examples", "echo" + (".exe" if "windows" in target else ""))
    if "android" not in target and "apple-ios" not in target and os.path.exists(echo):
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

    verify_archive(archive, target)
    return archive


# Files every archive must carry, relative to the archive root.
REQUIRED = {
    "include/rci.h",
    "python/demo.py",
    "USING_THIS_ARCHIVE.md",
    "README.md",
    "LICENSE",
}


def verify_archive(archive, target):
    """Fail packaging when an archive is missing a file a binding needs.

    Checked here rather than in a workflow step so the rule travels with the
    packaging code and runs for every target.
    """
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as handle:
            names = handle.namelist()
    else:
        with tarfile.open(archive) as handle:
            names = handle.getnames()

    # Strip the single top-level directory each archive is wrapped in.
    stripped = {name.split("/", 1)[1] for name in names if "/" in name}
    missing = REQUIRED - stripped
    if missing:
        sys.exit(f"{archive} is missing: {', '.join(sorted(missing))}")

    # A target that builds a library must ship one, and must ship the static
    # form too: an app that embeds the library links the .a/.lib, not a .so.
    has_shared = any(
        name.startswith("lib/") and name.rsplit("/", 1)[-1] in LIBRARIES
        for name in stripped
    )
    has_static = any(
        name.startswith("lib/") and name.rsplit("/", 1)[-1] in STATIC_LIBRARIES
        for name in stripped
    )
    if not has_shared:
        sys.exit(f"{archive} carries no shared library")
    if not has_static:
        sys.exit(f"{archive} carries no static library")


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
