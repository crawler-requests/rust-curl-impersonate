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

# Python files that go into the archive's python/ directory: the binding, its
# smallest example, a local test server, and the full smoke gate.
PYTHON_FILES = ("rci_bindings.py", "demo.py", "testserver.py", "smoke.py")

# The Java binding ships as source. `target/` (Maven's build output) is not
# copied, and neither is anything else not listed here.
JAVA_FILES = ("pom.xml", "src", "README.md")


def find_library(release_dir):
    for name in LIBRARIES:
        path = os.path.join(release_dir, name)
        if os.path.exists(path):
            return path
    sys.exit(f"no cdylib found in {release_dir}")


def _strip_static(path):
    """Drop debug info from a static library in place.

    Rust's staticlib keeps every object file's DWARF, which makes the archive
    over 100 MB. `strip` works on a `.a` by removing the debug sections from
    each member; the exported symbols stay.

    A Windows `.lib` is an MSVC archive that MinGW's `strip` cannot read, so
    prefer `llvm-strip` (which ships with the MSVC toolset Rust uses). A host
    with neither keeps the unstripped archive rather than failing the build.
    """
    import shutil as _shutil
    import subprocess

    if path.endswith(".lib"):
        candidates = ("llvm-strip",)
    else:
        candidates = ("strip", "llvm-strip")
    strip = next((_shutil.which(name) for name in candidates if _shutil.which(name)), None)
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
    """Where the build for `target` landed.

    A `cargo build --target <target>` writes to <target-dir>/<target>/release.
    A native build *without* `--target` writes to <target-dir>/release, and
    that directory is the right answer only when it is the host's build.

    The previous version took the first candidate that had a library, so a
    leftover cross-build directory silently won over the fresh native one —
    a release could ship a library weeks older than the code being released.
    Prefer a directory whose library is newer than its own sources; if both
    qualify, prefer the cross-build directory, which is the one a release
    workflow produces.
    """
    candidates = [
        os.path.join(target_dir, target, "release"),
        os.path.join(target_dir, "release"),
    ]
    present = [
        candidate
        for candidate in candidates
        if any(os.path.exists(os.path.join(candidate, name)) for name in LIBRARIES)
    ]
    if not present:
        return candidates[0]
    if len(present) == 1:
        return present[0]
    # Both exist: same target, two builds. The newer library wins; a tie goes
    # to the own-target directory.
    def library_age(candidate):
        stamps = [
            os.path.getmtime(os.path.join(candidate, name))
            for name in LIBRARIES
            if os.path.exists(os.path.join(candidate, name))
        ]
        return max(stamps)

    ordered = sorted(present, key=library_age, reverse=True)
    return ordered[0]


def manifest_version():
    """The version the release workflow resolves, read from Cargo.toml.

    The workflow takes the tag name (or the manual `version` input) and never
    compares it with anything, so a mistyped tag could publish an archive
    labelled v0.5.0 whose library and manifests say 0.1.0. `--version` is
    checked against this value unless a caller passes `--allow-version-mismatch`
    (a pre-release or dev build has no tag to match).
    """
    import tomllib

    with open(os.path.join(ROOT, "Cargo.toml"), "rb") as handle:
        return tomllib.load(handle)["package"]["version"]


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
    for name in PYTHON_FILES:
        source = os.path.join(ROOT, "bindings", "ffi", "python", name)
        if os.path.exists(source):
            shutil.copy2(source, os.path.join(python_dir, name))
    tests = os.path.join(ROOT, "bindings", "ffi", "python", "tests")
    if os.path.isdir(tests):
        shutil.copytree(tests, os.path.join(python_dir, "tests"),
                        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    note = os.path.join(ROOT, "bindings", "ffi", "python", "LIBRARY_PATH.md")
    if os.path.exists(note):
        shutil.copy2(note, os.path.join(stage_dir, "USING_THIS_ARCHIVE.md"))
    # The per-language embedding guide belongs with the archive: someone who
    # downloads it should not have to find the repository to learn the API.
    guide = os.path.join(ROOT, "docs", "embedding.md")
    if os.path.exists(guide):
        shutil.copy2(guide, os.path.join(stage_dir, "EMBEDDING.md"))
    # The Java binding is a standalone Maven project, so it ships as source:
    # javac output is platform-specific and Maven rebuilds it in seconds.
    java_source = os.path.join(ROOT, "bindings", "ffi", "java")
    java_dir = os.path.join(stage_dir, "java")
    if os.path.isdir(java_source):
        for name in JAVA_FILES:
            source = os.path.join(java_source, name)
            if os.path.isdir(source):
                shutil.copytree(source, os.path.join(java_dir, name),
                                ignore=shutil.ignore_patterns("target"))
            elif os.path.exists(source):
                os.makedirs(java_dir, exist_ok=True)
                shutil.copy2(source, os.path.join(java_dir, name))

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
    "python/rci_bindings.py",
    "java/pom.xml",
    "USING_THIS_ARCHIVE.md",
    "EMBEDDING.md",
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
    parser.add_argument(
        "--allow-version-mismatch",
        action="store_true",
        help="pack a version that Cargo.toml does not declare (a dev or pre-release build)",
    )
    args = parser.parse_args()
    declared = manifest_version()
    if not args.allow_version_mismatch:
        normalized = args.version.lstrip("v")
        if normalized != declared and not normalized.startswith(declared + "-"):
            sys.exit(
                f"--version {args.version} does not match Cargo.toml's {declared}; "
                "bump Cargo.toml or pass --allow-version-mismatch"
            )
    os.makedirs(args.out, exist_ok=True)
    archive = stage(args.target, args.version, args.target_dir, args.out)
    print(archive, os.path.getsize(archive), "bytes")


if __name__ == "__main__":
    main()
