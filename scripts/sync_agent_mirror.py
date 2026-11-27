#!/usr/bin/env python3
"""Copy the installable skill into the published site, or verify it matches.

The site at https://crawler-requests.github.io/rust-curl-impersonate/ is the
URL an agent reads when it lands on this repository: `<repo-url>/agent.md`
points at the raw files under `/skills/rust-curl-impersonate-native/`.

Those files are copies, and copies drift. Run this from the repository root:

    python3 scripts/sync_agent_mirror.py --from ../rust-curl-impersonate-skills
    python3 scripts/sync_agent_mirror.py --from ../rust-curl-impersonate-skills --check

`--from` is the skills repository (the one with `.claude-plugin/marketplace.json`).
`--check` exits 1 when a published file differs from its source, so a release
checklist can run it instead of trusting that someone remembered.
"""

import argparse
import filecmp
import json
import os
import shutil
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLISHED = os.path.join(ROOT, "website", "public", "skills", "rust-curl-impersonate-native")
SKILL = "skills/rust-curl-impersonate-native"
# The marketplace manifest sits one level above the skill, next to it on the
# site, so `plugin marketplace add <site-url>` resolves the same plugin the
# skills repository publishes.
MARKETPLACE = os.path.join(ROOT, "website", "public", ".claude-plugin", "marketplace.json")

# What an agent needs to do the work: the procedure, the contract, the scripts
# and the ready-made bindings. Everything else in the skills repository
# (CI, the skills README) is not part of the mirror.
MIRRORED = [
    ".claude-plugin/plugin.json",
    "SKILL.md",
    "references",
    "scripts",
    "assets/python/rci_bindings.py",
    "assets/python/testserver.py",
    "assets/python/tests",
    "assets/java/pom.xml",
    "assets/java/README.md",
    "assets/java/src",
]

IGNORE = {".git", "__pycache__", ".pytest_cache", "target", ".DS_Store", "*.pyc"}


def _ignored(name):
    return name in IGNORE or name.endswith(".pyc")


def files(root):
    """Regular files under `root`, as paths relative to it."""
    found = set()
    for base, directories, names in os.walk(root):
        directories[:] = [d for d in directories if not _ignored(d)]
        for name in names:
            if not _ignored(name):
                found.add(os.path.relpath(os.path.join(base, name), root))
    return found


def pairs(source_repo):
    """(source path, published path) for every file the mirror carries."""
    for entry in MIRRORED:
        path = os.path.join(source_repo, SKILL, entry)
        if os.path.isdir(path):
            for name in sorted(files(path)):
                yield (os.path.join(path, name), os.path.join(PUBLISHED, entry, name))
        elif os.path.isfile(path):
            yield (path, os.path.join(PUBLISHED, entry))


# A marketplace fetched over plain HTTP(S) is a *catalog*: it may list plugins
# that live on other services, but it has no local tree of its own, so a
# `./skills/...` entry is refused at install time. The published manifest
# therefore points at the plugin's own git repository with a `git-subdir`
# source (the plugin directory inside it), and carries a distinct marketplace
# name so it never collides with the skills repository's own marketplace.
PUBLISHED_NAME = "rust-curl-impersonate"
SITE = "https://crawler-requests.github.io/rust-curl-impersonate"
PLUGIN = "rust-curl-impersonate-native"
ARCHIVE = os.path.join(ROOT, "website", "public", PLUGIN + ".zip")

# A marketplace fetched over plain HTTPS is a *catalog*: `./skills/...` entries
# are refused at install time because there is no local tree. The catalog
# points at the plugin archive served next to it instead, which is a static
# file — no git, no npm, nothing but an HTTP GET.
def manifest_for_site(source_repo):
    """The repository's marketplace manifest, adapted for the published URL."""
    manifest = json.load(open(os.path.join(source_repo, ".claude-plugin", "marketplace.json")))
    manifest["name"] = PUBLISHED_NAME
    manifest["description"] = (
        "Installable skills for rust-curl-impersonate, published as a catalog so "
        "an agent can install them from one URL: " + SITE + "/"
    )
    for entry in manifest["plugins"]:
        entry["source"] = {
            "source": "archive",
            "url": f"{SITE}/{PLUGIN}.zip",
        }
        entry["homepage"] = f"{SITE}/agent.md"
    return manifest


def build_archive():
    """Zip the published plugin, plugin root at the top of the archive.

    The install path hashes the archive per version, so the entries are added
    sorted with a fixed timestamp: the same content always produces the same
    zip.
    """
    entries = sorted(files(PUBLISHED), key=lambda name: name.replace(os.sep, "/"))
    with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED) as handle:
        for name in entries:
            path = os.path.join(PUBLISHED, name)
            info = zipfile.ZipInfo(name.replace(os.sep, "/"), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            handle.writestr(info, open(path, "rb").read())
    return len(entries), os.path.getsize(ARCHIVE)


def sync(source_repo):
    # The manifest's plugin entry must match the plugin.json it points at,
    # otherwise `marketplace add` and the published copy disagree.
    manifest = manifest_for_site(source_repo)
    os.makedirs(os.path.dirname(MARKETPLACE), exist_ok=True)
    with open(MARKETPLACE, "w") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    copied = 0
    for source, target in pairs(source_repo):
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if not os.path.exists(target) or not filecmp.cmp(source, target, shallow=False):
            shutil.copy2(source, target)
            copied += 1
    # Drop files the source no longer has, so the mirror never carries a stale
    # copy of something that was renamed or deleted upstream.
    expected = {target for _, target in pairs(source_repo)}
    removed = 0
    for name in files(PUBLISHED):
        path = os.path.join(PUBLISHED, name)
        if path not in expected:
            os.remove(path)
            removed += 1
    return copied, removed


def check(source_repo):
    missing = []
    different = []
    extra = []
    expected = set()
    for source, target in pairs(source_repo):
        expected.add(target)
        if not os.path.exists(target):
            missing.append(os.path.relpath(target, ROOT))
        elif not filecmp.cmp(source, target, shallow=False):
            different.append(os.path.relpath(target, ROOT))
    for name in files(PUBLISHED):
        path = os.path.join(PUBLISHED, name)
        if path not in expected:
            extra.append(os.path.relpath(path, ROOT))
    expected_manifest = manifest_for_site(source_repo)
    if not os.path.exists(MARKETPLACE) or json.load(open(MARKETPLACE)) != expected_manifest:
        different.append(os.path.relpath(MARKETPLACE, ROOT))
    # The archive is generated from the mirror, so a stale one would install a
    # previous copy of the skill from the site.
    expected_names = sorted(files(PUBLISHED), key=lambda name: name.replace(os.sep, "/"))
    if not os.path.exists(ARCHIVE):
        missing.append(os.path.relpath(ARCHIVE, ROOT))
    else:
        with zipfile.ZipFile(ARCHIVE) as handle:
            if sorted(handle.namelist()) != [n.replace(os.sep, "/") for n in expected_names]:
                different.append(os.path.relpath(ARCHIVE, ROOT))
            else:
                for name in expected_names:
                    packed = name.replace(os.sep, "/")
                    if handle.read(packed) != open(os.path.join(PUBLISHED, name), "rb").read():
                        different.append(os.path.relpath(ARCHIVE, ROOT) + f" ({packed})")
                        break
    return missing, different, extra


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--from", dest="source", required=True,
                        help="the rust-curl-impersonate-skills checkout")
    parser.add_argument("--check", action="store_true",
                        help="verify the published mirror without writing")
    arguments = parser.parse_args()

    source_repo = os.path.abspath(arguments.source)
    if not os.path.isdir(os.path.join(source_repo, SKILL)):
        sys.exit(f"{source_repo} has no {SKILL}/")

    if arguments.check:
        missing, different, extra = check(source_repo)
        expected = {target for _, target in pairs(source_repo)}
        for label, entries in (("missing", missing), ("differs", different), ("stale", extra)):
            for entry in entries:
                print(f"{label}: {entry}")
        if missing or different or extra:
            print("the published skill mirror is out of step with the source")
            sys.exit(1)
        print(
            f"mirror matches {len(expected)} published files, "
            f"archive packs the same {len(files(PUBLISHED))}"
        )
        return

    copied, removed = sync(source_repo)
    entries, size = build_archive()
    print(
        f"copied {copied}, removed {removed} stale file(s) under website/public/; "
        f"{PLUGIN}.zip: {entries} files, {size // 1024} KB"
    )


if __name__ == "__main__":
    main()
