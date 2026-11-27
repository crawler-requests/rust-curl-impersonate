#!/usr/bin/env python3
"""Verify the URLs the published agent entry point hands to other agents.

`website/public/agent.md` is what an agent reads when it lands on the project,
so every URL in it must resolve without a login. This checks two things:

1. the checksummed files the mirror publishes match their source (the skills
   repository), by running `scripts/sync_agent_mirror.py --check` when a
   sibling checkout is available;
2. every URL in `agent.md` answers 200 (`--live`).

    python3 scripts/check_agent_entry.py                 # offline checks
    python3 scripts/check_agent_entry.py --live          # + fetch every URL
    python3 scripts/check_agent_entry.py --live --site-only

`--site-only` skips the raw.githubusercontent.com URLs, which need network
access to GitHub; the site URLs alone prove the published copy.
"""

import argparse
import os
import json
import re
import subprocess
import zipfile
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "website", "public", "agent.md")
OPENAPI = os.path.join(ROOT, "website", "public", "agent.openapi.yaml")
MANIFEST = os.path.join(ROOT, "website", "public", ".claude-plugin", "marketplace.json")
ARCHIVE = os.path.join(ROOT, "website", "public", "rust-curl-impersonate-native.zip")
SITE = "https://crawler-requests.github.io/rust-curl-impersonate"
MIRROR = os.path.join(ROOT, "website", "public", "skills", "rust-curl-impersonate-native")
SKILLS_REPO = os.path.join(os.path.dirname(ROOT), "rust-curl-impersonate-skills")

URL = re.compile(r"https?://[^\s`|)\"]+")


def urls():
    """Every URL in agent.md, with the one template filled in."""
    text = open(AGENT, encoding="utf-8").read()
    found = {url for url in URL.findall(text) if "<" not in url}
    # The language reference is a template; check every concrete file instead.
    for name in ("python", "java", "go", "node", "php", "csharp", "swift",
                 "android", "c", "rust"):
        found.add(f"{SITE}/skills/rust-curl-impersonate-native/references/languages/{name}.md")
    # The OpenAPI document indexes paths, not URLs; check it too.
    found.add(f"{SITE}/agent.openapi.yaml")
    return sorted(found)


def head(url, timeout=25, attempts=3):
    """GET the first bytes of `url`; returns (status, length).

    This machine's route to GitHub is slow and drops connections, so a
    transport error is retried a few times before it counts as a failure;
    an HTTP status is not retried, because a 404 is an answer.
    """
    last = None
    for _ in range(attempts):
        request = urllib.request.Request(url, headers={"User-Agent": "rci-agent-entry-check"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, len(response.read(512))
        except urllib.error.HTTPError as error:
            return error.code, 0
        except Exception as error:  # noqa: BLE001 - transport flake, or a bad URL
            last = error
    return f"error: {last}", 0


def check_manifests():
    """Both manifests parse and agree, and the installed plugin resolves."""
    marketplace = json.load(open(MANIFEST, encoding="utf-8"))
    entries = marketplace["plugins"]
    assert entries, "the marketplace lists no plugins"
    for entry in entries:
        source = entry["source"]
        # A catalog fetched over HTTP installs a static archive; the plugin
        # directory beside it is what that archive is built from.
        if isinstance(source, dict):
            assert source.get("source") == "archive", (
                f"{entry['name']}: unsupported source {source}"
            )
            url = source.get("url", "")
            assert url.startswith("https://"), (
                f"{entry['name']}: archive url {url!r} must be https"
            )
            assert url.rstrip().endswith(".zip"), f"{entry['name']}: archive url {url!r}"
        else:
            assert source.startswith("./"), f"{entry['name']}: source {source} is not relative"
        plugin = os.path.join(os.path.dirname(os.path.dirname(MANIFEST)),
                              "skills", entry["name"])
        manifest = os.path.join(plugin, ".claude-plugin", "plugin.json")
        assert os.path.isfile(manifest), f"{entry['name']}: no {manifest}"
        declared = json.load(open(manifest, encoding="utf-8"))
        assert declared["name"] == entry["name"], (
            f"{entry['name']}: plugin.json says {declared['name']}"
        )
        skill = os.path.join(plugin, "SKILL.md")
        assert os.path.isfile(skill), f"{entry['name']}: no SKILL.md"
        if isinstance(source, dict):
            with zipfile.ZipFile(ARCHIVE) as archive:
                names = archive.namelist()
            assert ".claude-plugin/plugin.json" in names, "the archive has no plugin.json"
            assert "SKILL.md" in names, "the archive has no SKILL.md"
    print(
        f"marketplace {marketplace['name']}: {len(entries)} plugin entr"
        f"{'y' if len(entries) == 1 else 'ies'}, manifests agree, "
        "archive carries plugin.json + SKILL.md"
    )


def check_site_docs():
    """Every document an agent.md link points at must be published here."""
    published = os.path.join(ROOT, "website", "public")
    for name in ("README.md", "rci.h", "docs/embedding.md", "docs/wrapper-guide.md",
                 "docs/provider-protocol.md", "bindings/README.md"):
        path = os.path.join(published, name)
        assert os.path.isfile(path), f"{name} is not published"
    print("repository documents are published next to agent.md")


def check_local():
    """Every file the agent.md table links under the mirror must exist."""
    text = open(AGENT, encoding="utf-8").read()
    missing = []
    for entry in re.findall(r"`" + SITE + r"/skills/rust-curl-impersonate-native/([^`]+)`", text):
        # One row is a template (`references/languages/<language>.md`); every
        # concrete language file is checked by `urls()`.
        if "<" in entry:
            continue
        path = os.path.join(MIRROR, entry)
        if not os.path.exists(path):
            missing.append(entry)
    if not os.path.exists(OPENAPI):
        missing.append("agent.openapi.yaml")
    if not os.path.exists(ARCHIVE):
        missing.append("rust-curl-impersonate-native.zip")
    for entry in missing:
        print(f"missing from the published copy: {entry}")
    if missing:
        sys.exit(1)
    print(f"every published file agent.md links exists ({len(os.listdir(MIRROR))} entries in the mirror)")


def check_mirror():
    if not os.path.isdir(os.path.join(SKILLS_REPO, "skills")):
        print("no sibling skills checkout; skipping the source comparison")
        return
    result = subprocess.run(
        [sys.executable, "-I", os.path.join(ROOT, "scripts", "sync_agent_mirror.py"),
         "--from", SKILLS_REPO, "--check"],
        capture_output=True, text=True,
    )
    print(result.stdout.strip() or result.stderr.strip())
    if result.returncode != 0:
        sys.exit(result.returncode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="fetch every URL and require 200")
    parser.add_argument("--site-only", action="store_true",
                        help="with --live, skip raw.githubusercontent.com URLs")
    arguments = parser.parse_args()

    check_local()
    check_site_docs()
    check_manifests()
    check_mirror()

    if not arguments.live:
        return

    failures = []
    for url in urls():
        if arguments.site_only and "raw.githubusercontent.com" in url:
            print(f"skip  {url}")
            continue
        status, length = head(url)
        ok = status == 200 and length > 0
        print(("ok    " if ok else "FAIL  ") + f"{status}  {url}")
        if not ok:
            failures.append((status, url))
    if failures:
        print(f"{len(failures)} URL(s) do not resolve")
        sys.exit(1)
    print("every URL resolves")


if __name__ == "__main__":
    main()
