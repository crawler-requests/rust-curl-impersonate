#!/usr/bin/env python3
"""Report, per embedded record, how the live handshake compares with its capture.

Usage: library_report.py <capture-dir> <echo-dir>...

Each echo directory holds `<record>.log` files written by
`target/debug/examples/echo <record>`. The first directory that has a log for a
record wins, so the library can be echoed in batches. The output has one line
per base record plus a summary that the README quotes.
"""

import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


gen = module(os.path.join(HERE, "gen_fingerprints.py"), "gen_fingerprints")
cmp = module(os.path.join(HERE, "compare_echo.py"), "compare_echo")
subset_check = module(os.path.join(HERE, "check_subset.py"), "check_subset")


def library(path):
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if isinstance(document, dict):
        return document["fingerprints"]
    return document


def find_log(name, echo_dirs):
    for directory in echo_dirs:
        path = os.path.join(directory, name + ".log")
        if os.path.exists(path):
            return path
    return None


def ja4(tls):
    return tls.get("ja4") or "-"


def main():
    records = library(os.path.join(HERE, "..", "src", "fingerprint", "builtin.json"))
    capture_dir = os.path.join(HERE, "capture", "raw")
    echo_dirs = sys.argv[1:]
    if not echo_dirs:
        print(__doc__.strip())
        return 2

    base = [record for record in records if not record.get("extends")]
    lines = []
    identical = ja4_same = subset = missing = 0
    for record in base:
        name = record["name"]
        log = find_log(name, echo_dirs)
        if log is None:
            missing += 1
            lines.append(f"{name:<24} {'-':<8} no echo")
            continue
        raw = cmp.load_capture(os.path.join(capture_dir, name + ".json"))
        live = cmp.load_echo(log)
        problems = cmp.compare(raw, live)
        same_ja4 = ja4(raw["tls"]) == ja4(live["tls"])
        faithful = not problems and same_ja4
        if faithful:
            identical += 1
        if same_ja4:
            ja4_same += 1
        if not subset_check.compare(raw, live):
            subset += 1
        state = "identical" if faithful else "differs"
        lines.append(
            f"{name:<24} {str(record.get('fidelity') or '-'):<8} {state:<10} "
            f"{ja4(raw['tls'])} -> {ja4(live['tls'])}"
        )
        if problems and not faithful:
            lines.append("    " + "; ".join(problems))

    print(f"全库实测：{len(base)} 条基础记录 + {len(records) - len(base)} 个别名；"
          "examples/echo 对 tls.peet.ws 逐条握手。")
    print()
    print("字段说明：identical = cipher/曲线/签名算法/扩展集合与顺序/ALPN/JA4 与抓包完全一致；"
          "differs 后面列出差异字段。")
    print()
    print("\n".join(lines))
    print()
    print(f"summary: identical {identical}/{len(base)}, JA4 identical {ja4_same}/{len(base)}, "
          f"supported subset {subset}/{len(base)}, no echo {missing}/{len(base)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
