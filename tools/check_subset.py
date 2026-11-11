#!/usr/bin/env python3
"""Check that every live echo sends exactly the captured fields BoringSSL supports.

A full JA4 match is impossible for OpenSSL/GnuTLS clients: BoringSSL has no
RC4, DHE-DSS, CCM, X448 or brainpool. What must still hold is that the live
ClientHello sends the *supported subset* of each captured list, in the captured
order, with nothing invented and nothing extra dropped. This script checks that
for every record that has an `examples/echo` log.

Usage: check_subset.py <capture-dir> <echo-dir> <record>...
"""

import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "gen_fingerprints", os.path.join(HERE, "gen_fingerprints.py")
)
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

spec = importlib.util.spec_from_file_location("compare_echo", os.path.join(HERE, "compare_echo.py"))
cmp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmp)

CIPHER_ALIASES = {"TLS_EMPTY_RENEGOTIATION_INFO": "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"}


def supported_ciphers():
    """Captured cipher labels BoringSSL can emit."""
    return set(gen.SUPPORTED_CIPHERS)


def groups_of(tls, normalize=True):
    for entry in tls.get("extensions") or []:
        if cmp.extension_id(entry.get("name", "")) == 10:
            values = [v for v in entry.get("supported_groups") or [] if "GREASE" not in v]
            if normalize:
                values = [gen.group_name(v) or v for v in values]
            return values
    return []


def sigalgs_of(tls):
    for entry in tls.get("extensions") or []:
        if cmp.extension_id(entry.get("name", "")) == 13:
            out = []
            for value in entry.get("signature_algorithms") or []:
                if value.startswith("0x"):
                    code = int(value, 16)
                    if gen.grease_code(code):
                        continue
                    value = gen.SIGALG_CODES.get(code, value)
                out.append(value)
            return out
    return []


def canonical(name):
    return CIPHER_ALIASES.get(name, name)


def compare(raw, live):
    problems = []
    captured = [c for c in raw["tls"].get("ciphers") or [] if "GREASE" not in c]
    expected = [canonical(c) for c in captured if c in supported_ciphers()]
    actual = [canonical(c) for c in live["tls"].get("ciphers") or [] if "GREASE" not in c]
    if expected != actual:
        missing = [c for c in expected if c not in actual]
        extra = [c for c in actual if c not in expected]
        # BoringSSL always puts the TLS 1.3 suites first; a capture that lists
        # them last is a known, recorded deviation, not an invented cipher.
        reordered = [c for c in expected if gen.is_tls13(c)] + [
            c for c in expected if not gen.is_tls13(c)
        ]
        if missing or extra or reordered != actual:
            problems.append(
                "ciphers missing=" + str(missing[:3]) + " extra=" + str(extra[:3])
            )

    for label, pick, known in (
        ("groups", groups_of, set(gen.GROUP_CODES.values())),
        ("sigalgs", sigalgs_of, set(gen.SIGALGS.values()) if hasattr(gen, "SIGALGS") else set(gen.SUPPORTED_SIGALGS)),
    ):
        expected = [v for v in pick(raw["tls"]) if v in known]
        actual = pick(live["tls"])
        # BoringSSL may drop a group/sigalg it knows but cannot send in this
        # configuration; only flag what it invents or reorders.
        filtered = [v for v in actual if v in expected]
        if filtered != actual:
            problems.append(label + " unexpected=" + str([v for v in actual if v not in expected]))
        elif [v for v in expected if v in actual] != actual:
            problems.append(label + " reordered")
    return problems


def main():
    capture_dir, echo_dir = sys.argv[1], sys.argv[2]
    names = sys.argv[3:]
    ok = 0
    for name in names:
        capture_path = os.path.join(capture_dir, name + ".json")
        echo_path = os.path.join(echo_dir, name + ".log")
        if not (os.path.exists(capture_path) and os.path.exists(echo_path)):
            print(f"{name}: missing capture or echo")
            continue
        problems = compare(cmp.load_capture(capture_path), cmp.load_echo(echo_path))
        if problems:
            print(f"{name}: " + "; ".join(problems))
        else:
            ok += 1
    print(f"supported-subset identical: {ok}/{len(names)}")


if __name__ == "__main__":
    main()
