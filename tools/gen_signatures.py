#!/usr/bin/env python3
"""Derive per-language declarations from rci.h, so the header stays the one source.

A C ABI has no reflection: a binding author only knows what the library exposes
from the header and the export table. This tool reads `bindings/ffi/rci.h` and
emits (or checks) the declarations other languages need, so adding a function
to the header cannot leave a binding silently behind.

Usage:
    python3 tools/gen_signatures.py --check          # CI gate
    python3 tools/gen_signatures.py --java           # print the Java interface body
    python3 tools/gen_signatures.py --go             # print a Go cgo extern block
    python3 tools/gen_signatures.py --list           # print the ABI table
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER = os.path.join(ROOT, "bindings", "ffi", "rci.h")
JAVA = os.path.join(
    ROOT, "bindings", "ffi", "java", "src", "main", "java",
    "io", "github", "crawlerrequests", "impersonate", "RciLibrary.java",
)

# The same prototype pattern rci_bindings.py uses: a return type (maybe a
# pointer), the name, and a parameter list.
PROTOTYPE = re.compile(
    r"^\s*(?P<ret>(?:const\s+)?\w+(?:\s+\w+)*\s*\*?)(?:\s*)"
    r"(?P<name>rci_[a-z0-9_]+)"
    r"\s*\((?P<params>[^;{}]*)\)\s*;",
    re.MULTILINE,
)

PARAM_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*$")


def parse_header(text):
    """Return [(return type, name, [(type, param name)]), ...] in header order."""
    functions = []
    for match in PROTOTYPE.finditer(text):
        params = match.group("params").strip()
        if not params or params == "void":
            arguments = []
        else:
            arguments = []
            for part in params.split(","):
                spelling = " ".join(part.split())
                name_match = PARAM_NAME.search(spelling)
                if name_match is None:
                    raise SystemExit(f"cannot read parameter {part!r}")
                type_text = spelling[: name_match.start()].strip()
                arguments.append((type_text, name_match.group(0)))
        functions.append((" ".join(match.group("ret").split()), match.group("name"), arguments))
    return functions


# -- Java -----------------------------------------------------------------

# C type -> Java type. A `char *` result is owned by the library, so JNA must
# see a raw Pointer; a `const char *` result is borrowed, so String is safe.
JAVA_SCALARS = {
    "uint32_t": "int",
    "uint16_t": "short",
    "int": "int",
    "size_t": "long",
    "bool": "boolean",
    "void": "void",
}


def java_type(spelling, is_result):
    spelling = " ".join(spelling.split())
    if spelling in JAVA_SCALARS:
        return JAVA_SCALARS[spelling]
    if spelling.startswith("const ") and spelling.endswith("*"):
        inner = spelling[len("const "): -1].strip()
        if inner == "char":
            # A `const char *` argument is a borrowed input string: JNA accepts
            # a Java String and converts it to UTF-8. As a result it is the
            # caller's to free, so the same spelling becomes String.
            return "String"
        if inner == "uint8_t":
            return "byte[]"
        return "Pointer"
    if spelling.endswith("*"):
        if spelling == "char *" and is_result:
            return "Pointer"      # owned by the library
        return "Pointer"
    return spelling


def java_declaration(return_type, name, arguments):
    params = ", ".join(
        f"{java_type(type_text, False)} {param_name}"
        for type_text, param_name in arguments
    )
    return f"{java_type(return_type, True)} {name}({params});"


JAVA_METHOD = re.compile(r"\s*[A-Za-z_][A-Za-z0-9_<>\[\], ]*\s+rci_[a-z0-9_]+\([^;]*\);")


def java_methods(text):
    """The rci_* method declarations present in a Java source file."""
    return [" ".join(match.group(0).split()) for match in JAVA_METHOD.finditer(text)]


def check_java(functions):
    if not os.path.exists(JAVA):
        return [f"{JAVA} is missing"]
    declared = java_methods(open(JAVA, encoding="utf-8").read())
    expected = [java_declaration(*function) for function in functions]
    problems = []
    missing = [line for line in expected if line not in declared]
    extra = [line for line in declared if line not in expected]
    for line in missing:
        problems.append(f"Java is missing: {line}")
    for line in extra:
        problems.append(f"Java declares something rci.h does not: {line}")
    return problems


# -- Go -------------------------------------------------------------------


def go_block(functions):
    """A cgo `// #include` preamble declaring every function in C, plus the
    opaque handle. This is the block a Go consumer pastes above `import "C"`."""
    lines = [
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef struct RciClient RciClient;",
    ]
    for return_type, name, arguments in functions:
        params = ", ".join(f"{t} {n}" for t, n in arguments) or "void"
        # A pointer return type already ends with a space: `char *`. A scalar
        # one does not: `uint32_t`.
        separator = "" if return_type.endswith("*") else " "
        lines.append(f"extern {return_type}{separator}{name}({params});")
    return "\n".join(lines)


# -- main -----------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail when a binding is out of step")
    parser.add_argument("--java", action="store_true", help="print the Java interface body")
    parser.add_argument("--go", action="store_true", help="print a Go cgo extern block")
    parser.add_argument("--list", action="store_true", help="print the ABI table")
    args = parser.parse_args()

    functions = parse_header(open(HEADER, encoding="utf-8").read())
    if not functions:
        sys.exit(f"no rci_* prototypes found in {HEADER}")

    if args.list or not (args.check or args.java or args.go):
        for return_type, name, arguments in functions:
            params = ", ".join(f"{t} {n}" for t, n in arguments) or "void"
            print(f"{name}({params}) -> {return_type}")
        print(f"\n{len(functions)} functions, ABI version "
              + re.search(r"ABI version (\d+)", open(HEADER, encoding="utf-8").read()).group(1))
    if args.java:
        print("\n".join(java_declaration(*function) for function in functions))
    if args.go:
        print(go_block(functions))
    if args.check:
        problems = check_java(functions)
        if problems:
            print("\n".join(problems), file=sys.stderr)
            sys.exit(1)
        print(f"rci.h and {os.path.relpath(JAVA, ROOT)} agree on "
              f"{len(functions)} functions")


if __name__ == "__main__":
    main()
