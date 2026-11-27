#!/usr/bin/env python3
"""Derive binding declarations from the authoritative header.

A C ABI has no reflection. A binding author — human or agent — knows the API
only from `rci.h` and the export table, so declarations must be derived from
the header rather than typed from memory.

    python3 gen_declarations.py --header ./rci/include/rci.h --list
    python3 gen_declarations.py --header ./rci/include/rci.h --java
    python3 gen_declarations.py --header ./rci/include/rci.h --go
    python3 gen_declarations.py --header ./rci/include/rci.h --ctypes
"""

import argparse
import os
import re
import sys


def resolve_header(explicit):
    """Find rci.h: the flag, then the skill's usual fetch destinations."""
    if explicit:
        if not os.path.exists(explicit):
            sys.exit(f"no header at {explicit}")
        return explicit
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        "rci/include/rci.h", "include/rci.h",
        os.path.join(here, "..", "..", "..", "..", "rci", "include", "rci.h"),
    ):
        if os.path.exists(candidate):
            return candidate
    sys.exit("no rci.h found; pass --header (fetch_library.py writes rci/include/rci.h)")

PROTOTYPE = re.compile(
    # Return type: "uint32_t", "char *", "RciClient *", "const char *".
    # `char *rci_targets` has no space between the star and the name.
    r"^\s*(?P<ret>(?:const\s+)?\w+(?:\s+\w+)*\s*\*?)"
    r"(?:\s*)(?P<name>rci_[a-z0-9_]+)"
    r"\s*\((?P<params>[^;{}]*)\)\s*;",
    re.MULTILINE,
)
PARAM_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*$")


def parse(text):
    functions = []
    for match in PROTOTYPE.finditer(text):
        params = match.group("params").strip()
        arguments = []
        if params and params != "void":
            for part in params.split(","):
                spelling = " ".join(part.split())
                name = PARAM_NAME.search(spelling)
                if name is None:
                    sys.exit(f"cannot read parameter {part!r}")
                arguments.append((spelling[: name.start()].strip(), name.group(0)))
        functions.append((" ".join(match.group("ret").split()), match.group("name"), arguments))
    return functions


JAVA = {
    "uint32_t": "int", "uint16_t": "short", "int": "int",
    "size_t": "long", "bool": "boolean", "void": "void",
}


def java_type(spelling, is_result):
    spelling = " ".join(spelling.split())
    if spelling in JAVA:
        return JAVA[spelling]
    if spelling.startswith("const ") and spelling.endswith("*"):
        inner = spelling[len("const "): -1].strip()
        if inner == "char":
            return "String"          # borrowed input or borrowed result
        if inner == "uint8_t":
            return "byte[]"
        return "Pointer"
    if spelling.endswith("*"):
        return "Pointer"             # char * results are owned: keep the raw pointer
    return spelling


def java_declaration(ret, name, args):
    params = ", ".join(f"{java_type(t, False)} {n}" for t, n in args)
    return f"{java_type(ret, True)} {name}({params});"


CTYPES = {
    "uint32_t": "c_uint32", "uint16_t": "c_uint16", "int": "c_int",
    "size_t": "c_size_t", "bool": "c_bool", "void": "None",
}


def ctypes_type(spelling, is_result):
    spelling = " ".join(spelling.split())
    if spelling in CTYPES:
        return CTYPES[spelling]
    if spelling.startswith("const ") and spelling.endswith("*"):
        # const char * result is borrowed and must not be freed: c_char_p copies.
        return "c_char_p" if is_result else "c_char_p"
    if spelling.endswith("*"):
        # char * results are owned by the library: c_void_p keeps the pointer.
        return "c_void_p" if is_result else "c_void_p"
    return spelling


def ctypes_declaration(ret, name, args):
    argtypes = ", ".join(ctypes_type(t, False) for t, _ in args)
    return (f"    lib.{name}.argtypes = [{argtypes}]\n"
            f"    lib.{name}.restype = ctypes.{ctypes_type(ret, True)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", help="path to rci.h; defaults to ./rci/include/rci.h "
                                         "or this skill's fetch target")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--java", action="store_true")
    parser.add_argument("--go", action="store_true")
    parser.add_argument("--ctypes", action="store_true")
    args = parser.parse_args()

    text = open(resolve_header(args.header), encoding="utf-8").read()
    functions = parse(text)
    if not functions:
        sys.exit(f"no rci_* prototypes found in {args.header}")

    if not (args.list or args.java or args.go or args.ctypes):
        args.list = True
    if args.list:
        for ret, name, arguments in functions:
            params = ", ".join(f"{t} {n}" for t, n in arguments) or "void"
            print(f"{name}({params}) -> {ret}")
        version = re.search(r"ABI version (\d+)", text)
        print(f"\n{len(functions)} functions"
              + (f", ABI version {version.group(1)}" if version else ""))
    if args.java:
        print("\n".join(java_declaration(*f) for f in functions))
    if args.go:
        # <stdlib.h> is not optional: every Go binding pairs C.CString with
        # C.free, and without it the compiler cannot resolve C.free.
        lines = ["#include <stddef.h>", "#include <stdint.h>", "#include <stdlib.h>",
                 "", "typedef struct RciClient RciClient;"]
        for ret, name, arguments in functions:
            params = ", ".join(f"{t} {n}" for t, n in arguments) or "void"
            separator = "" if ret.endswith("*") else " "
            lines.append(f"extern {ret}{separator}{name}({params});")
        print("\n".join(lines))
    if args.ctypes:
        print('p = ctypes.c_void_p  # a char * the library owns; free with rci_string_free')
        print("\n".join(ctypes_declaration(*f) for f in functions))


if __name__ == "__main__":
    main()
