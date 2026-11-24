"""List the export names in a PE (Windows DLL) without dumpbin.

Usage: python3 peexports.py <path.dll>

Reads the export directory directly, so it works on any host with Python,
not only in an MSVC developer prompt. Handles both PE32 and PE32+.
"""

import struct
import sys

# Optional-header data-directory index for the export table.
EXPORT_DIRECTORY = 0


def read_exports(path):
    with open(path, "rb") as handle:
        data = handle.read()
    if data[:2] != b"MZ":
        raise ValueError(f"{path} is not a PE file (no MZ header)")

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\x00\x00":
        raise ValueError(f"{path} has no PE signature")

    coff = pe + 4
    machine, nsections = struct.unpack_from("<HH", data, coff)
    size_optional = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    # PE32+ (0x20b) places the data directories at offset 112; PE32 at 96.
    directories = opt + (112 if magic == 0x20B else 96)

    export_rva, export_size = struct.unpack_from("<II", data, directories + EXPORT_DIRECTORY * 8)
    if export_rva == 0 or export_size == 0:
        return []

    # Section table follows the optional header; use it to map an RVA to a
    # file offset.
    sections = []
    table = opt + size_optional
    for index in range(nsections):
        base = table + index * 40
        virtual_size, virtual_address, size_raw, offset_raw = struct.unpack_from(
            "<IIII", data, base + 8
        )
        sections.append((virtual_address, virtual_size, offset_raw, size_raw))

    def to_offset(rva):
        for virtual_address, virtual_size, offset_raw, size_raw in sections:
            span = max(virtual_size, size_raw)
            if virtual_address <= rva < virtual_address + span:
                return offset_raw + (rva - virtual_address)
        raise ValueError(f"RVA {rva:#x} is in no section")

    export_off = to_offset(export_rva)
    number_of_names = struct.unpack_from("<I", data, export_off + 24)[0]
    names_rva = struct.unpack_from("<I", data, export_off + 32)[0]
    names_off = to_offset(names_rva)

    names = []
    for index in range(number_of_names):
        name_rva = struct.unpack_from("<I", data, names_off + index * 4)[0]
        name_off = to_offset(name_rva)
        end = name_off
        while data[end] != 0:
            end += 1
        names.append(data[name_off:end].decode("ascii", "replace"))
    return names


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: peexports.py <path.dll>")
    names = read_exports(sys.argv[1])
    for name in names:
        print(name)


if __name__ == "__main__":
    main()
