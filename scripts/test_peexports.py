"""Tests for scripts/peexports.py.

A real DLL is not in the repository, so these build a minimal PE image in
memory: one section that holds an export directory with two named exports.
The point is to catch a broken RVA-to-offset map, which would make the
release check silently see zero exports instead of failing loudly.
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import peexports  # noqa: E402


def build_pe(magic, names):
    """Return bytes of a PE with one section exporting `names`.

    Layout: MZ header, PE signature, COFF header, optional header, one
    section header, then a blob holding the export directory followed by the
    name strings. Every RVA is relative to the section's virtual address.
    """
    # A generous fixed layout keeps the arithmetic explicit.
    pe_offset = 0x40
    coff = pe_offset + 4
    opt = coff + 20
    # Optional header sizes for a full 16-entry data-directory table: PE32+ is
    # 240 bytes, PE32 is 224.
    size_optional = 240 if magic == 0x20B else 224
    section = opt + size_optional
    image_start = section + 40
    virtual_address = 0x1000  # section RVA base

    # Blob: export directory (40 bytes) then names.
    blob = bytearray(40)
    name_offsets = []
    for name in names:
        name_offsets.append(len(blob))
        blob += name.encode() + b"\0"

    # Directory fields we set: NumberOfNames (offset 24) and AddressOfNames
    # (offset 32, an RVA to the name-pointer array). Append the pointer array
    # after the strings.
    names_array_offset = len(blob)
    blob += b"\0\0\0\0" * len(names)
    for index, offset in enumerate(name_offsets):
        struct.pack_into("<I", blob, names_array_offset + index * 4, virtual_address + offset)
    struct.pack_into("<I", blob, 24, len(names))
    struct.pack_into("<I", blob, 32, virtual_address + names_array_offset)
    # AddressOfNameOrdinals (offset 36) is read by no test path.

    # Directories start where the format puts them; set export entry (index 0).
    directories_offset = 112 if magic == 0x20B else 96
    export_rva = virtual_address + 0
    export_size = len(blob)

    out = bytearray(b"MZ" + b"\0" * 62)
    struct.pack_into("<I", out, 0x3C, pe_offset)
    out += b"\0" * (pe_offset - len(out))
    out += b"PE\0\0"
    # COFF: machine, sections, ..., SizeOfOptionalHeader at offset 16.
    coff_fields = bytearray(20)
    struct.pack_into("<HH", coff_fields, 0, 0x8664 if magic == 0x20B else 0x14C, 1)
    struct.pack_into("<H", coff_fields, 16, size_optional)
    out += coff_fields
    optional = bytearray(size_optional)
    struct.pack_into("<H", optional, 0, magic)
    struct.pack_into("<II", optional, directories_offset, export_rva, export_size)
    out += optional
    section_header = bytearray(40)
    # VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData.
    struct.pack_into("<IIII", section_header, 8, len(blob), virtual_address, len(blob), image_start)
    out += section_header
    # Pad to the image start, then the blob.
    while len(out) < image_start:
        out += b"\0"
    out += blob
    return bytes(out)


class PeExportTests(unittest.TestCase):
    def test_pe32_plus_exports_are_listed(self):
        data = build_pe(0x20B, ["rci_version", "rci_get"])
        path = self._write(data)
        self.assertEqual(peexports.read_exports(path), ["rci_version", "rci_get"])

    def test_pe32_exports_are_listed(self):
        # PE32 puts the data directories 16 bytes earlier than PE32+.
        data = build_pe(0x10B, ["rci_one"])
        path = self._write(data)
        self.assertEqual(peexports.read_exports(path), ["rci_one"])

    def test_a_non_pe_is_rejected(self):
        path = self._write(b"not a PE file at all")
        with self.assertRaises(ValueError):
            peexports.read_exports(path)

    @staticmethod
    def _write(data):
        import tempfile

        handle = tempfile.NamedTemporaryFile(suffix=".dll", delete=False)
        handle.write(data)
        handle.close()
        return handle.name


if __name__ == "__main__":
    unittest.main()
