import pathlib
import struct
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recomp.runtime_capture import pe_executable_sections, overlay_pe_sections


def make_pe(path):
    data = bytearray(0x204)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    sec = 0x80 + 24 + 0xF0
    data[sec:sec+8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, sec+8, 4, 0x1000, 4, 0x200)
    struct.pack_into("<I", data, sec+36, 0x60000020)
    data[0x200:0x204] = b"ABCD"
    path.write_bytes(data)


class RuntimeCapturePureTests(unittest.TestCase):
    def test_finds_executable_pe_section(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "sample.exe"
            make_pe(p)
            sections = pe_executable_sections(p)
            self.assertEqual(len(sections), 1)
            self.assertEqual(sections[0]["name"], ".text")
            self.assertEqual(sections[0]["rva"], 0x1000)

    def test_overlays_live_code_and_counts_changes(self):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "sample.exe"
            out = pathlib.Path(td) / "runtime.exe"
            make_pe(src)
            changes = overlay_pe_sections(str(src), 0x140000000,
                lambda address, size: b"WXYZ" if address == 0x140001000 and size == 4 else None, str(out))
            self.assertEqual(changes[0]["bytes_changed"], 4)
            self.assertEqual(out.read_bytes()[0x200:0x204], b"WXYZ")


if __name__ == "__main__":
    unittest.main()
