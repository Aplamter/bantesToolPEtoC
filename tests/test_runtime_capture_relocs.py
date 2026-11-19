"""Runtime-capture overlays against real MinGW-built PE files.

Windows loads a relocatable module wherever it likes (ASLR) and applies its
base relocations, so the live code of an unmodified module differs from the
file at every relocated address. These tests simulate exactly that with
lift.rebase_pe (an independent relocation implementation) and check that the
overlay is normalised back to the file's ImageBase: an unmodified module must
report 0 changed bytes, and a real change must still be found and located.

Skipped when MinGW is not installed.
"""
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recomp.runtime_capture import (pe_layout, overlay_pe_sections, read_chunked,
                                    subtract_ranges)
from recomp.lift import rebase_pe

SRC_X64 = r"""
int counter;
static int helper(int x) { return x * 3 + counter; }
__declspec(dllexport) int api(int x) { return helper(x) + 1; }
__declspec(dllexport) void *table(void) {
    void *p;
    /* an absolute 64-bit address inside .text: a DIR64 relocation in code */
    __asm__ volatile("movabs %1, %0" : "=r"(p) : "i"(helper));
    return p;
}
"""

SRC_X86 = r"""
int counter;
static int helper(int x) { return x * 3 + counter; }
__declspec(dllexport) int api(int x) { counter++; return helper(x) + counter; }
__declspec(dllexport) void *ptr(void) { return (void *)helper; }
"""


def build(td, cc, src, name):
    if not shutil.which(cc):
        raise unittest.SkipTest(f"{cc} not installed")
    c = pathlib.Path(td) / (name + ".c")
    c.write_text(src)
    out = pathlib.Path(td) / (name + ".dll")
    subprocess.run([cc, "-O1", "-shared", "-o", str(out), str(c)], check=True,
                   capture_output=True)
    return out


def memory_of(pe_path):
    """a read_memory(address, size) over a PE file 'loaded' at its ImageBase"""
    lay = pe_layout(pe_path)
    raw = pathlib.Path(pe_path).read_bytes()
    ib = lay["imagebase"]
    spans = [(ib + s["rva"], s["raw_offset"], s["raw_size"]) for s in lay["sections"] if s["raw_size"]]

    def read(address, size):
        for va, off, n in spans:
            if va <= address and address + size <= va + n:
                return raw[off + address - va:off + address - va + size]
        return None
    return read, ib


def text_of(path):
    lay = pe_layout(path)
    raw = pathlib.Path(path).read_bytes()
    s = next(x for x in lay["sections"] if x["name"] == ".text")
    n = min(s["raw_size"], s["virtual_size"])
    return raw[s["raw_offset"]:s["raw_offset"] + n], s


class OverlayRelocationTests(unittest.TestCase):
    def check_unmodified(self, cc, src, new_base):
        with tempfile.TemporaryDirectory() as td:
            dll = build(td, cc, src, "mod")
            lay = pe_layout(dll)
            text_va = next(s for s in lay["sections"] if s["name"] == ".text")["rva"]
            in_text = [r for r in lay["relocs"] if text_va <= r[0] < text_va + 0x100000]
            self.assertTrue(in_text, "test DLL should have relocations inside .text")
            loaded = pathlib.Path(td) / "loaded.dll"
            rebase_pe(str(dll), str(loaded), new_base)
            read, base = memory_of(loaded)
            self.assertEqual(base, new_base)
            # the raw bytes really do differ before normalisation
            self.assertNotEqual(text_of(dll)[0], text_of(loaded)[0])
            out = pathlib.Path(td) / "overlay.dll"
            changes = overlay_pe_sections(str(dll), new_base, read, str(out))
            t = next(c for c in changes if c["section"] == ".text")
            self.assertEqual(t["status"], "captured")
            self.assertEqual(t["bytes_changed"], 0, t)
            self.assertGreater(t["relocations_normalized"], 0)
            self.assertEqual(out.read_bytes(), dll.read_bytes())

    def test_x64_aslr_load_is_not_a_change(self):
        self.check_unmodified("x86_64-w64-mingw32-gcc", SRC_X64, 0x7FF812340000)

    def test_x86_aslr_load_is_not_a_change(self):
        self.check_unmodified("i686-w64-mingw32-gcc", SRC_X86, 0x6A000000)

    def test_real_change_survives_normalisation(self):
        with tempfile.TemporaryDirectory() as td:
            dll = build(td, "x86_64-w64-mingw32-gcc", SRC_X64, "mod")
            loaded = pathlib.Path(td) / "loaded.dll"
            new_base = 0x7FF900000000
            rebase_pe(str(dll), str(loaded), new_base)
            text, sec = text_of(loaded)
            # "runtime" writes 8 bytes of new code 0x40 bytes into .text
            data = bytearray(loaded.read_bytes())
            patch_at = sec["raw_offset"] + 0x40
            data[patch_at:patch_at + 8] = b"\x90\x90\x90\x90\x31\xc0\xc3\xcc"
            loaded.write_bytes(data)
            read, _ = memory_of(loaded)
            out = pathlib.Path(td) / "overlay.dll"
            changes = overlay_pe_sections(str(dll), new_base, read, str(out))
            t = next(c for c in changes if c["section"] == ".text")
            self.assertTrue(1 <= t["bytes_changed"] <= 8, t)
            lo, hi = (int(x, 16) for x in t["changed_ranges"][0])
            self.assertTrue(sec["rva"] + 0x40 <= lo and hi <= sec["rva"] + 0x48, t["changed_ranges"])
            ov = out.read_bytes()
            off = sec["raw_offset"] + 0x40
            self.assertEqual(ov[off:off + 8], b"\x90\x90\x90\x90\x31\xc0\xc3\xcc")

    def test_unreadable_page_keeps_rest_of_section(self):
        with tempfile.TemporaryDirectory() as td:
            dll = build(td, "x86_64-w64-mingw32-gcc", SRC_X64, "mod")
            lay = pe_layout(dll)
            sec = next(s for s in lay["sections"] if s["name"] == ".text")
            read, ib = memory_of(dll)
            bad_page = ib + sec["rva"]          # first page of .text: unreadable

            def partial(address, size):
                if address < bad_page + 0x1000 and address + size > bad_page:
                    return None
                return read(address, size)
            out = pathlib.Path(td) / "overlay.dll"
            changes = overlay_pe_sections(str(dll), ib, partial, str(out))
            t = next(c for c in changes if c["section"] == ".text")
            n = min(sec["raw_size"], sec["virtual_size"])
            if n <= 0x1000:
                self.skipTest(".text too small for a partial read")
            self.assertEqual(t["status"], "partial")
            self.assertEqual(t["unreadable_bytes"], 0x1000)
            self.assertEqual(t["bytes_changed"], 0)


class PurePieces(unittest.TestCase):
    def test_read_chunked_splits_on_pages(self):
        mem = {a: 0xAB for a in range(0x10000, 0x13000)}

        def rd(a, n):
            if 0x11000 <= a < 0x12000 or (a < 0x12000 and a + n > 0x11000):
                return None
            return bytes(mem[x] for x in range(a, a + n))
        pieces, bad = read_chunked(rd, 0x10800, 0x2000)
        self.assertEqual(bad, [(0x800, 0x1000)])
        self.assertEqual([(o, len(b)) for o, b in pieces], [(0, 0x800), (0x1800, 0x800)])

    def test_subtract_ranges(self):
        self.assertEqual(subtract_ranges(0, 100, [(10, 20), (15, 30), (90, 200)]),
                         [(0, 10), (30, 90)])
        self.assertEqual(subtract_ranges(0, 100, []), [(0, 100)])
        self.assertEqual(subtract_ranges(0, 100, [(0, 100)]), [])

    def test_iat_inside_text_is_masked(self):
        # minimal PE32+ with .text holding an import table and its IAT
        d = bytearray(0x600)
        d[:2] = b"MZ"
        struct.pack_into("<I", d, 0x3C, 0x80)
        d[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", d, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
        opt = 0x98
        struct.pack_into("<H", d, opt, 0x20B)
        struct.pack_into("<Q", d, opt + 24, 0x140000000)
        struct.pack_into("<I", d, opt + 108, 16)
        struct.pack_into("<II", d, opt + 112 + 8, 0x1100, 40)     # import directory
        sec = 0x80 + 24 + 0xF0
        d[sec:sec + 8] = b".text\0\0\0"
        struct.pack_into("<IIII", d, sec + 8, 0x400, 0x1000, 0x400, 0x200)
        struct.pack_into("<I", d, sec + 36, 0x60000020)
        f = lambda rva: 0x200 + rva - 0x1000
        struct.pack_into("<IIIII", d, f(0x1100), 0, 0, 0, 0x1180, 0x1200)  # descriptor
        struct.pack_into("<Q", d, f(0x1200), 0x1190)                       # 1 thunk
        d[f(0x1180):f(0x1180) + 6] = b"k.dll\0"
        d[f(0x1000):f(0x1000) + 4] = b"\x31\xc0\xc3\xcc"
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "iat.exe"
            p.write_bytes(d)
            lay = pe_layout(p)
            self.assertIn((0x1200, 8), lay["iat"])
            raw = bytes(d)

            def live(a, n):
                o = 0x200 + a - 0x140001000
                b = bytearray(raw[o:o + n])
                at = 0x1200 - 0x1000 - (a - 0x140001000)
                if 0 <= at < n:          # the loader wrote an API address
                    struct.pack_into("<Q", b, at, 0x7FFA12345678)
                return bytes(b)
            changes = overlay_pe_sections(str(p), 0x140000000, live, str(pathlib.Path(td) / "o.exe"))
            self.assertEqual(changes[0]["bytes_changed"], 0)
            self.assertEqual(changes[0]["iat_bytes_masked"], 8)


if __name__ == "__main__":
    unittest.main()
