"""capture_pid against a fake kernel32/psapi: exercises the module/region
walk (overlay coverage, private regions, dedupe across snapshots, the memory
cap) on any OS. It does not prove the real Windows API calls are right; a
live Windows run still has to do that."""
import ctypes
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from recomp import runtime_capture as rc
from recomp.lift import rebase_pe
import test_runtime_capture_relocs as helpers

MEM_COMMIT, MEM_FREE = 0x1000, 0x10000
JIT_BASE = 0x2000000


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong), ("PartitionId", ctypes.c_ushort),
                ("RegionSize", ctypes.c_size_t), ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", ctypes.c_ulong),
                ("EntryPoint", ctypes.c_void_p)]


class FakeProcess:
    """a module 'loaded' at a non-preferred base plus one JIT page"""
    def __init__(self, dll, loaded, base):
        self.dll, self.base = dll, base
        lay = rc.pe_layout(loaded)
        raw = pathlib.Path(loaded).read_bytes()
        self.mem = {}
        self.regions = []   # (base, size, protect, type, alloc_base)
        self.regions.append((base, 0x1000, 0x02, rc.MEM_IMAGE, base))       # headers
        for s in lay["sections"]:
            va = base + s["rva"]
            size = (max(s["virtual_size"], s["raw_size"]) + 0xFFF) & ~0xFFF
            data = raw[s["raw_offset"]:s["raw_offset"] + min(s["raw_size"], size)]
            self.mem[va] = data + bytes(size - len(data))
            prot = 0x20 if s["characteristics"] & 0x20000000 else 0x02
            self.regions.append((va, size, prot, rc.MEM_IMAGE, base))
        self.mem[JIT_BASE] = b"\x48\x89\xc8\xc3" + bytes(0xFFC)    # mov rax,rcx; ret
        self.regions.append((JIT_BASE, 0x1000, 0x40, rc.MEM_PRIVATE, JIT_BASE))
        self.regions.sort()

    def read(self, address, size):
        for va, data in self.mem.items():
            if va <= address and address + size <= va + len(data):
                return data[address - va:address - va + size]
        return None


def fake_api(proc):
    k32 = mock.MagicMock()
    psapi = mock.MagicMock()
    k32.OpenProcess.return_value = 1
    k32.IsWow64Process.return_value = 1

    def vq(h, addr, pmbi, n):
        a = addr.value or 0
        m = pmbi._obj
        for base, size, prot, typ, ab in proc.regions:
            if base <= a < base + size:
                m.BaseAddress, m.RegionSize, m.State, m.Protect, m.Type, m.AllocationBase = \
                    base, size, MEM_COMMIT, prot, typ, ab
                return ctypes.sizeof(m)
        nxt = [r[0] for r in proc.regions if r[0] > a]
        if not nxt:
            return 0
        m.BaseAddress, m.RegionSize, m.State, m.Protect, m.Type, m.AllocationBase = \
            a, nxt[0] - a, MEM_FREE, 0x01, 0, 0
        return ctypes.sizeof(m)
    k32.VirtualQueryEx.side_effect = vq

    def gsi(p):
        si = p._obj
        si.dwPageSize = 0x1000
        si.lpMinimumApplicationAddress = 0x10000
        si.lpMaximumApplicationAddress = 0x7FFFFFFEFFFF
    k32.GetSystemInfo.side_effect = gsi
    psapi.EnumProcessModulesEx.return_value = 1
    return k32, psapi, MODULEINFO, MBI


class FakeWindowsCapture(unittest.TestCase):
    def setUp(self):
        if not shutil.which("x86_64-w64-mingw32-gcc"):
            self.skipTest("MinGW not installed")
        self.td = tempfile.mkdtemp()
        game = pathlib.Path(self.td) / "game"
        game.mkdir()
        self.dll = helpers.build(str(game), "x86_64-w64-mingw32-gcc", helpers.SRC_X64, "engine")
        loaded = pathlib.Path(self.td) / "loaded.dll"
        self.base = 0x7FF812340000
        rebase_pe(str(self.dll), str(loaded), self.base)
        self.proc = FakeProcess(self.dll, loaded, self.base)
        api = fake_api(self.proc)
        mods = [{"base": self.base, "size": 0x20000, "path": str(self.dll)}]
        self.patches = [mock.patch.object(rc, "_windows_api", return_value=api),
                        mock.patch.object(rc, "_modules", return_value=mods),
                        mock.patch.object(rc, "_read_process",
                                          side_effect=lambda k, h, a, n: self.proc.read(a, n))]
        for p in self.patches:
            p.start()
        self.game = game

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.td, ignore_errors=True)

    def test_snapshot(self):
        seen = {}
        rep = rc.capture_pid(1234, pathlib.Path(self.td) / "s0", allowed_root=self.game, seen_regions=seen)
        mod = rep["modules"][0]
        self.assertEqual(mod["changed_executable_bytes"], 0, mod)
        self.assertEqual(mod["preferred_base"], hex(rc.pe_layout(self.dll)["imagebase"]))
        kinds = [r.get("candidate_kind") for r in rep["executable_regions"]]
        self.assertIn("private_dynamic_or_jit", kinds)
        jit = next(r for r in rep["executable_regions"] if r.get("candidate_kind") == "private_dynamic_or_jit")
        self.assertEqual(jit["base"], hex(JIT_BASE))
        self.assertTrue(pathlib.Path(jit["file"]).read_bytes().startswith(b"\x48\x89\xc8\xc3"))
        # only the zero tail of .text past its file bytes is outside the overlay
        for r in rep["executable_regions"]:
            if r.get("memory_type") == "MEM_IMAGE":
                self.assertEqual(r["candidate_kind"], "game_module_exec_page_not_in_overlay")
                self.assertLess(r["captured_size"], 0x1000)
        self.assertFalse(rep["executable_capture_truncated"])

        rep2 = rc.capture_pid(1234, pathlib.Path(self.td) / "s1", allowed_root=self.game, seen_regions=seen)
        jit2 = next(r for r in rep2["executable_regions"] if r.get("candidate_kind") == "private_dynamic_or_jit")
        self.assertTrue(jit2.get("same_bytes_saved_as"))
        self.assertEqual(rep2["executable_capture_bytes"], 0)
        self.assertFalse((pathlib.Path(self.td) / "s1" / "private_exec" / f"region_{JIT_BASE:x}.bin").exists())

    def test_module_outside_game_folder_is_ignored(self):
        other = pathlib.Path(self.td) / "elsewhere"
        other.mkdir()
        rep = rc.capture_pid(1, pathlib.Path(self.td) / "s", allowed_root=other)
        self.assertEqual(rep["modules"], [])
        self.assertEqual([r["memory_type"] for r in rep["executable_regions"]], ["MEM_PRIVATE"])

    def test_cap_is_reported(self):
        self.proc.mem[JIT_BASE + 0x100000] = bytes(0x200000)
        self.proc.regions.append((JIT_BASE + 0x100000, 0x200000, 0x20, rc.MEM_PRIVATE, JIT_BASE + 0x100000))
        self.proc.regions.sort()
        rep = rc.capture_pid(1, pathlib.Path(self.td) / "s", allowed_root=self.game, max_exec_mb=1)
        self.assertTrue(rep["executable_capture_truncated"])
        self.assertLessEqual(rep["executable_capture_bytes"], 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
