import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recomp.vmdecode import decode
from recomp.vmc import compile_ir


class VMDecodeTests(unittest.TestCase):
    def test_documented_bytecode_to_ir_to_c(self):
        cc = shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("requires gcc or clang")
        with tempfile.TemporaryDirectory() as td:
            raw = pathlib.Path(td) / "code.bin"
            isa = pathlib.Path(td) / "isa.json"
            ir = pathlib.Path(td) / "ir.json"
            raw.write_bytes(bytes([1, 0, 19, 0, 0, 0, 1, 1, 23, 0, 0, 0, 2, 2, 0, 1, 3, 2]))
            isa.write_text(json.dumps({"registers": 4, "byte_order": "little", "opcodes": [
                {"code": 1, "op": "const", "fields": {"dst": "u8", "value": "i32"}},
                {"code": 2, "op": "add", "fields": {"dst": "u8", "a": "u8", "b": "u8"}},
                {"code": 3, "op": "ret", "fields": {"src": "u8"}}]}), encoding="utf-8")
            report = decode(str(raw), str(isa), str(ir))
            self.assertEqual(report["instructions"], 4)
            compile_ir(str(ir), td)
            (pathlib.Path(td) / "main.c").write_text(
                '#include "recomp_vm.h"\nint main(void) { return recomp_vm_run() == 42 ? 0 : 1; }\n', encoding="utf-8")
            subprocess.run([cc, "recomp_vm.c", "main.c", "-o", "test"], cwd=td, check=True)
            subprocess.run(["./test"], cwd=td, check=True)

    def test_unknown_opcode_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            raw = pathlib.Path(td) / "bad.bin"
            isa = pathlib.Path(td) / "isa.json"
            out = pathlib.Path(td) / "out.json"
            raw.write_bytes(b"\xff")
            isa.write_text(json.dumps({"registers": 1, "opcodes": [{"code": 0, "op": "nop"}]}))
            with self.assertRaisesRegex(ValueError, "unknown opcode"):
                decode(str(raw), str(isa), str(out))

    def test_truncated_operand_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            raw = pathlib.Path(td) / "bad.bin"
            isa = pathlib.Path(td) / "isa.json"
            out = pathlib.Path(td) / "out.json"
            raw.write_bytes(bytes([1, 0, 9]))
            isa.write_text(json.dumps({"registers": 1, "opcodes": [
                {"code": 1, "op": "const", "fields": {"dst": "u8", "value": "i32"}}]}))
            with self.assertRaisesRegex(ValueError, "truncated"):
                decode(str(raw), str(isa), str(out))


if __name__ == "__main__":
    unittest.main()
