import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recomp.vmc import compile_ir


class VMCCompileTests(unittest.TestCase):
    def test_neutral_ir_compiles_and_runs(self):
        cc = shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("requires gcc or clang")
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "ir.json"
            src.write_text(json.dumps({"registers": 4, "instructions": [
                {"op": "const", "dst": 0, "value": 19},
                {"op": "const", "dst": 1, "value": 23},
                {"op": "add", "dst": 2, "a": 0, "b": 1},
                {"op": "ret", "src": 2}]}), encoding="utf-8")
            report = compile_ir(str(src), td)
            self.assertEqual(report["instructions"], 4)
            (pathlib.Path(td) / "main.c").write_text(
                '#include "recomp_vm.h"\nint main(void) { return recomp_vm_run() == 42 ? 0 : 1; }\n', encoding="utf-8")
            subprocess.run([cc, "-std=c99", "recomp_vm.c", "main.c", "-o", "test"], cwd=td, check=True)
            subprocess.run(["./test"], cwd=td, check=True)


    def test_rejects_external_call_opcode(self):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "external.json"
            src.write_text(json.dumps({"registers": 1, "instructions": [
                {"op": "call_ext", "function": "some_api", "args": [], "dst": 0},
                {"op": "ret", "src": 0}]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                compile_ir(str(src), td)

    def test_rejects_invalid_jump(self):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "bad.json"
            src.write_text(json.dumps({"registers": 1, "instructions": [{"op": "jmp", "target": 99}]}))
            with self.assertRaises(ValueError):
                compile_ir(str(src), td)


if __name__ == "__main__":
    unittest.main()
