"""Compile documented neutral register-VM IR to portable C.

This backend consumes explicitly supplied IR. It does not inspect or decode
commercial protector internals.
"""
import json
import os
_OPS = {"nop", "const", "mov", "add", "sub", "mul", "div", "mod", "and", "or", "xor",
        "shl", "shr", "eq", "lt", "le", "jmp", "jz", "jnz", "ret"}


def _reg(v, count, where):
    if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < count:
        raise ValueError(f"{where} must be a register index in [0, {count - 1}]")
    return f"r[{v}]"


def compile_ir(input_path, out_dir):
    with open(input_path, "r", encoding="utf-8") as f:
        spec = json.load(f)
    if not isinstance(spec, dict):
        raise ValueError("IR root must be an object")
    count, ins = spec.get("registers", 8), spec.get("instructions")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 256:
        raise ValueError("registers must be an integer from 1 to 256")
    if not isinstance(ins, list) or not ins or len(ins) > 100000:
        raise ValueError("instructions must be a non-empty array (maximum 100000)")

    lines = ["/* Generated from documented, user-supplied neutral VM IR. */",
             '#include "recomp_vm.h"', "#include <stdint.h>", "#include <limits.h>"]
    lines += ["", "static int recomp_vm_error_code;",
              "int recomp_vm_last_error(void) { return recomp_vm_error_code; }",
              "int64_t recomp_vm_run(void)", "{", f"    int64_t r[{count}] = {{0}};",
              "    recomp_vm_error_code = 0;", "    uint64_t u, v;", "    (void)u; (void)v;", "    goto L0;", ""]
    for pc, item in enumerate(ins):
        if not isinstance(item, dict):
            raise ValueError(f"instruction {pc} must be an object")
        op = item.get("op")
        if op not in _OPS:
            raise ValueError(f"instruction {pc}: unsupported op {op!r}")
        lines.append(f"L{pc}:")
        nxt = f"L{pc + 1}" if pc + 1 < len(ins) else "LEND"
        if op == "nop":
            lines.append(f"    goto {nxt};")
        elif op == "const":
            d = _reg(item.get("dst"), count, f"instruction {pc}.dst")
            val = item.get("value")
            if not isinstance(val, int) or isinstance(val, bool) or not -(1 << 63) <= val < (1 << 63):
                raise ValueError(f"instruction {pc}.value must be signed 64-bit")
            lines.append(f"    {d} = (int64_t)UINT64_C({val & ((1 << 64) - 1)}); goto {nxt};")
        elif op == "mov":
            d = _reg(item.get("dst"), count, f"instruction {pc}.dst")
            src = _reg(item.get("src"), count, f"instruction {pc}.src")
            lines.append(f"    {d} = {src}; goto {nxt};")
        elif op in {"add", "sub", "mul", "and", "or", "xor", "shl", "shr", "div", "mod", "eq", "lt", "le"}:
            d = _reg(item.get("dst"), count, f"instruction {pc}.dst")
            a = _reg(item.get("a"), count, f"instruction {pc}.a")
            b = _reg(item.get("b"), count, f"instruction {pc}.b")
            if op in {"add", "sub", "mul", "and", "or", "xor", "shl", "shr"}:
                expr = {"add": f"(uint64_t){a} + (uint64_t){b}",
                        "sub": f"(uint64_t){a} - (uint64_t){b}",
                        "mul": f"(uint64_t){a} * (uint64_t){b}",
                        "and": f"(uint64_t){a} & (uint64_t){b}",
                        "or": f"(uint64_t){a} | (uint64_t){b}",
                        "xor": f"(uint64_t){a} ^ (uint64_t){b}",
                        "shl": f"(uint64_t){a} << ((uint64_t){b} & 63u)",
                        "shr": f"(uint64_t){a} >> ((uint64_t){b} & 63u)"}[op]
                lines.append(f"    {d} = (int64_t)({expr}); goto {nxt};")
            elif op in {"div", "mod"}:
                lines.append(f"    if ({b} == 0) return 0;")
                lines.append(f"    if ({a} == INT64_MIN && {b} == -1) {d} = 0;")
                lines.append(f"    else {d} = {a} {'/' if op == 'div' else '%'} {b}; goto {nxt};")
            else:
                cmp = {"eq": "==", "lt": "<", "le": "<="}[op]
                lines.append(f"    {d} = ({a} {cmp} {b}) ? 1 : 0; goto {nxt};")
        elif op in {"jmp", "jz", "jnz"}:
            target = item.get("target")
            if not isinstance(target, int) or isinstance(target, bool) or not 0 <= target < len(ins):
                raise ValueError(f"instruction {pc}.target must reference an instruction index")
            if op == "jmp":
                lines.append(f"    goto L{target};")
            else:
                cond = _reg(item.get("cond"), count, f"instruction {pc}.cond")
                test = "== 0" if op == "jz" else "!= 0"
                lines.append(f"    if ({cond} {test}) goto L{target}; else goto {nxt};")
        elif op == "ret":
            src = item.get("src")
            lines.append("    return 0;" if src is None else f"    return {_reg(src, count, f'instruction {pc}.src')};")
        lines.append("")
    lines += ["LEND:", "    return 0;", "}", ""]
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "recomp_vm.h"), "w", encoding="utf-8") as f:
        f.write("#ifndef RECOMP_VM_H\n#define RECOMP_VM_H\n#include <stdint.h>\nint64_t recomp_vm_run(void);\nint recomp_vm_last_error(void);\n#endif\n")
    with open(os.path.join(out_dir, "recomp_vm.c"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    report = {"input": os.path.basename(input_path), "instructions": len(ins), "registers": count,
              "translation": "self-contained documented neutral VM IR to C",
              "limitations": ["Does not parse or devirtualize protected VM bytecode.",
                              "External calls are not supported by this standalone backend.",
                              "Arithmetic uses 64-bit VM registers; adapt semantics if the source VM differs."]}
    with open(os.path.join(out_dir, "vm_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(out_dir, "VM_README.md"), "w", encoding="utf-8") as f:
        f.write("# recomp VM IR backend\\n\\nCompiles documented user-supplied neutral VM IR to C. It does not extract, decode, decrypt, or devirtualize VMProtect or another commercial protector. External calls are not supported by this standalone backend.\\n")
    return report
