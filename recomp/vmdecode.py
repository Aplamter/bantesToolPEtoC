"""Decode user-supplied bytecode using a declarative, documented ISA map.

This is a generic format adapter. It does not identify or decode proprietary
VMProtect handlers, extract protected code, defeat anti-tamper, or decrypt data.
"""
from __future__ import annotations
import json
import os
import struct

_FIELD_FORMATS = {
    "u8": (1, "B"), "i8": (1, "b"),
    "u16": (2, "H"), "i16": (2, "h"),
    "u32": (4, "I"), "i32": (4, "i"),
    "u64": (8, "Q"), "i64": (8, "q"),
}
_ALLOWED = {"nop", "const", "mov", "add", "sub", "mul", "div", "mod",
            "and", "or", "xor", "shl", "shr", "eq", "lt", "le",
            "jmp", "jz", "jnz", "ret"}


def decode(bytecode_path, isa_path, out_path):
    with open(isa_path, "r", encoding="utf-8") as f:
        isa = json.load(f)
    with open(bytecode_path, "rb") as f:
        blob = f.read()
    regs = isa.get("registers", 8)
    endian = isa.get("byte_order", "little")
    opcodes = isa.get("opcodes")
    if not isinstance(regs, int) or isinstance(regs, bool) or not 1 <= regs <= 256:
        raise ValueError("ISA registers must be an integer from 1 to 256")
    if endian not in {"little", "big"}:
        raise ValueError("byte_order must be 'little' or 'big'")
    if not isinstance(opcodes, list) or not opcodes:
        raise ValueError("ISA opcodes must be a non-empty array")
    table = {}
    for entry in opcodes:
        if not isinstance(entry, dict):
            raise ValueError("each opcode entry must be an object")
        code, op = entry.get("code"), entry.get("op")
        fields = entry.get("fields", {})
        if not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 255 or code in table:
            raise ValueError(f"invalid or duplicate opcode value: {code!r}")
        if op not in _ALLOWED or not isinstance(fields, dict):
            raise ValueError(f"unsupported VM operation or invalid fields for opcode {code}")
        parsed_fields = []
        for name, typ in fields.items():
            if not isinstance(name, str) or not name.isidentifier() or typ not in _FIELD_FORMATS:
                raise ValueError(f"invalid field {name!r} or field type {typ!r}")
            parsed_fields.append((name, typ))
        table[code] = (op, parsed_fields)

    decoded = []
    byte_to_index = {}
    pos = 0
    while pos < len(blob):
        start = pos
        byte_to_index[start] = len(decoded)
        code = blob[pos]
        pos += 1
        if code not in table:
            raise ValueError(f"unknown opcode 0x{code:02x} at byte offset 0x{start:x}; refusing to guess")
        op, fields = table[code]
        item = {"op": op}
        for name, typ in fields:
            size, fmt = _FIELD_FORMATS[typ]
            if pos + size > len(blob):
                raise ValueError(f"truncated {typ} operand '{name}' at byte offset 0x{start:x}")
            prefix = "<" if endian == "little" else ">"
            item[name] = struct.unpack(prefix + fmt, blob[pos:pos + size])[0]
            pos += size
        decoded.append((start, pos, item))

    # Branch operands are absolute byte offsets and must land on instruction starts.
    instructions = []
    for start, end, item in decoded:
        if item["op"] in {"jmp", "jz", "jnz"}:
            target = item.get("target")
            if target not in byte_to_index:
                raise ValueError(f"branch at 0x{start:x} targets non-instruction offset 0x{target:x}")
            item["target"] = byte_to_index[target]
        instructions.append(item)

    ir = {"registers": regs, "instructions": instructions,
          "source_format": "user-defined documented ISA map"}
    out_dir = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(ir, f, indent=2)
        f.write("\n")
    return {"bytes": len(blob), "instructions": len(instructions), "registers": regs}
