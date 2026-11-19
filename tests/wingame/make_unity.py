"""Writes small but real-format Unity files for testing the game analyzer:
  serialized files (format 22 and 17) holding TextAssets, and a UnityFS
  bundle (LZ4HC blocks + LZ4HC block table) holding a serialized file.
UnityPy parses them; the analyzer must split them and rebuild them exactly."""
import os
import struct
import sys

import lz4.block


def s4(b):
    """Unity string: int32 length + bytes, aligned to 4"""
    return struct.pack("<i", len(b)) + b + b"\0" * (-len(b) % 4)


def text_asset(name, script):
    return s4(name.encode()) + s4(script)


def serialized(version, objects, unity="2020.3.0f1"):
    """objects: [(path_id, class_id, bytes)]"""
    classes = sorted({c for _, c, _ in objects})
    meta = bytearray(unity.encode() + b"\0")
    meta += struct.pack("<i", 19)                 # StandaloneWindows64
    meta += b"\0"                                 # no type trees
    meta += struct.pack("<i", len(classes))
    for c in classes:
        meta += struct.pack("<i", c) + b"\0" + struct.pack("<h", -1) + bytes(16)
    meta += struct.pack("<i", len(objects))
    hdr_len = 48 if version >= 22 else 20
    # object data layout: aligned to 8
    offs, pos = [], 0
    for _, _, data in objects:
        pos += -pos % 8
        offs.append(pos)
        pos += len(data)
    for (pid, c, data), off in zip(objects, offs):
        while (hdr_len + len(meta)) % 4:          # align_stream before each entry
            meta += b"\0"
        meta += struct.pack("<q", pid)
        meta += struct.pack("<q", off) if version >= 22 else struct.pack("<I", off)
        meta += struct.pack("<Ii", len(data), classes.index(c))
    meta += struct.pack("<i", 0)                  # script types
    meta += struct.pack("<i", 0)                  # externals
    if version >= 20:
        meta += struct.pack("<i", 0)              # ref types
    meta += b"\0"                                 # user information
    data_off = hdr_len + len(meta)
    data_off += -data_off % 16
    body = bytearray()
    for (_, _, data), off in zip(objects, offs):
        body += b"\0" * (off - len(body)) + data
    size = data_off + len(body)
    if version >= 22:
        hdr = struct.pack(">IIII", 0, 0, version, 0) + b"\0\0\0\0" + struct.pack(">IQQQ", len(meta), size, data_off, 0)
    else:
        hdr = struct.pack(">IIII", len(meta), size, version, data_off) + b"\0\0\0\0"
    out = hdr + meta
    return out + b"\0" * (data_off - len(out)) + body


def bundle(files, unity="2020.3.0f1"):
    """UnityFS version 7 with LZ4HC (level 9) blocks of 128 KB"""
    stream, nodes = bytearray(), []
    for name, data in files:
        nodes.append((len(stream), len(data), 4, name))
        stream += data
    blocks, comp = [], bytearray()
    for o in range(0, len(stream), 0x20000):
        raw = bytes(stream[o:o + 0x20000])
        c = lz4.block.compress(raw, mode="high_compression", compression=9, store_size=False)
        blocks.append((len(raw), len(c), 3))
        comp += c
    info = bytearray(16) + struct.pack(">i", len(blocks))
    for u, c, f in blocks:
        info += struct.pack(">IIH", u, c, f)
    info += struct.pack(">i", len(nodes))
    for off, size, f, name in nodes:
        info += struct.pack(">qqI", off, size, f) + name.encode() + b"\0"
    cinfo = lz4.block.compress(bytes(info), mode="high_compression", compression=9, store_size=False)
    head = b"UnityFS\0" + struct.pack(">I", 7) + b"5.x.x\0" + unity.encode() + b"\0"
    flags = 0x43                                    # LZ4HC block table, right after the header
    fixed = 8 + 12
    pad = -(len(head) + fixed) % 16
    total = len(head) + fixed + pad + len(cinfo) + len(comp)
    return head + struct.pack(">qIII", total, len(cinfo), len(info), flags) + b"\0" * pad + cinfo + bytes(comp)


if __name__ == "__main__":
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    lore = b"The forest remembers every test.\n" * 50
    big = bytes((i * 7 + (i >> 5)) & 0xFF for i in range(300000))   # spans several bundle blocks
    with open(os.path.join(out, "resources.assets"), "wb") as f:
        f.write(serialized(22, [(1, 49, text_asset("lore", lore)), (2, 49, text_asset("credits", b"made by tests")),
                                (7, 49, text_asset("level1", b"forest of tests"))]))
    with open(os.path.join(out, "sharedassets0.assets"), "wb") as f:
        f.write(serialized(17, [(1, 49, text_asset("old_format", b"version 17 file"))], unity="2017.4.0f1"))
    cab = serialized(22, [(5, 49, text_asset("dlc_text", b"bundled text")), (6, 49, text_asset("blob", big))])
    with open(os.path.join(out, "dlc.bundle"), "wb") as f:
        f.write(bundle([("CAB-0123456789abcdef", cab), ("CAB-0123456789abcdef.resS", big[:5000])]))
