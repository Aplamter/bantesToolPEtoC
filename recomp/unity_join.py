"""Rebuild Unity asset files from a split folder (written by recomp's unity.py).

Standalone: copied into every game project and used by build_game.py. Needs
only the Python standard library (plus `pip install lz4` for asset bundles).

A split folder holds recipe.json and the pieces of one original file:

  serialized file (.assets, level0, globalgamemanagers, ...):
      objects/NNNNNN_<pathid>_<Type>.bin   every object's exact bytes
      glue/NNN.bin                          header, type tree, object table,
                                            padding - everything that isn't an object
      preview/                              PNG/text/JSON exports, for looking only

  asset bundle (UnityFS):
      head.bin / tail.bin                   bundle header and block table
      nodes/<path>                          the files inside the bundle (each
                                            serialized one split again, *.split/)
      blocks/NNNNN.bin                      compressed blocks we could not
                                            reproduce by recompressing

Unchanged pieces always rebuild the original file byte for byte.
"""
import hashlib
import json
import lzma
import os
import shutil
import struct
import tempfile


class JoinError(Exception):
    pass


def _read(base, rel):
    with open(os.path.join(base, rel), "rb") as f:
        return f.read()


def join(split_dir, out_path):
    """write the file described by split_dir/recipe.json to out_path.
    Returns 'exact' or 'modified' (pieces were edited: valid, not identical)."""
    with open(os.path.join(split_dir, "recipe.json")) as f:
        r = json.load(f)
    if r["kind"] == "serialized":
        return _join_serialized(split_dir, r, out_path)
    if r["kind"] == "bundle":
        return _join_bundle(split_dir, r, out_path)
    raise JoinError(f"unknown recipe kind {r['kind']}")


def _join_serialized(d, r, out_path):
    pos = 0
    with open(out_path, "wb") as out:
        for seg in r["segments"]:
            kind, ref = seg[0], seg[1]
            if kind == "h":
                b = bytes.fromhex(ref)
            else:
                b = _read(d, ref)
            if kind == "o" and len(b) != seg[2]:
                raise JoinError(f"{ref}: object size changed ({seg[2]} -> {len(b)} bytes); "
                                "changing object sizes needs the object table rewritten, which "
                                "this joiner does not do yet - keep the size or edit in place")
            out.write(b)
            pos += len(b)
    return "exact" if pos == r["size"] and _sha(out_path) == r["sha256"] else "modified"


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---- asset bundles -------------------------------------------------------
def lzma_props(props):
    d = props[0]
    lc, d = d % 9, d // 9
    lp, pb = d % 5, d // 5
    return {"id": lzma.FILTER_LZMA1, "dict_size": struct.unpack_from("<I", props, 1)[0],
            "lc": lc, "lp": lp, "pb": pb}


def decompress(codec_flags, data, usize):
    c = codec_flags & 0x3F
    if c == 0:
        return data
    if c == 1:
        dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[lzma_props(data[:5])])
        return dec.decompress(data[5:], max_length=usize)
    if c in (2, 3):
        import lz4.block
        return lz4.block.decompress(data, uncompressed_size=usize)
    raise JoinError(f"unknown bundle compression {c}")


def compress(codec, data):
    """codec names written by the splitter: none, lz4, lz4hc:N"""
    if codec == "none":
        return data
    import lz4.block
    if codec == "lz4":
        return lz4.block.compress(data, mode="default", store_size=False)
    if codec.startswith("lz4hc:"):
        return lz4.block.compress(data, mode="high_compression",
                                  compression=int(codec[6:]), store_size=False)
    raise JoinError(f"cannot compress with {codec}")


def _node_bytes(d, node, tmpdir):
    if "split" in node:
        p = os.path.join(tmpdir, f"node{abs(hash(node['path']))}.bin")
        join(os.path.join(d, node["split"]), p)
        with open(p, "rb") as f:
            b = f.read()
        os.remove(p)
        return b
    return _read(d, node["file"])


def _join_bundle(d, r, out_path):
    with tempfile.TemporaryDirectory() as tmp:
        stream = bytearray()
        for piece in r["stream"]:
            if piece[0] == "gap":
                stream += bytes.fromhex(piece[1])
            else:
                stream += _node_bytes(d, r["nodes"][piece[1]], tmp)
        unchanged = (len(stream) == r["stream_size"] and
                     hashlib.sha256(stream).hexdigest() == r["stream_sha256"])
        if unchanged:
            with open(out_path, "wb") as out:
                out.write(_read(d, r["head"]))
                pos = 0
                for b in r["blocks"]:
                    raw = bytes(stream[pos:pos + b["u"]])
                    pos += b["u"]
                    out.write(_read(d, b["file"]) if b["codec"] == "stored" else compress(b["codec"], raw))
                if r.get("tail"):
                    out.write(_read(d, r["tail"]))
            return "exact" if _sha(out_path) == r["sha256"] else "modified"
        return _repack_bundle(r, d, tmp, out_path)


def _repack_bundle(r, d, tmp, out_path):
    """contents were edited: write a fresh, valid UnityFS file (LZ4HC blocks,
    uncompressed block table) with the same header strings and nodes"""
    import lz4.block
    nodes, stream = [], bytearray()
    for n in r["nodes"]:
        b = _node_bytes(d, n, tmp)
        nodes.append((len(stream), len(b), n["flags"], n["path"]))
        stream += b
    blocks, data = [], bytearray()
    for o in range(0, len(stream), 0x20000):
        raw = bytes(stream[o:o + 0x20000])
        c = lz4.block.compress(raw, mode="high_compression", compression=9, store_size=False)
        if len(c) < len(raw):
            blocks.append((len(raw), len(c), 3))
            data += c
        else:
            blocks.append((len(raw), len(raw), 0))
            data += raw
    info = bytearray(16) + struct.pack(">i", len(blocks))
    for u, c, fl in blocks:
        info += struct.pack(">IIH", u, c, fl)
    info += struct.pack(">i", len(nodes))
    for off, size, fl, path in nodes:
        info += struct.pack(">qqI", off, size, fl) + path.encode() + b"\0"
    h = r["header"]
    head = b"UnityFS\0" + struct.pack(">I", h["version"]) + h["unity_version"].encode() + b"\0" + \
        h["revision"].encode() + b"\0"
    fixed_len = 8 + 4 + 4 + 4
    flags = 0x40          # block table directly after the header, uncompressed
    pad = 0
    if h["version"] >= 7:
        pad = -(len(head) + fixed_len) % 16
    total = len(head) + fixed_len + pad + len(info) + len(data)
    with open(out_path, "wb") as out:
        out.write(head + struct.pack(">qIII", total, len(info), len(info), flags) + b"\0" * pad)
        out.write(info)
        out.write(data)
    return "modified"


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        sys.exit("usage: unity_join.py SPLIT_DIR OUT_FILE")
    print(join(sys.argv[1], sys.argv[2]))
