"""Split Unity asset files into their pieces (the analysis side).

The pieces + recipe.json rebuild the original byte for byte (unity_join.py,
which needs no UnityPy). Viewable exports (PNG, text, JSON) are written to
preview/ for looking at and modding; UnityPy (`pip install UnityPy`) is used
to find the object boundaries and to make the previews.
"""
import gc
import hashlib
import json
import os
import sys
import re
import shutil
import struct
import time

from . import unity_join


class UnitySplitError(Exception):
    pass


def detect(path):
    """'bundle', 'unity' (serialized file) or None"""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            h = f.read(48)
    except OSError:
        return None
    if h.startswith(b"UnityFS\0"):
        return "bundle"
    if len(h) < 20:
        return None
    meta, fsize, ver, doff = struct.unpack_from(">IIII", h, 0)
    if 9 <= ver < 22 and fsize == size and 0 < doff <= size and meta < size:
        return "unity"
    if 22 <= ver <= 40 and len(h) >= 48:
        meta2, fsize2, doff2 = struct.unpack_from(">IQQ", h, 20)
        if fsize2 == size and 0 < doff2 <= size and meta2 < size:
            return "unity"
    return None


def safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(name))[:80] or "_"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def remove_file(path, log=None):
    """os.remove that copes with Windows: a file that something still has open
    (a virus scanner looking at a file we just wrote, a search indexer) cannot
    be deleted there. Retry for a few seconds, then leave it: a leftover copy
    is harmless, a crash is not."""
    for delay in (0, 0.05, 0.2, 0.5, 1, 2, 3):
        if delay:
            gc.collect()
            time.sleep(delay)
        try:
            os.remove(path)
            return True
        except FileNotFoundError:
            return True
        except PermissionError:
            continue
    if log:
        log(f"could not delete {path} (in use by another program): left in place")
    return False


def close_env(env):
    """UnityPy opens the files it loads and never closes them. On Windows an
    open file cannot be deleted or replaced, so close them all ourselves."""
    stack, seen = list(getattr(env, "files", {}).values()), set()
    while stack:
        f = stack.pop()
        if f is None or id(f) in seen:
            continue
        seen.add(id(f))
        for x in (f, getattr(f, "reader", None)):
            st = getattr(x, "stream", None)
            try:
                if st is not None and hasattr(st, "close"):
                    st.close()
            except Exception:
                pass
        sub = getattr(f, "files", None)
        if isinstance(sub, dict):
            stack.extend(sub.values())
    gc.collect()


# MonoBehaviours (the game's own script data) carry no type tree in a built
# game. UnityPy can work their layout out from the game's code: the C#
# assemblies of a Mono game (*_Data/Managed) or GameAssembly.dll +
# global-metadata.dat of an IL2CPP game. Needs `pip install
# TypeTreeGeneratorAPI`; without it those objects just get no JSON preview.
_generators = {}


def typetree_generator(game_root, unity_version, log):
    """a UnityPy TypeTreeGenerator for the game (one per game, cached) or None"""
    if not game_root or not unity_version:
        return None
    key = (os.path.abspath(game_root), str(unity_version))
    if key in _generators:
        return _generators[key]
    gen = None
    try:
        import TypeTreeGeneratorAPI  # noqa: F401  (UnityPy only fails later without it)
        from UnityPy.helpers.TypeTreeGenerator import TypeTreeGenerator
        root = key[0]
        names = os.listdir(root)
        data = next((n for n in names if n.endswith("_Data") and os.path.isdir(os.path.join(root, n))), None)
        ga = next((n for n in names if n.lower() == "gameassembly.dll"), None)
        meta = os.path.join(root, data, "il2cpp_data", "Metadata", "global-metadata.dat") if data else None
        managed = os.path.join(root, data, "Managed") if data else None
        if data is None and os.path.isdir(os.path.join(root, "assets", "bin", "Data")):
            # an unpacked Android APK: assets/bin/Data, the IL2CPP code in lib/<abi>/libil2cpp.so
            data = os.path.join("assets", "bin", "Data")
            meta = os.path.join(root, data, "Managed", "Metadata", "global-metadata.dat")
            managed = os.path.join(root, data, "Managed")
            for abi in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
                if os.path.isfile(os.path.join(root, "lib", abi, "libil2cpp.so")):
                    ga = os.path.join("lib", abi, "libil2cpp.so")
                    break
        gen = TypeTreeGenerator(key[1])
        if ga and meta and os.path.isfile(meta):
            with open(os.path.join(root, ga), "rb") as f:
                ga_raw = f.read()
            with open(meta, "rb") as f:
                gen.load_il2cpp(ga_raw, f.read())
            log(f"script data previews: layouts from {os.path.basename(ga)} + global-metadata.dat (IL2CPP)")
        elif managed and os.path.isdir(managed):
            k = 0
            for fn in sorted(os.listdir(managed)):
                if fn.lower().endswith(".dll"):
                    try:
                        with open(os.path.join(managed, fn), "rb") as f:
                            gen.load_dll(f.read())
                        k += 1
                    except Exception:
                        pass        # a native DLL that sits in Managed, ...
            log(f"script data previews: layouts from {k} assemblies in {os.path.basename(managed)} (Mono)")
        else:
            gen = None
    except ImportError:
        log("script data (MonoBehaviour) gets no JSON preview: pip install TypeTreeGeneratorAPI")
        gen = None
    except Exception as e:
        log(f"script data (MonoBehaviour) gets no JSON preview: {e}")
        gen = None
    _generators[key] = gen
    return gen


def split(src, outdir, log=print, game_root=None):
    """game_root: the game's folder (the one with the exe); only used to make
    previews of script data, never for the pieces themselves"""
    kind = detect(src)
    if kind is None:
        raise UnitySplitError("not a Unity asset file")
    shutil.rmtree(outdir, ignore_errors=True)
    os.makedirs(outdir)
    res = (split_serialized(src, outdir, log, game_root) if kind == "unity"
           else split_bundle(src, outdir, log, game_root))
    # prove it: rebuild into a temp file and compare
    tmp = os.path.join(outdir, ".verify.tmp")
    try:
        how = unity_join.join(outdir, tmp)
    except Exception as e:
        raise UnitySplitError(f"rebuild check failed: {e}")
    finally:
        ok = os.path.exists(tmp) and sha256_file(tmp) == sha256_file(src)
        remove_file(tmp)
    if how != "exact" or not ok:
        raise UnitySplitError("rebuild check failed: the pieces do not give the original bytes")
    return res


# ---- serialized files ----------------------------------------------------
def split_serialized(src, outdir, log, game_root=None):
    try:
        import UnityPy
    except ImportError:
        raise UnitySplitError("UnityPy is not installed (pip install UnityPy)")
    env = None
    try:
        try:
            env = UnityPy.load(src)
        except Exception as e:
            raise UnitySplitError(f"UnityPy could not parse it: {e}")
        return _split_serialized(env, src, outdir, log, game_root)
    finally:
        # UnityPy keeps src open; the caller may want to delete it
        if env is not None:
            close_env(env)
        env = None
        gc.collect()


def _split_serialized(env, src, outdir, log, game_root):
    try:
        sfs = [f for f in env.files.values() if hasattr(f, "objects")]
        if not sfs:
            raise UnitySplitError("UnityPy found no objects")
        sf = sfs[0]
        objs = sorted(sf.objects.values(), key=lambda o: o.byte_start)
    except UnitySplitError:
        raise
    except Exception as e:
        raise UnitySplitError(f"UnityPy could not parse it: {e}")
    size = os.path.getsize(src)
    os.makedirs(os.path.join(outdir, "objects"))
    os.makedirs(os.path.join(outdir, "glue"))
    segs, pos, nglue = [], 0, 0
    with open(src, "rb") as f:
        def glue(upto):
            nonlocal pos, nglue
            if upto <= pos:
                return
            f.seek(pos)
            b = f.read(upto - pos)
            if len(b) <= 32:
                segs.append(["h", b.hex()])
            else:
                rel = f"glue/{nglue:03d}.bin"
                with open(os.path.join(outdir, rel), "wb") as g:
                    g.write(b)
                segs.append(["g", rel])
                nglue += 1
            pos = upto
        for k, o in enumerate(objs):
            if o.byte_start < pos or o.byte_start + o.byte_size > size:
                raise UnitySplitError(f"object {o.path_id} overlaps another or the end of the file")
            glue(o.byte_start)
            tname = getattr(o.type, "name", str(o.type))
            try:
                oname = o.peek_name() or ""
            except Exception:
                oname = ""
            rel = (f"objects/{k:06d}_{o.path_id & 0xFFFFFFFFFFFFFFFF:x}_{safe(tname)}"
                   f"{'_' + safe(oname)[:40] if oname else ''}.bin")
            f.seek(o.byte_start)
            with open(os.path.join(outdir, rel), "wb") as g:
                g.write(f.read(o.byte_size))
            segs.append(["o", rel, o.byte_size])
            pos = o.byte_start + o.byte_size
        glue(size)
    recipe = {"kind": "serialized", "size": size, "sha256": sha256_file(src),
              "unity_version": str(getattr(sf, "unity_version", "")),
              "format_version": getattr(getattr(sf, "header", None), "version", None),
              "segments": segs}
    with open(os.path.join(outdir, "recipe.json"), "w") as f:
        json.dump(recipe, f, indent=0)
    try:
        with native_output_captured():        # the library may print while loading the game's code
            env.typetree_generator = typetree_generator(game_root, recipe["unity_version"], log)
    except Exception:
        pass
    with native_output_captured() as cap:
        n = previews(objs, os.path.join(outdir, "preview"))
    log(f"{len(objs)} objects, {n} previews")
    noise = cap.summary()
    if noise:
        with open(os.path.join(outdir, "preview_errors.txt"), "w", encoding="utf-8") as f:
            f.write(cap.text)
        top = sorted(noise.items(), key=lambda kv: -kv[1])[:3]
        log("   no preview for some script objects (TypeTreeGenerator): " +
            "; ".join(f"{c}x {m[:120]}" for m, c in top) + f"  [full text: preview_errors.txt]")
    return {"objects": len(objs), "previews": n}


class native_output_captured:
    """Collect what native libraries print to the process's stdout/stderr while
    the block runs. The TypeTreeGenerator library prints "Error generating tree
    nodes: ..." for every script object whose layout it can't work out -
    thousands of lines for one game. They are counted and summarised instead.

    One capture file is used for the whole process and never closed: a library
    that looked up its output handle once (as .NET's Console does) keeps
    writing into it, also in later blocks. Each block reads what was added
    since the previous one. On Windows the Win32 standard handles are pointed
    at the file too (WriteFile(GetStdHandle(...)) and other C runtimes, not
    only Python's file descriptors 1 and 2)."""
    _file = None
    _pos = 0

    def __enter__(self):
        import tempfile
        self.text = ""
        self.saved = None
        try:
            sys.stdout.flush(); sys.stderr.flush()
            cls = native_output_captured
            if cls._file is None:
                cls._file = tempfile.TemporaryFile()
            self.saved = [os.dup(1), os.dup(2)]
            os.dup2(cls._file.fileno(), 1)
            os.dup2(cls._file.fileno(), 2)
            self.win = None
            if os.name == "nt":
                import ctypes
                import msvcrt
                k32 = ctypes.WinDLL("kernel32")
                k32.GetStdHandle.restype = ctypes.c_void_p
                k32.SetStdHandle.argtypes = [ctypes.c_ulong, ctypes.c_void_p]
                h = msvcrt.get_osfhandle(cls._file.fileno())
                self.win = (k32, k32.GetStdHandle(ctypes.c_ulong(-11 & 0xFFFFFFFF)),
                            k32.GetStdHandle(ctypes.c_ulong(-12 & 0xFFFFFFFF)))
                k32.SetStdHandle(-11 & 0xFFFFFFFF, h)
                k32.SetStdHandle(-12 & 0xFFFFFFFF, h)
                # other C runtimes loaded by native libraries keep their own
                # descriptor tables: point their 1 and 2 at the file as well
                self.crts = []
                k32.GetModuleHandleW.restype = ctypes.c_void_p
                for name in ("msvcrt", "msvcr120", "msvcr110", "msvcr100", "msvcr90"):
                    if not k32.GetModuleHandleW(name):
                        continue
                    try:
                        crt = ctypes.CDLL(name)
                        crt.fflush.argtypes = [ctypes.c_void_p]
                        crt._open_osfhandle.argtypes = [ctypes.c_void_p, ctypes.c_int]
                        crt.fflush(None)
                        fd = crt._open_osfhandle(h, 0)
                        if fd < 0:
                            continue
                        keep = (crt._dup(1), crt._dup(2))
                        crt._dup2(fd, 1); crt._dup2(fd, 2)
                        self.crts.append((crt, keep, fd))
                    except (OSError, AttributeError):
                        pass
        except (OSError, ValueError, AttributeError):
            self.saved = None
        return self

    def __exit__(self, *exc):
        if self.saved is None:
            return False
        try:
            sys.stdout.flush(); sys.stderr.flush()
        except (OSError, ValueError):
            pass
        for crt, keep, fd in getattr(self, "crts", []):
            crt.fflush(None)
            if keep[0] >= 0:
                crt._dup2(keep[0], 1); crt._close(keep[0])
            if keep[1] >= 0:
                crt._dup2(keep[1], 2); crt._close(keep[1])
        if self.win:
            k32, out_h, err_h = self.win
            k32.SetStdHandle(-11 & 0xFFFFFFFF, out_h)
            k32.SetStdHandle(-12 & 0xFFFFFFFF, err_h)
        os.dup2(self.saved[0], 1)
        os.dup2(self.saved[1], 2)
        os.close(self.saved[0]); os.close(self.saved[1])
        cls = native_output_captured
        f = cls._file
        f.seek(cls._pos)
        data = f.read()
        cls._pos = f.tell()
        self.text = data.decode("utf-8", "replace")
        return False

    def summary(self):
        """{message: count}, for lines starting with "Error ..." (the next line is the reason)"""
        lines = [ln.strip() for ln in self.text.splitlines() if ln.strip()]
        out, i = {}, 0
        while i < len(lines):
            msg = lines[i]
            if msg.endswith(":") and i + 1 < len(lines):
                msg = f"{msg} {lines[i + 1]}"
                i += 1
            out[msg] = out.get(msg, 0) + 1
            i += 1
        return out


def previews(objs, pdir):
    """viewable copies: textures/sprites -> PNG, text -> file, anything with a
    type tree -> JSON. Best effort: failures only mean no preview."""
    os.makedirs(pdir, exist_ok=True)
    n = 0
    for o in objs:
        tname = getattr(o.type, "name", str(o.type))
        try:
            data = name = None
            if tname in ("Texture2D", "Sprite", "TextAsset", "AudioClip", "Mesh"):
                data = o.read()
                name = getattr(data, "m_Name", "")
            else:
                try:
                    name = o.peek_name()
                except Exception:
                    pass
            name = safe(name or f"{o.path_id & 0xFFFFFFFFFFFFFFFF:x}")
            base = os.path.join(pdir, f"{tname}_{name}_{o.path_id & 0xFFFFFFFFFFFFFFFF:x}")
            if tname in ("Texture2D", "Sprite"):
                data.image.save(base + ".png")
            elif tname == "TextAsset":
                s = data.m_Script
                with open(base + ".txt", "wb") as f:
                    f.write(s.encode("utf-8", "surrogateescape") if isinstance(s, str) else bytes(s))
            elif tname == "AudioClip":
                for nm, wav in data.samples.items():
                    with open(base + "_" + safe(nm), "wb") as f:
                        f.write(wav)
            elif tname == "Mesh":
                with open(base + ".obj", "w") as f:
                    f.write(data.export())
            else:
                tree = o.read_typetree()
                with open(base + ".json", "w") as f:
                    json.dump(tree, f, indent=1, default=lambda x: x.hex() if isinstance(x, bytes) else str(x))
            n += 1
        except Exception:
            continue
    return n


# ---- asset bundles -------------------------------------------------------
def cstr(b, o):
    e = b.index(b"\0", o)
    return b[o:e].decode("utf-8", "replace"), e + 1


def split_bundle(src, outdir, log, game_root=None):
    """UnityFS: header, block table (maybe compressed), compressed data
    blocks; the decompressed blocks form one stream holding the bundle's files"""
    size = os.path.getsize(src)
    with open(src, "rb") as f:
        head = f.read(min(size, 4096))
        o = 8
        ver = struct.unpack_from(">I", head, o)[0]
        uver, o = cstr(head, o + 4)
        rev, o = cstr(head, o)
        total, csz, usz, flags = struct.unpack_from(">qIII", head, o)
        o += 20
        if ver >= 7:
            o += -o % 16
        if total != size:
            raise UnitySplitError("bundle size field does not match the file")
        at_end = bool(flags & 0x80)
        info_off = size - csz if at_end else o
        f.seek(info_off)
        cinfo = f.read(csz)
        info = unity_join.decompress(flags, cinfo, usz)
        p = 16
        nblocks = struct.unpack_from(">i", info, p)[0]
        p += 4
        blocks = []
        for _ in range(nblocks):
            u, c, bf = struct.unpack_from(">IIH", info, p)
            blocks.append((u, c, bf))
            p += 10
        nnodes = struct.unpack_from(">i", info, p)[0]
        p += 4
        nodes = []
        for _ in range(nnodes):
            off, nsz, nf = struct.unpack_from(">qqI", info, p)
            path, p = cstr(info, p + 20)
            nodes.append({"path": path, "offset": off, "size": nsz, "flags": nf})
        data_off = o if at_end else o + csz
        if flags & 0x200:
            data_off += -data_off % 16
        # header (and the block table when it is up front) stays as raw bytes
        f.seek(0)
        with open(os.path.join(outdir, "head.bin"), "wb") as g:
            g.write(f.read(data_off))
        tail = None
        if at_end:
            tail = "tail.bin"
            with open(os.path.join(outdir, tail), "wb") as g:
                g.write(cinfo)
        # decompress blocks one by one into the stream file
        os.makedirs(os.path.join(outdir, "blocks"))
        stream_path = os.path.join(outdir, ".stream.tmp")
        brec, codec_guess, stored = [], None, 0
        sh = hashlib.sha256()
        f.seek(data_off)
        with open(stream_path, "wb") as st:
            for k, (u, c, bf) in enumerate(blocks):
                comp = f.read(c)
                raw = unity_join.decompress(bf, comp, u)
                if len(raw) != u:
                    raise UnitySplitError(f"block {k} decompressed to the wrong size")
                st.write(raw)
                sh.update(raw)
                codec, codec_guess = find_codec(bf, raw, comp, codec_guess)
                b = {"u": u, "c": c, "flags": bf, "codec": codec or "stored"}
                if not codec:
                    b["file"] = f"blocks/{k:05d}.bin"
                    with open(os.path.join(outdir, b["file"]), "wb") as g:
                        g.write(comp)
                    stored += 1
                brec.append(b)
    stream_size = sum(b["u"] for b in brec)
    # the bundle's files, split again when they are serialized files
    os.makedirs(os.path.join(outdir, "nodes"))
    pieces, pos, nobj = [], 0, 0
    with open(stream_path, "rb") as st:
        for i, n in sorted(enumerate(nodes), key=lambda x: x[1]["offset"]):
            if n["offset"] < pos:
                raise UnitySplitError("overlapping files inside the bundle")
            if n["offset"] > pos:
                st.seek(pos)
                pieces.append(["gap", st.read(n["offset"] - pos).hex()])
            rel = "nodes/" + safe(n["path"])
            st.seek(n["offset"])
            with open(os.path.join(outdir, rel), "wb") as g:
                left = n["size"]
                while left:
                    b = st.read(min(left, 1 << 22))
                    g.write(b)
                    left -= len(b)
            n["file"] = rel
            if detect(os.path.join(outdir, rel)) == "unity":
                try:
                    r = split(os.path.join(outdir, rel), os.path.join(outdir, rel + ".split"),
                              log=lambda m: None, game_root=game_root)
                    remove_file(os.path.join(outdir, rel), log)
                    del n["file"]
                    n["split"] = rel + ".split"
                    nobj += r["objects"]
                except UnitySplitError:
                    shutil.rmtree(os.path.join(outdir, rel + ".split"), ignore_errors=True)
            pieces.append(["node", i])
            pos = n["offset"] + n["size"]
        if pos < stream_size:
            st.seek(pos)
            pieces.append(["gap", st.read().hex()])
    remove_file(stream_path, log)
    recipe = {"kind": "bundle", "size": size, "sha256": sha256_file(src),
              "header": {"version": ver, "unity_version": uver, "revision": rev},
              "head": "head.bin", "tail": tail, "blocks": brec, "nodes": nodes, "stream": pieces,
              "stream_size": stream_size, "stream_sha256": sh.hexdigest()}
    with open(os.path.join(outdir, "recipe.json"), "w") as f:
        json.dump(recipe, f, indent=0)
    log(f"bundle: {len(nodes)} files, {nobj} objects, {len(blocks)} blocks "
        f"({stored} kept compressed as-is, {codec_guess or 'none'} for the rest)")
    return {"objects": nobj, "files": len(nodes)}


def find_codec(flags, raw, comp, guess):
    """which compressor settings reproduce this block exactly? (codec or None, guess)"""
    c = flags & 0x3F
    if c == 0:
        return "none", guess
    if c not in (2, 3):
        return None, guess          # LZMA: practically never reproducible, keep as-is
    cands = ([guess] if guess else []) + ["lz4"] + [f"lz4hc:{k}" for k in (9, 12, 11, 10, 8, 7, 6, 5, 4, 3, 2, 1)]
    for cd in cands:
        try:
            if unity_join.compress(cd, raw) == comp:
                return cd, cd
        except Exception:
            return None, guess
    return None, guess
