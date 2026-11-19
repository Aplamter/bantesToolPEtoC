"""
scan.py - look at ANY file (Linux ELF, Windows .exe, console ROM, game .pak ...)
and report:
  * an entropy map of the whole file
  * regions that look encrypted / compressed, with a guess at what they are
  * known packer signatures (UPX, etc.)
  * embedded assets (images, audio, archives, ...) - optionally carved out to disk

Pure Python, no dependencies.
"""
import math
import mmap
import os
import struct
import zlib

# --------------------------------------------------------------------------
# entropy
# --------------------------------------------------------------------------

def byte_counts(buf) -> list:
    """histogram of byte values. Big buffers (a memory-mapped file) are
    counted 4 MB at a time, so they are never copied into RAM whole."""
    counts = [0] * 256
    if len(buf) <= 1 << 16:
        for b in bytes(buf):
            counts[b] += 1
        return counts
    for o in range(0, len(buf), 1 << 22):
        chunk = buf[o:o + (1 << 22)]
        for v in range(256):
            counts[v] += chunk.count(bytes((v,)))
    return counts


def shannon(buf: bytes) -> float:
    """bits per byte, 0.0 (all same byte) .. 8.0 (perfectly random)"""
    if not buf:
        return 0.0
    counts = byte_counts(buf)
    n = len(buf)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def chi_square(buf: bytes) -> float:
    """how far the byte histogram is from uniform. Encrypted data is ~255,
    compressed data is usually noticeably higher."""
    n = len(buf)
    if n == 0:
        return 0.0
    exp = n / 256
    counts = byte_counts(buf)
    return sum((c - exp) ** 2 / exp for c in counts)


def entropy_map(data: bytes, block: int = 4096):
    """generator: (offset, size, entropy, chi2) per block"""
    for off in range(0, len(data), block):
        chunk = data[off:off + block]
        yield off, len(chunk), shannon(chunk), chi_square(chunk)


def classify_block(ent: float, chi: float, size: int) -> str:
    if ent < 1.0:
        return "padding/zeros"
    if ent < 6.0:
        return "code/data"
    if ent < 7.2:
        return "dense data (tables, compressed-ish)"
    # high entropy: compressed or encrypted.  For blocks of 4 KiB a truly
    # random block has chi^2 around 255 +- 22.
    expected = 255
    if size >= 1024 and chi < expected + 3 * 22.6:
        return "ENCRYPTED (or very well compressed)"
    return "COMPRESSED"


def high_entropy_regions(data: bytes, block: int = 4096, min_blocks: int = 2):
    """merge consecutive high-entropy blocks into regions"""
    regions = []
    cur = None
    for off, size, ent, chi in entropy_map(data, block):
        hot = ent >= 7.2
        if hot:
            if cur is None:
                cur = [off, off + size, [ent], [chi]]
            else:
                cur[1] = off + size
                cur[2].append(ent)
                cur[3].append(chi)
        elif cur is not None:
            regions.append(cur)
            cur = None
    if cur is not None:
        regions.append(cur)
    out = []
    for start, end, ents, chis in regions:
        if len(ents) < min_blocks and (end - start) < 2 * block:
            continue
        avg_e = sum(ents) / len(ents)
        avg_c = sum(chis) / len(chis)
        out.append({
            "start": start,
            "end": end,
            "entropy": avg_e,
            "chi2": avg_c,
            "kind": classify_block(avg_e, avg_c, block),
        })
    return out


# --------------------------------------------------------------------------
# packers / protectors
# --------------------------------------------------------------------------

PACKER_SIGS = [
    (b"UPX!", "UPX packer (unpack with: upx -d file)"),
    (b"UPX0", "UPX section name"),
    (b"MPRESS1", "MPRESS packer"),
    (b".aspack", "ASPack packer"),
    (b".themida", "Themida protector"),
    (b".vmp0", "VMProtect protector"),
    (b".enigma1", "Enigma protector"),
    (b"PEC2", "PECompact packer"),
    (b".petite", "Petite packer"),
    (b"FSG!", "FSG packer"),
    (b".nsp0", "NsPack packer"),
    (b"Obsidium", "Obsidium protector"),
    (b".denuvo", "Denuvo anti-tamper (DRM)"),
    (b"steam_api", "Steamworks API (may use Steam DRM wrapper)"),
    (b".bind", "possible Steam DRM .bind section"),
]


def find_packers(data: bytes):
    hits = []
    for sig, name in PACKER_SIGS:
        i = data.find(sig)
        if i >= 0:
            hits.append((i, name))
    return hits


# --------------------------------------------------------------------------
# executable sections (ELF / PE) - lets us say "section .text is encrypted"
# --------------------------------------------------------------------------

def sections(data: bytes):
    """returns list of (name, file_offset, size, is_exec) for ELF64/ELF32/PE"""
    out = []
    try:
        if data[:4] == b"\x7fELF":
            is64 = data[4] == 2
            le = "<" if data[5] == 1 else ">"
            if is64:
                shoff, = struct.unpack_from(le + "Q", data, 0x28)
                shentsize, shnum, shstrndx = struct.unpack_from(le + "HHH", data, 0x3A)
            else:
                shoff, = struct.unpack_from(le + "I", data, 0x20)
                shentsize, shnum, shstrndx = struct.unpack_from(le + "HHH", data, 0x2E)
            if shoff == 0 or shnum == 0:
                return out
            def sh(i):
                base = shoff + i * shentsize
                if is64:
                    name, typ, flags, addr, off, size = struct.unpack_from(le + "IIQQQQ", data, base)
                else:
                    name, typ, flags, addr, off, size = struct.unpack_from(le + "IIIIII", data, base)
                return name, typ, flags, off, size
            _, _, _, stroff, _ = sh(shstrndx)
            for i in range(shnum):
                name, typ, flags, off, size = sh(i)
                if typ == 8:  # NOBITS
                    continue
                end = data.find(b"\0", stroff + name)
                nm = data[stroff + name:end].decode(errors="replace")
                out.append((nm, off, size, bool(flags & 4)))
        elif data[:2] == b"MZ":
            pe, = struct.unpack_from("<I", data, 0x3C)
            if data[pe:pe + 4] != b"PE\0\0":
                return out
            nsec, = struct.unpack_from("<H", data, pe + 6)
            optsz, = struct.unpack_from("<H", data, pe + 20)
            sec = pe + 24 + optsz
            for i in range(nsec):
                b = sec + i * 40
                nm = data[b:b + 8].rstrip(b"\0").decode(errors="replace")
                vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, b + 8)
                chars, = struct.unpack_from("<I", data, b + 36)
                out.append((nm, rawoff, rawsize, bool(chars & 0x20000000)))
    except struct.error:
        pass
    return out


# --------------------------------------------------------------------------
# asset carving
# --------------------------------------------------------------------------

def _png_len(d, i):
    j = i + 8
    while j + 12 <= len(d):
        ln, = struct.unpack_from(">I", d, j)
        typ = d[j + 4:j + 8]
        j += 12 + ln
        if typ == b"IEND":
            return j - i
        if ln > 0x7FFFFFFF:
            return None
    return None


def _riff_len(d, i):
    ln, = struct.unpack_from("<I", d, i + 4)
    return ln + 8 if i + ln + 8 <= len(d) else None


def _jpg_len(d, i):
    j = d.find(b"\xff\xd9", i + 2)
    return (j + 2 - i) if j > 0 else None


def _gif_len(d, i):
    j = d.find(b"\x00\x3b", i + 6)
    return (j + 2 - i) if j > 0 else None


def _bmp_len(d, i):
    ln, = struct.unpack_from("<I", d, i + 2)
    rsv, = struct.unpack_from("<I", d, i + 6)
    if rsv != 0 or ln < 26 or i + ln > len(d):
        return None
    return ln


def _ogg_len(d, i):
    j = i
    while d[j:j + 4] == b"OggS" and j + 27 <= len(d):
        nseg = d[j + 26]
        segs = d[j + 27:j + 27 + nseg]
        j += 27 + nseg + sum(segs)
        if d[i + 5] & 4:
            pass
    return j - i if j > i else None


def _dds_len(d, i):
    # DDS: header 128 bytes, we can't easily size the payload; take until the
    # next known magic or 4MB, whichever is first.
    return None


def _zip_len(d, i):
    # find end-of-central-directory after i
    j = d.find(b"PK\x05\x06", i)
    if j < 0:
        return None
    clen, = struct.unpack_from("<H", d, j + 20)
    return j + 22 + clen - i


def _wav_ok(d, i):
    return d[i + 8:i + 12] in (b"WAVE", b"AVI ", b"WEBP")


ASSET_SIGS = [
    # (magic, extension, length_fn or None, extra check)
    (b"\x89PNG\r\n\x1a\n", "png", _png_len, None),
    (b"\xff\xd8\xff", "jpg", _jpg_len, None),
    (b"GIF89a", "gif", _gif_len, None),
    (b"GIF87a", "gif", _gif_len, None),
    (b"RIFF", "riff", _riff_len, _wav_ok),
    (b"OggS\x00\x02", "ogg", _ogg_len, None),
    (b"fLaC", "flac", None, None),
    (b"ID3", "mp3", None, None),
    (b"DDS |", "dds", _dds_len, None),
    (b"BM", "bmp", _bmp_len, None),
    (b"PK\x03\x04", "zip", _zip_len, None),
    (b"7z\xbc\xaf\x27\x1c", "7z", None, None),
    (b"\x1f\x8b\x08", "gz", None, None),
    (b"glTF", "glb", lambda d, i: struct.unpack_from("<I", d, i + 8)[0], None),
    (b"FSB5", "fsb", None, None),                 # FMOD sound bank
    (b"BKHD", "bnk", None, None),                 # Wwise sound bank
    (b"UnityFS", "unity3d", None, None),          # Unity asset bundle
    (b"\xc1\x83\x2a\x9e", "uasset", None, None),  # Unreal package
    (b"GVAS", "sav", None, None),                 # Unreal save
    (b"OTTO", "otf", None, None),
    (b"\x00\x01\x00\x00\x00", "ttf", None, None),
    (b"MThd", "mid", None, None),
    (b"IMPM", "it", None, None),                  # Impulse Tracker module
    (b"Extended Module:", "xm", None, None),
    (b"SQLite format 3\x00", "sqlite", None, None),
    (b"Vorbis", "vorbis_hdr", None, None),
]

RIFF_EXT = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}


def find_assets(data: bytes, max_unknown_len: int = 1 << 20):
    found = []
    taken = []  # (start,end) to avoid nested duplicates (e.g. png inside zip)

    def inside(i):
        for s, e in taken:
            if s <= i < e:
                return True
        return False

    for magic, ext, lfn, check in ASSET_SIGS:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            start = i + 1
            if inside(i):
                continue
            if check and not check(data, i):
                continue
            if ext in ("ttf", "otf"):
                # sane table count + a printable 4-letter table tag
                nt = int.from_bytes(data[i + 4:i + 6], "big") if i + 16 <= len(data) else 0
                tag = data[i + 12:i + 16]
                if not (4 <= nt <= 64 and all(48 <= c <= 122 for c in tag)):
                    continue
            if ext == "mp3" and not (i + 10 <= len(data) and data[i + 3] in (2, 3, 4) and data[i + 5] & 0x0F == 0):
                continue
            if ext == "gz" and not (i + 10 <= len(data) and data[i + 3] < 0x20 and data[i + 9] in (0, 3, 7, 11, 255)):
                continue
            if ext == "mid" and data[i + 4:i + 8] != b"\0\0\0\x06":
                continue
            if ext == "bmp" and _bmp_len(data, i) is None:
                continue
            ln = None
            if lfn:
                try:
                    ln = lfn(data, i)
                except (struct.error, IndexError):
                    ln = None
            exact = ln is not None and ln > 0
            if not exact:
                if ext in ("png", "jpg", "gif", "riff", "zip", "bmp", "glb"):
                    continue  # strong formats: if we can't size it, it's a false hit
                ln = min(max_unknown_len, len(data) - i)
            e2 = RIFF_EXT.get(data[i + 8:i + 12], ext) if ext == "riff" else ext
            found.append({"offset": i, "length": ln, "ext": e2, "exact_size": exact})
            if exact:
                taken.append((i, i + ln))
    # zlib streams (very common in game archives)
    i = -1
    while True:
        i = data.find(b"\x78", i + 1, len(data) - 2)
        if i < 0:
            break
        if data[i + 1] in (0x01, 0x5E, 0x9C, 0xDA) and not inside(i):
            if (data[i] << 8 | data[i + 1]) % 31:
                continue
            try:
                dobj = zlib.decompressobj()
                out = dobj.decompress(data[i:i + (1 << 22)], 1 << 24)
                if len(out) >= 64 and dobj.eof:
                    used = min(1 << 22, len(data) - i) - len(dobj.unused_data)
                    found.append({"offset": i, "length": used, "ext": "zlib",
                                  "exact_size": True, "unpacked": len(out)})
                    taken.append((i, i + used))
            except zlib.error:
                pass
    found.sort(key=lambda a: a["offset"])
    return found


def carve(data: bytes, assets, outdir: str):
    os.makedirs(outdir, exist_ok=True)
    paths = []
    for n, a in enumerate(assets):
        blob = data[a["offset"]:a["offset"] + a["length"]]
        ext = a["ext"]
        if ext == "zlib":
            try:
                blob = zlib.decompress(blob)
                ext = guess_ext(blob) or "bin"
            except zlib.error:
                ext = "zlib"
        p = os.path.join(outdir, f"asset_{n:04d}_{a['offset']:08x}.{ext}")
        with open(p, "wb") as f:
            f.write(blob)
        paths.append(p)
    return paths


def guess_ext(blob: bytes):
    for magic, ext, _, _ in ASSET_SIGS:
        if blob.startswith(magic):
            return RIFF_EXT.get(blob[8:12], ext) if ext == "riff" else ext
    if blob[:4] == b"\x7fELF":
        return "elf"
    if blob[:2] == b"MZ":
        return "exe"
    if all(32 <= c < 127 or c in (9, 10, 13) for c in blob[:256]):
        return "txt"
    return None


# --------------------------------------------------------------------------
# what kind of program is this? -> which tool should handle it
# --------------------------------------------------------------------------

def identify(data: bytes):
    """returns {'summary': str, 'route': str, 'dotnet': bool, ...}"""
    r = {"dotnet": False}
    def has(*xs):
        return any(data.find(x) >= 0 for x in xs)   # works on bytes and mmap
    if data[:4] == b"\x7fELF":
        arch = {62: "x86-64", 3: "x86", 183: "ARM64", 40: "ARM", 8: "MIPS", 20: "PowerPC"}.get(
            struct.unpack_from("<H", data, 18)[0], "unknown CPU")
        dyn = b"/lib64/ld-linux" in data[:4096] or b"/lib/ld-" in data[:4096]
        r["summary"] = f"Linux ELF, {arch}, {'dynamically' if dyn else 'statically'} linked"
        r["route"] = "lift (native machine code)"
    elif data[:2] == b"MZ" and len(data) > 0x40:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            r["summary"], r["route"] = "16-bit DOS program", "DOSBox / a DOS decompiler, not this tool"
            return r
        mach = struct.unpack_from("<H", data, pe + 4)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        dd = opt + (112 if magic == 0x20B else 96)
        clr = struct.unpack_from("<I", data, dd + 14 * 8)[0] if len(data) > dd + 120 else 0
        arch = {0x8664: "x64", 0x14C: "x86 (32-bit)", 0xAA64: "ARM64"}.get(mach, hex(mach))
        sub = struct.unpack_from("<H", data, opt + 68)[0]
        kind = {2: "GUI", 3: "console"}.get(sub, f"subsystem {sub}")
        if clr:
            r["dotnet"] = True
            r["summary"] = f"Windows .NET assembly ({arch}, {kind}): contains IL bytecode, not CPU code"
            r["route"] = "dotnet (IL -> C# with ILSpy); the recompiler is the wrong tool"
            if has(b"UnityEngine"):
                r["summary"] += "; Unity game scripts (Mono)"
        elif has(b"il2cpp", b"IL2CPP") or has(b"global-metadata.dat"):
            r["summary"] = f"Windows {arch} {kind} program built with Unity IL2CPP (native code)"
            r["route"] = "lift GameAssembly.dll; names can be recovered from global-metadata.dat (Il2CppDumper)"
        elif has(b"System.Private.CoreLib") and has(b"__managed__Main", b"RhpNewFast", b"S_P_CoreLib"):
            r["summary"] = f"Windows {arch} {kind} program compiled with .NET NativeAOT (native code)"
            r["route"] = "lift (native machine code)"
        elif has(b"PyInstaller", b"_MEIPASS", b"pyi-windows-manifest"):
            r["summary"] = f"Windows {arch} PyInstaller bundle: a Python interpreter + .pyc files"
            r["route"] = "extract with pyinstxtractor, decompile .pyc (pycdc); don't recompile"
        elif has(b"UnityPlayer.dll") and len(data) < 2_000_000:
            r["summary"] = f"Windows {arch} Unity launcher stub"
            r["route"] = "the game code is in GameAssembly.dll (IL2CPP) or Managed/*.dll (Mono)"
        else:
            r["summary"] = f"Windows PE, {arch}, {kind}"
            r["route"] = "lift (native machine code)" if mach == 0x8664 else \
                "lift (native machine code; rebuilt as a 32-bit program, needs i686-w64-mingw32-gcc)" \
                if mach == 0x14C else "lift works, but only x64 and 32-bit x86 have a runtime so far"
        if has(b"UnityPlayer", b"UnityEngine"):
            r["engine"] = "Unity"
        elif has(b"UE4", b"UnrealEngine", b"/Script/Engine"):
            r["engine"] = "Unreal"
        elif has(b"Godot Engine", b"GDScript"):
            r["engine"] = "Godot"
    elif data[:4] == b"\xca\xfe\xba\xbe" or data[:2] == b"PK" and b"META-INF/MANIFEST.MF" in data[:65536]:
        r["summary"], r["route"] = "Java class/JAR", "a Java decompiler (CFR, Vineflower); not this tool"
    elif data[:4] in (b"\x80\x37\x12\x40", b"\x37\x80\x40\x12"):
        r["summary"], r["route"] = "Nintendo 64 ROM (MIPS)", "lift works for MIPS; N64 runtime not written yet (see N64Recomp)"
    else:
        r["summary"], r["route"] = "not an executable (data / archive / asset file)", "scan --extract"
    return r


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def bar(ent):
    n = int(round(ent / 8 * 20))
    return "#" * n + "." * (20 - n)


def report(path: str, extract_dir: str = None, block: int = 4096, verbose=False):
    f = open(path, "rb")
    try:
        size = os.fstat(f.fileno()).st_size
        # memory-mapped: the OS reads the file from disk as it's scanned
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) if size else b""
        try:
            return _report(path, data, extract_dir, block, verbose)
        finally:
            if size:
                data.close()
    finally:
        f.close()


def _report(path, data, extract_dir, block, verbose):
    lines = []
    w = lines.append
    w(f"== scan: {path}  ({len(data)} bytes)")
    w(f"   whole-file entropy: {shannon(data):.3f} bits/byte")
    kind = identify(data)
    apk_lines = []
    if data[:2] == b"PK":
        from . import apk
        if apk.is_apk(path):
            r = apk.info(path)
            kind = dict(kind, summary="Android APK", engine="Unity (" + r["unity"]["backend"] + ")" if r["unity"] else None,
                        route=("recomp.py game APK -o PROJECT  (Unity: assets split, native code lifted for analysis; "
                               "build_game.py writes a signed APK)" if r["unity"] else
                               "recomp.py lift APK -o PROJECT  (native code lifted for analysis; "
                               "build_game.py writes a signed APK)"))
            apk_lines = ["   " + ln.strip() for ln in apk.summary_text(r).splitlines()[1:]]
        elif apk.is_split_container(path):
            kind = dict(kind, summary="split APK container (.xapk/.apks/.apkm)",
                        route="extract it and pass the base APK (the one with the app's code) to recomp")
    w(f"   type:  {kind['summary']}")
    if kind.get("engine"):
        w(f"   engine: {kind['engine']}")
    w(f"   route: {kind['route']}")
    lines.extend(apk_lines)

    secs = sections(data)
    if secs:
        w("\n-- sections")
        for nm, off, size, ex in secs:
            if size == 0 or off + size > len(data):
                continue
            ent = shannon(data[off:off + size])
            flag = ""
            if ex and ent > 7.2:
                flag = "  <-- EXECUTABLE BUT HIGH ENTROPY: packed/encrypted code"
            elif ent > 7.5:
                flag = "  <-- high entropy"
            w(f"   {nm:<20} off={off:#010x} size={size:#9x} exec={'Y' if ex else 'n'} "
              f"entropy={ent:.2f} [{bar(ent)}]{flag}")

    pk = find_packers(data)
    if pk:
        w("\n-- packer / protector signatures")
        for off, name in pk:
            w(f"   {off:#010x}  {name}")

    regs = high_entropy_regions(data, block)
    w("\n-- high-entropy regions (possible encryption / compression)")
    if not regs:
        w("   none - nothing looks encrypted")
    for r in regs:
        w(f"   {r['start']:#010x}-{r['end']:#010x} ({r['end'] - r['start']:>9} bytes) "
          f"entropy={r['entropy']:.3f} chi2={r['chi2']:.0f}  => {r['kind']}")
    if regs:
        w("   how to get the plaintext: if the program decrypts this itself at runtime,")
        w("   the key is inside it -> run/emulate it and dump memory after the decrypt")
        w("   routine (find it by xrefs to the region's address). If no code references")
        w("   the region, the key probably comes from outside (server/hardware).")

    if verbose:
        w("\n-- entropy map")
        for off, size, ent, chi in entropy_map(data, block):
            w(f"   {off:#010x} {ent:5.2f} [{bar(ent)}] {classify_block(ent, chi, size)}")

    assets = find_assets(data)
    w(f"\n-- embedded assets: {len(assets)} found")
    for a in assets[:200]:
        extra = f" unpacks to {a['unpacked']} bytes" if "unpacked" in a else ""
        sz = a["length"] if a["exact_size"] else f"~{a['length']} (size unknown)"
        w(f"   {a['offset']:#010x}  {a['ext']:<8} size={sz}{extra}")
    if len(assets) > 200:
        w(f"   ... and {len(assets) - 200} more")
    if extract_dir and assets:
        paths = carve(data, assets, extract_dir)
        w(f"   extracted {len(paths)} files to {extract_dir}")
    return "\n".join(lines), {"regions": regs, "assets": assets, "packers": pk}


def text_runs(blob: bytes, min_len: int = 256):
    """long runs of printable text (level files, scripts, configs, dialogue)"""
    out, start = [], None
    for i, c in enumerate(blob + b"\0"):
        ok = 32 <= c < 127 or c in (9, 10, 13)
        if ok and start is None:
            start = i
        elif not ok and start is not None:
            if i - start >= min_len:
                out.append({"offset": start, "length": i - start, "ext": "txt", "exact_size": True})
            start = None
    return out
