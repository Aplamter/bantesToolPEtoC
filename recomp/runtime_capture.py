"""Windows runtime code snapshotting for executables the user launches.

This module does not inject code, alter page protections, bypass anti-tamper
checks, or change the target process. It reads executable pages from a process
that the user launched normally, overlays loaded PE executable sections onto
copies of their on-disk images, and records private executable regions (for
example JIT/dynamic code) as raw evidence for later analysis.
"""
from __future__ import annotations
import bisect
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time

PAGE_EXECUTE = {0x10, 0x20, 0x40, 0x80}
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03


PAGE = 0x1000
MAX_CHANGED_RANGES = 256


def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
def _u64(b, o): return struct.unpack_from("<Q", b, o)[0]


def pe_layout(path):
    """Parse what runtime capture needs from a PE file: preferred ImageBase,
    sections, base relocation sites and import-address-table ranges.
    Pure Python and unit-testable."""
    with open(path, "rb") as f:
        d = f.read()
    if len(d) < 0x40 or d[:2] != b"MZ":
        raise ValueError(f"not a PE file: {path}")
    peoff = _u32(d, 0x3C)
    if peoff + 24 > len(d) or d[peoff:peoff + 4] != b"PE\0\0":
        raise ValueError(f"invalid PE header: {path}")
    nsects, opt_size = _u16(d, peoff + 6), _u16(d, peoff + 20)
    if not 0 < nsects <= 96 or opt_size > 4096:
        raise ValueError(f"implausible PE section table: {path}")
    opt = peoff + 24
    if opt + opt_size > len(d) or opt_size < 2:
        raise ValueError(f"truncated PE optional header: {path}")
    magic = _u16(d, opt)
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"unsupported PE optional header: {path}")
    pe64 = magic == 0x20B
    if pe64:
        imagebase = _u64(d, opt + 24) if opt_size >= 32 else 0
        ddir, ndirs = opt + 112, _u32(d, opt + 108) if opt_size >= 112 else 0
    else:
        imagebase = _u32(d, opt + 28) if opt_size >= 32 else 0
        ddir, ndirs = opt + 96, _u32(d, opt + 92) if opt_size >= 96 else 0
    ndirs = max(0, min(ndirs, 16, (opt + opt_size - ddir) // 8))
    dirs = [(_u32(d, ddir + 8 * i), _u32(d, ddir + 8 * i + 4)) for i in range(ndirs)]
    dirs += [(0, 0)] * (16 - len(dirs))
    tab = opt + opt_size
    if tab + nsects * 40 > len(d):
        raise ValueError(f"truncated PE section table: {path}")
    sections = []
    for i in range(nsects):
        s = d[tab + i * 40:tab + (i + 1) * 40]
        name = s[:8].split(b"\0", 1)[0].decode("ascii", "replace")
        vsize, rva, rawsize, rawoff = struct.unpack_from("<IIII", s, 8)
        sections.append({"name": name, "virtual_size": vsize, "rva": rva,
                         "raw_size": rawsize, "raw_offset": rawoff,
                         "characteristics": _u32(s, 36)})

    def rva2off(rva):
        for s in sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["rva"] <= rva < s["rva"] + span:
                k = rva - s["rva"]
                return s["raw_offset"] + k if k < s["raw_size"] else None
        return None

    # base relocations: (rva, width). Only the two types Windows uses for
    # x86/x64 images matter here; anything else is recorded, not guessed.
    relocs, odd = [], {}
    rrva, rsz = dirs[5]
    o = rva2off(rrva) if rrva else None
    if o is not None:
        end = min(o + rsz, len(d))
        while o + 8 <= end:
            page, size = _u32(d, o), _u32(d, o + 4)
            if size < 8 or o + size > len(d):
                break
            for k in range((size - 8) // 2):
                e = _u16(d, o + 8 + 2 * k)
                typ = e >> 12
                if typ == 0:
                    continue
                if typ == 10:
                    relocs.append((page + (e & 0xFFF), 8))
                elif typ == 3:
                    relocs.append((page + (e & 0xFFF), 4))
                else:
                    odd[typ] = odd.get(typ, 0) + 1
            o += size

    # import address tables: the loader writes resolved API addresses there,
    # so those bytes always differ from disk. Some linkers put the IAT inside
    # an executable section; those bytes must not count as "changed code".
    iat = []
    tsz = 8 if pe64 else 4
    irva, _ = dirs[1]
    o = rva2off(irva) if irva else None
    while o is not None and o + 20 <= len(d):
        name_rva, ft = _u32(d, o + 12), _u32(d, o + 16)
        if not name_rva and not ft:
            break
        if ft:
            n, t = 0, rva2off(ft)
            while t is not None and t + tsz <= len(d) and n < 65536:
                if not (_u64(d, t) if pe64 else _u32(d, t)):
                    break
                n += 1
                t += tsz
            if n:
                iat.append((ft, n * tsz))
        o += 20
    # the IAT directory (12) covers all of them when present
    if dirs[12][0] and dirs[12][1]:
        iat.append(dirs[12])
    return {"imagebase": imagebase, "pe64": pe64, "sections": sections,
            "relocs": sorted(relocs), "unsupported_reloc_types": odd, "iat": iat}


def pe_executable_sections(path):
    """Executable sections that have file bytes (the ones an overlay can patch)."""
    return [s for s in pe_layout(path)["sections"]
            if s["characteristics"] & 0x20000000 and s["raw_size"] and s["raw_offset"]]


def read_chunked(read_memory, address, size, page=PAGE):
    """Read [address, address+size) through read_memory(address, size).
    Tries one read first; if it fails or is short, retries page by page so
    one unreadable (guard/no-access) page does not discard a whole section.
    Returns (bytes or None per page-aligned piece list, unreadable list):
    pieces is a list of (offset, bytes) for readable spans."""
    data = read_memory(address, size)
    if data is not None and len(data) == size:
        return [(0, bytes(data))], []
    pieces, bad = [], []
    off = 0
    while off < size:
        step = min(size - off, page - ((address + off) % page))
        chunk = read_memory(address + off, step)
        if chunk is not None and len(chunk) == step:
            if pieces and pieces[-1][0] + len(pieces[-1][1]) == off:
                pieces[-1] = (pieces[-1][0], pieces[-1][1] + bytes(chunk))
            else:
                pieces.append((off, bytes(chunk)))
        else:
            bad.append((off, step))
        off += step
    return pieces, bad


def _diff_offsets(a, b, block=4096):
    """offsets where a and b differ; compares whole blocks first so large
    unchanged sections cost one slice comparison per block"""
    if a == b:
        return []
    out = []
    for o in range(0, len(a), block):
        x, y = a[o:o + block], b[o:o + block]
        if x != y:
            out.extend(o + i for i in range(len(x)) if x[i] != y[i])
    return out


def _coalesce(diffs, gap=16, cap=MAX_CHANGED_RANGES):
    out = []
    for i in diffs:
        if out and i - out[-1][1] <= gap:
            out[-1][1] = i + 1
        elif len(out) < cap:
            out.append([i, i + 1])
        else:
            return out, True
    return out, False


def overlay_pe_sections(path, base, read_memory, out_path, layout=None):
    """Patch loaded executable section bytes into a copy of the original PE.

    Live bytes are first normalised back to the file's preferred ImageBase:
    when Windows loads a module somewhere else (ASLR), every relocated
    absolute address in its code differs from the file by the load delta.
    Without undoing that, every relocated module looks "changed", and the
    overlay would contain addresses for the wrong base (the lifter maps the
    image at the ImageBase in its header). IAT slots inside executable
    sections are kept at their disk bytes for the same reason. What is left
    after normalisation is a real candidate runtime modification."""
    lay = layout or pe_layout(path)
    ib = lay["imagebase"]
    width_mask = {4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
    delta = (base - ib) & 0xFFFFFFFFFFFFFFFF
    relocs = lay["relocs"]
    # plain read/write (not shutil.copy2: it needs CopyFile2, which Wine lacks)
    with open(path, "rb") as f_in, open(out_path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out, 1 << 20)
    changes = []
    with open(out_path, "r+b") as dst, open(path, "rb") as src:
        for s in lay["sections"]:
            if not (s["characteristics"] & 0x20000000 and s["raw_size"] and s["raw_offset"]):
                continue
            n = min(s["raw_size"], s["virtual_size"] or s["raw_size"])
            if n <= 0:
                continue
            src.seek(s["raw_offset"])
            disk = src.read(n)
            n = len(disk)
            pieces, bad = read_chunked(read_memory, base + s["rva"], n)
            if not pieces:
                changes.append({"section": s["name"], "rva": hex(s["rva"]), "status": "read_failed",
                                "bytes_changed": None, "unreadable_bytes": n})
                continue
            live = bytearray(disk)           # unreadable pages keep their disk bytes
            readable = bytearray(n)
            for off, chunk in pieces:
                live[off:off + len(chunk)] = chunk
                readable[off:off + len(chunk)] = b"\1" * len(chunk)
            # undo relocations inside this section
            normalized = 0
            if delta:
                lo, hi = s["rva"], s["rva"] + n
                k = bisect.bisect_left(relocs, (lo, 0))
                while k < len(relocs) and relocs[k][0] < hi:
                    rva, w = relocs[k]
                    k += 1
                    at = rva - lo
                    if at + w > n or not readable[at]:
                        continue
                    fmt = "<Q" if w == 8 else "<I"
                    v = struct.unpack_from(fmt, live, at)[0]
                    struct.pack_into(fmt, live, at, (v - delta) & width_mask[w])
                    normalized += 1
            # import address table slots inside the section
            iat_masked = 0
            for irva, isz in lay["iat"]:
                a, b = max(irva, s["rva"]), min(irva + isz, s["rva"] + n)
                if a < b:
                    live[a - s["rva"]:b - s["rva"]] = disk[a - s["rva"]:b - s["rva"]]
                    iat_masked += b - a
            diffs = _diff_offsets(disk, live)
            ranges, more = _coalesce(diffs)
            dst.seek(s["raw_offset"])
            dst.write(live)
            unreadable = sum(sz for _, sz in bad)
            changes.append({"section": s["name"], "rva": hex(s["rva"]),
                            "status": "partial" if bad else "captured",
                            "bytes_compared": n - unreadable, "bytes_changed": len(diffs),
                            "unreadable_bytes": unreadable,
                            "relocations_normalized": normalized,
                            "iat_bytes_masked": iat_masked,
                            "changed_ranges": [[hex(s["rva"] + a), hex(s["rva"] + b)] for a, b in ranges],
                            "changed_ranges_truncated": more,
                            "disk_sha256": hashlib.sha256(disk).hexdigest(),
                            "memory_sha256": hashlib.sha256(bytes(live)).hexdigest()})
    return changes


def subtract_ranges(lo, hi, covered):
    """[lo, hi) minus the union of covered [a, b) ranges -> list of [a, b)."""
    out, cur = [], lo
    for a, b in sorted(covered):
        if b <= cur or a >= hi:
            continue
        if a > cur:
            out.append((cur, a))
        cur = max(cur, b)
        if cur >= hi:
            break
    if cur < hi:
        out.append((cur, hi))
    return out


def _windows_api():
    if os.name != "nt":
        raise RuntimeError("runtime memory capture is supported on Windows only")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    HANDLE = ctypes.c_void_p
    SIZE_T = ctypes.c_size_t

    class MODULEINFO(ctypes.Structure):
        _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", ctypes.c_ulong),
                    ("EntryPoint", ctypes.c_void_p)]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong), ("PartitionId", ctypes.c_ushort),
                    ("RegionSize", SIZE_T), ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong)]

    k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    k32.OpenProcess.restype = HANDLE
    k32.CloseHandle.argtypes = [HANDLE]
    k32.ReadProcessMemory.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_void_p, SIZE_T,
                                      ctypes.POINTER(SIZE_T)]
    k32.ReadProcessMemory.restype = ctypes.c_int
    k32.VirtualQueryEx.argtypes = [HANDLE, ctypes.c_void_p,
                                   ctypes.POINTER(MEMORY_BASIC_INFORMATION), SIZE_T]
    k32.VirtualQueryEx.restype = SIZE_T
    k32.GetSystemInfo.argtypes = [ctypes.c_void_p]
    k32.GetCurrentProcess.restype = HANDLE
    k32.IsWow64Process.argtypes = [HANDLE, ctypes.POINTER(ctypes.c_int)]
    k32.IsWow64Process.restype = ctypes.c_int
    psapi.EnumProcessModulesEx.argtypes = [HANDLE, ctypes.POINTER(HANDLE), ctypes.c_ulong,
                                           ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]
    psapi.EnumProcessModulesEx.restype = ctypes.c_int
    psapi.GetModuleFileNameExW.argtypes = [HANDLE, HANDLE, ctypes.c_wchar_p, ctypes.c_ulong]
    psapi.GetModuleFileNameExW.restype = ctypes.c_ulong
    psapi.GetModuleInformation.argtypes = [HANDLE, HANDLE, ctypes.POINTER(MODULEINFO),
                                           ctypes.c_ulong]
    psapi.GetModuleInformation.restype = ctypes.c_int
    return k32, psapi, MODULEINFO, MEMORY_BASIC_INFORMATION


def _read_process(k32, handle, address, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got))
    if not ok and got.value == 0:
        return None
    return buf.raw[:got.value]


def _modules(psapi, handle, module_info_type):
    arr = (ctypes.c_void_p * 4096)()
    needed = ctypes.c_ulong()
    if not psapi.EnumProcessModulesEx(handle, arr, ctypes.sizeof(arr), ctypes.byref(needed), LIST_MODULES_ALL):
        raise ctypes.WinError(ctypes.get_last_error())
    count = min(needed.value // ctypes.sizeof(ctypes.c_void_p), len(arr))
    out = []
    for i in range(count):
        hmod = arr[i]
        namebuf = ctypes.create_unicode_buffer(32768)
        n = psapi.GetModuleFileNameExW(handle, hmod, namebuf, len(namebuf))
        info = module_info_type()
        if not n or not psapi.GetModuleInformation(handle, hmod, ctypes.byref(info), ctypes.sizeof(info)):
            continue
        out.append({"base": int(info.lpBaseOfDll or 0), "size": int(info.SizeOfImage),
                    "path": namebuf.value})
    return out


def _is_wow64(k32, handle):
    flag = ctypes.c_int(0)
    if not k32.IsWow64Process(handle, ctypes.byref(flag)):
        return None
    return bool(flag.value)


def _check_bitness(k32, handle):
    """A 32-bit Python can't enumerate or read a 64-bit process: fail with a
    clear message instead of an empty or partial report."""
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        return
    me = _is_wow64(k32, k32.GetCurrentProcess())
    target = _is_wow64(k32, handle)
    if me and target is False:
        raise RuntimeError("the game is a 64-bit process; run recomp with 64-bit Python for runtime capture")


def _in_root(path, root):
    try:
        return os.path.normcase(os.path.commonpath([str(path), str(root)])) == os.path.normcase(str(root))
    except ValueError:
        return False


def _save_region(out_dir, name, data, seen, entry):
    """write a raw region unless an identical one was already saved by an
    earlier snapshot (seen: sha256 -> file); fills entry in place"""
    h = hashlib.sha256(data).hexdigest()
    entry["sha256"] = h
    if seen is not None and h in seen:
        entry["file"] = seen[h]
        entry["same_bytes_saved_as"] = seen[h]
        return 0
    out_dir.mkdir(exist_ok=True)
    fn = out_dir / name
    fn.write_bytes(data)
    entry["file"] = str(fn)
    if seen is not None:
        seen[h] = str(fn)
    return len(data)


def capture_pid(pid, out_dir, allowed_root=None, max_exec_mb=128, seen_regions=None):
    """Snapshot executable PE sections and private executable pages of a PID.

    seen_regions: dict shared between snapshots of one run (sha256 -> file);
    a region identical to an earlier snapshot's is referenced, not re-saved."""
    k32, psapi, MODULEINFO, MBI = _windows_api()
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    allowed = Path(allowed_root).resolve() if allowed_root else None
    report = {"schema": 2, "pid": int(pid), "platform": "windows",
              "modules": [], "executable_regions": [],
              "notes": ["Read-only snapshot; no injection or page-protection changes.",
                        "Module overlays are normalised to each file's preferred ImageBase "
                        "(relocations undone, IAT slots kept at disk bytes) before comparison.",
                        "A changed executable section is a candidate runtime image, not proof of decrypted code."]}
    reader = lambda address, size: _read_process(k32, handle, address, size)
    try:
        _check_bitness(k32, handle)
        wow = _is_wow64(k32, handle)
        report["process_bits"] = 32 if (wow and ctypes.sizeof(ctypes.c_void_p) == 8) or \
            ctypes.sizeof(ctypes.c_void_p) == 4 else 64
        mods = _modules(psapi, handle, MODULEINFO)
        snap_modules = root / "modules"
        snap_modules.mkdir(exist_ok=True)
        module_by_base = {}
        covered = []              # absolute [a, b) already saved through an overlay
        for idx, mod in enumerate(mods):
            try:
                path = Path(mod["path"]).resolve()
                if allowed and not _in_root(path, allowed):
                    continue
                module_by_base[mod["base"]] = str(path)
                lay = pe_layout(str(path))
                if not any(x["characteristics"] & 0x20000000 for x in lay["sections"]):
                    continue
                safe = re_safe(path.name)
                overlay = snap_modules / f"{idx:04d}_{mod['base']:x}_{safe}"
                changes = overlay_pe_sections(str(path), mod["base"], reader, str(overlay), layout=lay)
                vs = {x["rva"]: x["virtual_size"] for x in lay["sections"]}
                for c in changes:
                    if c["status"] in ("captured", "partial"):
                        rva = int(c["rva"], 16)
                        a = mod["base"] + rva
                        n = c["bytes_compared"] + c["unreadable_bytes"]
                        # the file bytes cover the whole section: the rest of its
                        # last page is the loader's zero fill, nothing to save
                        end = a + n
                        if n >= vs.get(rva, n):
                            end = a + ((max(n, vs.get(rva, n)) + PAGE - 1) & ~(PAGE - 1))
                        covered.append((a, end))
                report["modules"].append({"path": str(path), "base": hex(mod["base"]),
                    "preferred_base": hex(lay["imagebase"]), "size": mod["size"],
                    "overlay": str(overlay), "sections": changes,
                    "unsupported_reloc_types": lay["unsupported_reloc_types"],
                    "changed_executable_bytes": sum(x.get("bytes_changed") or 0 for x in changes)})
            except (OSError, ValueError, ctypes.ArgumentError) as exc:
                report["modules"].append({"path": mod["path"], "base": hex(mod["base"]),
                                          "status": "skipped", "reason": str(exc)})

        # Executable MEM_PRIVATE pages (often JIT/dynamic code), plus
        # executable MEM_IMAGE pages of game modules that no overlay covers
        # (e.g. a section with no file bytes that is filled at run time).
        # Bounded; never changes memory.
        class SYSTEM_INFO(ctypes.Structure):
            _fields_ = [("wProcessorArchitecture", ctypes.c_ushort), ("wReserved", ctypes.c_ushort),
                ("dwPageSize", ctypes.c_ulong), ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p), ("dwActiveProcessorMask", ctypes.c_void_p),
                ("dwNumberOfProcessors", ctypes.c_ulong), ("dwProcessorType", ctypes.c_ulong),
                ("dwAllocationGranularity", ctypes.c_ulong), ("wProcessorLevel", ctypes.c_ushort),
                ("wProcessorRevision", ctypes.c_ushort)]
        si = SYSTEM_INFO(); k32.GetSystemInfo(ctypes.byref(si))
        address = int(si.lpMinimumApplicationAddress or 0)
        maximum = int(si.lpMaximumApplicationAddress or 0)
        cap = max(1, int(max_exec_mb)) * 1024 * 1024
        used = 0
        truncated = False
        private_dir = root / "private_exec"
        while address < maximum:
            mbi = MBI()
            got = k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not got:
                break             # past the last region of the process
            base = int(mbi.BaseAddress or address)
            size = int(mbi.RegionSize or 0)
            if size <= 0:
                break
            protect = int(mbi.Protect) & 0xFF
            mem_type = int(mbi.Type)
            alloc_base = int(mbi.AllocationBase or 0)
            if (int(mbi.State) == MEM_COMMIT and not int(mbi.Protect) & 0x100 and protect in PAGE_EXECUTE):
                if mem_type == MEM_PRIVATE:
                    spans, kind = [(base, base + size)], "private_dynamic_or_jit"
                elif mem_type == MEM_IMAGE and alloc_base in module_by_base:
                    spans, kind = subtract_ranges(base, base + size, covered), "game_module_exec_page_not_in_overlay"
                else:
                    spans = []
                for a, b in spans:
                    if used >= cap:
                        truncated = True
                        break
                    take = min(b - a, cap - used)
                    truncated |= take < b - a
                    pieces, bad = read_chunked(reader, a, take)
                    for off, data in pieces:
                        at = a + off
                        if not data.strip(b"\0"):
                            report["zero_bytes_skipped"] = report.get("zero_bytes_skipped", 0) + len(data)
                            continue
                        entry = {"base": hex(at), "region_base": hex(base), "region_size": size,
                                 "captured_size": len(data), "memory_type":
                                 "MEM_PRIVATE" if mem_type == MEM_PRIVATE else "MEM_IMAGE",
                                 "candidate_kind": kind, "allocation_base": hex(alloc_base),
                                 "protect": hex(int(mbi.Protect))}
                        if mem_type == MEM_IMAGE:
                            entry["module"] = module_by_base[alloc_base]
                            entry["module_rva"] = hex(at - alloc_base)
                        used += _save_region(private_dir, f"region_{at:x}.bin", data, seen_regions, entry)
                        report["executable_regions"].append(entry)
                    if bad:
                        report["executable_regions"].append({"base": hex(a), "status": "partly_unreadable",
                            "unreadable_bytes": sum(x for _, x in bad)})
            address = base + size
        report["executable_capture_bytes"] = used
        report["executable_capture_truncated"] = truncated
        if truncated:
            report["notes"].append(f"executable memory cap of {max_exec_mb} MB reached; raise --runtime-max-exec-mb")
    finally:
        k32.CloseHandle(handle)
    (root / "runtime_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def re_safe(name):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:120] or "module.bin"


def diff_reports(prev, cur):
    """What changed between two snapshots of the same process: executable
    regions that appeared, disappeared or changed bytes, and module sections
    whose live bytes changed."""
    def regions(r):
        return {e["base"]: e for e in r.get("executable_regions", []) if "sha256" in e}

    def sections(r):
        out = {}
        for m in r.get("modules", []):
            for sec in m.get("sections", []):
                if sec.get("memory_sha256"):
                    out[(m["path"], sec["section"])] = sec
        return out
    pr, cr = regions(prev), regions(cur)
    ps, cs = sections(prev), sections(cur)
    d = {"regions_new": [{"base": k, "size": v["captured_size"], "kind": v.get("candidate_kind")}
                         for k, v in cr.items() if k not in pr],
         "regions_gone": [{"base": k, "size": v["captured_size"]} for k, v in pr.items() if k not in cr],
         "regions_changed": [{"base": k, "size": v["captured_size"]} for k, v in cr.items()
                             if k in pr and pr[k]["sha256"] != v["sha256"]],
         "sections_changed": [{"module": k[0], "section": k[1], "bytes_changed_vs_disk": v.get("bytes_changed"),
                               "changed_ranges": v.get("changed_ranges", [])[:16]}
                              for k, v in cs.items() if k in ps and ps[k]["memory_sha256"] != v["memory_sha256"]]}
    d["summary"] = (f"{len(d['regions_new'])} new, {len(d['regions_gone'])} gone, "
                    f"{len(d['regions_changed'])} changed executable region(s); "
                    f"{len(d['sections_changed'])} module section(s) changed")
    return d


def _snapshot_loop(pid, alive, root, allowed_root, delay, duration, interval, max_exec_mb, log=None):
    """snapshot pid every `interval` seconds for `duration` seconds (after
    `delay`); alive() -> None while running, else the exit code"""
    time.sleep(float(delay))
    end = time.monotonic() + float(duration)
    snapshots, seen, prev = [], {}, None
    exit_code = None
    i = 0
    while True:
        exit_code = alive()
        if exit_code is not None:
            break
        snap = root / f"snapshot_{i:03d}"
        try:
            rep = capture_pid(pid, str(snap), allowed_root=allowed_root,
                              max_exec_mb=max_exec_mb, seen_regions=seen)
        except OSError:
            exit_code = alive()
            if exit_code is not None:      # it exited while being read
                break
            raise
        entry = {"directory": str(snap), "modules": len(rep["modules"]),
                 "executable_regions": len(rep["executable_regions"]),
                 "new_region_bytes": rep.get("executable_capture_bytes", 0),
                 "truncated": rep.get("executable_capture_truncated", False),
                 "changed_bytes": sum(m.get("changed_executable_bytes", 0) for m in rep["modules"])}
        if prev is not None:
            d = diff_reports(prev, rep)
            (snap / "diff_from_previous.json").write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
            entry["diff_from_previous"] = d["summary"]
        snapshots.append(entry)
        if log:
            log(f"   snapshot {i}: {entry['modules']} module(s), {entry['executable_regions']} region(s), "
                f"{entry['changed_bytes']} changed byte(s)" +
                (f"; vs previous: {entry['diff_from_previous']}" if "diff_from_previous" in entry else ""))
        prev = rep
        i += 1
        remaining = end - time.monotonic()
        if remaining <= 0 or duration <= 0:
            break
        time.sleep(min(float(interval), remaining))
    return snapshots, exit_code


def _validate(delay, duration, interval, max_exec_mb):
    if delay < 0 or duration < 0 or interval <= 0 or max_exec_mb < 1:
        raise ValueError("runtime delay/duration must be non-negative; interval and memory cap must be positive")


def launch_and_capture(executable, out_dir, cwd=None, delay=10, duration=20,
                       interval=10, max_exec_mb=128, log=None):
    """Launch the game normally, snapshot it during startup/runtime, leave it running."""
    if os.name != "nt":
        raise RuntimeError("--runtime-capture requires running recomp on Windows")
    executable = os.path.abspath(executable)
    if not os.path.isfile(executable):
        raise FileNotFoundError(executable)
    if not executable.lower().endswith(".exe"):
        raise ValueError("runtime capture launches an .exe; for a DLL, use game --runtime-capture on its host game")
    _validate(delay, duration, interval, max_exec_mb)
    proc = subprocess.Popen([executable], cwd=cwd or os.path.dirname(executable))
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    snapshots, exit_code = _snapshot_loop(proc.pid, proc.poll, root, cwd or os.path.dirname(executable),
                                          delay, duration, interval, max_exec_mb, log)
    summary = {"pid": proc.pid, "executable": executable, "snapshots": snapshots,
               "process_left_running": exit_code is None}
    if exit_code is not None:
        summary["process_exit_code"] = exit_code
        summary["note"] = ("the launched process exited; if it is a launcher that starts the real "
                           "game as another process, use: recomp.py capture --name Game.exe --wait 120")
    (root / "capture_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if not snapshots:
        raise RuntimeError(f"game exited with code {exit_code} before the first snapshot "
                           f"(launcher? see {root / 'capture_summary.json'})")
    return summary


# ---- attaching to a process that is already running ----------------------
def find_processes(name):
    """[(pid, exe name)] of running processes whose file name is `name` (case-insensitive)"""
    if os.name != "nt":
        raise RuntimeError("process lookup by name needs Windows")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_wchar * 260)]
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    k32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)           # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    out = []
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            if e.szExeFile.lower() == name.lower():
                out.append((int(e.th32ProcessID), e.szExeFile))
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def _process_path(pid):
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    k32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p,
                                               ctypes.POINTER(ctypes.c_ulong)]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.OpenProcess(0x1000, False, int(pid))          # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        n = ctypes.c_ulong(len(buf))
        return buf.value if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else None
    finally:
        k32.CloseHandle(h)


def _pid_alive(pid):
    """None while the process runs, else its exit code (or -1 if unknown)"""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.OpenProcess(0x1000, False, int(pid))
    if not h:
        return -1
    try:
        code = ctypes.c_ulong()
        if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return -1
        return None if code.value == 259 else int(code.value)    # STILL_ACTIVE
    finally:
        k32.CloseHandle(h)


def attach_and_capture(out_dir, pid=None, name=None, wait=0, root_dir=None, delay=0, duration=20,
                       interval=10, max_exec_mb=128, log=None):
    """Snapshot a process that is already running (started by you, a launcher
    or Steam): by PID, or by exe name, optionally waiting up to `wait` seconds
    for it to appear. Modules inside root_dir (default: the exe's folder) are
    overlaid. Nothing is injected; the process keeps running."""
    if os.name != "nt":
        raise RuntimeError("capture requires running recomp on Windows")
    _validate(delay, duration, interval, max_exec_mb)
    if pid is None:
        if not name:
            raise ValueError("give a PID or an exe name")
        t_end = time.monotonic() + max(0.0, float(wait))
        while True:
            found = find_processes(name)
            if found or time.monotonic() >= t_end:
                break
            time.sleep(1.0)
        if not found:
            raise RuntimeError(f"no running process named {name}" + (f" appeared within {wait:g}s" if wait else ""))
        if len(found) > 1 and log:
            log(f"   {len(found)} processes named {name}; using the newest (PID {found[-1][0]})")
        pid = found[-1][0]
    exe = _process_path(pid)
    root_dir = root_dir or (os.path.dirname(exe) if exe else None)
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if log:
        log(f"   attached to PID {pid} ({exe or '?'}); modules from {root_dir or 'every folder'}")
    snapshots, exit_code = _snapshot_loop(pid, lambda: _pid_alive(pid), root, root_dir,
                                          delay, duration, interval, max_exec_mb, log)
    summary = {"pid": pid, "executable": exe, "attached": True, "snapshots": snapshots,
               "process_left_running": exit_code is None}
    if exit_code is not None:
        summary["process_exit_code"] = exit_code
    (root / "capture_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if not snapshots:
        raise RuntimeError(f"process {pid} exited before the first snapshot")
    return summary


# ---- readable listings of raw code regions ---------------------------------
def disassemble_region(bin_path, base, bits=64, out_path=None, max_insns=20000):
    """Write a disassembly listing next to a raw region dump (needs pypcode).
    Undecodable bytes are listed as `db` and decoding resumes at the next byte.
    Returns (instructions, undecodable bytes) or None if pypcode is missing."""
    try:
        import pypcode
    except ImportError:
        return None
    data = Path(bin_path).read_bytes()
    ctx = pypcode.Context("x86:LE:64:default" if bits == 64 else "x86:LE:32:default")
    out_path = out_path or str(bin_path)[:-4] + ".asm.txt"
    n_ins = n_bad = 0
    off = 0
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"; {os.path.basename(str(bin_path))}: {len(data)} bytes at {base:#x}, x86-{bits}\n")
        while off < len(data) and n_ins < max_insns:
            if not data[off:off + 16].strip(b"\0") and off + 16 <= len(data):
                z = off
                while off < len(data) and data[off] == 0:
                    off += 1
                f.write(f"{base + z:016x}  ; {off - z} zero bytes\n")
                continue
            try:
                ins = ctx.disassemble(data[off:off + 16], base + off, 0, 0, 1).instructions
                if not ins or ins[0].length <= 0:
                    raise ValueError("no instruction")
                d = ins[0]
                f.write(f"{base + off:016x}  {data[off:off + d.length].hex():<30} {d.mnem} {d.body}\n")
                off += d.length
                n_ins += 1
            except Exception:
                f.write(f"{base + off:016x}  {data[off]:02x}{'':<28} db {data[off]:#04x}   ; undecodable\n")
                off += 1
                n_bad += 1
        if off < len(data):
            f.write(f"; ... stopped after {max_insns} instructions\n")
    return n_ins, n_bad


def lift_runtime_overlays(snapshot_dir, out_dir, log=print, lifted_hashes=None):
    """Feed changed module overlays back through recomp's normal lifter.

    lifted_hashes: dict shared across snapshots (overlay sha256 -> output);
    an overlay identical to one already lifted is not lifted again."""
    try:
        from . import lift
    except ImportError as exc:          # pypcode missing: still report and list what we can
        lift, lift_missing = None, str(exc)
    snap = Path(snapshot_dir)
    try:
        report = json.loads((snap / "runtime_report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    outputs = []
    for mod in report.get("modules", []):
        if not mod.get("overlay") or not mod.get("changed_executable_bytes"):
            continue
        src = Path(mod["overlay"])
        key = "".join(sec.get("memory_sha256", "") for sec in mod.get("sections", []))
        if lifted_hashes is not None and key in lifted_hashes:
            outputs.append({"module": mod.get("path"), "overlay": str(src),
                            "same_as": lifted_hashes[key]})
            continue
        target = Path(out_dir) / re_safe(src.name)
        if lift is None:
            outputs.append({"module": mod.get("path"), "overlay": str(src), "status": "not_lifted",
                            "reason": f"lifter unavailable ({lift_missing}): pip install pypcode",
                            "changed_executable_bytes": mod.get("changed_executable_bytes")})
            if lifted_hashes is not None:
                lifted_hashes[key] = "(not lifted)"
            continue
        try:
            lift.lift(str(src), str(target), log=log)
            outputs.append({"module": mod.get("path"), "overlay": str(src), "lift_output": str(target),
                            "changed_executable_bytes": mod.get("changed_executable_bytes"),
                            "changed_ranges": [r for sec in mod.get("sections", [])
                                               for r in sec.get("changed_ranges", [])]})
            if lifted_hashes is not None:
                lifted_hashes[key] = str(target)
        except Exception as exc:
            outputs.append({"module": mod.get("path"), "overlay": str(src),
                            "status": "not_lifted", "reason": str(exc)})
    bits = report.get("process_bits", 64)
    for e in report.get("executable_regions", []):
        if "file" in e and not e.get("same_bytes_saved_as") and os.path.isfile(e["file"]):
            r = disassemble_region(e["file"], int(e["base"], 16), bits)
            if r:
                outputs.append({"region": e["base"], "listing": e["file"][:-4] + ".asm.txt",
                                "instructions": r[0], "undecodable_bytes": r[1]})
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "runtime_lift_report.json").write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    return outputs
