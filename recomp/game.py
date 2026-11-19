"""recomp game: a whole game folder -> a project that builds back into the game.

    recomp.py game GAMEFOLDER -o PROJECT     analyze + decompile everything
    cd PROJECT && python build_game.py        compile it back into PROJECT/build/

What goes where in PROJECT:
    modules/<file>/   every native .exe/.dll as recompiled C (one lift output each)
    assets/<file>/    Unity asset files split into their objects, plus viewable
                      exports (PNG, text, JSON) - see unity.py
    files/<file>      every other file, unchanged
    game.json         the manifest: every original file, its kind, size, SHA-256
    build_game.py     standalone build script (needs make + gcc/mingw, no recomp)

The build writes the original folder layout to PROJECT/build/: recompiled
executables under their original names, data files byte-identical (checked
against the SHA-256 in game.json).
"""
import hashlib
import json
import os
import shutil
import struct
import time

from . import lift as liftmod
from . import unity

# Every rebuilt DLL needs its own address range: MSVC links all DLLs at
# 0x180000000. Slots start at 32 TB, 64 GB apart (original image + the
# recompiled code that follows it in the rebuilt file).
SLOT_BASE = 0x2000_0000_0000
SLOT_SIZE = 0x10_0000_0000
# 32-bit games have 2 GB for everything, so their DLLs get ranges just big
# enough: the image, then about 48 bytes of recompiled code per byte of
# original code. They are handed out upwards from 256 MB (the usual DLL
# address; the exe and its recompiled code sit below, system DLLs far above).
SLOT32_BASE = 0x1000_0000
SLOT32_END = 0x6800_0000
CODE_GROWTH = 48


def rebuilt_size(info):
    """estimated address range of a rebuilt 32-bit file, from its image base"""
    n = info["size"] + CODE_GROWTH * info["code"] + (4 << 20)
    return (n + 0xFFFFF) & ~0xFFFFF


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                return h.hexdigest()
            h.update(b)


def pe_info(path):
    """(kind, details) for a PE file without loading it whole"""
    with open(path, "rb") as f:
        head = f.read(4096)
        if len(head) < 0x40 or head[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        f.seek(pe)
        hdr = f.read(24 + 240)
    if len(hdr) < 24 + 112 or hdr[:4] != b"PE\0\0":
        return None
    machine = struct.unpack_from("<H", hdr, 4)[0]
    nsec, optsz = struct.unpack_from("<H", hdr, 6)[0], struct.unpack_from("<H", hdr, 20)[0]
    chars = struct.unpack_from("<H", hdr, 22)[0]
    magic = struct.unpack_from("<H", hdr, 24)[0]
    if magic == 0x20B:
        entry = struct.unpack_from("<I", hdr, 24 + 16)[0]
        base = struct.unpack_from("<Q", hdr, 24 + 24)[0]
        size = struct.unpack_from("<I", hdr, 24 + 56)[0]
        ndirs = struct.unpack_from("<I", hdr, 24 + 108)[0]
        clr = struct.unpack_from("<I", hdr, 24 + 112 + 8 * 14)[0] if ndirs > 14 else 0
        reloc = struct.unpack_from("<I", hdr, 24 + 112 + 8 * 5)[0] if ndirs > 5 else 0
    else:
        entry = struct.unpack_from("<I", hdr, 24 + 16)[0]
        base = struct.unpack_from("<I", hdr, 24 + 28)[0]
        size = struct.unpack_from("<I", hdr, 24 + 56)[0]
        ndirs = struct.unpack_from("<I", hdr, 24 + 92)[0]
        clr = struct.unpack_from("<I", hdr, 24 + 96 + 8 * 14)[0] if ndirs > 14 else 0
        reloc = struct.unpack_from("<I", hdr, 24 + 96 + 8 * 5)[0] if ndirs > 5 else 0
    code = 0                    # bytes in executable sections
    with open(path, "rb") as f:
        f.seek(pe + 24 + optsz)
        sec = f.read(40 * min(nsec, 96))
    for i in range(len(sec) // 40):
        vsize, _, rawsize = struct.unpack_from("<III", sec, 40 * i + 8)
        if struct.unpack_from("<I", sec, 40 * i + 36)[0] & 0x20000000:
            code += min(rawsize, vsize or rawsize)
    return {"machine": machine, "dll": bool(chars & 0x2000), "pe64": magic == 0x20B,
            "entry": entry, "base": base, "size": size, "clr": bool(clr), "code": code,
            "relocatable": bool(reloc) and not chars & 1}


def classify(path):
    """kind of a file in a game folder:
    native      x86-64 or 32-bit x86 Windows exe/dll with code -> recompiled to C
    managed     .NET assembly (Mono games: Assembly-CSharp.dll, ...)
    pe-other    ARM PE, or a DLL without code: copied as-is
    unity       Unity serialized asset file -> split into objects
    bundle      Unity asset bundle (UnityFS) -> unpacked + split
    data        anything else: copied as-is"""
    pi = pe_info(path)
    if pi:
        if pi["clr"]:
            return "managed", pi
        if pi["machine"] == 0x8664 and pi["pe64"] and (pi["entry"] or pi["dll"]):
            return "native", pi
        if pi["machine"] == 0x14c and not pi["pe64"] and pi["code"] and (pi["entry"] or pi["dll"]):
            return "native", pi
        return "pe-other", pi
    k = unity.detect(path)
    if k:
        return k, None
    return "data", None


# Microsoft's C++ runtime: games import it from the system, but its code
# (C++ exceptions: __CxxFrameHandler, _CxxThrowException) has to be
# recompiled too, so it is added to the project next to the game's exe.
# (Windows looks next to the exe before System32 for these.)
MS_RUNTIME = ["vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_1.dll",
              "msvcp140_2.dll", "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll", "concrt140.dll"]


def pe_imports(path):
    try:
        img = liftmod.Image(path)
        try:
            return {d.lower() for d, _, _ in img.imports}
        finally:
            img.close()
    except Exception:
        return set()


def runtime_dlls(folder, entries, dirs, log):
    """[(rel, abs path)] of MS runtime DLLs the game imports but doesn't ship"""
    have = {os.path.basename(r).lower() for r in entries}
    exes = sorted((r for r in entries if r.lower().endswith(".exe")), key=lambda r: (r.count("/"), r))
    home = os.path.dirname(exes[0]) if exes else ""
    search = list(dirs)
    if os.name == "nt":
        search.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"))
    want, todo, added = set(), [os.path.join(folder, r) for r in entries
                                if r.lower().endswith((".exe", ".dll"))], []
    while todo:
        path = todo.pop()
        pi = pe_info(path)
        if not pi or not pi["pe64"]:
            # 32-bit programs: C++ exceptions are frame based and work through
            # the system's own runtime DLLs, nothing has to be added
            continue
        for d in pe_imports(path):
            if d in MS_RUNTIME and d not in have and d not in want:
                want.add(d)
                src = next((os.path.join(x, d) for x in search if os.path.isfile(os.path.join(x, d))), None)
                if not src:
                    log(f"   the game uses {d} but it was not found (pass --runtime-dlls DIR, e.g. "
                        f"C:/Windows/System32): C++ exceptions thrown through it will not work")
                    continue
                rel = f"{home}/{d}" if home else d
                added.append((rel, src))
                todo.append(src)
                log(f"   adding {d} from {os.path.dirname(src)} (its code must be recompiled too)")
    return added


# ---- Mono games: C# (IL) -> C -----------------------------------------------
MONO_DLLS = ("mono-2.0-bdwgc.dll", "mono-2.0-sgen.dll", "mono-2.0-boehm.dll", "mono-2.0.dll", "mono.dll")
# Mono runs corlib code while it starts, before the translated C can be
# registered: corlib keeps its IL
CIL_SKIP = ("mscorlib.dll",)
MONO_API = ["mono_domain_get", "mono_get_corlib", "mono_image_loaded", "mono_image_get_name",
            "mono_assembly_name_new", "mono_assembly_name_free", "mono_assembly_load", "mono_assembly_get_image",
            "mono_class_get", "mono_class_from_name", "mono_class_init", "mono_class_vtable",
            "mono_runtime_class_init", "mono_vtable_get_static_field_data", "mono_class_value_size",
            "mono_class_get_element_class", "mono_class_enum_basetype", "mono_class_from_mono_type",
            "mono_class_get_type", "mono_class_get_image", "mono_class_is_valuetype", "mono_array_element_size",
            "mono_get_method", "mono_method_get_class", "mono_method_get_token", "mono_method_get_header",
            "mono_method_header_get_locals", "mono_method_signature", "mono_signature_get_params",
            "mono_method_desc_new", "mono_method_desc_search_in_class", "mono_method_desc_free",
            "mono_field_from_token", "mono_field_get_parent", "mono_field_get_offset", "mono_object_new",
            "mono_array_new", "mono_array_length", "mono_array_addr_with_size", "mono_object_get_class",
            "mono_object_isinst", "mono_value_box", "mono_object_unbox", "mono_ldstr", "mono_gchandle_new",
            "mono_object_get_virtual_method", "mono_runtime_invoke", "mono_type_get_object",
            "mono_method_get_object", "mono_gc_wbarrier_set_field", "mono_gc_wbarrier_set_arrayref",
            "mono_gc_wbarrier_generic_store", "mono_gc_wbarrier_value_copy", "mono_add_internal_call",
            "mono_raise_exception", "mono_exception_from_name", "mono_get_exception_null_reference",
            "mono_get_exception_divide_by_zero", "mono_get_exception_overflow",
            "mono_get_exception_index_out_of_range", "mono_get_exception_invalid_cast",
            "mono_get_exception_array_type_mismatch", "mono_get_exception_arithmetic"]


def translate_managed(project, manifest, folder, log, cil_all=False):
    """Mono game: every managed assembly -> C (project/cil), built into
    recomp_cil.dll next to the game exe; the build ships patched assemblies
    whose translated methods are internal calls into that C"""
    from .cil import compile as cilc
    files = manifest["files"]
    mono = next((e for e in files if os.path.basename(e["path"]).lower() in MONO_DLLS), None)
    managed = [e for e in files if e["kind"] == "managed" and
               (cil_all or os.path.basename(e["path"]).lower() not in CIL_SKIP)]
    if not mono or not managed:
        return
    if "module" not in mono:
        log(f"   {mono['path']} was not recompiled: C# stays IL")
        return
    if mono.get("bits") == 32:
        log("   32-bit Mono game: C# -> C is only done for 64-bit games, the C# stays IL")
        return
    exe = next((e for e in files if e.get("module") and e["path"].lower().endswith(".exe")), None)
    cdir = os.path.join(project, "cil")
    shutil.rmtree(cdir, ignore_errors=True)
    os.makedirs(cdir)
    dirs = sorted({os.path.join(folder, os.path.dirname(e["path"])) for e in files if e["kind"] == "managed"})
    log(f"== C# -> C: {len(managed)} assemblies (Mono runtime {mono['path']})")

    def run(e, avoid=()):
        try:
            return cilc.translate(os.path.join(folder, e["path"]), cdir, dirs, log=lambda m: log(m),
                                  patched_path=os.path.join(cdir, "patched", e["path"]), avoid_names=avoid)
        except (cilc.Unsupported, cilc.meta.MetaError, OSError) as ex:
            log(f"   {e['path']}: not translated ({ex})")
            return None
    reps = {e["path"]: run(e) for e in managed}
    # Mono finds internal calls by name only: a name defined twice keeps its IL
    seen, dup = {}, set()
    for path, r in reps.items():
        for n in (r or {}).get("icall_names", []):
            if n in seen and seen[n] != path:
                dup.add(n)
            seen.setdefault(n, path)
    if dup:
        log(f"   {len(dup)} method names exist in more than one assembly: those keep their IL")
        for path, r in list(reps.items()):
            if r and dup & set(r["icall_names"]):
                reps[path] = run(next(e for e in managed if e["path"] == path), dup)
    regs = []
    for e in managed:
        r = reps.get(e["path"])
        if not r:
            continue
        e["cil"] = os.path.relpath(r["patched"], project).replace(os.sep, "/")
        e["cil_methods"] = f"{r['translated']}/{r['methods_with_il']}"
        e["note"] = "C# translated to C (recomp_cil.dll); this file is patched to call it"
        regs.append(r["register"])
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cil")
    for fn in ("cil_rt.h", "cil_rt.c", "mono_api.h"):
        shutil.copyfile(os.path.join(here, fn), os.path.join(cdir, fn))
    with open(os.path.join(cdir, "cil_register.c"), "w") as f:
        f.write("/* called by recomp_rt.dll right after the game has started Mono */\n")
        f.write("".join(f"void {r}(void);\n" for r in regs))
        f.write("__declspec(dllexport) void cil_register_all(void) {\n")
        f.write("".join(f"    {r}();\n" for r in regs) + "}\n")
    mono_name = os.path.basename(mono["path"])
    with open(os.path.join(cdir, "mono.def"), "w") as f:
        f.write(f'LIBRARY "{mono_name}"\nEXPORTS\n' + "".join(f"  {n}\n" for n in MONO_API))
    objs = sorted(fn[:-2] + ".o" for fn in os.listdir(cdir) if fn.endswith(".c"))
    with open(os.path.join(cdir, "Makefile"), "w") as f:
        f.write("CC = x86_64-w64-mingw32-gcc\nDLLTOOL = x86_64-w64-mingw32-dlltool\n")
        f.write("CFLAGS ?= -O1 -w -fno-strict-aliasing -fwrapv\n")
        # gcc 14+ makes int<->pointer and pointer type mix-ups errors; in
        # translated IL they mean what a cast means (older gcc ignores these)
        f.write("CFLAGS += -fpermissive -Wno-error=int-conversion -Wno-error=incompatible-pointer-types\n")
        f.write("OUT = recomp_cil.dll\n")
        f.write(f"OBJS = {' '.join(objs)}\n")
        f.write("$(OUT): $(OBJS) libmono.a\n\t$(CC) -shared -o $@ $(OBJS) libmono.a -static-libgcc\n")
        f.write("libmono.a: mono.def\n\t$(DLLTOOL) -d mono.def -l libmono.a\n")
        f.write("%.o: %.c cil_rt.h mono_api.h\n\t$(CC) $(CFLAGS) -c $<\n")
        f.write("clean:\n\trm -f *.o libmono.a $(OUT)\n")
    where = os.path.dirname(exe["path"]) if exe else ""
    files.append({"path": (where + "/" if where else "") + "recomp_cil.dll", "kind": "generated",
                  "module": "cil", "note": "the C translated from the game's C#"})
    t = sum(r["translated"] for r in reps.values() if r)
    n = sum(r["methods_with_il"] for r in reps.values() if r)
    log(f"   {t}/{n} C# methods are now C ({100 * t // max(n, 1)}%); the rest keeps its IL "
        f"(reasons per method: cil/*_report.json)")
    import json as _json
    with open(os.path.join(cdir, "cil_report.json"), "w") as f:
        _json.dump(reps, f, indent=1)


def module_dir(rel):
    return rel.replace("\\", "/").replace("/", "__")


def elf_info(path):
    """(machine, type) of an ELF file, or None"""
    try:
        with open(path, "rb") as f:
            h = f.read(20)
    except OSError:
        return None
    if len(h) < 20 or h[:4] != b"\x7fELF":
        return None
    e_type, e_machine = struct.unpack_from("<HH", h, 16)
    return {"machine": e_machine, "type": e_type, "bits": 64 if h[4] == 2 else 32}


def analyze(folder, project, log=print, only_copy=False, runtime_dirs=(), add_runtime=True,
            cil=True, cil_all=False, keep=(), redo=(), android=None):
    """android: for an unpacked APK - {"lift_native": bool, "abi": the ABI whose
    libraries are lifted for analysis, "split_unity": bool}"""
    """redo: analyze only these files again (names or paths inside the game
    folder; "cil" = the C# -> C translation) and keep everything else of an
    existing project as it is. For trying a fix without the whole run."""
    t0 = time.time()
    folder = os.path.abspath(folder)
    project = os.path.abspath(project)
    if project.startswith(folder + os.sep):
        raise SystemExit("the project folder must not be inside the game folder")
    os.makedirs(project, exist_ok=True)
    entries = []
    for root, dirs, files in os.walk(folder):
        dirs.sort()
        for fn in sorted(files):
            p = os.path.join(root, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            entries.append(os.path.relpath(p, folder).replace(os.sep, "/"))
    log(f"== game: {android.get('display', folder) if android else folder}  ({len(entries)} files)")
    sources = [(r, os.path.join(folder, r), False) for r in entries]
    if add_runtime and not only_copy:
        sources += [(r, p, True) for r, p in runtime_dlls(folder, entries, runtime_dirs, log)]

    manifest = {"source": folder, "created": time.strftime("%Y-%m-%d %H:%M:%S"), "files": []}
    counts = {}
    keep = {k.replace("\\", "/").lower() for k in keep}
    redo = {k.replace("\\", "/").lower() for k in redo}
    old = {}
    if redo:
        try:
            with open(os.path.join(project, "game.json")) as f:
                old_manifest = json.load(f)
        except (OSError, ValueError):
            raise SystemExit(f"--redo needs an existing project: no game.json in {project}")
        old = {e["path"]: e for e in old_manifest["files"]}
        known = {r.lower() for r, _, _ in sources} | {os.path.basename(r).lower() for r, _, _ in sources} | {"cil"}
        for k in sorted(redo - known):
            raise SystemExit(f"--redo {k}: no such file in the game (use a name or a path inside the game folder)")

    def reuse(rel, e):
        """the old project's entry for a file that is not analyzed again"""
        o = old.get(rel)
        if not redo or rel.lower() in redo or os.path.basename(rel).lower() in redo or not o:
            return None
        if o.get("sha256") != e["sha256"]:
            return None             # the game file changed since
        if "cil" in redo:
            o = {k: v for k, v in o.items() if k not in ("cil", "cil_methods")}
            if o["kind"] == "managed":
                o["note"] = "managed .NET code (IL)"
        return o
    kinds = {rel: classify(src) for rel, src, _ in sources}
    if android is not None:
        for rel, src, _ in sources:
            ei = elf_info(src)
            if ei and rel.startswith("lib/") and rel.endswith(".so"):
                kinds[rel] = ("android-native", ei)
            elif kinds[rel][0] in ("unity", "bundle") and not android.get("split_unity", True):
                kinds[rel] = ("data", None)
            elif kinds[rel][0] in ("native", "managed", "pe-other"):
                # PE files inside an APK (Mono's C# assemblies): kept as they are
                kinds[rel] = ("managed" if kinds[rel][0] == "managed" else "data", kinds[rel][1])

    def kept(rel):
        return rel.lower() in keep or os.path.basename(rel).lower() in keep
    # exe keeps its address, DLLs get slots
    slot = 0
    # 32-bit: address ranges that are taken (the exes, and DLLs that can't be
    # moved), then every other DLL gets the next free range
    taken32 = []
    for rel, (kind, info) in kinds.items():
        if kind == "native" and not info["pe64"] and not only_copy and not kept(rel) and \
                not (info["dll"] and info["relocatable"]):
            taken32.append((info["base"] - 0x10000, info["base"] + rebuilt_size(info)))
    next32 = SLOT32_BASE

    def slot32(info, rel):
        nonlocal next32
        size = rebuilt_size(info) + 0x10000
        a = next32
        while any(a < hi and lo < a + size for lo, hi in taken32):
            a = max(hi for lo, hi in taken32 if a < hi and lo < a + size)
            a = (a + 0xFFFFF) & ~0xFFFFF
        if a + size > SLOT32_END:
            log(f"   WARNING: {rel}: the rebuilt 32-bit files need more address space than a 32-bit "
                f"process has below {SLOT32_END:#x}; use --keep to leave some DLLs as they are")
        next32 = a + size
        return a + 0x10000
    for rel, src, added in sources:
        kind, info = kinds[rel]
        e = {"path": rel, "kind": kind, "size": os.path.getsize(src), "sha256": sha256(src)}
        if added:
            e["added"] = f"not in the game folder; taken from {os.path.dirname(src)}"
        if only_copy and kind == "native":
            kind = e["kind"] = "data"
        if kind == "native" and kept(rel):
            kind = e["kind"] = "data"
            e["note"] = "kept as it is (--keep): runs as native code"
            log(f"   {rel}: kept unchanged (--keep)")
        if kind == "android-native":
            abi = rel.split("/")[1]
            e["abi"] = abi
            e["note"] = "native library: kept unchanged in the rebuilt APK"
            if android.get("lift_native", True) and abi == android.get("abi") and not only_copy and not kept(rel):
                o = reuse(rel, e)
                if o:
                    counts["kept from the project"] = counts.get("kept from the project", 0) + 1
                    manifest["files"].append(o)
                    continue
                md = module_dir(rel)
                mdir = os.path.join(project, "modules", md)
                try:
                    liftmod.lift(src, mdir, log=lambda m, rel=rel: log(f"   [{rel}] {m.strip()}") if _keep(m) else None,
                                 name=os.path.basename(rel))
                    try:
                        with open(os.path.join(mdir, "lift.json"), encoding="utf-8") as f:
                            rebuildable = str(json.load(f).get("cc", "")).startswith("a64:")
                    except (OSError, ValueError):
                        rebuildable = False
                    if rebuildable:
                        # ARM64: recompiled into a library that replaces the original in the APK
                        e.update({"module": f"modules/{md}", "builder": "build_lift"})
                        e["note"] = "native library: recompiled (P-code -> C -> ARM64)"
                        kind = "native"
                    else:
                        e["analysis"] = f"modules/{md}"
                        e["note"] += f"; lifted to C for analysis only in {e['analysis']} (see its lift_report.txt)"
                except (liftmod.LiftError, liftmod.NotNativeCode) as ex:
                    log(f"   {rel}: not lifted ({ex}); kept unchanged")
                except (MemoryError, KeyboardInterrupt):
                    raise
                except Exception as ex:          # a bug in recomp: this library stays as it is, the rest goes on
                    import traceback
                    os.makedirs(mdir, exist_ok=True)
                    with open(os.path.join(mdir, "LIFT_CRASH.txt"), "w", encoding="utf-8") as f:
                        traceback.print_exc(file=f)
                    log(f"   {rel}: recomp crashed while lifting it ({type(ex).__name__}: {ex}); kept unchanged "
                        f"(details: {os.path.join(mdir, 'LIFT_CRASH.txt')} - please report it)")
                    e["note"] += "; recomp crashed while lifting it (see LIFT_CRASH.txt)"
            elif kept(rel):
                e["note"] += " (--keep)"
            elif abi != android.get("abi"):
                e["note"] += f"; same code as the {android.get('abi')} library for another CPU, not lifted"
            if kind == "native":
                counts["native"] = counts.get("native", 0) + 1
                manifest["files"].append(e)
                continue
            kind = "data"
        if kind == "native":
            md = module_dir(rel)
            base = None
            e["bits"] = 64 if info["pe64"] else 32
            if info["dll"]:
                if info["relocatable"]:
                    if info["pe64"]:
                        base = SLOT_BASE + slot * SLOT_SIZE
                        slot += 1
                    else:
                        base = slot32(info, rel)
                else:
                    log(f"   {rel}: DLL without relocations, keeps its address {info['base']:#x}")
            # (addresses are handed out above even for files that are kept, so
            # every file gets the same one as in the first run)
            o = reuse(rel, e)
            if o:
                counts["kept from the project"] = counts.get("kept from the project", 0) + 1
                manifest["files"].append(o)
                continue
            try:
                liftmod.lift(src, os.path.join(project, "modules", md),
                             log=lambda m, rel=rel: log(f"   [{rel}] {m.strip()}") if _keep(m) else None,
                             base=base, name=os.path.basename(rel))
                e.update({"module": f"modules/{md}", "base": f"{base or info['base']:#x}"})
            except (liftmod.LiftError, liftmod.NotNativeCode) as ex:
                log(f"   {rel}: cannot recompile ({ex}); copied unchanged")
                kind = e["kind"] = "data"
        if kind != "native":
            o = reuse(rel, e)
            if o:
                counts["kept from the project"] = counts.get("kept from the project", 0) + 1
                manifest["files"].append(o)
                continue
        if kind in ("unity", "bundle"):
            ad = os.path.join(project, "assets", module_dir(rel))
            try:
                res = unity.split(src, ad, log=lambda m, rel=rel: log(f"   [{rel}] {m}"),
                                  game_root=folder)
                e.update({"assets": f"assets/{module_dir(rel)}", "objects": res.get("objects", 0)})
            except unity.UnitySplitError as ex:
                log(f"   {rel}: kept as one file ({ex})")
                shutil.rmtree(ad, ignore_errors=True)
                kind = e["kind"] = "data"
        if kind in ("data", "pe-other", "managed"):
            dst = os.path.join(project, "files", rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            if kind == "managed":
                e["note"] = "managed .NET code (IL)"
            elif kind == "pe-other":
                e["note"] = "not x86 code (or no code): copied unchanged"
        counts[kind] = counts.get(kind, 0) + 1
        manifest["files"].append(e)

    if redo and "cil" not in redo:
        manifest["files"] += [e for e in old.values() if e.get("kind") == "generated"]
    elif cil and not only_copy:
        translate_managed(project, manifest, folder, log, cil_all)
    with open(os.path.join(project, "game.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    here = os.path.dirname(os.path.abspath(__file__))
    shutil.copyfile(os.path.join(here, "build_game.py"), os.path.join(project, "build_game.py"))
    shutil.copyfile(os.path.join(here, "unity_join.py"), os.path.join(project, "unity_join.py"))
    log("   " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    log(f"   project written to {project} ({time.time() - t0:.0f}s)")
    if android is None:
        log(f"   build it:  cd {project} && python3 build_game.py")
    return manifest


def analyze_apk(apk_path, project, log=print, split_unity=True, lift_native=True, abi=None, keep=(), redo=()):
    """An Android APK -> a project: the APK is unpacked and analyzed like a game
    folder (Unity assets split, native libraries lifted for analysis, the rest
    kept as files). game.json records the APK's entries - order, compression,
    timestamps - and build_game.py writes them back into a signed APK."""
    import zipfile
    from . import apk as apkmod
    apk_path = os.path.abspath(apk_path)
    project = os.path.abspath(project)
    if apkmod.is_split_container(apk_path):
        raise SystemExit("this is a split-APK container (.xapk/.apks/.apkm): unzip it and give recomp the "
                         "base APK (the one with lib/ or classes.dex); OBB files can be added as files")
    if not apkmod.is_apk(apk_path):
        raise SystemExit(f"not an APK (no AndroidManifest.xml): {apk_path}")
    r = apkmod.info(apk_path)
    log(f"== apk: {apk_path}")
    for ln in apkmod.summary_text(r).splitlines():
        log("   " + ln.strip())
    if abi is None:
        abi = r["abis"][0] if r["abis"] else None
    elif abi not in r["abis"]:
        raise SystemExit(f"--abi {abi}: the APK has native code for {', '.join(r['abis']) or 'no CPU'}")
    os.makedirs(project, exist_ok=True)
    tmp = os.path.join(project, ".apk_unpacked")
    shutil.rmtree(tmp, ignore_errors=True)
    entries = []
    with zipfile.ZipFile(apk_path) as z:
        for zi in z.infolist():
            if zi.is_dir():
                continue
            name = zi.filename
            if name.startswith("/") or ".." in name.split("/"):
                raise SystemExit(f"unsafe file name in the APK: {name!r}")
            dst = os.path.join(tmp, *name.split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with z.open(zi) as src, open(dst, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
            entries.append({"name": name, "compress": zi.compress_type, "date_time": list(zi.date_time),
                            "external_attr": zi.external_attr, "create_system": zi.create_system,
                            "signature_file": apkmod.is_v1_signature_file(name)})
    try:
        man = analyze(tmp, project, log=log, add_runtime=False, cil=False, keep=keep, redo=redo,
                      android={"lift_native": lift_native, "abi": abi, "split_unity": split_unity,
                               "display": f"contents of {os.path.basename(apk_path)}"})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # the old signature is replaced when the APK is rebuilt: its files are not part of the project
    sigs = {e["name"] for e in entries if e["signature_file"]}
    man["files"] = [e for e in man["files"] if e["path"] not in sigs]
    for n in sigs:
        p = os.path.join(project, "files", *n.split("/"))
        if os.path.exists(p):
            os.remove(p)
    man["source"] = apk_path
    man["container"] = {"type": "apk", "name": os.path.basename(apk_path), "entries": entries,
                        "apk": {k: r[k] for k in ("manifest", "abis", "native_libs", "unity", "signatures")},
                        "analysis_abi": abi}
    with open(os.path.join(project, "game.json"), "w") as f:
        json.dump(man, f, indent=1)
    here = os.path.dirname(os.path.abspath(__file__))
    shutil.copyfile(os.path.join(here, "apk_sign.py"), os.path.join(project, "apk_sign.py"))
    out = os.path.splitext(os.path.basename(apk_path))[0] + "-rebuilt.apk"
    log(f"   the rebuilt APK will be: {os.path.join(project, out)} (signed with the project's key, see build_game.py)")
    return man


def _keep(msg):
    """lift messages worth showing per module in a whole-game run"""
    return any(k in msg for k in ("lifted", "moved from", "cannot", "WARNING", "could not be translated"))
