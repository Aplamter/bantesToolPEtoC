"""
lift.py - binary -> P-code -> C

The output is deliberately "dumb but exact": every machine instruction becomes
a handful of C statements that do precisely what Ghidra's P-code says the
instruction does.  Nothing is guessed, so the recompiled program behaves like
the original.  It is ugly on purpose - readability is a later layer.

Generated program layout
  ctx->R  the CPU register file (Ghidra 'register' space layout), per thread
  ctx->U  Ghidra 'unique' temporaries, per thread
  guest memory == host memory: the original image is mapped at its original
  address, so pointers inside the program just work.

  Code is split into chunks (normally one per function). Each chunk is a C
  function  uint64_t chunk(uint64_t pc, rt_ctx *ctx)  that runs from `pc`
  until control leaves the chunk and returns the next pc. The runtime loops:
        for(;;) pc = lookup(pc)(pc, ctx);

Formats: ELF (Linux) and PE (Windows .exe). Lifting works for any CPU Ghidra
knows; the runtimes exist for Linux x86-64, Windows x64 and Windows 32-bit x86.

32-bit Windows programs are rebuilt as 32-bit programs (i686 MinGW): they keep
using the real 32-bit system DLLs, the thread's real stack and the real TEB.
What the generated C does differently for them is marked `g32` below.
"""
import heapq
import json
import mmap
import os
import re
import shutil
import struct
import time
from array import array

import pypcode
from pypcode import OpCode as O

MAX_CHUNK = 1200  # instructions per C function, keeps compile time sane
# Generated C files are capped by line count instead of always being 1/16 of
# the program, so gcc never gets one gigantic file (that is what eats the RAM
# when building big programs). Override with RECOMP_FILE_LINES.
FILE_LINES = int(os.environ.get("RECOMP_FILE_LINES", "120000"))
# Compact C (default): no per-instruction comment, no labels nothing jumps
# to, no INSN() trace hook - about half the size, same machine code.
# RECOMP_VERBOSE_C=1 restores them (needed for `make TRACE=1` traces).
VERBOSE_C = os.environ.get("RECOMP_VERBOSE_C", "") == "1"
_LABEL_RE = re.compile(r"P[0-9a-f]+_[0-9]+")
MAX_INSN_BYTES = 32  # longest instruction on any supported CPU (x86 is 15)

ELF_ARCH = {
    62: ("x86:LE:64:default", True),     # x86-64
    3: ("x86:LE:32:default", False),     # i386
    183: ("AARCH64:LE:64:v8A", False),   # arm64
    40: ("ARM:LE:32:v7", False),         # arm
    8: ("MIPS:BE:32:default", False),    # mips (N64/PS1/PS2 are MIPS)
    20: ("PowerPC:BE:32:default", False),  # ppc (GameCube/Wii/Xbox360)
}
PE_ARCH = {
    0x8664: ("x86:LE:64:default", True),
    0x14c: ("x86:LE:32:default", True),   # runtime: rt_win32.c
    0xAA64: ("AARCH64:LE:64:v8A", False),
}


class LiftError(Exception):
    pass


class NotNativeCode(LiftError):
    """the file is not machine code (e.g. .NET IL) - route to another tool"""


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def rebase_pe(src, dst, new_base):
    """Copy a PE file to dst with every base relocation applied for new_base.
    All Windows DLLs built by MSVC want the same address (0x180000000), so in
    a game they can't all live where they want; each one is moved to its own
    address *before* lifting, so the generated C already uses the new
    addresses. Returns the number of patched places."""
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        d = mmap.mmap(f.fileno(), 0)
        try:
            u16 = lambda o: struct.unpack_from("<H", d, o)[0]
            u32 = lambda o: struct.unpack_from("<I", d, o)[0]
            pe = u32(0x3C)
            opt = pe + 24
            magic = u16(opt)
            if magic == 0x20B:
                old = struct.unpack_from("<Q", d, opt + 24)[0]
                ddir = opt + 112
            elif magic == 0x10B:
                old = u32(opt + 28)
                ddir = opt + 96
                if new_base >> 32:
                    raise LiftError("a 32-bit file can't be moved above 4 GB")
            else:
                raise LiftError("not a PE32 / PE32+ file")
            delta = (new_base - old) & 0xFFFFFFFFFFFFFFFF
            nsec, optsz = u16(pe + 6), u16(pe + 20)
            secs = []
            for i in range(nsec):
                b = opt + optsz + 40 * i
                secs.append((u32(b + 12), max(u32(b + 8), u32(b + 16)), u32(b + 20), u32(b + 16)))

            def off(rva):
                for va, vs, ro, rs in secs:
                    if va <= rva < va + vs:
                        return ro + rva - va if rva - va < rs else None
                return None
            rrva, rsz = u32(ddir + 8 * 5), u32(ddir + 8 * 5 + 4)
            if not rrva or u16(pe + 22) & 1:
                raise LiftError("the file has no relocation table, it can't be moved to another address")
            o, end, n = off(rrva), off(rrva) + rsz, 0
            while o + 8 <= end:
                page, size = u32(o), u32(o + 4)
                if size < 8:
                    break
                for k in range((size - 8) // 2):
                    e = u16(o + 8 + 2 * k)
                    typ, at = e >> 12, off(page + (e & 0xFFF))
                    if at is None or typ == 0:
                        continue
                    if typ == 10:      # IMAGE_REL_BASED_DIR64
                        v = struct.unpack_from("<Q", d, at)[0]
                        struct.pack_into("<Q", d, at, (v + delta) & 0xFFFFFFFFFFFFFFFF)
                    elif typ == 3:     # HIGHLOW
                        v = u32(at)
                        struct.pack_into("<I", d, at, (v + delta) & 0xFFFFFFFF)
                    else:
                        raise LiftError(f"unknown relocation type {typ}")
                    n += 1
                o += size
            if magic == 0x20B:
                struct.pack_into("<Q", d, opt + 24, new_base)
            else:
                struct.pack_into("<I", d, opt + 28, new_base)
            d.flush()
            return n
        finally:
            d.close()


def map_file(path):
    """read-only memory map of a file: the OS pages it in from disk on demand
    instead of the whole file being copied into Python's memory"""
    f = open(path, "rb")
    if os.fstat(f.fileno()).st_size == 0:
        f.close()
        return None, b""
    return f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)


class Image:
    """format-independent view of an executable:
    segments (vaddr, memsz, foff, fsize, flags), code regions, entry, function
    symbols, plus format-specific extras (imports for PE).

    The file is memory-mapped, and segments / code regions only store file
    offsets, so nothing is copied into RAM. Use seg_bytes() / code_bytes()
    when you really need the bytes."""

    def __init__(self, path):
        self.path = path
        self._f, self.raw = map_file(path)
        self.funcs = {}        # addr -> name (symbols, exports, .pdata, tls callbacks)
        self.code_ptrs = set() # PE: absolute pointers into code found via relocations
                               # (vtables, callbacks, function-pointer tables)
        self.datasyms = {}     # addr -> name (IAT slots etc., for logs only)
        self.code = []         # (vaddr, file offset, size, section name)
        self.segments = []
        self.imports = []      # (dll, name, iat_vaddr)
        self.notes = []        # human-readable facts for the report
        self.is_dll = False
        self.exports = []      # PE: (ordinal, name, rva, forwarder)
        self.resources = []    # PE: (type, name, lang, bytes)
        self.dllname = None
        self.relocs_stripped = True
        self.phdr = self.phnum = 0
        self.imagebase = 0
        self.subsystem = 0
        self.pe64 = False
        self.g32 = False       # 32-bit x86 Windows program (runtime: rt_win32.c)
        self.guess_ptrs = False  # no relocation table: code addresses in data are guessed
        self.a64 = False       # ARM64 shared library (runtime: runtime/a64)
        self.func_syms = set() # ELF: addresses of symbols that are functions
        self.dynelf = None
        self.stack_reserve = self.stack_commit = 0
        self.large_address = False
        if self.raw[:4] == b"\x7fELF":
            self.format = "elf"
            self._elf()
        elif self.raw[:2] == b"MZ":
            self.format = "pe"
            self._pe()
        else:
            raise LiftError("not an ELF or PE executable (the scanner still works on it)")

    def close(self):
        if self._f:
            self.raw.close()
            self._f.close()
            self._f = None

    def _resources(self, rrva, u16, u32):
        """the resource tree as [(type, name, lang, bytes)]; type/name are an
        int id or a string. Copied into the rebuilt file so icons, version
        info, manifests and FindResource() keep working."""
        out = []
        base = self.rva2off(rrva) if rrva else None
        if base is None:
            return out
        d = self.raw

        def ident(v):
            if v & 0x80000000:
                o = base + (v & 0x7FFFFFFF)
                n = u16(o)
                return d[o + 2:o + 2 + 2 * n].decode("utf-16-le", errors="replace")
            return v & 0xFFFF

        def entries(o):
            n = u16(o + 12) + u16(o + 14)
            for k in range(n):
                yield u32(o + 16 + 8 * k), u32(o + 20 + 8 * k)

        try:
            for tn, to in entries(base):
                if not to & 0x80000000:
                    continue
                for nn, no in entries(base + (to & 0x7FFFFFFF)):
                    if not no & 0x80000000:
                        continue
                    for ln, lo in entries(base + (no & 0x7FFFFFFF)):
                        if lo & 0x80000000:
                            continue
                        de = base + lo
                        drva, dsz = u32(de), u32(de + 4)
                        fo = self.rva2off(drva)
                        if fo is None:
                            continue
                        out.append((ident(tn), ident(nn), ln & 0xFFFF, bytes(d[fo:fo + dsz])))
        except struct.error:
            self.notes.append("resource directory is damaged; resources were not copied")
        return out

    def _guess_code_ptrs(self, u32):
        """32-bit PE without relocations: see _pe()"""
        d = self.raw
        ib = self.imagebase
        rng = [(c[0], c[0] + c[2]) for c in self.code]
        lo, hi = min(a for a, _ in rng), max(b for _, b in rng)

        def is_code(v):
            return lo <= v < hi and any(a <= v < b for a, b in rng)
        for name, rva, vsize, rawoff, rawsize, ch in self.sections:
            n = max(0, min(rawsize, vsize or rawsize, len(d) - rawoff)) if rawoff else 0
            if n < 4:
                continue
            if ch & 0x20000000:
                # jump tables: FF 24 <sib: scale 4, no base> <table address>
                o = d.find(b"\xff\x24", rawoff, rawoff + n)
                while 0 <= o < rawoff + n - 7:
                    if d[o + 2] & 0xC7 == 0x85:
                        t = self.rva2off(u32(o + 3) - ib) if u32(o + 3) >= ib else None
                        while t is not None and t + 4 <= len(d) and is_code(u32(t)):
                            self.code_ptrs.add(u32(t))
                            t += 4
                    o = d.find(b"\xff\x24", o + 1, rawoff + n)
            else:
                vals = array("I", bytes(d[rawoff:rawoff + (n & ~3)]))
                if vals.itemsize != 4:      # (never on the platforms recomp runs on)
                    continue
                self.code_ptrs.update(v for v in set(vals) if lo <= v < hi and is_code(v))

    def seg_bytes(self, s):
        """file-backed bytes of a segment (without the zero-filled tail)"""
        return self.raw[s["foff"]:s["foff"] + s["fsize"]]

    # ---- ELF ----------------------------------------------------------------
    def _elf(self):
        import lief
        b = lief.parse(self.path)
        if b is None:
            raise LiftError("lief could not parse this ELF file")
        mach = int(b.header.machine_type.value)
        if mach not in ELF_ARCH:
            raise LiftError(f"unsupported CPU (ELF e_machine={mach})")
        self.lang, self.abi_ok = ELF_ARCH[mach]
        dyn = b.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
        if self.abi_ok and dyn:
            raise LiftError("position-independent ELF. Rebuild with -no-pie "
                            "(PIE support is on the roadmap)")
        if self.abi_ok and b.has_interpreter:
            raise LiftError("dynamically linked ELF. Rebuild with -static "
                            "(import stubs are on the roadmap)")
        self.is_dll = dyn and not b.has_interpreter
        # ARM64 shared library (Android lib/arm64-v8a/*.so): rebuilt as a
        # shared library for the same CPU (a64.py, runtime/a64/)
        self.a64 = mach == 183 and self.is_dll
        if dyn and not self.a64:
            # no runtime for this CPU: the lift is for analysis (C, listing,
            # report), at the file's own link addresses
            self.notes.append(("shared library" if self.is_dll else "position-independent executable") +
                              f" for {self.lang.split(':')[0]}: lifted at its link addresses (base 0) for analysis")
        self.entry = b.entrypoint
        flen = len(self.raw)
        for s in b.segments:
            if s.type == lief.ELF.Segment.TYPE.LOAD:
                fo = min(s.file_offset, flen)
                self.segments.append({
                    "vaddr": s.virtual_address, "memsz": s.virtual_size,
                    "foff": fo, "fsize": max(0, min(s.physical_size, flen - fo)),
                    "flags": int(s.flags.value) if hasattr(s.flags, "value") else int(s.flags),
                })
        for s in b.segments:
            if s.type == lief.ELF.Segment.TYPE.PHDR:
                self.phdr = s.virtual_address
        if not self.phdr:
            for s in b.segments:
                if s.type == lief.ELF.Segment.TYPE.LOAD and s.file_offset == 0:
                    self.phdr = s.virtual_address + b.header.program_header_offset
        self.phnum = b.header.numberof_segments
        for sec in b.sections:
            if sec.has(lief.ELF.Section.FLAGS.EXECINSTR) and sec.size and \
                    sec.type != lief.ELF.Section.TYPE.NOBITS:
                fo = min(sec.offset, flen)
                self.code.append((sec.virtual_address, fo, max(0, min(sec.size, flen - fo)), sec.name))
        if not self.code:
            for s in self.segments:
                if s["flags"] & 1:
                    self.code.append((s["vaddr"], s["foff"], s["fsize"], "segment"))
        for sym in b.symbols:
            if sym.value and sym.name:
                if sym.type == lief.ELF.Symbol.TYPE.FUNC:
                    self.funcs.setdefault(sym.value, sym.name)
                    self.func_syms.add(sym.value)
                elif sym.type == lief.ELF.Symbol.TYPE.OBJECT:
                    self.datasyms.setdefault(sym.value, sym.name)
        if self.a64:
            from . import a64, a64elf
            try:
                why = a64.load(self)
            except (a64elf.ElfError, struct.error, IndexError, ValueError) as e:
                why = f"its dynamic section can't be read ({e})"
            if why:
                # can't be rebuilt: lifted for analysis like any other CPU
                self.a64 = False
                self.dynelf = None
                self.code_ptrs = set()
                self.notes.append(f"cannot be rebuilt: {why}; lifted for analysis only")
                self._elf_dynamic(b)
            else:
                self.abi_ok = True
        elif dyn:
            self._elf_dynamic(b)
        if self.entry:
            self.funcs.setdefault(self.entry, "_start")
        del b  # free lief's copy of the file right away

    def _elf_dynamic(self, b):
        """shared objects: exported functions (JNI_OnLoad, Java_*), imported
        symbols, init/fini arrays, and code pointers stored in data (found
        through relocations: vtables, callback tables)"""
        import lief
        lo_hi = [(c[0], c[0] + c[2]) for c in self.code]
        in_code = lambda v: any(a <= v < e for a, e in lo_hi)
        self.exports = []
        for sym in b.dynamic_symbols:
            if not sym.name:
                continue
            if sym.value:
                if sym.type == lief.ELF.Symbol.TYPE.FUNC or in_code(sym.value):
                    self.funcs.setdefault(sym.value, sym.name)
                    self.exports.append((0, sym.name, sym.value, None))
            elif sym.type in (lief.ELF.Symbol.TYPE.FUNC, lief.ELF.Symbol.TYPE.NOTYPE):
                self.imports.append(("", sym.name, 0))
        slots = {}
        for r in b.relocations:
            try:
                sym = r.symbol.name if r.has_symbol and r.symbol else ""
            except Exception:
                sym = ""
            if sym and r.address:
                slots.setdefault(sym, r.address)
                self.datasyms.setdefault(r.address, f"__got_{sym}")
            v = r.addend
            if not sym and v and in_code(v):
                self.code_ptrs.add(v)
        if slots:
            self.imports = [(d, n, slots.get(n, s_)) for d, n, s_ in self.imports]
        for k, tag in ((0, lief.ELF.DynamicEntry.TAG.INIT_ARRAY), (1, lief.ELF.DynamicEntry.TAG.FINI_ARRAY)):
            try:
                e = b.get(tag)
            except Exception:
                e = None
            for i, f in enumerate(getattr(e, "array", []) or []):
                if f and in_code(f):
                    self.funcs.setdefault(f, f"{'init' if k == 0 else 'fini'}_array_{i}")
        for tag, nm in ((lief.ELF.DynamicEntry.TAG.INIT, "_init"), (lief.ELF.DynamicEntry.TAG.FINI, "_fini")):
            try:
                e = b.get(tag)
                if e and e.value and in_code(e.value):
                    self.funcs.setdefault(e.value, nm)
            except Exception:
                pass
        self.notes.append(f"{len(self.exports)} exported functions, {len(self.imports)} imported symbols, "
                          f"{len(self.code_ptrs)} code pointers in data (relocations)")

    # ---- PE -----------------------------------------------------------------
    def _pe(self):
        d = self.raw
        u16 = lambda o: struct.unpack_from("<H", d, o)[0]
        u32 = lambda o: struct.unpack_from("<I", d, o)[0]
        u64 = lambda o: struct.unpack_from("<Q", d, o)[0]
        pe = u32(0x3C)
        if d[pe:pe + 4] != b"PE\0\0":
            raise LiftError("MZ file without a PE header (DOS program?)")
        coff = pe + 4
        machine, nsec = u16(coff), u16(coff + 2)
        symptr, nsyms, optsz = u32(coff + 8), u32(coff + 12), u16(coff + 16)
        opt = coff + 20
        magic = u16(opt)
        if machine not in PE_ARCH:
            raise LiftError(f"unsupported CPU (PE machine={machine:#x})")
        self.lang, self.abi_ok = PE_ARCH[machine]
        pe64 = self.pe64 = magic == 0x20B
        if pe64 != (machine != 0x14c):
            raise LiftError(f"PE header mismatch: machine {machine:#x} with optional header {magic:#x}")
        self.g32 = machine == 0x14c
        if pe64:
            self.imagebase = u64(opt + 24)
            ddir = opt + 112
            ndirs = u32(opt + 108)
            self.stack_reserve, self.stack_commit = u64(opt + 72), u64(opt + 80)
        else:
            self.imagebase = u32(opt + 28)
            ddir = opt + 96
            ndirs = u32(opt + 92)
            self.stack_reserve, self.stack_commit = u32(opt + 72), u32(opt + 76)
        self.large_address = bool(u16(coff + 18) & 0x20)
        self.entry_rva = u32(opt + 16)
        self.sizeofimage = u32(opt + 56)
        self.sizeofheaders = u32(opt + 60)
        self.subsystem = u16(opt + 68)
        self.dllchar = u16(opt + 70)
        dirs = [(u32(ddir + 8 * i), u32(ddir + 8 * i + 4)) for i in range(min(ndirs, 16))]
        dirs += [(0, 0)] * (16 - len(dirs))
        self.dirs = dirs
        ib = self.imagebase

        # ---- what kind of program is this? (routing) ----
        if dirs[14][0]:
            raise NotNativeCode(
                ".NET assembly: this file contains IL bytecode, not CPU instructions, so "
                "there is nothing for a machine-code recompiler to translate. Use "
                "`recomp.py dotnet FILE -o OUT` (IL -> C# with ILSpy) instead")
        self.is_dll = bool(u16(coff + 18) & 0x2000)
        self.relocs_stripped = bool(u16(coff + 18) & 0x0001) or not dirs[5][0]
        if self.is_dll:
            self.notes.append("this is a DLL: it is rebuilt as a DLL with the same exports")

        secs = opt + optsz
        self.sections = []
        for i in range(nsec):
            b = secs + 40 * i
            name = d[b:b + 8].rstrip(b"\0").decode(errors="replace")
            vsize, rva, rawsize, rawoff = u32(b + 8), u32(b + 12), u32(b + 16), u32(b + 20)
            ch = u32(b + 36)
            self.sections.append((name, rva, vsize, rawoff, rawsize, ch))
        self.rva2off = lambda rva: next((ro + rva - r for _, r, vs, ro, rs, _ in self.sections
                                         if r <= rva < r + max(vs, rs)), None)

        # segments: headers + every section, all at imagebase + rva
        flen = len(d)
        self.segments.append({"vaddr": ib, "memsz": self.sizeofheaders,
                              "foff": 0, "fsize": min(self.sizeofheaders, flen), "flags": 4})
        for name, rva, vsize, rawoff, rawsize, ch in self.sections:
            memsz = vsize or rawsize
            fo = min(rawoff, flen)
            fsize = max(0, min(rawsize, memsz, flen - fo)) if rawoff else 0
            fl = (4 if ch & 0x40000000 else 0) | (2 if ch & 0x80000000 else 0) | (1 if ch & 0x20000000 else 0)
            self.segments.append({"vaddr": ib + rva, "memsz": memsz, "foff": fo, "fsize": fsize,
                                  "flags": fl, "name": name})
            if ch & 0x20000000 and fsize:
                self.code.append((ib + rva, fo, fsize, name))
        self.entry = ib + self.entry_rva if self.entry_rva else 0
        if self.entry:
            self.funcs[self.entry] = "entry"

        def cstr(rva):
            o = self.rva2off(rva)
            if o is None:
                return "?"
            e = d.find(b"\0", o)
            return d[o:e if e >= 0 else len(d)].decode(errors="replace")

        # exports: (ordinal, name or None, rva, forwarder "dll.func" or None)
        erva, esz = dirs[0]
        self.exports = []
        self.dllname = None
        if erva and self.rva2off(erva) is not None:
            e = self.rva2off(erva)
            self.dllname = cstr(u32(e + 12))
            obase, nfun, nnames = u32(e + 16), u32(e + 20), u32(e + 24)
            afun, anames, aords = u32(e + 28), u32(e + 32), u32(e + 36)
            names = {}
            for k in range(nnames):
                names[u16(self.rva2off(aords) + 2 * k)] = cstr(u32(self.rva2off(anames) + 4 * k))
            for ordi in range(nfun):
                fo = self.rva2off(afun + 4 * ordi)
                frva = u32(fo) if fo is not None else 0
                if not frva:
                    continue
                fwd = cstr(frva) if erva <= frva < erva + esz else None
                self.exports.append((obase + ordi, names.get(ordi), frva, fwd))
                if not fwd:
                    sec = next((x for x in self.sections if x[1] <= frva < x[1] + max(x[2], x[4])), None)
                    if sec and sec[5] & 0x20000000:      # only code exports are functions
                        self.funcs[ib + frva] = names.get(ordi) or f"ordinal_{obase + ordi}"
                    else:
                        self.datasyms[ib + frva] = names.get(ordi) or f"ordinal_{obase + ordi}"

        # imports (for logs and the report; the runtime resolves them itself)
        irva, _ = dirs[1]
        if irva and self.rva2off(irva) is not None:
            o = self.rva2off(irva)
            while True:
                oft, name_rva, ft = u32(o), u32(o + 12), u32(o + 16)
                if not name_rva:
                    break
                dll = cstr(name_rva)
                thunks = oft or ft
                k = 0
                tsz = 8 if pe64 else 4      # size of one thunk (= one pointer of the program)
                while True:
                    to = self.rva2off(thunks + tsz * k)
                    if to is None:
                        break
                    v = u64(to) if pe64 else u32(to)
                    if not v:
                        break
                    fn = f"#{v & 0xFFFF}" if v >> (tsz * 8 - 1) else cstr((v & 0x7FFFFFFF) + 2)
                    slot = ib + ft + tsz * k
                    self.imports.append((dll, fn, slot))
                    self.datasyms[slot] = f"__imp_{dll}!{fn}"
                    k += 1
                o += 20

        # .pdata: exact start/end of every function (x64 unwind info)
        prva, psz = dirs[3]
        self.pdata = []
        if machine == 0x8664 and prva and self.rva2off(prva) is not None:
            o = self.rva2off(prva)
            for k in range(psz // 12):
                b0, e0 = u32(o + 12 * k), u32(o + 12 * k + 4)
                if b0 and e0 > b0:
                    self.pdata.append((ib + b0, ib + e0))
                    self.funcs.setdefault(ib + b0, f"sub_{ib + b0:x}")

        # Base relocations: every absolute address stored in the file has one.
        # A relocated pointer-sized value that points into an executable
        # section is a function pointer (vtable slot, callback table, a jump
        # table of a switch, ...): an indirect call/jump target that no
        # instruction names directly. (64-bit: DIR64, 32-bit: HIGHLOW.)
        rrva, rsz = dirs[5]
        ro = self.rva2off(rrva) if rrva and not self.relocs_stripped else None
        rtype, rlen = (10, 8) if pe64 else (3, 4)
        if ro is not None and self.code:
            lo_hi = [(c[0], c[0] + c[2]) for c in self.code]
            end = min(ro + rsz, len(d))
            while ro + 8 <= end:
                page, size = u32(ro), u32(ro + 4)
                if size < 8:
                    break
                for k in range((size - 8) // 2):
                    e = u16(ro + 8 + 2 * k)
                    if e >> 12 != rtype:
                        continue
                    at = self.rva2off(page + (e & 0xFFF))
                    if at is None or at + rlen > len(d):
                        continue
                    v = u64(at) if pe64 else u32(at)
                    for a, b in lo_hi:
                        if a <= v < b:
                            self.code_ptrs.add(v)
                            break
                ro += size
            if self.code_ptrs:
                self.notes.append(f"{len(self.code_ptrs)} code addresses found in data through "
                                  f"relocations (vtables/callbacks), decoded as function starts")
        elif self.g32 and self.code:
            # Most 32-bit exes have no relocation table. Their function
            # pointers are found by looking: every aligned 4-byte value in a
            # data section that is an address inside the code, and the jump
            # tables of `jmp [table + reg*4]` (compilers put those in the code
            # section). A wrong guess only costs some extra decoded
            # instructions: nothing is ever executed because of it.
            self.guess_ptrs = True
            self._guess_code_ptrs(u32)
            if self.code_ptrs:
                self.notes.append(f"no relocation table: {len(self.code_ptrs)} values in data and jump tables "
                                  f"look like code addresses, decoded as function starts")

        self.resources = self._resources(dirs[2][0], u16, u32)

        # TLS callbacks run before the entry point
        trva, _ = dirs[9]
        self.tls_callbacks = []
        if trva and self.rva2off(trva) is not None:
            t = self.rva2off(trva)
            cb_va = u64(t + 24) if pe64 else u32(t + 12)
            co = self.rva2off(cb_va - ib) if cb_va else None
            while co is not None and co + (8 if pe64 else 4) <= len(d):
                v = u64(co) if pe64 else u32(co)
                if not v:
                    break
                self.tls_callbacks.append(v)
                self.funcs.setdefault(v, f"tls_callback_{len(self.tls_callbacks)}")
                co += 8 if pe64 else 4

        # COFF symbol table (MinGW binaries keep it unless stripped)
        if symptr and nsyms and symptr < len(d):
            strtab = symptr + 18 * nsyms
            k = 0
            while k < nsyms:
                s = symptr + 18 * k
                if s + 18 > len(d):
                    break
                if d[s:s + 4] == b"\0\0\0\0":
                    so = strtab + u32(s + 4)
                    e = d.find(b"\0", so)
                    nm = d[so:e if e >= 0 else len(d)].decode(errors="replace")
                else:
                    nm = d[s:s + 8].rstrip(b"\0").decode(errors="replace")
                val, secno, typ, cls, naux = u32(s + 8), struct.unpack_from("<h", d, s + 12)[0], \
                    u16(s + 14), d[s + 16], d[s + 17]
                if 0 < secno <= len(self.sections) and cls in (2, 3) and nm and not nm.startswith("."):
                    sname, srva, _, _, _, ch = self.sections[secno - 1]
                    va = ib + srva + val
                    if ch & 0x20000000 and (typ & 0x30) == 0x20:
                        self.funcs[va] = nm          # real names beat sub_xxx
                    elif not ch & 0x20000000:
                        self.datasyms.setdefault(va, nm)
                k += 1 + naux
        sub = {1: "native", 2: "GUI", 3: "console"}.get(self.subsystem, str(self.subsystem))
        self.notes.append(f"PE image base {ib:#x}, {len(self.sections)} sections, subsystem {sub}, "
                          f"{len(self.imports)} imports, {len(self.pdata)} .pdata functions, "
                          f"{len(self.tls_callbacks)} TLS callbacks")
        if any(n.lower() in (".vmp0", ".vmp1", ".themida", ".enigma1", ".denuvo") for n, *_ in self.sections):
            self.notes.append("WARNING: protector sections found (VMProtect/Themida/Enigma/Denuvo). "
                              "Protected code is virtualized/encrypted; the result will not be the game's logic")


# --------------------------------------------------------------------------
# disassembly + lifting
# --------------------------------------------------------------------------

class Insn:
    __slots__ = ("addr", "length", "text", "ops", "raw")

    def __init__(self, addr, length, text, ops, raw):
        self.addr, self.length, self.text, self.ops, self.raw = addr, length, text, ops, raw


START, CONT = 1, 2   # coverage map values: first byte / later byte of an instruction

_GPR64 = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
          "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]
_GPR32 = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]


def decode_vex_gather(b, bits):
    """(length, Ghidra-style text) for a VEX-encoded AVX2 gather
    (VPGATHERDD/DQ/QD/QQ, VGATHERDPS/DPD/QPS/QPD), or None. Ghidra's 32-bit
    decoder rejects some of them (no base register: [disp32 + ymm*s]), so the
    lifter decodes these itself; gather_c() then emits them."""
    if len(b) < 6 or b[0] != 0xC4:
        return None
    b1, b2, opc = b[1], b[2], b[3]
    if b1 & 0x1F != 2 or b2 & 3 != 1 or opc not in (0x90, 0x91, 0x92, 0x93):
        return None                      # not map 0F38 / prefix 66 / a gather
    R, X, B = (~b1 >> 7) & 1, (~b1 >> 6) & 1, (~b1 >> 5) & 1
    W, vvvv, L = (b2 >> 7) & 1, (~b2 >> 3) & 15, (b2 >> 2) & 1
    if bits == 32:
        R = X = B = 0
        vvvv &= 7
    modrm, pos = b[4], 5
    mod, reg, rm = modrm >> 6, ((modrm >> 3) & 7) | (R << 3), modrm & 7
    if mod == 3 or rm != 4:
        return None                      # gathers always have a VSIB memory operand
    sib = b[pos]; pos += 1
    scale, idx, base = 1 << (sib >> 6), ((sib >> 3) & 7) | (X << 3), sib & 7
    disp = 0
    if mod == 0 and base == 5:
        if len(b) < pos + 4:
            return None
        disp = int.from_bytes(b[pos:pos + 4], "little", signed=True); pos += 4
        base_name = None
    else:
        base_name = (_GPR64 if bits == 64 else _GPR32)[base | (B << 3)]
        if mod == 1:
            disp = int.from_bytes(b[pos:pos + 1], "little", signed=True); pos += 1
        elif mod == 2:
            disp = int.from_bytes(b[pos:pos + 4], "little", signed=True); pos += 4
    qidx = opc in (0x91, 0x93)
    fp = opc in (0x92, 0x93)
    esz = 8 if W else 4
    mn = ("VGATHER" if fp else "VPGATHER") + ("Q" if qidx else "D") + \
         (("PD" if W else "PS") if fp else ("Q" if W else "D"))
    vl = "YMM" if L else "XMM"
    # register widths: dword data with qword index fills only half a register
    dst_v = "XMM" if (qidx and esz == 4) else vl
    idx_v = "XMM" if (not qidx and esz == 8) else vl
    if bits == 32:
        disp &= 0xFFFFFFFF
    terms = ([base_name] if base_name else []) + [f"{idx_v}{idx}*{scale:#x}"]
    if disp:
        terms.append(f"{disp:#x}" if disp > 0 else f"-{-disp:#x}")
    text = f"{mn} {dst_v}{reg}, {'qword' if esz == 8 else 'dword'} ptr [{' + '.join(terms)}], {dst_v}{vvvv}"
    return pos, text


_FMA_OPS = {}
for _k, _kind in ((0x96, "ADDSUB"), (0x97, "SUBADD"), (0x98, "ADD"), (0x9A, "SUB"), (0x9C, "NMADD"), (0x9E, "NMSUB")):
    for _j, _form in ((0, "132"), (0x10, "213"), (0x20, "231")):
        _FMA_OPS[_k + _j] = (_kind, _form, False)
        if _kind not in ("ADDSUB", "SUBADD"):
            _FMA_OPS[_k + _j + 1] = (_kind, _form, True)      # scalar (SS/SD)


def decode_vex_fma(b, bits, addr):
    """decoded VEX FMA instruction (VFMADD/VFMSUB/VFNMADD/VFNMSUB/VFMADDSUB/
    VFMSUBADD, 132/213/231, PS/PD/SS/SD) as a dict, or None. Ghidra's 32-bit
    x86 decoder has no FMA at all; the lifter emits these itself (fma_c)."""
    if len(b) < 5 or b[0] != 0xC4:
        return None
    b1, b2, opc = b[1], b[2], b[3]
    if b1 & 0x1F != 2 or b2 & 3 != 1 or opc not in _FMA_OPS:
        return None
    kind, form, scalar = _FMA_OPS[opc]
    R, X, B = (~b1 >> 7) & 1, (~b1 >> 6) & 1, (~b1 >> 5) & 1
    W, vvvv, L = (b2 >> 7) & 1, (~b2 >> 3) & 15, (b2 >> 2) & 1
    if bits == 32:
        R = X = B = 0
        vvvv &= 7
    modrm, pos = b[4], 5
    mod, reg, rm = modrm >> 6, ((modrm >> 3) & 7) | (R << 3), modrm & 7
    gpr = _GPR64 if bits == 64 else _GPR32
    mem = None
    if mod == 3:
        src3 = rm | (B << 3)
    else:
        src3 = None
        base = index = None
        scale, disp, rip = 1, 0, False
        if rm == 4:
            if len(b) <= pos:
                return None
            sib = b[pos]; pos += 1
            scale, ix, bs = 1 << (sib >> 6), ((sib >> 3) & 7) | (X << 3), sib & 7
            if ix != 4:
                index = gpr[ix]
            if mod == 0 and bs == 5:
                if len(b) < pos + 4:
                    return None
                disp = int.from_bytes(b[pos:pos + 4], "little", signed=True); pos += 4
            else:
                base = gpr[bs | (B << 3)]
        elif mod == 0 and rm == 5:
            if len(b) < pos + 4:
                return None
            disp = int.from_bytes(b[pos:pos + 4], "little", signed=True); pos += 4
            rip = bits == 64                 # 64-bit: RIP-relative; 32-bit: absolute
        else:
            base = gpr[rm | (B << 3)]
        if mod == 1:
            disp = int.from_bytes(b[pos:pos + 1], "little", signed=True); pos += 1
        elif mod == 2:
            disp = int.from_bytes(b[pos:pos + 4], "little", signed=True); pos += 4
        if rip:
            disp, base = disp + addr + pos, None
        mem = {"base": base, "index": index, "scale": scale, "disp": disp}
    esz = 8 if W else 4
    vl = 16 if (scalar or not L) else 32
    vn = "YMM" if vl == 32 else "XMM"
    mn = f"V{'FN' + kind[1:] if kind.startswith('N') else 'FM' + kind}{form}{'S' if scalar else 'P'}{'D' if W else 'S'}"
    if mem:
        t = ([mem["base"]] if mem["base"] else []) + ([f"{mem['index']}*{mem['scale']:#x}"] if mem["index"] else [])
        if mem["disp"] or not t:
            t.append(f"{mem['disp']:#x}" if mem["disp"] >= 0 else f"-{-mem['disp']:#x}")
        width = esz if scalar else vl
        op3 = f"{({4: 'dword', 8: 'qword', 16: 'xmmword', 32: 'ymmword'})[width]} ptr [{' + '.join(t)}]"
    else:
        op3 = f"{vn}{src3}"
    return {"len": pos, "text": f"{mn} {vn}{reg}, {vn}{vvvv}, {op3}", "kind": kind, "form": form,
            "scalar": scalar, "esz": esz, "vl": vl, "dst": f"XMM{reg}", "src2": f"XMM{vvvv}",
            "src3": f"XMM{src3}" if src3 is not None else None, "mem": mem}


class _SynVn:
    __slots__ = ("size",)

    def __init__(self, size):
        self.size = size


class _SynOp:
    """stand-in for the IMARK p-code op of an instruction decoded by recomp itself"""
    __slots__ = ("opcode", "inputs", "output")

    def __init__(self, length):
        self.opcode, self.inputs, self.output = O.IMARK, [_SynVn(length)], None


class CodeMap:
    """Which bytes of the code were decoded as instructions, kept in files on
    disk (one byte per code byte, memory-mapped) instead of a Python dict of
    instruction objects. A dict with P-code for every instruction is what used
    to need many GB of RAM for big programs; this needs none - the OS pages
    the map in and out as needed.

    Instructions are not stored: decode(addr) re-translates one instruction
    from the mapped file when the C for it is written."""

    def __init__(self, img, ctx, workdir):
        self.img, self.ctx, self.workdir = img, ctx, workdir
        os.makedirs(workdir, exist_ok=True)
        self.regions = []   # [base, foff, size, name, map, file]
        for i, (base, foff, size, name) in enumerate(sorted(img.code)):
            if size <= 0:
                continue
            fn = os.path.join(workdir, f"cov_{i:03d}.bin")
            fh = open(fn, "w+b")
            fh.truncate(size)
            m = mmap.mmap(fh.fileno(), size, access=mmap.ACCESS_WRITE)
            self.regions.append([base, foff, size, name, m, fh])
        self.count = 0
        # Instructions that start inside the bytes of another decoded
        # instruction but are real control-flow targets (a direct jump/call
        # lands there). The one-byte-per-byte map can't hold them, so they are
        # kept here: {addr: length}. Rare (obfuscation, prefix-skipping jumps,
        # padding before a function that has no .pdata entry).
        self.extra = {}
        self.calls = set()      # ARM64: targets of direct calls (chunks start there)
        self.synthetic = {}     # addr -> text of instructions recomp decoded itself
        self.synthetic_info = {}  # addr -> decoded fields (FMA) for the emitter

    def close(self):
        for r in self.regions:
            r[4].close()
            r[5].close()
        self.regions = []
        shutil.rmtree(self.workdir, ignore_errors=True)

    def region_of(self, a):
        for r in self.regions:
            if r[0] <= a < r[0] + r[2]:
                return r
        return None

    def window(self, r, off):
        """bytes of one instruction starting at region offset off"""
        foff, size = r[1], r[2]
        return self.img.raw[foff + off:foff + min(off + MAX_INSN_BYTES, size)]

    def translate(self, r, off):
        try:
            tx = self.ctx.translate(self.window(r, off), r[0] + off, 0, 0, 1)
            ops = list(tx.ops)
            if not ops or ops[0].opcode != O.IMARK:
                raise ValueError
            return ops
        except Exception:
            bits = 64 if "64" in self.img.lang else 32
            win = bytes(self.window(r, off))
            if self.img.a64:
                from . import a64
                s = a64.synthetic_decode(win) if not off & 3 else None
                if s is not None:
                    self.synthetic[r[0] + off] = s[1]
                    return [_SynOp(s[0])]
                raise
            g = decode_vex_gather(win, bits)
            if g is not None:
                self.synthetic[r[0] + off] = g[1]
                return [_SynOp(g[0])]
            f = decode_vex_fma(win, bits, r[0] + off)
            if f is not None:
                self.synthetic[r[0] + off] = f["text"]
                self.synthetic_info[r[0] + off] = f
                return [_SynOp(f["len"])]
            raise

    def __iter__(self):
        """(addr, length) of every instruction, in address order (overlapping
        extra instructions merged in, so the address table stays sorted)"""
        if not self.extra:
            return self._iter_main()
        return heapq.merge(self._iter_main(), sorted(self.extra.items()))

    def _iter_main(self):
        for r in self.regions:
            base, size, m = r[0], r[2], r[4]
            off = m.find(b"\x01")
            while off >= 0:
                ln = 1
                while off + ln < size and m[off + ln] == CONT:
                    ln += 1
                if off + ln == size:
                    # the last instruction of a region can be longer than the
                    # bytes left (the decoder pads); keep its real length
                    ln = self.translate(r, off)[0].inputs[0].size
                yield base + off, ln
                off = m.find(b"\x01", off + ln)

    def decode(self, addr, ln):
        """full instruction (text, P-code, bytes) - only while emitting its C"""
        r = self.region_of(addr)
        off = addr - r[0]
        ops = self.translate(r, off)
        if addr in self.synthetic:
            raw = self.img.raw[r[1] + off:r[1] + min(off + ln, r[2])]
            return Insn(addr, ln, self.synthetic[addr], [], bytes(raw))
        try:
            dd = self.ctx.disassemble(self.window(r, off), addr, 0, 0, 1).instructions[0]
            text = f"{dd.mnem} {dd.body}".strip()
        except Exception:
            text = "?"
        raw = self.img.raw[r[1] + off:r[1] + min(off + ln, r[2])]
        return Insn(addr, ln, text, ops[1:], bytes(raw))


def decode_error(e):
    """the decoder's own words for why bytes are not an instruction"""
    t = str(e).strip().splitlines()[0] if str(e).strip() else ""
    name = type(e).__name__
    if name == "ValueError" and not t:
        return "decoder produced no instruction"
    return f"{name}: {t}" if t else name


def discover(img: Image, ctx: pypcode.Context, report, workdir):
    """1) recursive descent from every known function start (symbols, exports,
    .pdata, entry, TLS callbacks): decode until an unconditional jump/return,
    and also decode every DIRECT jump/call target found on the way. Direct
    targets are certainly instructions too - e.g. leaf functions, which have
    no .pdata entry. A target that lands inside an instruction decoded
    earlier is kept as an extra, overlapping instruction instead of lost;
    2) linear sweep over all remaining executable bytes, so that jump tables
    and function pointers to unknown functions still land on lifted code.
    Results go to a disk-backed CodeMap, not to RAM."""
    cm = CodeMap(img, ctx, workdir)
    conflicts = 0
    bad_count = 0
    ranges = []        # undecodable byte ranges: [addr, first bytes, length, decoder error]
    MAX_RANGES = 200000
    path_bad = []      # decode failures on a control-flow path: (addr, error, from, start)

    truncated = False

    def note_bad(a, byte, err):
        nonlocal bad_count, truncated
        bad_count += 1
        if ranges and ranges[-1][0] + ranges[-1][2] == a:
            if len(ranges[-1][1]) < 64:
                ranges[-1][1].append(byte)
            ranges[-1][2] += 1
        elif len(ranges) < MAX_RANGES:
            ranges.append([a, [byte], 1, err])
        else:
            truncated = True
    last_err = [""]

    sweep_targets = []
    # 32-bit program without relocations: a 4-byte constant in an instruction
    # that is an address inside the code is probably a function pointer
    # (`push offset callback`, `mov [obj], offset method`)
    guess = getattr(img, "guess_ptrs", False)
    guessed = []
    # 64-bit: `lea reg, [rip+function]` takes the address of a function that
    # is then only called through a pointer (callbacks, once-initializers).
    # Such a function has no call instruction naming it and, as a leaf, no
    # .pdata entry either. It must be decoded from its own first byte: when
    # the linear sweep reaches it from data placed before it (a jump table),
    # the sweep is out of step and the real first instruction is never lifted.
    lea_ptrs = not getattr(img, "g32", False)
    # ARM64: every instruction is 4 bytes at an address that is a multiple of
    # 4, so the sweep moves in steps of 4 and can't get out of step; and a
    # 64-bit constant is half an address (ADRP), not a pointer
    a64 = getattr(img, "a64", False) or img.lang.startswith("AARCH64")
    step = 4 if a64 else 1
    if a64:
        lea_ptrs = False
    code_lo = min((r[0] for r in cm.regions), default=0)
    code_hi = max((r[0] + r[2] for r in cm.regions), default=0)

    def decode_run(r, off):
        nonlocal conflicts
        size, cov = r[2], r[4]
        while off < size:
            if cov[off] or (r[0] + off) in cm.extra:
                if cov[off] and cov[off] != START:
                    conflicts += 1
                return
            try:
                ops = cm.translate(r, off)
            except Exception as e:
                last_err[0] = decode_error(e)
                return off  # caller decides what to do with undecodable byte
            ln = ops[0].inputs[0].size
            if any(cov[off:off + ln]):
                conflicts += 1
                return
            end = min(off + ln, size)
            cov[off] = START
            if end > off + 1:
                cov[off + 1:end] = bytes([CONT]) * (end - off - 1)
            cm.count += 1
            # code found by the sweep (e.g. reached only through a jump table)
            # can still call functions nothing else points to: queue them
            for op in ops[1:]:
                oc = op.opcode
                if (oc == O.BRANCH or oc == O.CBRANCH or oc == O.CALL) and \
                        op.inputs[0].space.name != "const":
                    sweep_targets.append((op.inputs[0].offset, r[0] + off))
                    if a64 and oc == O.CALL:
                        cm.calls.add(op.inputs[0].offset)
                elif lea_ptrs and oc == O.COPY:
                    v = op.inputs[0]
                    if v.size == 8 and v.space.name == "const" and code_lo <= v.offset < code_hi:
                        sweep_targets.append((v.offset, r[0] + off))
            off += ln
        return

    def descend(r, off, work, frm=None):
        """decode one control-flow path; direct targets go onto `work` as
        (target, address of the instruction that names it)"""
        nonlocal conflicts
        base, size, cov = r[0], r[2], r[4]
        start = base + off
        while off < size:
            c = cov[off]
            if c == START or (base + off) in cm.extra:
                return                      # joined code that is already decoded
            try:
                ops = cm.translate(r, off)
            except Exception as e:
                # code that is really reached (a known function, a jump/call
                # target, or the fall-through of one) can't be decoded: unlike
                # sweep noise this will crash if it runs. The sweep counts the
                # bytes; this keeps how the path got here.
                if c == 0 and len(path_bad) < MAX_RANGES:
                    path_bad.append((base + off, decode_error(e), frm, start))
                return
            ln = ops[0].inputs[0].size
            end = min(off + ln, size)
            if c == 0 and not any(cov[off + 1:end]):
                cov[off] = START
                if end > off + 1:
                    cov[off + 1:end] = bytes([CONT]) * (end - off - 1)
            else:
                # starts inside, or runs into, an instruction decoded earlier
                conflicts += 1
                cm.extra[base + off] = ln
            cm.count += 1
            here, stop = base + off, False
            for op in ops[1:]:
                oc = op.opcode
                if oc == O.BRANCH or oc == O.CBRANCH or oc == O.CALL:
                    t = op.inputs[0]
                    if t.space.name == "const":
                        continue            # p-code-relative jump inside this instruction
                    work.append((t.offset, here))
                    if a64 and oc == O.CALL:
                        cm.calls.add(t.offset)
                    # BRANCH to itself is REP's loop, not the end of the path
                    if oc == O.BRANCH and t.offset != here:
                        stop = True
                elif oc == O.BRANCHIND or oc == O.RETURN:
                    stop = True
                elif guess and (oc == O.COPY or oc == O.STORE):
                    v = op.inputs[-1]
                    if v.size == 4 and code_lo <= v.offset < code_hi and v.space.name == "const":
                        guessed.append((v.offset, -3))
                elif lea_ptrs and oc == O.COPY:
                    v = op.inputs[0]
                    if v.size == 8 and v.space.name == "const" and code_lo <= v.offset < code_hi:
                        guessed.append((v.offset, -3))
            if stop:
                return
            off += ln

    def run_descent(work):
        while work:
            s, frm = work.pop()
            r = cm.region_of(s)
            if r and not (a64 and s & 3):
                descend(r, s - r[0], work, frm)

    # frm < 0 marks how a path's start is known: -1 symbol/export/.pdata/entry,
    # -2 code pointer stored in data (relocation), -3 guessed code pointer
    run_descent([(a, -1) for a in sorted(set(img.funcs), reverse=True)])
    # then everything data points at (vtables, callback tables): reached
    # only by indirect calls, so no instruction names these addresses
    run_descent([(a, -2) for a in sorted(getattr(img, "code_ptrs", ()), reverse=True)])
    while guessed:
        work, guessed[:] = sorted(set(guessed), reverse=True), []
        run_descent(work)
    seeded = cm.count
    # Sweep the bytes nothing reached, then follow the direct jump/call
    # targets the sweep found, and repeat until nothing new turns up.
    # Undecodable bytes are reported once (the first pass sees them all).
    first = True
    while True:
        for r in cm.regions:
            size, cov = r[2], r[4]
            off = 0
            while off < size:
                # jump to the next byte nobody decoded yet (fast, in C)
                nxt = cov.find(b"\x00", off)
                if nxt < 0:
                    break
                off = nxt
                if (r[0] + off) in cm.extra:
                    off += 1
                    continue
                if step > 1 and (r[0] + off) % step:
                    off += step - (r[0] + off) % step       # (bytes left over after an instruction)
                    continue
                res = decode_run(r, off)
                if isinstance(res, int):
                    if first:
                        for k in range(res, min(res + step, size)):
                            note_bad(r[0] + k, img.raw[r[1] + k], last_err[0])
                    off = res + step
                else:
                    while off < size and not cov[off]:
                        off += 1
        first = False
        if not sweep_targets:
            break
        before = cm.count
        work, sweep_targets[:] = sorted(set(sweep_targets), reverse=True), []
        run_descent(work)
        if cm.count == before:
            break
    report["decode"] = {"instructions": cm.count, "from_known_functions": seeded,
                        "from_linear_sweep": cm.count - seeded,
                        "undecodable_bytes": bad_count, "overlap_conflicts": conflicts,
                        "overlap_kept": len(cm.extra)}
    report["undecodable"] = [(x[0], bytes(x[1]).hex() + ("" if x[2] == len(x[1]) else f"... ({x[2]} bytes)"))
                             for x in ranges[:1000]]
    report["undecodable_truncated"] = truncated or len(ranges) > 1000
    # full detail for diagnostics.jsonl (not written into lift_report.json)
    report["_bad_ranges"] = ranges
    report["_bad_paths"] = path_bad
    return cm


# --------------------------------------------------------------------------
# C emission
# --------------------------------------------------------------------------

def cident(s):
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    return s if not s[:1].isdigit() else "_" + s


def cstring(s):
    """a C string literal, pure ASCII: anything else (symbol names from a
    binary can hold any bytes) becomes an octal escape of its UTF-8 bytes"""
    out = []
    for b in s.encode("utf-8", "replace"):
        if b == 0x22 or b == 0x5C:
            out.append("\\" + chr(b))
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03o}")
    return '"' + "".join(out) + '"'


# x87 instructions that run on the host's own FPU (g32): Ghidra's model of
# them is only approximate (FPREM as divide/truncate/multiply, FYL2X through a
# log2() op, FXAM without the class bits, ...), and programs print the results.
X87_HOST = {"FPREM", "FPREM1", "FYL2X", "FYL2XP1", "FSIN", "FCOS", "FSINCOS", "FPTAN", "FPATAN",
            "F2XM1", "FSCALE", "FXTRACT", "FXAM", "FRNDINT"}
# integer p-code ops on 9..64 byte values without a 128-bit C type (g32: rt_wide)
WIDE_OPS = {"INT_ADD", "INT_SUB", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR", "INT_NEGATE", "INT_2COMP",
            "INT_ZEXT", "INT_SEXT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_SLESS",
            "INT_SLESSEQUAL", "INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM", "INT_LEFT", "INT_RIGHT",
            "INT_SRIGHT", "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "POPCOUNT", "LZCOUNT"}
# an instruction with one of these can raise a CPU exception or leave the
# chunk: it records its address first (ctx->cur, read by the fault handler:
# a Windows __try/__except scope is found by the faulting instruction's
# address, and crash reports name it). RECOMP_FAULT_ADDR=0 turns it off for
# 64-bit programs (a little faster; faults then can't reach __except).
CUR_OPS = None
# Dead flag writes: an x86 instruction updates up to six status flags, and
# usually the next one overwrites them before anything reads them. Those
# writes are left out (RECOMP_DEAD_FLAGS=0 keeps every one).
DEAD_FLAGS = os.environ.get("RECOMP_DEAD_FLAGS", "1") != "0"
# At a CALL the six status flags are dead: every x86 calling convention
# treats them as scratch and none passes a value through them (DF is not
# among them). RECOMP_FLAGS_ABI=0 treats a call like any other exit.
FLAGS_ABI = os.environ.get("RECOMP_FLAGS_ABI", "1") != "0"
FAULT_ADDR = os.environ.get("RECOMP_FAULT_ADDR", "1") != "0"


class Emitter:
    MAX_SITES = 60          # unsupported sites kept in memory for the report

    def __init__(self, ctx, codemap, funcs, sites_file=None, g32=False, a64=None):
        global CUR_OPS
        if CUR_OPS is None:
            CUR_OPS = {O.LOAD, O.STORE, O.INT_DIV, O.INT_SDIV, O.INT_REM, O.INT_SREM, O.CALLOTHER,
                       O.CALL, O.CALLIND, O.BRANCHIND, O.RETURN}
        self.ctx = ctx
        self.cm = codemap
        self.funcs = funcs
        # g32: the program is a 32-bit Windows program and the generated C is
        # compiled as 32-bit code (no __int128; see rt_win32.c for the rest)
        self.g32 = g32
        reg = ctx.registers
        self.st_off = [reg[f"ST{i}"].offset for i in range(8)] if "ST7" in reg else []
        self.fs_off = reg["FS_OFFSET"].offset if "FS_OFFSET" in reg else -1
        self.fpu_ctl = {(reg[n].offset) for n in ("FPUControlWord", "MXCSR") if n in reg}
        self.sites_file = sites_file    # every unsupported site is streamed here
        self.regnames = {}
        for name, vn in ctx.registers.items():
            self.regnames.setdefault((vn.offset, vn.size), name)
        self.flag_offs = {reg[n].offset for n in ("CF", "PF", "AF", "ZF", "SF", "OF") if n in reg}
        # ARM64 shared library (a64.py): addresses in the C are relative to
        # where the library is loaded (GA(...)), every instruction is one
        # 4-byte slot, and some instructions are emitted as themselves
        self.a64 = a64
        self.aconsts = ()       # constants of the current instruction that are addresses
        if a64 is not None:
            self.flag_offs = set(a64.flag_offs)
            self.starts = set(funcs) | codemap.calls
        else:
            self.starts = funcs
        self.flags_dropped = self.flags_kept = 0
        self.used_regs = {}
        self.max_unique = 0
        self.userops = {}        # name -> id
        self.userop_sites = {}   # name -> [first 5 addrs]
        self.userop_count = {}   # name -> number of sites
        self.unsupported = {}    # reason -> count
        self.unsup_all = []      # (addr, asm, reason, bytes) for diagnostics.jsonl
        self.unsup_sites = []    # first MAX_SITES (addr, asm, reason)
        self.unsup_total = 0
        self.cur_text = ""

    # ---- varnodes -------------------------------------------------------
    def ptr(self, vn, tmp):
        """C expression for a uint8_t* to the varnode's storage"""
        sp = vn.space.name
        if sp == "register":
            nm = self.regnames.get((vn.offset, vn.size))
            if nm:
                nm = cident(nm)
                self.used_regs[nm] = vn.offset
                return f"r{nm}"
            return f"(R+{vn.offset:#x})"
        if sp == "unique":
            self.max_unique = max(self.max_unique, vn.offset + vn.size)
            return f"(U+{vn.offset:#x})"
        if sp == "ram":
            if self.a64 is not None:
                return f"((uint8_t*)(uintptr_t)GA({vn.offset:#x}ULL))"
            return f"((uint8_t*)(uintptr_t){vn.offset:#x}ULL)"
        if sp == "const":
            tmp.append(vn)
            if vn.offset in self.aconsts:
                return f"KP(GA({vn.offset:#x}ULL))"
            return f"KP({vn.offset:#x}ULL)"
        raise LiftError(f"unknown address space {sp}")

    def rd(self, vn, tmp):
        if vn.space.name == "const":
            if vn.offset in self.aconsts:
                return f"GA({vn.offset:#x}ULL)"
            return f"{vn.offset:#x}ULL"
        return f"L({self.ptr(vn, tmp)},{vn.size})"

    def rd128(self, vn, tmp):
        if vn.space.name == "const":
            return f"((u128){vn.offset:#x}ULL)"
        return f"L16({self.ptr(vn, tmp)},{vn.size})"

    def fail(self, w, reason):
        self.unsupported[reason] = self.unsupported.get(reason, 0) + 1
        self.unsup_total += 1
        if len(self.unsup_sites) < self.MAX_SITES:
            self.unsup_sites.append((self.cur_addr, self.cur_text, reason))
        raw = getattr(self, "cur_raw", b"")
        if len(self.unsup_all) < 200000:
            self.unsup_all.append((self.cur_addr, self.cur_text, reason, raw))
        if self.sites_file:
            self.sites_file.write(f"{self.cur_addr:#x}\t{self.cur_text}\t{reason}\t{raw.hex()}\n")
        w(f"rt_unsupported(ctx,{cstring(reason)},{self.cur_addr:#x}ULL);")

    # ---- one p-code op ----------------------------------------------------
    def op(self, insn, i, op, in_chunk, out):
        tmp = []
        oc = op.opcode
        o = op.output
        a = op.inputs
        w = out.append
        A = insn.addr

        def jump_to(vn, idx):
            if vn.space.name == "const":       # relative p-code op inside this instruction
                rel = vn.offset
                if rel >= 1 << 31:
                    rel -= 1 << 32
                return f"goto P{A - self.lbase:x}_{idx + rel};"
            t = vn.offset
            if t in in_chunk:
                return f"goto I{t - self.lbase:x};"
            if self.a64 is not None:
                return f"G_({t:#x})"
            return f"{{ pc = {t:#x}ULL; goto OUT; }}"

        def st(expr):
            expr = strip_outer(expr)        # a call argument needs no outer ( )
            if o.size <= 8:
                w(f"S({self.ptr(o, tmp)},{expr},{o.size});")
            elif o.size == 16:
                w(f"S16({self.ptr(o, tmp)},{expr},16);")
            else:
                raise LiftError(f"{oc.name} with {o.size}-byte result")

        big = max([v.size for v in a] + ([o.size] if o else [])) > 8
        sz0 = a[0].size if a else 0
        wlim = 8 if self.g32 else 16        # widest value the C integer types hold

        if self.g32 and oc == O.INT_ADD and o.size == 4 and \
                a[0].space.name == "register" and a[0].offset == self.fs_off and \
                a[1].space.name == "const" and a[1].offset == 0x2C:
            # fs:[0x2C] is TEB.ThreadLocalStoragePointer: static TLS
            # (__declspec(thread)) goes through the runtime's own array of TLS
            # blocks, where each rebuilt module has its slot
            st("(uint32_t)(uintptr_t)&ctx->tls_array")
        elif oc == O.COPY:
            if a[0].space.name == "const" and o.size <= 8:
                st(self.rd(a[0], tmp))
            else:
                w(f"memcpy({self.ptr(o, tmp)},{self.ptr(a[0], tmp)},{o.size});")
        elif oc == O.LOAD:
            w(f"memcpy({self.ptr(o, tmp)},(void*)(uintptr_t){self.rd(a[1], tmp)},{o.size});")
        elif oc == O.STORE:
            w(f"memcpy((void*)(uintptr_t){self.rd(a[1], tmp)},{self.ptr(a[2], tmp)},{a[2].size});")
        elif oc == O.BRANCH or oc == O.CALL:
            w(jump_to(a[0], i))
        elif oc == O.CBRANCH:
            w(f"if ({self.rd(a[1], tmp)}) {jump_to(a[0], i)}")
        elif oc == O.RETURN and self.g32:
            # a return may go to native code (the program was called by
            # Windows): the runtime has to know it is a return, not a call
            w(f"pc = {self.rd(a[0], tmp)} | RT_RETFLAG; goto OUT;")
        elif oc == O.RETURN and self.a64 is not None:
            # a RET may go back to native code (the function was called by the
            # system): the runtime has to know it is a return, not a call
            w(f"xr = 1; pc = {self.rd(a[0], tmp)}; goto DISPATCH;")
        elif oc in (O.BRANCHIND, O.CALLIND, O.RETURN):
            w(f"pc = {self.rd(a[0], tmp)}; goto DISPATCH;")
        elif oc == O.CALLOTHER and self.a64 is not None and a[0].getUserDefinedOpName() in self.a64.nop_ops:
            pass
        elif oc == O.CALLOTHER:
            name = a[0].getUserDefinedOpName()
            uid = self.userops.setdefault(name, len(self.userops))
            sites = self.userop_sites.setdefault(name, [])
            if len(sites) < 5:
                sites.append(A)
            self.userop_count[name] = self.userop_count.get(name, 0) + 1
            ins = a[1:]
            ps = ",".join(self.ptr(v, tmp) for v in ins) or "0"
            ss = ",".join(str(v.size) for v in ins) or "0"
            optr = self.ptr(o, tmp) if o else "0"
            osz = o.size if o else 0
            w(f"{{ static const int z[]={{{ss}}}; const uint8_t* p[]={{{ps}}}; "
              f"rt_callother(ctx,{uid},{A:#x}ULL,{optr},{osz},{len(ins)},p,z); }}")
            # A VEX/EVEX instruction that writes an XMM/YMM register zeroes the
            # rest of the vector register; Ghidra's p-code for some of them
            # (vpsrldq, vpsllq, vpsrad, ...) writes only the low part.
            if o is not None and "_avx" in name and o.space.name == "register" and o.size < 64:
                rn = self.regnames.get((o.offset, o.size), "")
                if rn.startswith("XMM") or rn.startswith("YMM"):
                    w(f"memset((R+{o.offset + o.size:#x}),0,{64 - o.size});")
        elif oc == O.PIECE:
            p = self.ptr(o, tmp)
            w(f"{{ uint8_t t[{o.size}]; memcpy(t,{self.ptr(a[1], tmp)},{a[1].size}); "
              f"memcpy(t+{a[1].size},{self.ptr(a[0], tmp)},{a[0].size}); memcpy({p},t,{o.size}); }}")
        elif oc == O.SUBPIECE:
            c = a[1].offset
            n = max(0, min(o.size, a[0].size - c))
            p = self.ptr(o, tmp)
            w(f"{{ uint8_t t[{o.size}]={{0}}; memcpy(t,{self.ptr(a[0], tmp)}+{c},{n}); memcpy({p},t,{o.size}); }}")
        elif oc in (O.INT_AND, O.INT_OR, O.INT_XOR) and o.size > 8:
            opch = {O.INT_AND: "&", O.INT_OR: "|", O.INT_XOR: "^"}[oc]
            w(f"{{ uint8_t x[{o.size}],y[{o.size}]; memcpy(x,{self.ptr(a[0], tmp)},{o.size}); "
              f"memcpy(y,{self.ptr(a[1], tmp)},{o.size}); for(int k=0;k<{o.size};k++) x[k]{opch}=y[k]; "
              f"memcpy({self.ptr(o, tmp)},x,{o.size}); }}")
        elif oc == O.INT_NEGATE and o.size > 8:
            w(f"{{ uint8_t x[{o.size}]; memcpy(x,{self.ptr(a[0], tmp)},{o.size}); "
              f"for(int k=0;k<{o.size};k++) x[k]=~x[k]; memcpy({self.ptr(o, tmp)},x,{o.size}); }}")
        elif oc in (O.INT_EQUAL, O.INT_NOTEQUAL) and sz0 > wlim:
            eq = "==" if oc == O.INT_EQUAL else "!="
            w(f"S({self.ptr(o, tmp)},(memcmp({self.ptr(a[0], tmp)},{self.ptr(a[1], tmp)},{sz0}) {eq} 0),1);")
        elif oc == O.INT_ZEXT and o.size > wlim:
            w(f"{{ uint8_t t[{o.size}]={{0}}; memcpy(t,{self.ptr(a[0], tmp)},{sz0}); "
              f"memcpy({self.ptr(o, tmp)},t,{o.size}); }}")
        elif oc in (O.INT_LEFT, O.INT_RIGHT, O.INT_SRIGHT) and o.size > wlim:
            kind = {O.INT_LEFT: 0, O.INT_RIGHT: 1, O.INT_SRIGHT: 2}[oc]
            w(f"WSHIFT({self.ptr(o, tmp)},{self.ptr(a[0], tmp)},{o.size},{self.rd(a[1], tmp) if a[1].size <= 8 else 'L(' + self.ptr(a[1], tmp) + ',8)'},{kind});")
        elif oc.name.startswith("FLOAT_"):
            self.float_op(op, tmp, w, st)
        elif big and self.g32:
            if oc.name not in WIDE_OPS or max([v.size for v in a] + [o.size]) > 64:
                raise LiftError(f"{oc.name} on {max(v.size for v in a)}-byte values")
            b = a[1] if len(a) > 1 else a[0]
            w(f"rt_wide(W_{oc.name},{self.ptr(o, tmp)},{o.size},{self.ptr(a[0], tmp)},{a[0].size},"
              f"{self.ptr(b, tmp)},{b.size});")
        elif big:
            self.int_op(op, tmp, w, st, wide=True)
        else:
            self.int_op(op, tmp, w, st, wide=False)

    def int_op(self, op, tmp, w, st, wide):
        oc, o, a = op.opcode, op.output, op.inputs
        if wide and max([v.size for v in a] + [o.size]) > 16:
            raise LiftError(f"{oc.name} on {max(v.size for v in a)}-byte values")
        if wide and self.a64 is not None and oc in (O.INT_DIV, O.INT_REM, O.INT_SDIV, O.INT_SREM):
            raise LiftError(f"{oc.name} on 16-byte values")     # (would need a compiler support library)
        rd = (lambda v: self.rd128(v, tmp)) if wide else (lambda v: self.rd(v, tmp))
        T = "u128" if wide else "uint64_t"
        SX = "SX16" if wide else "SX"
        s0 = a[0].size
        bits = s0 * 8
        x = rd(a[0])
        y = rd(a[1]) if len(a) > 1 else None
        sx = lambda e, s: f"{SX}({e},{s})"
        m = {
            O.INT_ADD: f"({x}+{y})", O.INT_SUB: f"({x}-{y})", O.INT_MULT: f"({x}*{y})",
            O.INT_AND: f"({x}&{y})", O.INT_OR: f"({x}|{y})", O.INT_XOR: f"({x}^{y})",
            O.INT_NEGATE: f"(~{x})", O.INT_2COMP: f"(-{x})",
            O.INT_ZEXT: f"({x})",
            O.INT_SEXT: f"(({T}){sx(x, s0)})",
            O.INT_EQUAL: f"({x}=={y})", O.INT_NOTEQUAL: f"({x}!={y})",
            O.INT_LESS: f"({x}<{y})", O.INT_LESSEQUAL: f"({x}<={y})",
            O.INT_SLESS: f"({sx(x, s0)}<{sx(y, s0)})", O.INT_SLESSEQUAL: f"({sx(x, s0)}<={sx(y, s0)})",
            O.INT_DIV: f"({x}/{y})", O.INT_REM: f"({x}%{y})",
            O.INT_SDIV: f"(({T})({sx(x, s0)}/{sx(y, s0)}))", O.INT_SREM: f"(({T})({sx(x, s0)}%{sx(y, s0)}))",
            O.BOOL_NEGATE: f"(!{x})", O.BOOL_AND: f"({x}&&{y})", O.BOOL_OR: f"({x}||{y})",
            O.BOOL_XOR: f"(({x}!=0)^({y}!=0))",
            O.INT_LEFT: f"(({y})>={bits}?0:({T})({x}<<({y})))",
            O.INT_RIGHT: f"(({y})>={bits}?0:({x}>>({y})))",
            O.INT_SRIGHT: f"(({T})(({y})>={bits}?({sx(x, s0)}<0?-1:0):({sx(x, s0)}>>({y}))))",
            O.INT_CARRY: f"((({x}+{y})&MASK{'16' if wide else ''}({s0}))<{x})",
            O.INT_SCARRY: f"CARRYS{'16' if wide else ''}({x},{y},{s0})",
            O.INT_SBORROW: f"BORROWS{'16' if wide else ''}({x},{y},{s0})",
            O.POPCOUNT: f"POPC{'16' if wide else ''}({x})",
            O.LZCOUNT: f"LZC{'16' if wide else ''}({x},{s0})",
        }
        if oc not in m:
            self.fail(w, f"p-code op {oc.name}")
            return
        st(m[oc])

    def float_op(self, op, tmp, w, st):
        oc, o, a = op.opcode, op.output, op.inputs
        F = {4: "float", 8: "double", 10: "long double", 16: "long double"}
        # the values that are floating point (e.g. half precision, 2 bytes,
        # has no C type here: that instruction becomes a reported failure)
        if oc == O.FLOAT_INT2FLOAT:
            fvals = [o]
        elif oc in (O.FLOAT_TRUNC, O.FLOAT_EQUAL, O.FLOAT_NOTEQUAL, O.FLOAT_LESS, O.FLOAT_LESSEQUAL, O.FLOAT_NAN):
            fvals = list(a)
        elif getattr(O, "FLOAT_FLOAT2INT", None) is not None and oc == O.FLOAT_FLOAT2INT:
            fvals = list(a)
        else:
            fvals = [o] + list(a)
        for v in fvals:
            if v is not None and v.size not in F:
                raise LiftError(f"{oc.name} on a {v.size}-byte floating-point value")

        def fr(v):
            if v.size not in F:
                raise LiftError(f"{v.size}-byte floating point value")
            return f"LF{v.size}({self.ptr(v, tmp)})"

        def fw(expr):
            if o.size not in F:
                raise LiftError(f"{o.size}-byte floating point result")
            w(f"SF{o.size}({self.ptr(o, tmp)},{expr});")

        x = fr(a[0]) if oc != O.FLOAT_INT2FLOAT else None
        y = fr(a[1]) if len(a) > 1 else None
        if oc == O.FLOAT_ADD: fw(f"({x}+{y})")
        elif oc == O.FLOAT_SUB: fw(f"({x}-{y})")
        elif oc == O.FLOAT_MULT: fw(f"({x}*{y})")
        elif oc == O.FLOAT_DIV: fw(f"({x}/{y})")
        elif oc == O.FLOAT_NEG: fw(f"(-{x})")
        elif oc == O.FLOAT_ABS: fw(f"fabsl({x})")
        elif oc == O.FLOAT_SQRT: fw(f"(({F[o.size]})sqrtl({x}))" if o.size > 8 else
                                    (f"sqrtf({x})" if o.size == 4 else f"sqrt({x})"))
        elif oc == O.FLOAT_CEIL: fw(f"ceill({x})")
        elif oc == O.FLOAT_FLOOR: fw(f"floorl({x})")
        elif oc == O.FLOAT_ROUND:
            x87 = 1 if self.cur_text.upper().startswith("F") else 0
            fw(f"FROUND({x},{x87})")
        elif oc == O.FLOAT_NAN: st(f"(uint64_t)isnan({x})")
        elif oc == O.FLOAT_EQUAL: st(f"(uint64_t)({x}=={y})")
        elif oc == O.FLOAT_NOTEQUAL: st(f"(uint64_t)({x}!={y})")
        elif oc == O.FLOAT_LESS: st(f"(uint64_t)({x}<{y})")
        elif oc == O.FLOAT_LESSEQUAL: st(f"(uint64_t)({x}<={y})")
        elif oc == O.FLOAT_FLOAT2FLOAT: fw(f"(({F[o.size]}){x})")
        elif oc == O.FLOAT_TRUNC:
            # Ghidra lifts CVTPS2DQ/CVTSS2SI/CVTSD2SI/CVTPD2DQ as truncation, but
            # the CPU rounds them by the MXCSR rounding mode (round-to-nearest
            # by default: 2.7 -> 3). Only the CVTT* forms truncate.
            mn = self.cur_text.split()[0].upper() if self.cur_text else ""
            if mn.lstrip("V").startswith("CVT") and not mn.lstrip("V").startswith("CVTT") and not mn.startswith("F"):
                mx = self.ctx.registers["MXCSR"].offset
                w("extern long double rt_rint_mx(long double, uint32_t);")
                st(f"TRUNCF(rt_rint_mx({x},(uint32_t)L((R+{mx:#x}),4)),{o.size})")
            else:
                st(f"TRUNCF({x},{o.size})")
        elif oc == O.FLOAT_INT2FLOAT: fw(f"(({F[o.size]})SX({self.rd(a[0], tmp)},{a[0].size}))")
        else:
            self.fail(w, f"p-code op {oc.name}")

    # ---- dead status flags -------------------------------------------------------
    def dead_flags(self, addrs, insns):
        """{instruction address: set of flag offsets whose writes can be left out}.
        Backward liveness over the instructions of one chunk. Everything that
        leaves the chunk (any call, return, indirect jump, a jump to another
        chunk, the end of a run of instructions) counts as reading every flag,
        so only writes that are certainly overwritten inside the chunk go.
        An instruction keeps all writes of a flag it also reads, and an
        instruction with an internal loop (REP) kills nothing."""
        F = self.flag_offs
        if not DEAD_FLAGS or not F:
            return {}
        in_chunk = set(addrs)
        info = {}
        for k, ad in enumerate(addrs):
            ins = insns[ad]
            reads, writes, succ = set(), set(), []
            exits, internal, falls, call = False, False, True, False
            for op in ins.ops:
                for v in op.inputs:
                    if v.space.name == "register":
                        for f in F:
                            if v.offset <= f < v.offset + v.size:
                                reads.add(f)
                o = op.output
                if o is not None and o.space.name == "register":
                    for f in F:
                        if o.offset <= f < o.offset + o.size:
                            writes.add(f)
                oc = op.opcode
                if oc in (O.BRANCH, O.CBRANCH):
                    t = op.inputs[0]
                    if t.space.name == "const":
                        internal = True
                    elif t.offset in in_chunk:
                        succ.append(t.offset)
                    else:
                        exits = True
                    if oc == O.BRANCH and t.space.name != "const":
                        falls = False
                elif oc in (O.CALL, O.CALLIND) and FLAGS_ABI:
                    call = True
                    falls = False
                elif oc == O.RETURN and FLAGS_ABI and self.a64 is not None:
                    call = True         # (AAPCS64: NZCV means nothing across a call or a return)
                    falls = False
                elif oc in (O.CALL, O.CALLIND, O.BRANCHIND, O.RETURN):
                    exits = True
                    falls = False
            nxt = ad + ins.length
            if self.a64 is not None:
                reads.update(self.a64.flag_reads(ins))
            if falls:
                if k + 1 < len(addrs) and addrs[k + 1] == nxt:
                    succ.append(nxt)
                else:
                    exits = True
            kills = set() if internal else writes - reads
            if call and not exits:
                kills = set(F)           # nothing after the call sees these flags
            info[ad] = (reads, kills, succ, exits, writes)
        live_in = {ad: set() for ad in addrs}
        changed = True
        while changed:
            changed = False
            for ad in reversed(addrs):
                reads, kills, succ, exits, _ = info[ad]
                out = set(F) if exits else set()
                for t in succ:
                    out |= live_in[t]
                new = reads | (out - kills)
                if new != live_in[ad]:
                    live_in[ad] = new
                    changed = True
        plan = {}
        for ad in addrs:
            reads, kills, succ, exits, writes = info[ad]
            out = set(F) if exits else set()
            for t in succ:
                out |= live_in[t]
            dead = writes - out - reads
            if dead:
                plan[ad] = dead
        return plan

    # ---- FMA ----------------------------------------------------------------------
    def fma_plan(self, ops):
        """VFMADD/VFMSUB/VFNMADD/VFNMSUB/VFMADDSUB/VFMSUBADD: Ghidra writes each
        lane as FLOAT_MULT (+ FLOAT_NEG) + FLOAT_ADD/SUB, which rounds twice;
        the CPU rounds once. Returns {consumer index: {"c": C line, "skip":
        indices}} fusing every such chain into one rt_fma()/rt_fmaf() call. Ghidra
        reuses one temporary for every lane, so a chain is fused only if no
        later op reads a skipped temporary before it is written again."""
        def key(v):
            return (v.space.name, v.offset, v.size)

        def read_later(k, start):
            for op in ops[start:]:
                if any(key(v) == k for v in op.inputs):
                    return True
                if op.output is not None and key(op.output) == k:
                    return False
            return False
        prod, plan = {}, {}
        for i, op in enumerate(ops):
            oc = op.opcode
            ins_keys = [key(v) for v in op.inputs]
            # the fused call reads the multiply's inputs at the add: drop a
            # pending product if anything in between overwrites one of them
            # (the op that consumes a product may overwrite its inputs: it runs as the fused call)
            if op.output is not None and prod:
                ok_ = key(op.output)
                for pk in [pk for pk, pv in prod.items()
                           if ok_ in (key(pv[0]), key(pv[1])) and pk not in ins_keys]:
                    del prod[pk]
            if oc == O.FLOAT_MULT and op.output is not None and op.output.space.name == "unique" \
                    and op.output.size in (4, 8):
                prod[key(op.output)] = (op.inputs[0], op.inputs[1], False, [i], [key(op.output)])
                continue
            if oc == O.FLOAT_NEG and ins_keys[0] in prod and op.output.space.name == "unique":
                x, y, neg, sk, ks = prod.pop(ins_keys[0])
                prod[key(op.output)] = (x, y, not neg, sk + [i], ks + [key(op.output)])
                continue
            if oc in (O.FLOAT_ADD, O.FLOAT_SUB) and op.output is not None and op.output.size in (4, 8) \
                    and (ins_keys[0] in prod or ins_keys[1] in prod):
                a0, a1 = op.inputs
                if ins_keys[0] in prod:
                    x, y, neg, sk, ks = prod.pop(ins_keys[0]); c, negc = a1, oc == O.FLOAT_SUB
                else:
                    x, y, neg, sk, ks = prod.pop(ins_keys[1]); c, negc = a0, False
                    if oc == O.FLOAT_SUB:
                        neg = not neg       # c - x*y
                if any(read_later(k, i + 1) for k in ks):
                    continue
                sz = op.output.size
                fn = "rt_fmaf" if sz == 4 else "rt_fma"
                tmp = []
                xs = f"LF{sz}({self.ptr(x, tmp)})"
                ys = f"LF{sz}({self.ptr(y, tmp)})"
                cs = f"LF{sz}({self.ptr(c, tmp)})"
                expr = f"{fn}({'-' if neg else ''}{xs},{ys},{'-' if negc else ''}{cs})"
                plan[i] = {"c": f"SF{sz}({self.ptr(op.output, tmp)},{expr});", "skip": sk}
                continue
            # anything else that reads a pending product: it is needed as is
            for k in ins_keys:
                prod.pop(k, None)
            if op.output is not None:
                prod.pop(key(op.output), None)
        if plan:
            self.fma_count = getattr(self, "fma_count", 0) + len(plan)
        return plan

    def fma_c(self, f):
        """C for an FMA instruction decoded by decode_vex_fma: one rt_fma per lane"""
        reg = self.ctx.registers
        T, LF, SF = ("float", "LF4", "SF4") if f["esz"] == 4 else ("double", "LF8", "SF8")
        fn = "rt_fmaf" if f["esz"] == 4 else "rt_fma"
        E = f["esz"]
        n = 1 if f["scalar"] else f["vl"] // E
        d, s2 = reg[f["dst"]].offset, reg[f["src2"]].offset
        lines = [f"{{ uint8_t f_r[64]; memcpy(f_r, R+{d:#x}, 64); const uint8_t *f_2 = R+{s2:#x}, *f_3;"]
        m = f["mem"]
        if m:
            parts = []
            if m["base"]:
                parts.append(f"L((R+{reg[m['base']].offset:#x}),{reg[m['base']].size})")
            if m["index"]:
                parts.append(f"L((R+{reg[m['index']].offset:#x}),{reg[m['index']].size})*{m['scale']}ULL")
            parts.append(f"(uint64_t)({m['disp']}LL)")
            amask = "0xffffffffULL" if self.g32 else "0xffffffffffffffffULL"
            lines.append(f"  f_3 = (const uint8_t*)(uintptr_t)(({' + '.join(parts)}) & {amask});")
        else:
            lines.append(f"  f_3 = R+{reg[f['src3']].offset:#x};")
        lines.append(f"  const uint8_t *f_d = R+{d:#x};")
        for k in range(n):
            o = k * E
            x, y, z = f"{LF}(f_d+{o})", f"{LF}(f_2+{o})", f"{LF}(f_3+{o})"
            a, b_, c = {"132": (x, z, y), "213": (y, x, z), "231": (y, z, x)}[f["form"]]
            kind = f["kind"]
            if kind == "ADDSUB":
                kind = "ADD" if k & 1 else "SUB"
            elif kind == "SUBADD":
                kind = "SUB" if k & 1 else "ADD"
            na = "-" if kind.startswith("N") else ""
            nc = "-" if kind in ("SUB", "NMSUB") else ""
            lines.append(f"  {SF}(f_r+{o},{fn}({na}{a},{b_},{nc}{c}));")
        keep = 16 if f["scalar"] else f["vl"]
        lines.append(f"  memset(f_r+{keep},0,{64 - keep}); memcpy(R+{d:#x}, f_r, 64); }}")
        self.fma_count = getattr(self, "fma_count", 0) + 1
        return lines

    def vpinsrd_fix(self, ins, ops):
        """VPINSRD: Ghidra's p-code tests `imm == 0` for every lane (all four lane
        updates use the first comparison), so only lane 0 can ever be written.
        Keep its p-code up to the COPY of the inserted value (that covers the
        memory form's address and LOAD), then insert into the right lane here.
        Returns (ops to emit, C lines after them) or None."""
        parts = ins.text.split(" ", 1)[1].split(", ") if " " in ins.text else []
        if len(parts) != 4:
            return None
        try:
            imm = int(parts[3], 0) & 3
        except ValueError:
            return None
        reg = self.ctx.registers
        dst, src1 = parts[0].upper(), parts[1].upper()
        if dst not in reg or src1 not in reg:
            return None
        k = next((i for i, op in enumerate(ops) if op.opcode == O.COPY and op.output is not None
                  and op.output.space.name == "unique" and op.output.size == 4), None)
        if k is None:
            return None
        val = self.ptr(ops[k].output, [])
        d, s1 = reg[dst].offset, reg[src1].offset
        self.pinsr_fix = getattr(self, "pinsr_fix", 0) + 1
        return ops[:k + 1], [f"{{ uint8_t pi_t[16]; memcpy(pi_t, R+{s1:#x}, 16); memcpy(pi_t+{imm * 4}, {val}, 4); "
                             f"memcpy(R+{d:#x}, pi_t, 16); memset(R+{d + 16:#x}, 0, 48); }}"]

    # ---- AVX2 gathers -----------------------------------------------------------
    _GATHER_RE = re.compile(r"^V(P?)GATHER([DQ])(D|Q|PS|PD)\s+([XY]MM\d+),\s*\w+\s+ptr\s*\[(.*)\],\s*([XY]MM\d+)\s*$", re.I)

    def gather_c(self, ins):
        """C for VPGATHERDD/DQ/QD/QQ and VGATHERDPS/DPD/QPS/QPD (VEX forms).
        Ghidra's p-code for them adds the whole index vector to the base as one
        wide integer, which is not an address; this emits the real per-lane
        loads instead. Returns None for anything it doesn't recognise (EVEX
        forms with a {k} mask, unusual address shapes) so the normal path - and
        its error reporting - still runs."""
        m = self._GATHER_RE.match(ins.text.strip())
        if not m:
            return None
        _, isz, dsz, dst, addr, msk = m.groups()
        IS = 4 if isz.upper() == "D" else 8
        ES = 4 if dsz.upper() in ("D", "PS") else 8
        reg = self.ctx.registers
        base_reg, idx_reg, scale, disp = None, None, 1, 0
        for t in re.findall(r"[+-]?\s*[^+-]+", addr.replace(" ", "")):
            neg = t.startswith("-")
            t = t.lstrip("+-")
            if "*" in t:
                r_, sc = t.split("*", 1)
                idx_reg, scale = r_.upper(), int(sc, 0)
            elif t.upper() in reg and not t.upper().startswith(("XMM", "YMM")):
                base_reg = t.upper()
            elif t.upper().startswith(("XMM", "YMM")):
                idx_reg = t.upper()
            else:
                try:
                    v = int(t, 0)
                except ValueError:
                    return None
                disp += -v if neg else v
        if idx_reg is None or idx_reg not in reg or dst.upper() not in reg or msk.upper() not in reg:
            return None
        dv, iv, mv = reg[dst.upper()], reg[idx_reg], reg[msk.upper()]
        n = min(dv.size // ES, iv.size // IS)
        bexpr = f"L((R+{reg[base_reg].offset:#x}),{reg[base_reg].size})" if base_reg else "0"
        sx = "(int64_t)(int32_t)" if IS == 4 else "(int64_t)"
        it = "uint32_t" if IS == 4 else "uint64_t"
        amask = "0xffffffffULL" if self.g32 else "0xffffffffffffffffULL"
        self.gather_count = getattr(self, "gather_count", 0) + 1
        return [
            f"{{ uint8_t *g_d = R+{dv.offset:#x}, *g_m = R+{mv.offset:#x}; const uint8_t *g_i = R+{iv.offset:#x}; "
            f"uint64_t g_b = {bexpr}; uint8_t g_r[64]; memcpy(g_r, g_d, 64);",
            f"  for (int g_k = 0; g_k < {n}; g_k++) if (g_m[g_k * {ES} + {ES - 1}] & 0x80) {{ "
            f"{it} g_x; memcpy(&g_x, g_i + g_k * {IS}, {IS}); "
            f"uint64_t g_a = (g_b + (uint64_t)({sx}g_x) * {scale}ULL + (uint64_t)({disp}LL)) & {amask}; "
            f"memcpy(g_r + g_k * {ES}, (const void*)(uintptr_t)g_a, {ES}); }}",
            f"  memset(g_r + {n * ES}, 0, {64 - n * ES}); memcpy(g_d, g_r, 64); memset(g_m, 0, 64); }}",
        ]

    # ---- atomic instructions ---------------------------------------------------
    @staticmethod
    def _overlaps(a, b):
        return a.space.name == b.space.name and a.offset < b.offset + b.size and b.offset < a.offset + a.size

    def atomic_plan(self, ins):
        """For a LOCK-prefixed instruction (or XCHG with memory), decide whether
        it can run as a real atomic compare-and-swap on its own address instead
        of under the runtime's single global lock. Returns None (use the lock)
        or a plan dict. Two shapes:
          "ls"  - memory reached through LOAD/STORE (any [reg+...] operand);
                  the address is captured once at the first LOAD, like the CPU
                  computes the effective address once, so it does not matter if
                  the instruction later overwrites the address register;
          "ram" - memory as a fixed address (a global: [rip+x]); every read of
                  it uses the snapshot and its single write is the CAS.
        Sizes 1/2/4/8, and 16 (CMPXCHG16B) through the runtime's rt_cas16."""
        ops = ins.ops
        loads, stores, rams, ram_writes = [], [], set(), []
        addr, n = None, None
        for i, op in enumerate(ops):
            oc = op.opcode
            if oc == O.CALLOTHER:
                if op.inputs[0].getUserDefinedOpName() in ("LOCK", "UNLOCK"):
                    continue
                return None
            if oc in (O.BRANCHIND, O.CALLIND, O.RETURN):
                return None
            if oc in (O.BRANCH, O.CBRANCH, O.CALL) and op.inputs[0].space.name != "const":
                return None
            if oc == O.LOAD or oc == O.STORE:
                av = op.inputs[1]
                sz = op.output.size if oc == O.LOAD else op.inputs[2].size
                if addr is None:
                    addr, n = av, sz
                elif (av.space.name, av.offset, av.size) != (addr.space.name, addr.offset, addr.size) or sz != n:
                    return None
                (loads if oc == O.LOAD else stores).append(i)
                continue
            for v in op.inputs:
                if v.space.name == "ram":
                    rams.add((v.offset, v.size))
            if op.output is not None and op.output.space.name == "ram":
                rams.add((op.output.offset, op.output.size))
                ram_writes.append(i)
        saves, seen = [], set()
        for op in ops:
            o = op.output
            if o is not None and o.space.name == "register" and (o.offset, o.size) not in seen:
                seen.add((o.offset, o.size))
                saves.append(o)
        if loads or stores:
            if rams or not loads or len(stores) != 1 or n not in (1, 2, 4, 8, 16) \
                    or addr.space.name == "const" or loads[0] > stores[0]:
                return None
            first = loads[0]
            if any(i < first and ops[i].opcode in (O.BRANCH, O.CBRANCH) for i in range(len(ops))):
                return None
            return {"mode": "ls", "first": first, "store": stores[0], "loads": set(loads),
                    "n": n, "saves": saves}
        if len(rams) != 1 or len(ram_writes) != 1:
            return None
        (off, n), = rams
        if n not in (1, 2, 4, 8, 16):
            return None
        return {"mode": "ram", "addr": off, "n": n, "write": ram_writes[0], "saves": saves}

    # ---- chunks -------------------------------------------------------------
    def chunks(self):
        """new chunk at every known function start, at gaps, and every
        MAX_CHUNK instructions. A generator: yields one chunk at a time,
        each a list of (addr, length)."""
        cur, prev_end = [], None
        for ad, ln in self.cm:
            if cur and (ad in self.starts or ad != prev_end or len(cur) >= MAX_CHUNK):
                yield cur
                cur = []
            cur.append((ad, ln))
            prev_end = ad + ln
        if cur:
            yield cur

    def emit_chunk(self, cid, group):
        """returns (C lines, {addr: line index}, [Insn]) for one chunk. The
        instructions are decoded here and dropped after the chunk is written."""
        insns = {}
        for ad, ln in group:
            try:
                insns[ad] = self.cm.decode(ad, ln)
            except Exception:
                raise LiftError(f"instruction at {ad:#x} decoded during discovery but not now")
        addrs = [ad for ad, _ in group]
        in_chunk = set(addrs)
        dead_plan = self.dead_flags(addrs, insns)
        name = self.funcs.get(addrs[0])
        out, where = [], {}
        w = out.append
        w(f"/* ===== chunk {cid}: {name or 'code'} @ {addrs[0]:#x} ({len(addrs)} instructions) ===== */")
        self.lbase = base = addrs[0]
        last = addrs[-1]
        span = last + insns[last].length - base
        # Entry dispatch: a table with one 4-byte entry per byte of the chunk,
        # holding the distance from label OUT to the instruction's label (GCC
        # label differences). Unlike `switch`, whose jump table holds 8-byte
        # absolute addresses that each need a relocation in the .o and in the
        # DLL, this needs no relocations at all - and is the same single jump.
        starts = set(addrs)
        # B_: this chunk's first address (C_(offset) records an instruction's
        # address relative to it); FN_/RU_/TB_/TE_: the same few lines every
        # chunk starts with (macros in the file header)
        w("#undef B_")
        w(f"#define B_ {base:#x}ULL")
        w(f"FN_(c{cid})")
        w("RU_")
        w("DISPATCH:")
        slot = 4 if self.a64 is not None else 1     # ARM64: one entry per instruction slot
        ent = [f"E({o:x})" if (base + o) in starts else "N" for o in range(0, span, slot)]
        w(f"TB_({len(ent)})")
        for j in range(0, len(ent), 64):
            w(",".join(ent[j:j + 64]) + ("," if j + 64 < len(ent) else ""))
        w(f"TE_({len(ent)})")
        w("X: return pc;")
        for k, ad in enumerate(addrs):
            ins = insns[ad]
            nxt = ad + ins.length
            if VERBOSE_C and ad in self.funcs:
                w(f"  /* ---- {self.funcs[ad].replace('*/', '* /')} ---- */")
            where[ad] = len(out)
            if VERBOSE_C:
                w(f"I{ad - self.lbase:x}: /* {ad:#x}: {ins.text.replace('*/', '* /')} */")
                w(f"  pc_here = {ad:#x}ULL; INSN(pc_here);")
            else:
                w(f"I{ad - self.lbase:x}:;")
                if (self.g32 or FAULT_ADDR) and any(o.opcode in CUR_OPS for o in ins.ops):
                    w(f"C_({ad - self.lbase:x});")
            body = []
            ops = ins.ops
            post = []
            mn = ins.text.split(" ")[0].upper()
            if self.st_off and mn in X87_HOST and not self.g32:
                # x87 transcendental/remainder instructions run on the host FPU:
                # bit-exact, and Ghidra models several of them only as opaque
                # ops (fsin, fpatan, ...) or with a lossy formula (FPREM)
                self.x87_host = getattr(self, "x87_host", 0) + 1
                body.append(f"rt_x87(ctx,X87_{mn});")
                ops = []
            self.aconsts = ()
            if self.a64 is not None:
                # instructions that are run as themselves (floating point,
                # SIMD, atomics, system registers): see a64.py
                self.aconsts = self.a64.addr_consts(ins)
                cu = self.a64.custom(ins)
                if cu is not None:
                    body.extend(cu)
                    ops = []
                elif ad in self.cm.synthetic:
                    self.cur_text, self.cur_addr, self.cur_raw = ins.text, ad, ins.raw
                    self.fail(body.append, "instruction of a newer CPU extension")
            if ad in self.cm.synthetic_info:
                body.extend(self.fma_c(self.cm.synthetic_info[ad]))
                ops = []
            elif mn == "VPINSRD":
                fx = self.vpinsrd_fix(ins, ops)
                if fx is not None:
                    ops, post_ = fx
                    post = post_ + post
            elif "GATHER" in mn:
                g = self.gather_c(ins)
                if g is not None:
                    body.extend(g)
                    ops = []
            if self.g32 and self.st_off:
                empty = lambda i: f"memcpy((R+{self.st_off[i]:#x}),RT_X87_EMPTY,10);"
                if mn in X87_HOST:
                    self.x87_host = getattr(self, "x87_host", 0) + 1
                    body.append(f"rt_x87(ctx,X87_{mn});")
                    ops = []
                elif mn in ("EMMS", "FNINIT", "FINIT", "FNSAVE", "FSAVE"):
                    post += [empty(i) for i in range(8)]
                elif mn in ("FFREE", "FFREEP"):
                    m = re.search(r"ST\(?(\d)\)?\s*$", ins.text.upper())
                    body.append(empty(int(m.group(1)) if m else 0))
                if any(o.output is not None and o.output.space.name == "register" and
                       o.output.offset in self.fpu_ctl for o in ops):
                    post.append("rt_fpsync(ctx);")     # the host FPU follows the program's control words
            self.cur_text, self.cur_addr, self.cur_raw = ins.text, ad, ins.raw
            # Atomic instructions: LOCK-prefixed ones (Ghidra marks them with LOCK()/
            # UNLOCK() userops) and XCHG with memory (atomic even without a prefix).
            # The whole instruction runs under the runtime lock; it has exactly one
            # exit (the end label), so the lock can't leak through an inner branch.
            has_lock = any(o.opcode == O.CALLOTHER and
                           o.inputs[0].getUserDefinedOpName() in ("LOCK", "UNLOCK") for o in ins.ops)
            implicit_lock = has_lock or (ins.text.upper().startswith("XCHG") and "ptr" in ins.text)
            # Atomic instructions run as a real compare-and-swap on their own
            # address: read a snapshot, compute, CAS the result back; if another
            # thread changed the value meanwhile, put the registers back and run
            # the instruction again. Only shapes atomic_plan() can't handle
            # (e.g. CMPXCHG16B) still take the runtime's single global lock -
            # with 100 game threads that lock is what made the game freeze.
            plan = self.atomic_plan(ins) if implicit_lock else None
            if plan and plan["n"] == 16 and self.g32:
                plan = None             # (no 16-byte atomics in 32-bit code)
            if plan:
                self.atomic_count = getattr(self, "atomic_count", 0) + 1
                N = plan["n"]
                T = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t", 16: "u128"}[N]
                if N == 16:     # CMPXCHG16B: the runtime's cmpxchg16b helpers
                    LOADF = lambda p: f"rt_atomic_load16((const void*)(uintptr_t)({p}), &a_cur);"
                    CASF = lambda p: f"rt_cas16((void*)(uintptr_t)({p}), &a_exp, &a_new)"
                else:
                    LOADF = lambda p: f"a_cur = __atomic_load_n(({T}*)(uintptr_t)({p}), __ATOMIC_SEQ_CST);"
                    CASF = lambda p: (f"__atomic_compare_exchange_n(({T}*)(uintptr_t)({p}), &a_exp, a_new, 0, "
                                      f"__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)")
                body.append("{")
                if N == 16:
                    body.append("extern void rt_atomic_load16(const void*, void*); "
                                "extern int rt_cas16(void*, void*, const void*);")
                body.append(f"{T} a_old = 0, a_cur = 0; uint64_t a_ptr = 0; (void)a_old; (void)a_ptr;")
                for k, v in enumerate(plan["saves"]):
                    body.append(f"uint8_t a_sv{k}[{v.size}]; memcpy(a_sv{k},{self.ptr(v, [])},{v.size});")
                restore = " ".join(f"memcpy({self.ptr(v, [])},a_sv{k},{v.size});"
                                   for k, v in enumerate(plan["saves"]))
                body.append(f"A{ad - self.lbase:x}:;")
                if plan["mode"] == "ram":
                    a_txt = f"{plan['addr']:#x}ULL"
                    body.append(f"{LOADF(a_txt)} a_old = a_cur;")
                    ram_ptr = f"((uint8_t*)(uintptr_t){plan['addr']:#x}ULL)"
                cas_fail = f"{{ {restore} goto A{ad - self.lbase:x}; }}"
            elif implicit_lock:
                self.locked_count = getattr(self, "locked_count", 0) + 1
                body.append("rt_lock();")
            skip_ops = set()
            fused = self.fma_plan(ops) if mn.startswith(("VFM", "VFNM")) else {}
            for k_ in fused:
                skip_ops.update(fused[k_]["skip"])
            for i, op in enumerate(ops):
                body.append(f"P{ad - self.lbase:x}_{i}:;")
                if i in fused:
                    body.append(fused[i]["c"])
                    continue
                if op.opcode == O.CALLOTHER and op.inputs[0].getUserDefinedOpName() in ("LOCK", "UNLOCK"):
                    continue
                if i in skip_ops:
                    continue
                dead_f = dead_plan.get(ad)
                if dead_f and op.output is not None and op.output.space.name == "register" \
                        and op.output.size == 1 and op.output.offset in dead_f \
                        and op.opcode not in (O.CALLOTHER, O.LOAD):
                    self.flags_dropped += 1
                    continue
                # VPMASKMOVD/Q, VMASKMOVPS/PD to memory: Ghidra computes the
                # full value and STOREs all of it, but the CPU writes only the
                # lanes whose mask bit is set (the others keep their memory).
                if op.opcode == O.CALLOTHER and i + 1 < len(ins.ops):
                    nm = op.inputs[0].getUserDefinedOpName().split("_avx")[0]
                    nx = ins.ops[i + 1]
                    if nm in ("vpmaskmovd", "vpmaskmovq", "vmaskmovps", "vmaskmovpd") and len(op.inputs) == 3 \
                            and nx.opcode == O.STORE and op.output is not None \
                            and (nx.inputs[2].space.name, nx.inputs[2].offset) == (op.output.space.name, op.output.offset):
                        e = 8 if nm in ("vpmaskmovq", "vmaskmovpd") else 4      # (vmaskmovpd: doubles)
                        mp, sp_ = self.ptr(op.inputs[1], []), self.ptr(op.inputs[2], [])
                        body.append(f"{{ uint8_t *mm_d = (uint8_t*)(uintptr_t){self.rd(nx.inputs[1], [])}; "
                                    f"for (int mm_i = 0; mm_i < {op.output.size}; mm_i += {e}) "
                                    f"if ({mp}[mm_i + {e - 1}] & 0x80) memcpy(mm_d + mm_i, {sp_} + mm_i, {e}); }}")
                        skip_ops.add(i + 1)
                        continue
                if plan and plan["mode"] == "ls" and i in plan["loads"]:
                    out_p = self.ptr(op.output, [])
                    if i == plan["first"]:
                        body.append(f"a_ptr = {self.rd(op.inputs[1], [])}; {LOADF('a_ptr')} a_old = a_cur;")
                    body.append(f"memcpy({out_p},&a_cur,{N});")
                    continue
                if plan and plan["mode"] == "ls" and i == plan["store"]:
                    body.append(f"{{ {T} a_new, a_exp = a_old; memcpy(&a_new,{self.ptr(op.inputs[2], [])},{N}); "
                                f"if (!{CASF('a_ptr')}) {cas_fail} a_cur = a_new; }}")
                    continue
                if plan and plan["mode"] == "ram":
                    tmp_body = []
                    try:
                        self.op(ins, i, op, in_chunk, tmp_body)
                    except LiftError as e:
                        self.fail(tmp_body.append, str(e))
                    body.extend(t.replace(ram_ptr, "((uint8_t*)&a_cur)") for t in tmp_body)
                    if i == plan["write"]:
                        body.append(f"{{ {T} a_new = a_cur, a_exp = a_old; "
                                    f"if (!{CASF(a_txt)}) {cas_fail} }}")
                    continue
                try:
                    self.op(ins, i, op, in_chunk, body)
                except LiftError as e:
                    self.fail(body.append, str(e))
                if self.g32 and op.opcode == O.COPY and self.st_off and \
                        op.output.space.name == "register" and op.output.offset == self.st_off[6] and \
                        op.inputs[0].space.name == "register" and op.inputs[0].offset == self.st_off[7]:
                    # the x87 stack was popped (ST6 = ST7 ends the shift): ST7
                    # is empty now. The runtime counts the values on the
                    # stack by this mark when the program calls native code.
                    body.append(f"memcpy((R+{self.st_off[7]:#x}),RT_X87_EMPTY,10);")
            body.append(f"P{ad - self.lbase:x}_{len(ops)}:;")
            body += post
            if plan:
                body.append("}")
            elif implicit_lock:
                body.append("rt_unlock();")
            if VERBOSE_C:
                for line in body:
                    w("  " + line)
            else:
                # keep only the micro-step labels something jumps to
                used = set(_LABEL_RE.findall(" ".join(l for l in body if "goto" in l)))
                for line in body:
                    if line.endswith(":;") and line.startswith("P") and line[:-2] not in used:
                        continue
                    w(line)
            if k + 1 < len(addrs) and addrs[k + 1] == nxt:
                continue
            w(f"G_({nxt:#x})" if self.a64 is not None else f"pc={nxt:#x}ULL;goto OUT;")
        w("OUT:")
        w("  return pc;")
        w("}")
        return out, where, [insns[ad] for ad in addrs]


# Compact spelling of the generated C: the same statements, written shorter
# (macros that expand to exactly what was there before). RECOMP_VERBOSE_C=1
# keeps the long forms.
_RE_S = re.compile(r"^S\((.*),([1248])\);$")
_RE_L = re.compile(r"\bL\((r\w+|\([UR]\+0x[0-9a-f]+\)),([1248])\)")
_RE_CUR = re.compile(r"^ctx->cur = (0x[0-9a-f]+)ULL;$")
_RE_GO = re.compile(r"\{ pc = (0x[0-9a-f]+)ULL; goto OUT; \}|pc=(0x[0-9a-f]+)ULL;goto OUT;")
_RE_U = re.compile(r"\(U\+0x([0-9a-f]+)\)")


def strip_outer(e):
    """(expr) -> expr when the first ( closes at the very end"""
    if len(e) < 2 or e[0] != "(" or e[-1] != ")":
        return e
    d = 0
    for i, c in enumerate(e):
        if c == "(":
            d += 1
        elif c == ")":
            d -= 1
            if d == 0:
                return e[1:-1] if i == len(e) - 1 else e
    return e


COMPACT_C = os.environ.get("RECOMP_COMPACT", "1") != "0"


def compact_line(t):
    if VERBOSE_C or not COMPACT_C:
        return t
    t = _RE_GO.sub(lambda m: f"G_({m.group(1) or m.group(2)});", t)
    t = t.replace("memcpy((void*)(uintptr_t)", "M(A_ ").replace("memcpy(", "M(")
    t = _RE_L.sub(lambda m: f"L{m.group(2)}({m.group(1)})", t)
    m = _RE_S.match(t)
    if m:
        t = f"S{m.group(2)}({m.group(1)});"
    return _RE_U.sub(lambda m: f"U_({m.group(1)})", t)


COMPACT_MACROS = ('/* short forms (see compact_line in lift.py) */\n'
                  '#define M memcpy\n#define A_ (void*)(uintptr_t)\n#define U_(o) (U+0x##o)\n'
                  '#define C_(o) (ctx->cur=B_+0x##o)\n#define G_(a) {pc=a##ULL;goto OUT;}\n'
                  '#define FN_(n) __attribute__((noinline,noclone)) uint64_t n(uint64_t pc, rt_ctx *ctx) {\n'
                  '#define RU_ uint8_t *const R = ctx->R, *const U = ctx->U; uint64_t pc_here = pc; (void)pc_here; (void)U;\n'
                  '#define TB_(n) { static const int T[n] = {\n'
                  '#define TE_(n) }; uint64_t o = pc - B_; if (o >= n##u) return pc; goto *(&&OUT + T[o]); }\n'
                  '#define L1(p) L(p,1)\n#define L2(p) L(p,2)\n#define L4(p) L(p,4)\n#define L8(p) L(p,8)\n'
                  '#define S1(p,v) S(p,v,1)\n#define S2(p,v) S(p,v,2)\n#define S4(p,v) S(p,v,4)\n'
                  '#define S8(p,v) S(p,v,8)\n')

HEADER = ('/* generated by recomp - do not edit, regenerate instead */\n#include "rt.h"\n#include "regs.h"\n' + COMPACT_MACROS +
          '/* entry tables: distance from label OUT to each instruction label */\n'
          '#define E(l) (&&I##l - &&OUT)\n#define N (&&X - &&OUT)\n')

DUMP_REGS = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
             "R12", "R13", "R14", "R15", "FS_OFFSET", "GS_OFFSET",
             "CF", "PF", "AF", "ZF", "SF", "DF", "OF"] + [f"XMM{i}" for i in range(16)]
RREG_NAMES = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "R8", "R9", "R10", "R11",
              "R12", "R13", "R14", "R15", "FS_OFFSET", "GS_OFFSET", "RIP", "FPUControlWord",
              "MXCSR", "CF", "PF", "AF", "ZF", "SF", "DF", "OF", "IF", "TF"] + [f"XMM{i}" for i in range(16)] + \
             ["ST0", "ST1", "FPUStatusWord", "C0", "C1", "C2", "C3"]
# 32-bit x86: the runtime's names for the general registers are the 64-bit
# ones (RREG_RAX is where EAX lives)
REG32 = {"RAX": "EAX", "RBX": "EBX", "RCX": "ECX", "RDX": "EDX", "RSI": "ESI", "RDI": "EDI",
         "RSP": "ESP", "RBP": "EBP", "RIP": "EIP"}
DUMP_REGS32 = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "FS_OFFSET",
               "CF", "PF", "AF", "ZF", "SF", "DF", "OF"] + [f"XMM{i}" for i in range(8)]


def copy_file_into(dst, path):
    with open(path, encoding="utf-8") as src:
        shutil.copyfileobj(src, dst, 1 << 20)


HOST_GAP = 0x10000   # the rebuilt PE file starts this far below the original image


def lift(path, outdir, log=print, base=None, name=None):
    """base: move a PE file to this ImageBase first (see rebase_pe).
    name: file name of the rebuilt program (default: the input's name)"""
    t0 = time.time()
    os.makedirs(outdir, exist_ok=True)
    src, tmp = path, None
    if base is not None:
        probe = Image(path)
        old, fmt = probe.imagebase, probe.format
        probe.close()
        if fmt == "pe" and base != old:
            tmp = os.path.join(outdir, "rebased.tmp")
            n = rebase_pe(path, tmp, base)
            log(f"   moved from ImageBase {old:#x} to {base:#x} ({n} relocations applied)")
            src = tmp
    img = Image(src)
    img.target = name or os.path.basename(path)
    try:
        return _lift(img, path, outdir, log, t0)
    finally:
        img.close()
        if tmp:
            os.remove(tmp)


def _lift(img, path, outdir, log, t0):
    rep = {"input": os.path.abspath(path), "format": img.format, "cpu": img.lang,
           "entry": img.entry, "notes": img.notes}
    log(f"== lift: {path}")
    log(f"   format={img.format} cpu={img.lang} entry={img.entry:#x} "
        f"known functions={len(img.funcs)}")
    for n in img.notes:
        log(f"   {n}")
    if not img.abi_ok:
        log("   WARNING: no runtime for this CPU/OS yet; C is generated but won't run")
    os.makedirs(outdir, exist_ok=True)
    # remove C files from an earlier lift: the number of files can change
    for fn in os.listdir(outdir):
        if re.fullmatch(r"code_\d+\.c|code_\d+\.o", fn):
            os.remove(os.path.join(outdir, fn))
    work = os.path.join(outdir, "work")   # scratch files, deleted at the end
    shutil.rmtree(work, ignore_errors=True)
    ctx = pypcode.Context(img.lang)
    cm = discover(img, ctx, rep, work)
    try:
        return _emit(img, ctx, cm, rep, outdir, work, log, t0)
    finally:
        cm.close()


def _emit(img, ctx, cm, rep, outdir, work, log, t0):
    dr = rep["decode"]
    log(f"   lifted {dr['instructions']} instructions ({dr['from_known_functions']} from known "
        f"functions, {dr['from_linear_sweep']} from sweep, {dr['undecodable_bytes']} "
        f"undecodable bytes, {dr['overlap_conflicts']} overlaps)")

    # Everything below is written straight to disk as it is produced: one
    # chunk of C at a time, the listing row by row, the address table into
    # scratch files that are spliced into tables.c at the end.
    sites_f = open(os.path.join(outdir, "unsupported_sites.tsv"), "w", encoding="utf-8")
    sites_f.write("address\tasm\treason\tbytes\n")
    g32 = img.g32
    a64mod = a64 = None
    if img.a64:
        from . import a64 as a64mod
        a64 = a64mod.A64(ctx, img)
    em = Emitter(ctx, cm, img.funcs, sites_f, g32=g32, a64=a64)
    header = a64mod.header(COMPACT_MACROS) if a64 else HEADER
    amap_f = open(os.path.join(work, "addr_chunk.bin"), "wb") if a64 else None
    files = []
    nchunks = naddr = total_lines = 0
    addrs_f = open(os.path.join(work, "addrs.inc"), "w", encoding="utf-8")
    achunk_f = open(os.path.join(work, "addr_chunk.inc"), "w", encoding="utf-8")
    listing_f = open(os.path.join(outdir, "listing.tsv"), "w", encoding="utf-8")
    listing_f.write("address\tlength\tbytes\tasm\tchunk\tc_source\n")
    cfile, fname, lineno = None, None, 0

    def close_cfile():
        nonlocal cfile, total_lines
        if cfile:
            cfile.close()
            total_lines += lineno - 1
            cfile = None

    try:
        for cid, group in enumerate(em.chunks()):
            if cfile is None or lineno > FILE_LINES:
                close_cfile()
                fname = f"code_{len(files):03d}.c"
                files.append(fname)
                cfile = open(os.path.join(outdir, fname), "w", encoding="utf-8")
                cfile.write(header)
                lineno = header.count("\n") + 1
            lines, where, insns = em.emit_chunk(cid, group)
            lines = [compact_line(t) for t in lines]
            for ins in insns:
                if amap_f:
                    amap_f.write(struct.pack("<QI", ins.addr, cid))
                else:
                    sep = "," if naddr else ""
                    nl = "\n" if naddr % 16 == 0 else ""
                    addrs_f.write(f"{sep}{nl}{ins.addr:#x}")
                    achunk_f.write(f"{sep}{nl}{cid}")
                naddr += 1
                listing_f.write(f"{ins.addr:#x}\t{ins.length}\t{ins.raw.hex()}\t{ins.text}\t{cid}\t"
                                f"{fname}:{lineno + where[ins.addr]}\n")
            cfile.write("\n".join(lines))
            cfile.write("\n")
            lineno += len(lines)
            nchunks += 1
            del lines, where, insns
        close_cfile()
    finally:
        close_cfile()
        for f in (addrs_f, achunk_f, listing_f, sites_f, amap_f):
            if f:
                f.close()
    log(f"   {nchunks} chunks in {len(files)} C files")
    rt_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime")
    if a64:
        return _emit_a64(img, ctx, em, a64mod, rep, outdir, work, rt_dir, files, nchunks, total_lines, log, t0)

    # ---- regs.h ----
    with open(os.path.join(outdir, "regs.h"), "w", encoding="utf-8") as f:
        if g32:
            f.write("/* a 32-bit Windows program, rebuilt as a 32-bit program (rt_win32.c) */\n"
                    "#define RT_GUEST32 1\n")
        f.write("/* register name -> pointer into the register file R[] */\n#ifndef RT_RUNTIME\n")
        for nm, off in sorted(em.used_regs.items(), key=lambda kv: kv[1]):
            f.write(f"#define r{nm} (R+{off:#x})\n")
        f.write("#endif\n")
        x86_32 = "EAX" in ctx.registers and "RAX" not in ctx.registers
        for nm in RREG_NAMES:
            src = REG32.get(nm, nm) if x86_32 else nm
            off = ctx.registers[src].offset if src in ctx.registers else 0
            f.write(f"#define RREG_{nm} {off:#x}\n")
        f.write("void WSHIFT(uint8_t *o, const uint8_t *a, int n, uint64_t s, int kind);\n")

    # ---- image + tables ----
    segs, pos = [], 0
    with open(os.path.join(outdir, "image.bin"), "wb") as f:
        for s in img.segments:
            segs.append((s["vaddr"], s["memsz"], pos, s["fsize"], s["flags"]))
            for k in range(0, s["fsize"], 1 << 23):    # 8 MB at a time
                f.write(img.raw[s["foff"] + k:s["foff"] + min(k + (1 << 23), s["fsize"])])
            pos += s["fsize"]
    syms = {}
    syms.update({a: n for a, n in img.datasyms.items()})
    syms.update(img.funcs)
    rodata = '.section .rdata,\\"dr\\"' if img.format == "pe" else ".section .rodata"
    us = "_" if g32 else ""     # 32-bit Windows: C names get a leading underscore
    with open(os.path.join(outdir, "tables.c"), "w", encoding="utf-8") as f:
        f.write('#include "rt_internal.h"\n')
        f.write(f'__asm__("{rodata}\\n.balign 64\\n.globl {us}rt_image\\n{us}rt_image:\\n'
                '.incbin \\"image.bin\\"\\n.text");\n')
        f.write("extern const uint8_t rt_image[];\n")
        f.write("static const rt_seg t_segs[] = {\n")
        for v, m, o, n, fl in segs:
            f.write(f"  {{{v:#x}ULL,{m:#x}ULL,{o:#x}ULL,{n:#x}ULL,{fl}}},\n")
        f.write("};\n")
        f.write("static const char* const t_opnames[] = {")
        f.write(",".join(cstring(n) for n, _ in sorted(em.userops.items(), key=lambda kv: kv[1])) or "0")
        f.write("};\n")
        for cid in range(nchunks):
            f.write(f"uint64_t c{cid}(uint64_t, rt_ctx*);\n")
        f.write("static rt_chunk_fn const t_chunks[] = {")
        for cid in range(nchunks):
            f.write(("," if cid else "") + ("\n" if cid % 16 == 0 else "") + f"c{cid}")
        f.write("};\n")
        f.write("static const uint64_t t_addrs[] = {")
        copy_file_into(f, os.path.join(work, "addrs.inc"))
        f.write("};\n")
        f.write("static const uint32_t t_addr_chunk[] = {")
        copy_file_into(f, os.path.join(work, "addr_chunk.inc"))
        f.write("};\n")
        f.write("static const rt_sym t_syms[] = {\n")
        for a in sorted(syms):
            f.write(f"  {{{a:#x}ULL,{cstring(syms[a])}}},\n")
        f.write("  {0,0}};\n")
        regs = [(n, ctx.registers[n].offset, ctx.registers[n].size)
                for n in (DUMP_REGS32 if g32 else DUMP_REGS) if n in ctx.registers]
        f.write("static const rt_regdesc t_regs[] = {" +
                ",".join(f'{{"{n}",{o},{s}}}' for n, o, s in regs) + "};\n")
        tls = img.tls_callbacks if img.format == "pe" else []
        f.write("static const uint64_t t_tls[] = {" + (",".join(f"{a:#x}ULL" for a in tls) or "0") + "};\n")
        pe = img.format == "pe"
        if pe:
            f.write("extern uint8_t rt_guest[];\n")
        f.write("rt_module rt_this_module = {\n")
        f.write(f"  .name = {cstring(getattr(img, 'target', os.path.basename(img.path)))}, "
                f".format = {int(pe)}, .is_dll = {int(img.is_dll)},\n")
        f.write(f"  .imagebase = {img.imagebase:#x}ULL, "
                f".sizeofimage = {(img.sizeofimage if pe else 0):#x}ULL, "
                f".hostbase = {(img.imagebase - HOST_GAP if pe else 0):#x}ULL,\n")
        f.write(f"  .entry = {img.entry:#x}ULL, .phdr = {img.phdr:#x}ULL, .phnum = {img.phnum}, "
                f".usize = {em.max_unique + 64:#x}ULL,\n")
        f.write(f"  .image = rt_image, .nsegs = {len(segs)}, .segs = t_segs,\n")
        f.write(f"  .nops = {len(em.userops)}, .opnames = t_opnames, .chunks = t_chunks,\n")
        f.write(f"  .naddr = {naddr}ULL, .addrs = t_addrs, .addr_chunk = t_addr_chunk,\n")
        f.write(f"  .nsyms = {len(syms)}, .syms = t_syms, .nregs = {len(regs)}, .regs = t_regs,\n")
        f.write(f"  .ntls = {len(tls)}, .tls_callbacks = t_tls, .guest = {'rt_guest' if pe else '0'},\n")
        f.write("};\n")
    files.append("tables.c")

    # ---- runtime + Makefile ----
    if not img.abi_ok:
        # no runtime for this CPU/OS: nothing to build (C, listing and report are the output)
        for fn in ("Makefile", "lift.json", "build_lift.py"):
            if os.path.exists(os.path.join(outdir, fn)):
                os.remove(os.path.join(outdir, fn))
        with open(os.path.join(outdir, "ANALYSIS_ONLY.txt"), "w", encoding="utf-8") as f:
            f.write(f"This lift is for analysis: recomp has no runtime for {img.lang} yet, so the C\n"
                    "can be read and searched (code_*.c, listing.tsv, lift_report.txt) but not built\n"
                    "into a working program.\n")
    elif img.format == "pe":
        write_pe_host(img, outdir, rt_dir, files)
    else:
        for fn in ("rt.h", "rt_internal.h", "rt_common.c", "rt_linux.c"):
            shutil.copyfile(os.path.join(rt_dir, fn), os.path.join(outdir, fn))
        files += ["rt_common.c", "rt_linux.c"]
        objs = " ".join(f.replace(".c", ".o") for f in files)
        with open(os.path.join(outdir, "Makefile"), "w", encoding="utf-8") as f:
            f.write("CC = gcc\nCFLAGS ?= -O1 -w -fno-strict-aliasing -fwrapv -fPIE\nCFLAGS += -fno-reorder-blocks-and-partition\n")
            f.write("LDFLAGS = -pie\nOUT = recompiled\n")
            f.write("ifeq ($(TRACE),1)\nCFLAGS += -DRECOMP_TRACE_INSN\nendif\n")
            f.write(f"OBJS = {objs}\n")
            f.write("$(OUT): $(OBJS)\n\t$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm\n")
            f.write("%.o: %.c rt.h regs.h\n\t$(CC) $(CFLAGS) -c $<\n")
            f.write("tables.o rt_common.o rt_linux.o: rt_internal.h\n")
            f.write("tables.o: image.bin\n")
            f.write("clean:\n\trm -f *.o $(OUT)\n")
        cflags = ["-O1", "-w", "-fno-strict-aliasing", "-fwrapv", "-fPIE", "-fno-reorder-blocks-and-partition"]
        ol = objs.split()
        write_build_manifest(outdir, {
            "out": "recompiled", "cc": "gcc",
            "compiles": [{"obj": o, "src": o[:-2] + ".c", "flags": cflags} for o in ol],
            "link": {"prefix": ["-pie", "-o", "recompiled"], "objs": ol, "suffix": ["-lm"]},
            "clean": ["recompiled"]})

    _finish(img, em, rep, outdir, syms, nchunks, len(files) - 3, total_lines, log, t0)
    return outdir


def _emit_a64(img, ctx, em, a64mod, rep, outdir, work, rt_dir, files, nchunks, total_lines, log, t0):
    """the rest of an ARM64 shared library's output: see a64.write_outputs"""
    with open(os.path.join(outdir, "regs.h"), "w", encoding="utf-8") as f:
        f.write("/* an ARM64 shared library, rebuilt as an ARM64 shared library (rt_a64.c) */\n"
                f"#define RT_GLO {img.dynelf.lo:#x}ULL   /* lowest address of the original image */\n"
                "/* register name -> pointer into the register file R[] */\n")
        for nm, off in sorted(em.used_regs.items(), key=lambda kv: kv[1]):
            f.write(f"#define r{nm} (R+{off:#x})\n")

    def chunk_of():
        with open(os.path.join(work, "addr_chunk.bin"), "rb") as f:
            while True:
                b = f.read(12 * 65536)
                if not b:
                    return
                yield from struct.iter_unpack("<QI", b)
    ncode = len(files)
    try:
        info = a64mod.write_outputs(img, em, outdir, rt_dir, files, chunk_of(), nchunks, cstring,
                                    write_build_manifest)
    except ValueError as e:
        raise LiftError(str(e))
    rep["a64"] = info
    for n in info.get("notes", []):
        log(f"   {n}")
    nat = info.get("native_instructions") or {}
    if nat:
        log("   run as themselves: " + ", ".join(f"{v} {k}" for k, v in sorted(nat.items(), key=lambda kv: -kv[1])))
    syms = {}
    syms.update(img.datasyms)
    syms.update(img.funcs)
    _finish(img, em, rep, outdir, syms, nchunks, ncode, total_lines, log, t0)
    log(f"   build it:  python build_lift.py   (in {outdir}; finds or installs the Android compiler)")
    return outdir


def _finish(img, em, rep, outdir, syms, nchunks, ncfiles, total_lines, log, t0):
    # ---- symbols + report ----
    with open(os.path.join(outdir, "symbols.tsv"), "w", encoding="utf-8") as f:
        for a in sorted(syms):
            f.write(f"{a:#x}\t{syms[a]}\n")
    rep.update({"chunks": nchunks, "c_files": ncfiles, "c_lines": total_lines,
                "seconds": round(time.time() - t0, 1),
                "unsupported": em.unsupported,
                "atomic_cas": getattr(em, "atomic_count", 0),
                "atomic_locked": getattr(em, "locked_count", 0),
                "dead_flag_writes_dropped": em.flags_dropped,
                "unsupported_total": em.unsup_total,
                "unsupported_sites": [(f"{a:#x}", t, r) for a, t, r in em.unsup_sites],
                "cpu_ops": {n: [f"{a:#x}" for a in s] +
                            ([f"... {em.userop_count[n]} total"] if em.userop_count[n] > 5 else [])
                            for n, s in em.userop_sites.items()},
                "imports": [(d, n, f"{s:#x}") for d, n, s in img.imports]})
    rep["problems"] = write_diagnostics(outdir, img, rep, em)
    write_report(outdir, rep, img)
    log(f"   wrote {total_lines} lines of C -> {outdir}  ({rep['seconds']}s)")
    miss = rep["problems"].get("cpu_ops_not_in_runtime", {})
    if miss:
        log(f"   {len(miss)} special CPU op(s) the runtime doesn't implement (the program stops if it reaches "
            f"one): {', '.join(sorted(miss)[:12])}{' ...' if len(miss) > 12 else ''}")
    bp = rep["problems"].get("undecodable_on_code_path", 0)
    if bp:
        log(f"   {bp} place(s) on real code paths could not be decoded (they crash if reached): "
            f"see PROBLEMS in lift_report.txt")
    if em.unsupported:
        log(f"   {em.unsup_total} instructions could not be translated "
            f"(they abort with a crash report if ever executed):")
        for k, v in sorted(em.unsupported.items(), key=lambda kv: -kv[1])[:8]:
            log(f"     {v:6d}  {k}")
    log(f"   details: {os.path.join(outdir, 'lift_report.txt')}")


def write_rsrc(resources, outdir):
    """the original file's resources (icon, version info, manifest, dialogs,
    custom data) as a ready-made .rsrc section: rsrc.S (the directory) and
    rsrc.bin (the data, byte for byte as in the original).

    windres is not used: it parses and re-writes every resource, and stops
    (or crashes) on ones that are slightly off, like the version info of
    OVRPlugin.dll. Windows itself is far more tolerant, so the bytes are
    copied unseen."""
    def key(v):         # names first (sorted without case), then ids
        return (0, v.upper(), v) if isinstance(v, str) else (1, v & 0xFFFF, "")
    tree = {}
    for typ, name, lang, data in resources:
        tree.setdefault(typ, {}).setdefault(name, {}).setdefault(lang & 0xFFFF, data)
    types = sorted(tree, key=key)
    # directory tables in the usual order: root, types, names; then the data
    # entries, the name strings and the data
    tables = [[(t, None) for t in types]]
    type_at, name_at = {}, {}
    for t in types:
        type_at[t] = len(tables)
        tables.append([(n, None) for n in sorted(tree[t], key=key)])
    leaves = []
    for t in types:
        for n in sorted(tree[t], key=key):
            name_at[t, n] = len(tables)
            row = []
            for lang in sorted(tree[t][n]):
                row.append((lang, len(leaves)))
                leaves.append(tree[t][n][lang])
            tables.append(row)
    off, pos = [], 0
    for tb in tables:
        off.append(pos)
        pos += 16 + 8 * len(tb)
    leaf_off = pos
    pos += 16 * len(leaves)
    strings, str_off = [], {}
    for tb in tables:
        for ident, _ in tb:
            if isinstance(ident, str) and ident not in str_off:
                str_off[ident] = pos
                raw = ident.encode("utf-16-le")[:2 * 0xFFFF]
                strings.append(struct.pack("<H", len(raw) // 2) + raw)
                pos += len(strings[-1])
    L = ['/* the original file\'s resources, copied byte for byte (see lift.py write_rsrc) */',
         '.section .rsrc,"dw"', '.balign 4']

    def table(k, child):
        tb = tables[k]
        named = sum(1 for ident, _ in tb if isinstance(ident, str))
        L.append(f".long 0, 0\n.short 0, 0, {named}, {len(tb) - named}")
        for ident, leaf in tb:
            idv = 0x80000000 | str_off[ident] if isinstance(ident, str) else ident & 0xFFFF
            to = leaf_off + 16 * leaf if leaf is not None else 0x80000000 | off[child(ident)]
            L.append(f".long {idv:#x}, {to:#x}")
    table(0, lambda t: type_at[t])
    k = 1
    for t in types:
        table(k, lambda n, t=t: name_at[t, n])
        k += 1
    while k < len(tables):
        table(k, None)
        k += 1
    blob, where = bytearray(), []
    for d in leaves:
        blob += b"\0" * (-len(blob) % 8)
        where.append(len(blob))
        blob += d
    for i, d in enumerate(leaves):
        L.append(f".rva .Lres_data + {where[i]:#x}\n.long {len(d):#x}, 0, 0")
    for raw in strings:
        L.append(".byte " + ", ".join(str(x) for x in raw))
    L.append('.balign 8\n.Lres_data:\n.incbin "rsrc.bin"\n.balign 8')
    with open(os.path.join(outdir, "rsrc.bin"), "wb") as f:
        f.write(bytes(blob) or b"\0")
    with open(os.path.join(outdir, "rsrc.S"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    for old in ("resources.res",):
        if os.path.exists(os.path.join(outdir, old)):
            os.remove(os.path.join(outdir, old))


def def_name(n):
    """an export name for a .def file. Always in quotes: C++ names contain @
    and ?, Burst's are hex numbers (a name must not start with a digit) and
    some are .def keywords (DATA, NAME, ...)"""
    return '"' + n.replace('"', '') + '"'


RUNTIME_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime")
RUNTIME_FILES = ("rt.h", "rt_internal.h", "rt_common.c", "rt_linux.c", "rt_win.h", "rt_win.c",
                 "rt_seh.c", "rt_win32.c", "rt_module_win.c", "guest.lds", "guest32.lds")


_KNOWN_OPS = None


def runtime_known_ops():
    """(exact names, name prefixes, SIMD base names) of the CPU ops the
    runtime implements, read from runtime/rt_common.c (resolve_ops and the
    SIMD_OPS list), so a lift can say which ops would stop the program."""
    global _KNOWN_OPS
    if _KNOWN_OPS is None:
        try:
            with open(os.path.join(RUNTIME_DIR, "rt_common.c"), encoding="utf-8") as f:
                src = f.read()
            a = src.index("#define SIMD_OPS")
            b = src.index("#define S_ENUM")
            simd = set(re.findall(r"X\((\w+)\)", src[a:b]))
            r0 = src.index("static void resolve_ops(rt_module *m) {")
            body = src[r0:src.index("\n}\n", r0)]
            exact = set(re.findall(r'!strcmp\(s, "(\w+)"\)', body))
            pref = re.findall(r'!strncmp\(s, "(\w+)", \d+\)', body)
            _KNOWN_OPS = (exact, pref, simd)
        except (OSError, ValueError):
            _KNOWN_OPS = (set(), [], set())
    return _KNOWN_OPS


def op_implemented(name):
    exact, pref, simd = runtime_known_ops()
    if not exact and not simd:
        return True                      # can't tell: don't report
    if name in exact or any(name.startswith(p) for p in pref):
        return True
    b = name
    for suf in ("_avx", "_sha", "_f16c"):
        k = b.find(suf)
        if k > 0:
            b = b[:k]
            if b.startswith("v"):
                b = b[1:]
            break
    return b in simd


def refresh_runtime(project, log=print):
    """Copy the current runtime sources over the copies a lift put into its
    output folder(s), so a rebuild uses runtime fixes without lifting again.
    project: one lift output, or a game project (every modules/*/ folder).
    Only files the folder already has are replaced; returns the changed paths."""
    dirs = [project]
    mods = os.path.join(project, "modules")
    if os.path.isdir(mods):
        dirs += [os.path.join(mods, d) for d in sorted(os.listdir(mods))]
    changed = []
    for d in dirs:
        if not os.path.isfile(os.path.join(d, "Makefile")):
            continue
        for fn in RUNTIME_FILES:
            dst, src = os.path.join(d, fn), os.path.join(RUNTIME_DIR, fn)
            if not (os.path.isfile(dst) and os.path.isfile(src)):
                continue
            with open(src, "rb") as a, open(dst, "rb") as b:
                if a.read() == b.read():
                    continue
            shutil.copyfile(src, dst)
            changed.append(dst)
    if changed:
        log(f"   runtime updated in {len({os.path.dirname(c) for c in changed})} folder(s): "
            f"{', '.join(sorted({os.path.basename(c) for c in changed}))}")
    return changed


def write_build_manifest(outdir, m):
    """lift.json + build_lift.py: everything needed to compile this output
    with only the compiler (no make). The steps are the Makefile's, exactly."""
    m["trace_flags"] = ["-DRECOMP_TRACE_INSN"]
    with open(os.path.join(outdir, "lift.json"), "w", encoding="utf-8") as f:
        json.dump(m, f, indent=1)
    here = os.path.dirname(os.path.abspath(__file__))
    shutil.copyfile(os.path.join(here, "build_lift.py"), os.path.join(outdir, "build_lift.py"))


def write_pe_host(img, outdir, rt_dir, files):
    """Windows build files. The rebuilt .exe/.dll keeps the original file's
    image inside a non-executable section `.guest` placed right after its
    headers, at exactly the original address (host base = image base - 64K):

      - exports of a rebuilt DLL point straight into that image, so
        GetProcAddress gives the original code/data address. Calling an export
        faults on the non-executable page and the runtime runs the recompiled
        code instead (same mechanism as any callback)
      - data exports, GetModuleHandleEx(FROM_ADDRESS) and FindResource with
        the module handle all work, because the image is part of the module
      - the original resources (icon, version, manifest) are copied in"""
    g32 = img.g32
    us = "_" if g32 else ""     # 32-bit Windows: C names get a leading underscore
    rtsrc = ["rt_common.c", "rt_win32.c"] if g32 else ["rt_common.c", "rt_win.c", "rt_seh.c"]
    lds = "guest32.lds" if g32 else "guest.lds"
    for fn in ["rt.h", "rt_internal.h", "rt_win.h", "rt_module_win.c", lds] + rtsrc:
        shutil.copyfile(os.path.join(rt_dir, fn), os.path.join(outdir, fn))
    for fn in ("rt_win.c", "rt_seh.c", "rt_win32.c", "guest.lds", "guest32.lds"):   # from a lift of the other kind
        if fn not in rtsrc and fn != lds and os.path.exists(os.path.join(outdir, fn)):
            os.remove(os.path.join(outdir, fn))
    files += ["rt_module_win.c"]
    # labels inside .guest for every export target
    targets = sorted({rva for _, _, rva, fwd in img.exports if not fwd and rva < img.sizeofimage})
    with open(os.path.join(outdir, "guest.S"), "w", encoding="utf-8") as f:
        f.write("/* the original image lives here (filled in by the runtime at start-up) */\n")
        f.write(f'.section .guest,"bw"\n.globl {us}rt_guest\n{us}rt_guest:\n')
        pos = 0
        for rva in targets:
            if rva > pos:
                f.write(f".space {rva - pos:#x}\n")
            f.write(f".globl {us}__rx_{rva:x}\n{us}__rx_{rva:x}:\n")
            pos = rva
        f.write(f".space {max(img.sizeofimage - pos, 1):#x}\n")
    with open(os.path.join(outdir, "exports.def"), "w", encoding="utf-8") as f:
        if img.is_dll:
            f.write(f'LIBRARY "{img.target}"\n')
        f.write("EXPORTS\n")
        used = set()
        for ordi, name, rva, fwd in img.exports:
            if fwd:
                if name:
                    f.write(f"  {def_name(name)} = {fwd} @{ordi}\n")
                continue
            if rva >= img.sizeofimage:
                continue
            nm = name or f"__ordinal_{ordi}"
            f.write(f"  {def_name(nm)} = __rx_{rva:x} @{ordi}{'' if name else ' NONAME'}\n")
            used.add(nm)
    has_res = bool(img.resources)
    if has_res:
        write_rsrc(img.resources, outdir)
    objs = " ".join(f.replace(".c", ".o") for f in files) + " guest.o" + (" rsrc.o" if has_res else "")
    host = img.imagebase - HOST_GAP
    tool = "i686-w64-mingw32-" if g32 else "x86_64-w64-mingw32-"
    # 32-bit: float/double math in SSE registers (exact float and double
    # arithmetic, like the SSE instructions it stands for); `long double`
    # stays on the x87 unit, whose control word is the program's own
    fp = " -msse2 -mfpmath=sse" if g32 else ""
    with open(os.path.join(outdir, "Makefile"), "w", encoding="utf-8") as f:
        f.write(f"CC = {tool}gcc\nWINDRES = {tool}windres\n")
        f.write(f"CFLAGS ?= -O1 -w -fno-strict-aliasing -fwrapv{fp}\nCFLAGS += -fno-reorder-blocks-and-partition\n")
        if img.is_dll:
            f.write("CFLAGS += -DRT_DLL\n")
        kind = "-shared" if img.is_dll else ("-mwindows" if img.subsystem == 2 else "-mconsole")
        # fixed address, the original image first: see write_pe_host in lift.py
        extra = ""
        if g32:
            # the original code must not be executable (NX), and the program
            # runs on the thread's real stack: same stack size as the original
            extra = " -Wl,--nxcompat"
            if img.large_address:
                extra += " -Wl,--large-address-aware"
            if not img.is_dll and img.stack_reserve:
                extra += f" -Xlinker --stack={img.stack_reserve:#x}" + \
                         (f",{img.stack_commit:#x}" if img.stack_commit else "")
        f.write(f"LDFLAGS = {kind} -static -s -Wl,-T,{lds} -Wl,--image-base={host:#x} "
                f"-Wl,--section-alignment=0x10000 -Wl,--disable-dynamicbase{extra} exports.def\n")
        # make splits target names at spaces ("Gorilla Tag.exe" would be two
        # targets): the built file gets a make-safe name. build_game.py copies
        # it to the original name.
        f.write(f"OUT = {re.sub(r'[^A-Za-z0-9_.+-]', '_', img.target)}\n")
        f.write("ifeq ($(TRACE),1)\nCFLAGS += -DRECOMP_TRACE_INSN\nendif\n")
        f.write(f"OBJS = {objs}\n")
        # the shared runtime: one recomp_rt.dll for the whole program
        f.write(f"RTSRC = {' '.join(rtsrc)}\n")
        f.write("all: $(OUT) recomp_rt.dll\n")
        f.write("recomp_rt.dll: $(RTSRC) rt.h rt_internal.h rt_win.h regs.h\n"
                f"\t$(CC) -O2 -w -fno-strict-aliasing{fp} -shared -o recomp_rt.dll $(RTSRC) "
                "-Wl,--out-implib,librecomp_rt.a -static -s -lm\n")
        f.write("librecomp_rt.a: recomp_rt.dll\n")
        f.write(f"$(OUT): $(OBJS) exports.def {lds} librecomp_rt.a\n"
                "\t$(CC) -o $@ $(OBJS) $(LDFLAGS) -L. -lrecomp_rt -lm\n")
        f.write("%.o: %.c rt.h regs.h\n\t$(CC) $(CFLAGS) -c $<\n")
        f.write("guest.o: guest.S\n\t$(CC) -c guest.S\n")
        if has_res:
            f.write("rsrc.o: rsrc.S rsrc.bin\n\t$(CC) -c rsrc.S\n")
        f.write("tables.o rt_module_win.o: rt_internal.h\n")
        f.write("tables.o: image.bin\n")
        f.write("clean:\n\trm -f *.o $(OUT) recomp_rt.dll librecomp_rt.a\n")
    out_name = re.sub(r'[^A-Za-z0-9_.+-]', '_', img.target)
    cflags = ["-O1", "-w", "-fno-strict-aliasing", "-fwrapv"] + fp.split() + ["-fno-reorder-blocks-and-partition"] + \
             (["-DRT_DLL"] if img.is_dll else [])
    ldflags = [kind, "-static", "-s", f"-Wl,-T,{lds}", f"-Wl,--image-base={host:#x}",
               "-Wl,--section-alignment=0x10000", "-Wl,--disable-dynamicbase"] + extra.split() + ["exports.def"]
    ol = objs.split()
    asm = {"guest.o": "guest.S", "rsrc.o": "rsrc.S"}
    write_build_manifest(outdir, {
        "out": out_name, "cc": f"{tool}gcc",
        "compiles": [{"obj": o, "src": asm[o], "flags": []} if o in asm else
                     {"obj": o, "src": o[:-2] + ".c", "flags": cflags} for o in ol],
        "runtime": {"out": "recomp_rt.dll",
                    "argv": ["-O2", "-w", "-fno-strict-aliasing"] + fp.split() + ["-shared", "-o", "recomp_rt.dll"] +
                            list(rtsrc) + ["-Wl,--out-implib,librecomp_rt.a", "-static", "-s", "-lm"],
                    "deps": list(rtsrc) + ["rt.h", "rt_internal.h", "rt_win.h", "regs.h"]},
        "link": {"prefix": ["-o", out_name], "objs": ol, "suffix": ldflags + ["-L.", "-lrecomp_rt", "-lm"],
                 "deps": ["exports.def", lds, "librecomp_rt.a"]},
        "clean": [out_name, "recomp_rt.dll", "librecomp_rt.a"]})


# --------------------------------------------------------------------------
# diagnostics: every problem with its exact location
# --------------------------------------------------------------------------

class Locator:
    """address -> where it is: RVA, file offset, section, containing function"""

    def __init__(self, img):
        import bisect
        self._bisect = bisect
        self.img = img
        self.ib = img.imagebase if img.format == "pe" else 0
        self.segs = sorted((sg["vaddr"], sg["memsz"], sg["foff"], sg["fsize"], sg.get("name", ""))
                           for sg in img.segments)
        self.code = sorted(img.code)
        self.fa = sorted(img.funcs)

    def __call__(self, va):
        d = {"va": f"{va:#x}"}
        if self.img.format == "pe":
            d["rva"] = f"{va - self.ib:#x}"
        sec = None
        for base, foff, size, name in self.code:
            if base <= va < base + size:
                sec, d["file_offset"] = name, f"{foff + va - base:#x}"
                break
        if sec is None:
            for vaddr, memsz, foff, fsize, name in self.segs:
                if vaddr <= va < vaddr + memsz:
                    sec = name
                    if va - vaddr < fsize:
                        d["file_offset"] = f"{foff + va - vaddr:#x}"
                    break
        d["section"] = sec or "?"
        k = self._bisect.bisect_right(self.fa, va) - 1
        if k >= 0 and va - self.fa[k] < 0x100000:
            off = va - self.fa[k]
            d["function"] = self.img.funcs[self.fa[k]] + (f"+{off:#x}" if off else "")
        return d

    def bytes_at(self, va, n):
        for base, foff, size, _ in self.code:
            if base <= va < base + size:
                k = va - base
                return bytes(self.img.raw[foff + k:foff + min(k + n, size)])
        return b""


def guess_bytes(b):
    """what undecodable bytes most likely are"""
    if not b:
        return "unknown"
    if all(x == 0xCC for x in b):
        return "int3 padding between functions"
    if all(x == 0 for x in b):
        return "zero padding / alignment"
    if all(x == 0x90 for x in b):
        return "nop padding"
    if len(b) >= 4 and sum(32 <= x < 127 or x in (9, 10, 13, 0) for x in b) >= 0.85 * len(b):
        return "text: string data inside the code section"
    if len(b) >= 8 and len(b) % 4 == 0:
        return "data (table/constants) or an instruction the decoder doesn't know"
    return "data or an instruction the decoder doesn't know"


def write_diagnostics(outdir, img, rep, em):
    """diagnostics.jsonl: one JSON object per problem. Returns counts."""
    loc = Locator(img)
    counts = {"undecodable_on_code_path": 0, "undecodable_at_data_pointer": 0,
              "undecodable_ranges": 0, "untranslatable": 0}
    guesses, reasons = {}, {}
    examples = {"path": [], "untranslatable": {}, "ranges": {}}
    path_from = {-1: "start of a known function (symbol/export/.pdata/entry)",
                 -2: "address stored in data (relocation: vtable/callback/jump table)",
                 -3: "guessed code pointer (constant that points into code)"}
    with open(os.path.join(outdir, "diagnostics.jsonl"), "w", encoding="utf-8") as f:
        on_path = {}
        for addr, err, frm, start in rep.get("_bad_paths", []):
            # a path that starts at an address only DATA points to (relocated
            # pointer, guessed constant) may be a table in the code section,
            # not code: a warning. Known function starts and jump/call targets
            # are certainly code: an error.
            weak = frm in (-2, -3)
            kind = "undecodable_at_data_pointer" if weak else "undecodable_on_code_path"
            on_path[addr] = kind
            d = {"kind": kind, "severity": "warning" if weak else "error", **loc(addr),
                 "bytes": loc.bytes_at(addr, 16).hex(), "decoder_error": err}
            if frm is None or frm < 0:
                d["reached_by"] = path_from.get(frm, "?")
            else:
                d["reached_by"] = f"jump/call at {frm:#x}" + (f" ({loc(frm).get('function')})" if loc(frm).get("function") else "")
            if start != addr:
                d["path_start"] = f"{start:#x}"
            d["what_happens"] = "the recompiled program crashes with a report if it ever gets here"
            d["hint"] = ("only data points here: usually a table or marker inside the code section "
                         "(e.g. a constructor list), harmless unless something really calls it") if weak else \
                        ("real code the decoder can't read: a newer/unknown instruction, or bytes that are "
                         "only valid after the program changes them at run time (packed/self-modifying code; "
                         "try --runtime-capture)")
            f.write(json.dumps(d) + "\n")
            counts[kind] += 1
            if len(examples["path"]) < 20 and not weak:
                examples["path"].append(d)
            elif weak and len(examples.setdefault("weak", [])) < 10:
                examples["weak"].append(d)
        for addr, first, n, err in rep.get("_bad_ranges", []):
            b = bytes(first)
            g = guess_bytes(b)
            hit = next((on_path[a] for a in range(addr, addr + n) if a in on_path), None)
            d = {"kind": "undecodable_range", "severity": "info" if "padding" in g or g.startswith("text") else "warning",
                 **loc(addr), "length": n, "bytes": b[:32].hex(), "decoder_error": err, "guess": g,
                 "reached_by": f"also a {hit} record" if hit else "linear sweep only (nothing jumps or calls here)"}
            f.write(json.dumps(d) + "\n")
            counts["undecodable_ranges"] += 1
            guesses[g] = guesses.get(g, 0) + n
            ex = examples["ranges"].setdefault(g, [])
            if len(ex) < 5:
                ex.append(d)
        for addr, asm, reason, raw in em.unsup_all:
            d = {"kind": "untranslatable", "severity": "error", **loc(addr), "asm": asm,
                 "bytes": raw.hex(), "reason": reason,
                 "what_happens": "rt_unsupported(): the recompiled program stops with a crash report if this runs"}
            f.write(json.dumps(d) + "\n")
            counts["untranslatable"] += 1
            reasons[reason] = reasons.get(reason, 0) + 1
            ex = examples["untranslatable"].setdefault(reason, [])
            if len(ex) < 3:
                ex.append(d)
        missing = {}
        for n, sites in em.userop_sites.items():
            if op_implemented(n):
                continue
            missing[n] = em.userop_count.get(n, len(sites))
            for a in sites:
                d = {"kind": "cpu_op_not_in_runtime", "severity": "error", **loc(a), "op": n,
                     "bytes": loc.bytes_at(a, 15).hex(), "sites_total": em.userop_count.get(n, 0),
                     "what_happens": "rt_callother(): the recompiled program stops with "
                                     "'unimplemented special CPU instruction' if this runs",
                     "hint": "add the op to rt_callother()/simd_op() in runtime/rt_common.c"}
                f.write(json.dumps(d) + "\n")
        counts["cpu_ops_not_in_runtime"] = missing
    rep["_problem_examples"] = examples
    counts["undecodable_bytes_by_guess"] = guesses
    counts["untranslatable_by_reason"] = reasons
    return counts


def _where(d):
    parts = [d["va"]]
    if "rva" in d:
        parts.append(f"rva {d['rva']}")
    if "file_offset" in d:
        parts.append(f"file+{d['file_offset']}")
    parts.append(d.get("section", "?"))
    if d.get("function"):
        parts.append(f"<{d['function']}>")
    return "  ".join(parts)


def write_report(outdir, rep, img):
    with open(os.path.join(outdir, "lift_report.json"), "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in rep.items() if not k.startswith("_")}, f, indent=1, default=str)
    L = []
    w = L.append
    w(f"recomp lift report - {rep['input']}")
    w("=" * 78)
    w(f"format: {rep['format']}   cpu: {rep['cpu']}   entry: {rep['entry']:#x}")
    for n in rep["notes"]:
        w(f"note: {n}")
    d = rep["decode"]
    w("")
    w("DECODING")
    w(f"  {d['instructions']} instructions lifted")
    w(f"    {d['from_known_functions']} by following known function starts (symbols/exports/.pdata) "
      f"and every direct jump/call target")
    w(f"    {d['from_linear_sweep']} by linear sweep of the remaining code bytes")
    w(f"  {d['undecodable_bytes']} bytes could not be decoded as instructions "
      f"(usually padding or data inside code sections)")
    for a, hx in rep["undecodable"][:40]:
        w(f"    {a:#x}: {hx[:48]}{'...' if len(hx) > 48 else ''}")
    if len(rep["undecodable"]) > 40 or rep.get("undecodable_truncated"):
        w(f"    ... more ranges in lift_report.json")
    w(f"  {d['overlap_conflicts']} places where two decodings overlapped "
      f"(data in code or deliberate obfuscation)")
    if d.get("overlap_kept"):
        w(f"    {d['overlap_kept']} of them are jump/call targets inside another instruction: "
          f"lifted as extra overlapping instructions")
    w("")
    w("TRANSLATION")
    w(f"  {rep['chunks']} chunks, {rep['c_lines']} lines of C in {rep['c_files']} files")
    if rep["unsupported"]:
        w(f"  {rep['unsupported_total']} instructions use something the generator can't "
          f"translate yet. They compile to a call that stops the program with a crash report, "
          f"so if they never run, nothing breaks:")
        for k, v in sorted(rep["unsupported"].items(), key=lambda kv: -kv[1]):
            w(f"    {v:6d}  {k}")
        w("  first sites (all of them: unsupported_sites.tsv):")
        for a, t, r in rep["unsupported_sites"][:60]:
            w(f"    {a}  {t:<40} {r}")
    else:
        w("  every instruction was translated")
    if rep.get("atomic_cas") or rep.get("atomic_locked"):
        w(f"  atomic (LOCK/XCHG) instructions: {rep.get('atomic_cas', 0)} run as real compare-and-swap, "
          f"{rep.get('atomic_locked', 0)} under the runtime's global lock")
    w("")
    w("SPECIAL CPU OPS (handled by the runtime; if one is missing, the program stops with a report)")
    for n, s in sorted(rep["cpu_ops"].items()):
        w(f"  {n:<40} at {', '.join(s)}")
    if rep["imports"]:
        w("")
        how = "called as native code, directly on the program's own stack" if getattr(img, "g32", False) \
            else "called natively through the Win64 ABI adapter"
        w(f"IMPORTS ({len(rep['imports'])}) - {how}")
        by = {}
        for dll, n, slot in rep["imports"]:
            by.setdefault(dll, []).append(n)
        for dll, ns in by.items():
            w(f"  {dll}: {', '.join(ns[:30])}{' ...' if len(ns) > 30 else ''}")
    w("")
    w("FILES")
    w("  listing.tsv   every instruction: address, bytes, assembly, chunk, generated C line")
    w("  symbols.tsv   every known function / data symbol")
    w("  code_*.c      generated C      tables.c  address tables + image")
    pr = rep.get("problems")
    if pr:
        ex = rep.get("_problem_examples", {})
        w("")
        w("PROBLEMS  (every one, with exact location and bytes: diagnostics.jsonl)")
        w(f"  {pr['undecodable_on_code_path']} undecodable instruction(s) on real code paths  [ERROR: crash if reached]")
        for d in ex.get("path", []):
            w(f"    {_where(d)}")
            w(f"      bytes {d['bytes']}   decoder: {d['decoder_error']}")
            w(f"      reached by: {d['reached_by']}")
        w(f"  {pr['undecodable_at_data_pointer']} undecodable place(s) that only data points to  "
          f"[WARNING: usually a table/marker in the code section]")
        for d in ex.get("weak", [])[:5]:
            w(f"    {_where(d)}  bytes {d['bytes']}")
        w(f"  {pr['untranslatable']} instruction(s) decoded but not translatable  [ERROR: crash if reached]")
        for reason, n in sorted(pr["untranslatable_by_reason"].items(), key=lambda kv: -kv[1]):
            w(f"    {n:6d}  {reason}")
            for d in ex.get("untranslatable", {}).get(reason, []):
                w(f"            {_where(d)}  {d['asm']}  bytes {d['bytes']}")
        miss = pr.get("cpu_ops_not_in_runtime", {})
        w(f"  {len(miss)} special CPU op(s) the runtime doesn't implement  [ERROR: stops the program if reached]")
        for n, c in sorted(miss.items(), key=lambda kv: -kv[1]):
            w(f"    {c:6d}  {n}   (sites in diagnostics.jsonl)")
        w(f"  {pr['undecodable_ranges']} undecodable byte range(s) found only by the linear sweep "
          f"(nothing jumps there; usually not code)")
        for g, n in sorted(pr["undecodable_bytes_by_guess"].items(), key=lambda kv: -kv[1]):
            w(f"    {n:8d} bytes  {g}")
            for d in ex.get("ranges", {}).get(g, [])[:3]:
                w(f"              {_where(d)}  len {d['length']}  bytes {d['bytes'][:32]}  ({d['decoder_error']})")
    with open(os.path.join(outdir, "lift_report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
