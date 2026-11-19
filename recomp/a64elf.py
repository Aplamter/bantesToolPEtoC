"""ARM64 ELF shared objects (Android lib/arm64-v8a/*.so, Linux aarch64 .so):
what the dynamic loader would read from the file - program headers, the
dynamic section, dynamic symbols and every dynamic relocation (RELA, the PLT
table, RELR and Android's packed "APS2" format) - and a writer for the
relocatable object file (guest.o) that carries the original image into the
rebuilt library.

The rebuilt library is linked by the normal linker. The original image goes
into it segment by segment, at the same distances and with the same access
rights (see a64.py); every place the loader would have relocated is
described to the linker again as a relocation against a symbol, so the
rebuilt library gets real dynamic relocations, imports and exports, and the
system loader does for it what it did for the original.
"""
import struct

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_TLS, PT_GNU_EH_FRAME = 1, 2, 3, 7, 0x6474e550
DT_NEEDED, DT_PLTRELSZ, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ = 1, 2, 4, 5, 6, 7, 8
DT_STRSZ, DT_INIT, DT_FINI, DT_SONAME, DT_SYMBOLIC, DT_REL, DT_RELSZ = 10, 12, 13, 14, 16, 17, 18
DT_JMPREL, DT_INIT_ARRAY, DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ = 23, 25, 26, 27, 28
DT_FLAGS, DT_PREINIT_ARRAY, DT_RELRSZ, DT_RELR = 30, 32, 35, 36
DT_ANDROID_REL, DT_ANDROID_RELSZ, DT_ANDROID_RELA, DT_ANDROID_RELASZ = 0x6000000f, 0x60000010, 0x60000011, 0x60000012
DT_ANDROID_RELR, DT_ANDROID_RELRSZ = 0x6fffe000, 0x6fffe001
DT_GNU_HASH, DT_FLAGS_1 = 0x6ffffef5, 0x6ffffffb

R_ABS64, R_COPY, R_GLOB_DAT, R_JUMP_SLOT, R_RELATIVE = 257, 1024, 1025, 1026, 1027
R_TLS_DTPMOD, R_TLS_DTPREL, R_TLS_TPREL, R_TLSDESC, R_IRELATIVE = 1028, 1029, 1030, 1031, 1032
R_NAMES = {257: "ABS64", 1024: "COPY", 1025: "GLOB_DAT", 1026: "JUMP_SLOT", 1027: "RELATIVE",
           1028: "TLS_DTPMOD", 1029: "TLS_DTPREL", 1030: "TLS_TPREL", 1031: "TLSDESC", 1032: "IRELATIVE"}

STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_TLS, STT_GNU_IFUNC = 0, 1, 2, 3, 6, 10
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
SHN_UNDEF, SHN_ABS = 0, 0xfff1


class ElfError(Exception):
    pass


class Sym:
    __slots__ = ("name", "value", "size", "type", "bind", "vis", "shndx")

    def __init__(self, name, value, size, info, other, shndx):
        self.name, self.value, self.size = name, value, size
        self.type, self.bind, self.vis, self.shndx = info & 15, info >> 4, other & 3, shndx

    @property
    def defined(self):
        return self.shndx != SHN_UNDEF


def _sleb(d, o):
    r = sh = 0
    while True:
        b = d[o]
        o += 1
        r |= (b & 0x7f) << sh
        sh += 7
        if not b & 0x80:
            if b & 0x40:
                r -= 1 << sh
            return r, o


class DynElf:
    """the loader's view of a 64-bit little-endian ELF shared object"""

    def __init__(self, raw):
        d = self.raw = raw
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            raise ElfError("not a 64-bit little-endian ELF file")
        (self.e_type, self.machine, _, self.entry, phoff, shoff, _, _, phentsize, phnum,
         shentsize, shnum, _) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
        self.phdrs = []
        for i in range(phnum):
            t, fl, off, va, _, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", d, phoff + i * phentsize)
            self.phdrs.append({"type": t, "flags": fl, "offset": off, "vaddr": va, "filesz": fsz,
                               "memsz": msz, "align": al})
        self.loads = [p for p in self.phdrs if p["type"] == PT_LOAD]
        if not self.loads:
            raise ElfError("no loadable segments")
        self.has_interp = any(p["type"] == PT_INTERP for p in self.phdrs)
        self.tls = next((p for p in self.phdrs if p["type"] == PT_TLS), None)
        self.eh_frame_hdr = next((p for p in self.phdrs if p["type"] == PT_GNU_EH_FRAME), None)
        self.lo = min(p["vaddr"] for p in self.loads) & ~0xfff
        self.file_end = max(p["vaddr"] + p["filesz"] for p in self.loads)
        self.mem_end = max(p["vaddr"] + p["memsz"] for p in self.loads)
        self.dyn = {}
        self.needed = []
        self.soname = None
        dynp = next((p for p in self.phdrs if p["type"] == PT_DYNAMIC), None)
        needed_offs, soname_off = [], None
        if dynp:
            o = dynp["offset"]
            end = min(len(d), o + dynp["filesz"])
            while o + 16 <= end:
                tag, val = struct.unpack_from("<qQ", d, o)
                o += 16
                if tag == 0:
                    break
                if tag == DT_NEEDED:
                    needed_offs.append(val)
                elif tag == DT_SONAME:
                    soname_off = val
                else:
                    self.dyn.setdefault(tag, val)
        self.strtab = self.dyn.get(DT_STRTAB)
        self.needed = [self.dynstr(v) for v in needed_offs]
        if soname_off is not None:
            self.soname = self.dynstr(soname_off)
        self.symbolic = DT_SYMBOLIC in self.dyn or bool(self.dyn.get(DT_FLAGS, 0) & 2)
        self.syms = self._dynsyms()
        self.relocs, self.reloc_format = self._relocs()

    # ---- addresses ---------------------------------------------------------
    def off(self, va, n=1):
        """file offset of n bytes at virtual address va, or None"""
        for p in self.loads:
            if p["vaddr"] <= va and va + n <= p["vaddr"] + p["filesz"]:
                return p["offset"] + va - p["vaddr"]
        return None

    def u64(self, va):
        o = self.off(va, 8)
        return struct.unpack_from("<Q", self.raw, o)[0] if o is not None else 0

    def dynstr(self, i):
        if self.strtab is None:
            return ""
        o = self.off(self.strtab + i)
        if o is None:
            return ""
        e = self.raw.find(b"\0", o)
        return bytes(self.raw[o:e]).decode("utf-8", "replace")

    def array(self, tag, size_tag):
        """values of an init/fini array as stored in the file (before relocation)"""
        va, n = self.dyn.get(tag), self.dyn.get(size_tag, 0) // 8
        return (va, n) if va else (0, 0)

    # ---- dynamic symbols ---------------------------------------------------
    def _nsyms(self):
        d = self.raw
        if DT_HASH in self.dyn:
            o = self.off(self.dyn[DT_HASH], 8)
            if o is not None:
                return struct.unpack_from("<I", d, o + 4)[0]
        if DT_GNU_HASH in self.dyn:
            o = self.off(self.dyn[DT_GNU_HASH], 16)
            if o is not None:
                nb, symoff, bloom, _ = struct.unpack_from("<IIII", d, o)
                buckets = o + 16 + 8 * bloom
                top = max(struct.unpack_from(f"<{nb}I", d, buckets) or (0,))
                if top < symoff:
                    return symoff
                chain = buckets + 4 * nb
                k = top
                while not struct.unpack_from("<I", d, chain + 4 * (k - symoff))[0] & 1:
                    k += 1
                return k + 1
        return 0

    def _dynsyms(self):
        st = self.dyn.get(DT_SYMTAB)
        if st is None:
            return []
        n = self._nsyms()
        o = self.off(st, 24 * n) if n else None
        if o is None:
            # no usable hash table: the symbols end where the strings start
            if self.strtab and self.strtab > st:
                n = (self.strtab - st) // 24
                o = self.off(st, 24 * n)
            if o is None:
                return []
        out = []
        for i in range(n):
            name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.raw, o + 24 * i)
            out.append(Sym(self.dynstr(name).split("@")[0] if name else "", value, size, info, other, shndx))
        return out

    # ---- relocations -------------------------------------------------------
    def _rela(self, va, size, out):
        o = self.off(va, size)
        if o is None:
            raise ElfError("relocation table is outside the file")
        for k in range(size // 24):
            r_off, info, add = struct.unpack_from("<QQq", self.raw, o + 24 * k)
            out.append((r_off, info & 0xffffffff, info >> 32, add))

    def _relr(self, va, size, out):
        o = self.off(va, size)
        if o is None:
            raise ElfError("RELR table is outside the file")
        base = 0
        for k in range(size // 8):
            e = struct.unpack_from("<Q", self.raw, o + 8 * k)[0]
            if not e & 1:
                out.append((e, R_RELATIVE, 0, self.u64(e)))
                base = e + 8
            else:
                i = 0
                e >>= 1
                while e:
                    if e & 1:
                        a = base + 8 * i
                        out.append((a, R_RELATIVE, 0, self.u64(a)))
                    e >>= 1
                    i += 1
                base += 63 * 8

    def _aps2(self, va, size, out, rela):
        o = self.off(va, size)
        d = self.raw
        if o is None or bytes(d[o:o + 4]) != b"APS2":
            raise ElfError("Android packed relocations: unknown format")
        p = o + 4
        count, p = _sleb(d, p)
        r_off, p = _sleb(d, p)
        addend = 0
        done = 0
        while done < count:
            gsize, p = _sleb(d, p)
            gflags, p = _sleb(d, p)
            by_info, by_delta, by_addend, has_addend = gflags & 1, gflags & 2, gflags & 4, gflags & 8
            gdelta = ginfo = 0
            if by_delta:
                gdelta, p = _sleb(d, p)
            if by_info:
                ginfo, p = _sleb(d, p)
            if has_addend and by_addend:
                v, p = _sleb(d, p)
                addend += v
            elif not has_addend:
                addend = 0
            for _ in range(gsize):
                if by_delta:
                    r_off += gdelta
                else:
                    v, p = _sleb(d, p)
                    r_off += v
                if by_info:
                    info = ginfo
                else:
                    info, p = _sleb(d, p)
                if has_addend and not by_addend:
                    v, p = _sleb(d, p)
                    addend += v
                info &= 0xffffffffffffffff
                a = addend if rela else self.u64(r_off)
                out.append((r_off & 0xffffffffffffffff, info & 0xffffffff, info >> 32, a))
                done += 1

    def _relocs(self):
        """[(address, type, symbol index, addend)], and how the file stores
        them ("rela", "relr", "android": what the rebuilt file should use too)"""
        dy, out, fmt = self.dyn, [], set()
        if DT_REL in dy and dy.get(DT_RELSZ):
            raise ElfError("REL relocations (no addends) are not used by ARM64 files")
        if DT_RELA in dy and dy.get(DT_RELASZ):
            self._rela(dy[DT_RELA], dy[DT_RELASZ], out)
            fmt.add("rela")
        if DT_JMPREL in dy and dy.get(DT_PLTRELSZ):
            self._rela(dy[DT_JMPREL], dy[DT_PLTRELSZ], out)
        for t, s in ((DT_RELR, DT_RELRSZ), (DT_ANDROID_RELR, DT_ANDROID_RELRSZ)):
            if t in dy and dy.get(s):
                self._relr(dy[t], dy[s], out)
                fmt.add("relr")
        if DT_ANDROID_RELA in dy and dy.get(DT_ANDROID_RELASZ):
            self._aps2(dy[DT_ANDROID_RELA], dy[DT_ANDROID_RELASZ], out, True)
            fmt.add("android")
        if DT_ANDROID_REL in dy and dy.get(DT_ANDROID_RELSZ):
            self._aps2(dy[DT_ANDROID_REL], dy[DT_ANDROID_RELSZ], out, False)
            fmt.add("android")
        return out, fmt


# --------------------------------------------------------------------------
# guest.o: the original image as a relocatable object file
# --------------------------------------------------------------------------
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
R_CALL26, R_JUMP26, R_ADR_PAGE, R_ADD_LO12 = 283, 282, 275, 277


def write_object(path, sections, symbols):
    """ELF64 AArch64 relocatable object.
      sections  [{"name", "flags" (SHF_*), "align", "data": bytes or a list of
                  byte strings written one after another, or "size": n for
                  zero-filled memory (no bytes in the file),
                  "relocs": [(offset, type, symbol, addend)]}]
                a relocation's symbol is a name from `symbols`, or
                ("section", name) for the start of a section of this file
      symbols   [(name, section name or None for an import, value, size,
                  type, bind, visibility)]"""
    names = [s["name"] for s in sections]
    sec_index = {n: i + 1 for i, n in enumerate(names)}
    relas = [s for s in sections if s.get("relocs")]
    nsec = 1 + len(sections) + len(relas) + 4       # null, sections, .rela.*, symtab, strtab, shstrtab, note
    i_sym = 1 + len(sections) + len(relas)
    shstr = bytearray(b"\0")
    sh_name = {}

    def shn(n):
        if n not in sh_name:
            sh_name[n] = len(shstr)
            shstr.extend(n.encode() + b"\0")
        return sh_name[n]
    strtab = bytearray(b"\0")
    str_idx = {}

    def stri(s):
        if s not in str_idx:
            str_idx[s] = len(strtab)
            strtab.extend(s.encode("utf-8", "surrogateescape") + b"\0")
        return str_idx[s]
    # locals first: null, one section symbol per section
    syms = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    for i in range(len(sections)):
        syms.append(struct.pack("<IBBHQQ", 0, STT_SECTION, 0, i + 1, 0, 0))
    nlocal = len(syms)
    index = {}
    for name, where, value, ssize, typ, bind, vis in symbols:
        if name in index:
            continue
        index[name] = len(syms)
        syms.append(struct.pack("<IBBHQQ", stri(name), (bind << 4) | typ, vis, sec_index[where] if where else 0,
                                value, ssize))
    symtab = b"".join(syms)
    # layout
    pos = 64
    lay = []            # (offset, size) per section
    for s in sections:
        al = 16
        pos += (-pos) % al
        if "data" in s:
            parts = s["data"] if isinstance(s["data"], (list, tuple)) else [s["data"]]
            size = sum(len(p) for p in parts)
            lay.append((pos, size, parts))
            pos += size
        else:
            lay.append((pos, s["size"], None))
    rela_lay = []
    for s in relas:
        pos += (-pos) % 8
        rela_lay.append((pos, 24 * len(s["relocs"])))
        pos += 24 * len(s["relocs"])
    pos += (-pos) % 8
    sym_off = pos
    pos += len(symtab)
    str_off = pos
    pos += len(strtab)
    for n in names + [".rela" + s["name"] for s in relas] + [".symtab", ".strtab", ".shstrtab", ".note.GNU-stack"]:
        shn(n)
    shstr_off = pos
    pos += len(shstr)
    pos += (-pos) % 8
    sh_off = pos

    def sh(name, typ, flags, off, sz, link=0, info=0, al=1, ent=0):
        return struct.pack("<IIQQQQIIQQ", shn(name) if name else 0, typ, flags, 0, off, sz, link, info, al, ent)
    shdrs = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for s, (off, size, parts) in zip(sections, lay):
        shdrs.append(sh(s["name"], 1 if parts is not None else 8, s["flags"], off, size, al=s.get("align", 1)))
    for s, (off, size) in zip(relas, rela_lay):
        shdrs.append(sh(".rela" + s["name"], 4, 0x40, off, size, link=i_sym, info=sec_index[s["name"]], al=8, ent=24))
    shdrs.append(sh(".symtab", 2, 0, sym_off, len(symtab), link=i_sym + 1, info=nlocal, al=8, ent=24))
    shdrs.append(sh(".strtab", 3, 0, str_off, len(strtab)))
    shdrs.append(sh(".shstrtab", 3, 0, shstr_off, len(shstr)))
    shdrs.append(sh(".note.GNU-stack", 1, 0, shstr_off, 0))
    assert len(shdrs) == nsec
    with open(path, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01" + bytes(9))
        f.write(struct.pack("<HHIQQQIHHHHHH", 1, 183, 1, 0, 0, sh_off, 0, 64, 0, 0, 64, nsec, i_sym + 2))
        for off, size, parts in lay:
            if parts is None:
                continue
            f.write(bytes(off - f.tell()))
            for p in parts:
                f.write(p)
        for s, (off, size) in zip(relas, rela_lay):
            f.write(bytes(off - f.tell()))
            out = bytearray()
            for r_off, typ, sym, addend in s["relocs"]:
                si = sec_index[sym[1]] if isinstance(sym, tuple) else index[sym]
                out += struct.pack("<QQq", r_off, (si << 32) | typ, addend)
            f.write(out)
        f.write(bytes(sym_off - f.tell()))
        f.write(symtab)
        f.write(strtab)
        f.write(shstr)
        f.write(bytes(sh_off - f.tell()))
        f.write(b"".join(shdrs))


def patch_eh_frame_hdr(path, guest_va, eh_va, eh_size):
    """Point the rebuilt library's PT_GNU_EH_FRAME at the ORIGINAL image's
    .eh_frame_hdr (eh_va: its address inside the original, guest_va: the
    original's address 0 inside the rebuilt file). Unwinders - the one inside
    the library, or the C++ runtime's - find the unwind tables of a code
    address through this program header, and the code addresses the program
    has on its stack are those of the original image."""
    with open(path, "r+b") as f:
        d = f.read()
        phoff, = struct.unpack_from("<Q", d, 32)
        phentsize, phnum = struct.unpack_from("<HH", d, 54)
        loads, slot = [], None
        for i in range(phnum):
            o = phoff + i * phentsize
            t, fl, off, va, _, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", d, o)
            if t == PT_LOAD:
                loads.append((va, fsz, off))
            elif t == PT_GNU_EH_FRAME:
                slot = o
        if slot is None:
            return False
        va = guest_va + eh_va
        foff = next((off + va - lva for lva, fsz, off in loads if lva <= va < lva + fsz), None)
        if foff is None:
            return False
        f.seek(slot)
        f.write(struct.pack("<IIQQQQQQ", PT_GNU_EH_FRAME, 4, foff, va, va, eh_size, eh_size, 4))
    return True


def section_addr(path, name):
    """address of a section in a linked ELF file, or None"""
    with open(path, "rb") as f:
        d = f.read(64)
        shoff, = struct.unpack_from("<Q", d, 40)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 58)
        f.seek(shoff)
        sh = f.read(shentsize * shnum)
        so, ssz = struct.unpack_from("<QQ", sh, shstrndx * shentsize + 24)
        f.seek(so)
        names = f.read(ssz)
    want = name.encode()
    for i in range(shnum):
        n, = struct.unpack_from("<I", sh, i * shentsize)
        if names[n:names.index(b"\0", n)] == want:
            return struct.unpack_from("<Q", sh, i * shentsize + 16)[0]
    return None
