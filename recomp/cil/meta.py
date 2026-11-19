"""ECMA-335 metadata reader: .NET assemblies (DLL/EXE) -> tables, signatures,
method bodies. Pure Python, reads the file through a memory map."""
import mmap
import struct

TABLES = [
    ("Module", "u2 str guid guid guid"),
    ("TypeRef", "ResolutionScope str str"),
    ("TypeDef", "u4 str str TypeDefOrRef T4 T6"),
    ("FieldPtr", "T4"),
    ("Field", "u2 str blob"),
    ("MethodPtr", "T6"),
    ("MethodDef", "u4 u2 u2 str blob T8"),
    ("ParamPtr", "T8"),
    ("Param", "u2 u2 str"),
    ("InterfaceImpl", "T2 TypeDefOrRef"),
    ("MemberRef", "MemberRefParent str blob"),
    ("Constant", "u2 HasConstant blob"),
    ("CustomAttribute", "HasCustomAttribute CustomAttributeType blob"),
    ("FieldMarshal", "HasFieldMarshal blob"),
    ("DeclSecurity", "u2 HasDeclSecurity blob"),
    ("ClassLayout", "u2 u4 T2"),
    ("FieldLayout", "u4 T4"),
    ("StandAloneSig", "blob"),
    ("EventMap", "T2 T20"),
    ("EventPtr", "T20"),
    ("Event", "u2 str TypeDefOrRef"),
    ("PropertyMap", "T2 T23"),
    ("PropertyPtr", "T23"),
    ("Property", "u2 str blob"),
    ("MethodSemantics", "u2 T6 HasSemantics"),
    ("MethodImpl", "T2 MethodDefOrRef MethodDefOrRef"),
    ("ModuleRef", "str"),
    ("TypeSpec", "blob"),
    ("ImplMap", "u2 MemberForwarded str T26"),
    ("FieldRVA", "u4 T4"),
    ("EncLog", "u4 u4"),
    ("EncMap", "u4"),
    ("Assembly", "u4 u2 u2 u2 u2 u4 blob str str"),
    ("AssemblyProcessor", "u4"),
    ("AssemblyOS", "u4 u4 u4"),
    ("AssemblyRef", "u2 u2 u2 u2 u4 blob str str blob"),
    ("AssemblyRefProcessor", "u4 T35"),
    ("AssemblyRefOS", "u4 u4 u4 T35"),
    ("File", "u4 str blob"),
    ("ExportedType", "u4 u4 str str Implementation"),
    ("ManifestResource", "u4 u4 str Implementation"),
    ("NestedClass", "T2 T2"),
    ("GenericParam", "u2 u2 TypeOrMethodDef str"),
    ("MethodSpec", "MethodDefOrRef blob"),
    ("GenericParamConstraint", "T42 TypeDefOrRef"),
]
TID = {n: i for i, (n, _) in enumerate(TABLES)}
CODED = {
    "TypeDefOrRef": (2, ["TypeDef", "TypeRef", "TypeSpec"]),
    "HasConstant": (2, ["Field", "Param", "Property"]),
    "HasCustomAttribute": (5, ["MethodDef", "Field", "TypeRef", "TypeDef", "Param", "InterfaceImpl",
                               "MemberRef", "Module", "DeclSecurity", "Property", "Event", "StandAloneSig",
                               "ModuleRef", "TypeSpec", "Assembly", "AssemblyRef", "File", "ExportedType",
                               "ManifestResource", "GenericParam", "GenericParamConstraint", "MethodSpec"]),
    "HasFieldMarshal": (1, ["Field", "Param"]),
    "HasDeclSecurity": (2, ["TypeDef", "MethodDef", "Assembly"]),
    "MemberRefParent": (3, ["TypeDef", "TypeRef", "ModuleRef", "MethodDef", "TypeSpec"]),
    "HasSemantics": (1, ["Event", "Property"]),
    "MethodDefOrRef": (1, ["MethodDef", "MemberRef"]),
    "MemberForwarded": (1, ["Field", "MethodDef"]),
    "Implementation": (2, ["File", "AssemblyRef", "ExportedType"]),
    "CustomAttributeType": (3, [None, None, "MethodDef", "MemberRef", None]),
    "ResolutionScope": (2, ["Module", "ModuleRef", "AssemblyRef", "TypeRef"]),
    "TypeOrMethodDef": (1, ["TypeDef", "MethodDef"]),
}


class MetaError(Exception):
    pass


class Assembly:
    def __init__(self, path):
        self.path = path
        f = open(path, "rb")
        self.d = d = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        f.close()
        u16 = lambda o: struct.unpack_from("<H", d, o)[0]
        u32 = lambda o: struct.unpack_from("<I", d, o)[0]
        if d[:2] != b"MZ":
            raise MetaError("not a PE file")
        pe = u32(0x3C)
        nsec, optsz = u16(pe + 6), u16(pe + 20)
        opt = pe + 24
        magic = u16(opt)
        ddir = opt + (112 if magic == 0x20B else 96)
        self.secs = []
        for i in range(nsec):
            b = opt + optsz + 40 * i
            self.secs.append((u32(b + 12), max(u32(b + 8), u32(b + 16)), u32(b + 20)))
        cli_rva = u32(ddir + 8 * 14)
        if not cli_rva:
            raise MetaError("no CLI header: not a .NET assembly")
        cli = self.off(cli_rva)
        meta_rva, meta_size = u32(cli + 8), u32(cli + 12)
        self.entry_token = u32(cli + 20)
        m = self.off(meta_rva)
        if d[m:m + 4] != b"BSJB":
            raise MetaError("bad metadata signature")
        vlen = u32(m + 12)
        p = m + 16 + vlen
        nstreams = u16(p + 2)
        p += 4
        self.streams = {}
        for _ in range(nstreams):
            off, size = u32(p), u32(p + 4)
            p += 8
            e = d.find(b"\0", p)
            name = d[p:e].decode()
            p = e + 1
            p += -(p - m) % 4
            self.streams[name] = (m + off, size)
        self.strings = self.streams["#Strings"][0]
        self.blobs = self.streams.get("#Blob", (0, 0))[0]
        self.us = self.streams.get("#US", (0, 0))[0]
        self._tables(self.streams.get("#~") or self.streams["#-"])

    def off(self, rva):
        for va, vs, ro in self.secs:
            if va <= rva < va + vs:
                return ro + rva - va
        raise MetaError(f"RVA {rva:#x} is in no section")

    # ---- heaps ----
    def string(self, i):
        o = self.strings + i
        e = self.d.find(b"\0", o)
        return self.d[o:e].decode("utf-8", "replace")

    def blob(self, i):
        o = self.blobs + i
        n, o = decode_cint(self.d, o)
        return bytes(self.d[o:o + n])

    def user_string(self, i):
        o = self.us + i
        n, o = decode_cint(self.d, o)
        return self.d[o:o + n - 1].decode("utf-16-le", "surrogatepass") if n else ""

    # ---- tables ----
    def _tables(self, stream):
        d, o = self.d, stream[0]
        heap = d[o + 6]
        valid = struct.unpack_from("<Q", d, o + 8)[0]
        o += 24
        self.rows = [0] * 64
        for i in range(64):
            if valid >> i & 1:
                self.rows[i] = struct.unpack_from("<I", d, o)[0]
                o += 4
        if heap & 0x40:
            o += 4
        sizes = {"str": 4 if heap & 1 else 2, "guid": 4 if heap & 2 else 2, "blob": 4 if heap & 4 else 2,
                 "u2": 2, "u4": 4}

        def colsize(c):
            if c in sizes:
                return sizes[c]
            if c[0] == "T" and c[1:].isdigit():
                return 2 if self.rows[int(c[1:])] < 0x10000 else 4
            bits, tabs = CODED[c]
            mx = max(self.rows[TID[t]] for t in tabs if t)
            return 2 if mx < (1 << (16 - bits)) else 4
        self.tab = {}
        for i, (name, schema) in enumerate(TABLES):
            cols = schema.split()
            cs = [colsize(c) for c in cols]
            rowsize = sum(cs)
            self.tab[name] = (o, rowsize, cols, cs, self.rows[i])
            o += rowsize * self.rows[i]
        self._cache = {}

    def nrows(self, name):
        return self.tab[name][4]

    def row(self, name, i):
        """1-based row -> tuple of column values (coded indexes as (table, row))"""
        key = (name, i)
        r = self._cache.get(key)
        if r is not None:
            return r
        o, rs, cols, cs, n = self.tab[name]
        if not 1 <= i <= n:
            raise MetaError(f"{name} row {i} out of range")
        p = o + rs * (i - 1)
        out = []
        for c, s in zip(cols, cs):
            v = struct.unpack_from("<H" if s == 2 else "<I", self.d, p)[0]
            p += s
            if c in CODED:
                bits, tabs = CODED[c]
                v = (tabs[v & ((1 << bits) - 1)], v >> bits)
            elif c == "str":
                v = self.string(v)
            out.append(v)
        r = tuple(out)
        self._cache[key] = r
        return r

    def rows_of(self, name):
        return (self.row(name, i) for i in range(1, self.nrows(name) + 1))

    def range_of(self, table, col, i, target):
        """rows of `target` owned by row i of `table` (FieldList, MethodList...)"""
        start = self.row(table, i)[col]
        end = self.row(table, i + 1)[col] if i < self.nrows(table) else self.nrows(target) + 1
        return range(start, end)

    # ---- method bodies ----
    def body(self, rva):
        d = self.d
        o = self.off(rva)
        h = d[o]
        if h & 3 == 2:                       # tiny header
            return {"code": bytes(d[o + 1:o + 1 + (h >> 2)]), "maxstack": 8, "locals": 0, "eh": [],
                    "init_locals": False}
        flags, maxstack, size, ltok = struct.unpack_from("<HHII", d, o)
        hsize = (flags >> 12) * 4
        code = bytes(d[o + hsize:o + hsize + size])
        eh = []
        p = o + hsize + size
        more = flags & 8
        while more:
            p += -p % 4
            kind = d[p]
            if kind & 0x40:                  # fat sections
                n = (struct.unpack_from("<I", d, p)[0] >> 8)
                cnt = (n - 4) // 24
                for k in range(cnt):
                    eh.append(struct.unpack_from("<IIIIII", d, p + 4 + 24 * k))
                p += n
            else:
                n = d[p + 1]
                cnt = (n - 4) // 12
                for k in range(cnt):
                    fl, to, tl, ho, hl, ct = struct.unpack_from("<HHBHBI", d, p + 4 + 12 * k)
                    eh.append((fl, to, tl, ho, hl, ct))
                p += n
            more = kind & 0x80
        return {"code": code, "maxstack": maxstack, "locals": ltok, "eh": eh,
                "init_locals": bool(flags & 0x10)}

    def field_rva_data(self, field_row, size):
        for i in range(1, self.nrows("FieldRVA") + 1):
            rva, f = self.row("FieldRVA", i)
            if f == field_row:
                o = self.off(rva)
                return bytes(self.d[o:o + size])
        return None


def decode_cint(d, o):
    b = d[o]
    if b & 0x80 == 0:
        return b, o + 1
    if b & 0xC0 == 0x80:
        return ((b & 0x3F) << 8) | d[o + 1], o + 2
    return ((b & 0x1F) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3], o + 4


class Sig:
    """reader over a signature blob"""
    def __init__(self, b):
        self.b, self.o = b, 0

    def u8(self):
        v = self.b[self.o]
        self.o += 1
        return v

    def cint(self):
        v, self.o = decode_cint(self.b, self.o)
        return v

    def tdor(self):
        v = self.cint()
        return (["TypeDef", "TypeRef", "TypeSpec"][v & 3], v >> 2)

    def peek(self):
        return self.b[self.o]


PRIM = {0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "i1", 0x05: "u1", 0x06: "i2", 0x07: "u2",
        0x08: "i4", 0x09: "u4", 0x0A: "i8", 0x0B: "u8", 0x0C: "r4", 0x0D: "r8", 0x18: "i", 0x19: "u",
        0x0E: "string", 0x1C: "object", 0x16: "typedref"}


def read_type(s):
    """signature type -> nested tuples (resolved later by the compiler):
       ('prim', name) | ('tok', (table,row), is_valuetype) | ('szarray', t) |
       ('array', t, rank) | ('byref', t) | ('ptr', t) | ('var', n) | ('mvar', n) |
       ('ginst', base, is_valuetype, (args...)) | ('fnptr',)"""
    e = s.u8()
    while e in (0x1F, 0x20):                 # custom modifiers
        s.tdor()
        e = s.u8()
    if e == 0x45:                            # pinned
        return read_type(s)
    if e in PRIM:
        return ("prim", PRIM[e])
    if e == 0x11:
        return ("tok", s.tdor(), True)
    if e == 0x12:
        return ("tok", s.tdor(), False)
    if e == 0x1D:
        return ("szarray", read_type(s))
    if e == 0x14:
        t = read_type(s)
        rank = s.cint()
        for _ in range(s.cint()):
            s.cint()
        for _ in range(s.cint()):
            s.cint()
        return ("array", t, rank)
    if e == 0x10:
        return ("byref", read_type(s))
    if e == 0x0F:
        return ("ptr", read_type(s))
    if e == 0x13:
        return ("var", s.cint())
    if e == 0x1E:
        return ("mvar", s.cint())
    if e == 0x15:
        kind = s.u8()
        base = s.tdor()
        n = s.cint()
        return ("ginst", base, kind == 0x11, tuple(read_type(s) for _ in range(n)))
    if e == 0x1B:
        read_method_sig(s)
        return ("fnptr",)
    raise MetaError(f"unsupported signature element {e:#x}")


def read_method_sig(s):
    cc = s.u8()
    gen = s.cint() if cc & 0x10 else 0
    n = s.cint()
    ret = read_type(s)
    params = []
    for _ in range(n):
        if s.peek() == 0x41:                 # vararg sentinel
            s.u8()
        params.append(read_type(s))
    return {"hasthis": bool(cc & 0x20), "explicit": bool(cc & 0x40), "generic": gen,
            "ret": ret, "params": params, "vararg": (cc & 0xF) == 5}


def method_sig(b):
    return read_method_sig(Sig(b))


def field_sig(b):
    s = Sig(b)
    if s.u8() != 0x06:
        raise MetaError("not a field signature")
    return read_type(s)


def locals_sig(b):
    s = Sig(b)
    if s.u8() != 0x07:
        raise MetaError("not a locals signature")
    return [read_type(s) for _ in range(s.cint())]


def typespec_sig(b):
    return read_type(Sig(b))


def methodspec_sig(b):
    s = Sig(b)
    if s.u8() != 0x0A:
        raise MetaError("not a method spec")
    return tuple(read_type(s) for _ in range(s.cint()))
