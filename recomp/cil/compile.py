"""cil2c: .NET IL (C#) -> C that runs inside the Mono runtime.

Every method that can be translated becomes a C function. In a patched copy of
the assembly those methods are marked InternalCall and the C functions are
registered with mono_add_internal_call, so Mono runs the C code instead of
JIT-compiling the IL. Objects, classes, GC, strings and reflection stay
Mono's; the C code uses them through Mono's public embedding API.

What stays IL (Mono compiles it as before), each listed in the report with
the reason: generic methods and methods of generic classes, exception filters,
calli/localloc, multi-dimensional array constructors and a few rarer opcodes.
"""
import os
import re
import shutil
import struct

from . import meta

# ---------------------------------------------------------------------------
# opcodes: code -> (name, operand kind)
OPS = {}
_one = """00 nop - 01 break - 02 ldarg.0 - 03 ldarg.1 - 04 ldarg.2 - 05 ldarg.3 - 06 ldloc.0 - 07 ldloc.1 -
08 ldloc.2 - 09 ldloc.3 - 0a stloc.0 - 0b stloc.1 - 0c stloc.2 - 0d stloc.3 - 0e ldarg.s u8 0f ldarga.s u8
10 starg.s u8 11 ldloc.s u8 12 ldloca.s u8 13 stloc.s u8 14 ldnull - 15 ldc.i4.m1 - 16 ldc.i4.0 - 17 ldc.i4.1 -
18 ldc.i4.2 - 19 ldc.i4.3 - 1a ldc.i4.4 - 1b ldc.i4.5 - 1c ldc.i4.6 - 1d ldc.i4.7 - 1e ldc.i4.8 - 1f ldc.i4.s i8
20 ldc.i4 i32 21 ldc.i8 i64 22 ldc.r4 r4 23 ldc.r8 r8 25 dup - 26 pop - 27 jmp tok 28 call tok 29 calli tok
2a ret - 2b br.s b8 2c brfalse.s b8 2d brtrue.s b8 2e beq.s b8 2f bge.s b8 30 bgt.s b8 31 ble.s b8 32 blt.s b8
33 bne.un.s b8 34 bge.un.s b8 35 bgt.un.s b8 36 ble.un.s b8 37 blt.un.s b8 38 br b32 39 brfalse b32
3a brtrue b32 3b beq b32 3c bge b32 3d bgt b32 3e ble b32 3f blt b32 40 bne.un b32 41 bge.un b32
42 bgt.un b32 43 ble.un b32 44 blt.un b32 45 switch sw 46 ldind.i1 - 47 ldind.u1 - 48 ldind.i2 -
49 ldind.u2 - 4a ldind.i4 - 4b ldind.u4 - 4c ldind.i8 - 4d ldind.i - 4e ldind.r4 - 4f ldind.r8 -
50 ldind.ref - 51 stind.ref - 52 stind.i1 - 53 stind.i2 - 54 stind.i4 - 55 stind.i8 - 56 stind.r4 -
57 stind.r8 - 58 add - 59 sub - 5a mul - 5b div - 5c div.un - 5d rem - 5e rem.un - 5f and - 60 or -
61 xor - 62 shl - 63 shr - 64 shr.un - 65 neg - 66 not - 67 conv.i1 - 68 conv.i2 - 69 conv.i4 -
6a conv.i8 - 6b conv.r4 - 6c conv.r8 - 6d conv.u4 - 6e conv.u8 - 6f callvirt tok 70 cpobj tok 71 ldobj tok
72 ldstr tok 73 newobj tok 74 castclass tok 75 isinst tok 76 conv.r.un - 79 unbox tok 7a throw -
7b ldfld tok 7c ldflda tok 7d stfld tok 7e ldsfld tok 7f ldsflda tok 80 stsfld tok 81 stobj tok
82 conv.ovf.i1.un - 83 conv.ovf.i2.un - 84 conv.ovf.i4.un - 85 conv.ovf.i8.un - 86 conv.ovf.u1.un -
87 conv.ovf.u2.un - 88 conv.ovf.u4.un - 89 conv.ovf.u8.un - 8a conv.ovf.i.un - 8b conv.ovf.u.un -
8c box tok 8d newarr tok 8e ldlen - 8f ldelema tok 90 ldelem.i1 - 91 ldelem.u1 - 92 ldelem.i2 -
93 ldelem.u2 - 94 ldelem.i4 - 95 ldelem.u4 - 96 ldelem.i8 - 97 ldelem.i - 98 ldelem.r4 - 99 ldelem.r8 -
9a ldelem.ref - 9b stelem.i - 9c stelem.i1 - 9d stelem.i2 - 9e stelem.i4 - 9f stelem.i8 - a0 stelem.r4 -
a1 stelem.r8 - a2 stelem.ref - a3 ldelem tok a4 stelem tok a5 unbox.any tok b3 conv.ovf.i1 -
b4 conv.ovf.u1 - b5 conv.ovf.i2 - b6 conv.ovf.u2 - b7 conv.ovf.i4 - b8 conv.ovf.u4 - b9 conv.ovf.i8 -
ba conv.ovf.u8 - c2 refanyval tok c3 ckfinite - c6 mkrefany tok d0 ldtoken tok d1 conv.u2 - d2 conv.u1 -
d3 conv.i - d4 conv.ovf.i - d5 conv.ovf.u - d6 add.ovf - d7 add.ovf.un - d8 mul.ovf - d9 mul.ovf.un -
da sub.ovf - db sub.ovf.un - dc endfinally - dd leave b32 de leave.s b8 df stind.i - e0 conv.u -"""
_two = """00 arglist - 01 ceq - 02 cgt - 03 cgt.un - 04 clt - 05 clt.un - 06 ldftn tok 07 ldvirtftn tok
09 ldarg u16 0a ldarga u16 0b starg u16 0c ldloc u16 0d ldloca u16 0e stloc u16 0f localloc -
11 endfilter - 12 unaligned. u8 13 volatile. - 14 tail. - 15 initobj tok 16 constrained. tok 17 cpblk -
18 initblk - 19 no. u8 1a rethrow - 1c sizeof tok 1d refanytype - 1e readonly. -"""
for _src, _pre in ((_one, 0), (_two, 0xFE00)):
    _t = _src.split()
    for _i in range(0, len(_t), 3):
        OPS[_pre | int(_t[_i], 16)] = (_t[_i + 1], _t[_i + 2])


class Unsupported(Exception):
    pass


def decode(code):
    """IL bytes -> [(offset, name, operand, next_offset)]"""
    out, o = [], 0
    while o < len(code):
        start = o
        op = code[o]
        o += 1
        if op == 0xFE:
            op = 0xFE00 | code[o]
            o += 1
        if op not in OPS:
            raise Unsupported(f"unknown opcode {op:#x}")
        name, kind = OPS[op]
        arg = None
        if kind == "u8":
            arg = code[o]; o += 1
        elif kind == "i8":
            arg = struct.unpack_from("<b", code, o)[0]; o += 1
        elif kind == "b8":
            arg = struct.unpack_from("<b", code, o)[0] + o + 1; o += 1
        elif kind == "u16":
            arg = struct.unpack_from("<H", code, o)[0]; o += 2
        elif kind == "i32":
            arg = struct.unpack_from("<i", code, o)[0]; o += 4
        elif kind == "b32":
            arg = struct.unpack_from("<i", code, o)[0] + o + 4; o += 4
        elif kind == "tok":
            arg = struct.unpack_from("<I", code, o)[0]; o += 4
        elif kind == "i64":
            arg = struct.unpack_from("<q", code, o)[0]; o += 8
        elif kind == "r4":
            arg = struct.unpack_from("<f", code, o)[0]; o += 4
        elif kind == "r8":
            arg = struct.unpack_from("<d", code, o)[0]; o += 8
        elif kind == "sw":
            n = struct.unpack_from("<I", code, o)[0]; o += 4
            base = o + 4 * n
            arg = [struct.unpack_from("<i", code, o + 4 * k)[0] + base for k in range(n)]
            o = base
        out.append((start, name, arg, o))
    return out


# ---------------------------------------------------------------------------
# types
PRIM_C = {"bool": "uint8_t", "char": "uint16_t", "i1": "int8_t", "u1": "uint8_t", "i2": "int16_t",
          "u2": "uint16_t", "i4": "int32_t", "u4": "uint32_t", "i8": "int64_t", "u8": "uint64_t",
          "r4": "float", "r8": "double", "i": "intptr_t", "u": "uintptr_t"}
PRIM_STACK = {"bool": "i4", "char": "i4", "i1": "i4", "u1": "i4", "i2": "i4", "u2": "i4", "i4": "i4",
              "u4": "i4", "i8": "i8", "u8": "i8", "r4": "r4", "r8": "r8", "i": "i", "u": "i"}
STACK_C = {"i4": "int32_t", "i8": "int64_t", "r4": "float", "r8": "double", "i": "intptr_t",
           "o": "MonoObject *"}
SYS_PRIM = {"Boolean": "bool", "Char": "char", "SByte": "i1", "Byte": "u1", "Int16": "i2", "UInt16": "u2",
            "Int32": "i4", "UInt32": "u4", "Int64": "i8", "UInt64": "u8", "Single": "r4", "Double": "r8",
            "IntPtr": "i", "UIntPtr": "u"}
# Mono's names in internal-call signatures (mono_type_get_desc)
DESC = {"void": "void", "bool": "bool", "char": "char", "i1": "sbyte", "u1": "byte", "i2": "int16",
        "u2": "uint16", "i4": "int", "u4": "uint", "i8": "long", "u8": "ulong", "r4": "single",
        "r8": "double", "i": "intptr", "u": "uintptr", "string": "string", "object": "object",
        "typedref": "typedbyref"}


class T:
    """a resolved type: kind in prim|obj|vt|ptr|void; prim -> p (bool..u);
    vt -> cls (C expression for its MonoClass*), key (identity)"""
    __slots__ = ("kind", "p", "cls", "key", "sig")

    def __init__(self, kind, p=None, cls=None, key=None, sig=None):
        self.kind, self.p, self.cls, self.key, self.sig = kind, p, cls, key, sig

    @property
    def stack(self):
        return {"prim": None, "obj": "o", "ptr": "i", "vt": "vt", "void": None}[self.kind] or PRIM_STACK[self.p]

    @property
    def ctype(self):
        if self.kind == "prim":
            return PRIM_C[self.p]
        return {"obj": "MonoObject *", "ptr": "void *", "vt": "void *", "void": "void"}[self.kind]


class World:
    """assemblies by name (for enums and valuetypes of other assemblies)"""
    def __init__(self, dirs):
        self.dirs, self.cache = dirs, {}

    def get(self, name):
        if name not in self.cache:
            self.cache[name] = None
            for d in self.dirs:
                for ext in (".dll", ".exe"):
                    p = os.path.join(d, name + ext)
                    if os.path.exists(p):
                        try:
                            self.cache[name] = AsmInfo(meta.Assembly(p), self)
                        except meta.MetaError:
                            pass
                        break
                if self.cache[name]:
                    break
        return self.cache[name]


class AsmInfo:
    def __init__(self, a, world):
        self.a, self.world = a, world
        self.name = a.row("Assembly", 1)[7] if a.nrows("Assembly") else os.path.splitext(os.path.basename(a.path))[0]
        self.enclosing = {}
        for i in range(1, a.nrows("NestedClass") + 1):
            nested, encl = a.row("NestedClass", i)
            self.enclosing[nested] = encl
        self.generic_types, self.generic_methods = set(), set()
        for i in range(1, a.nrows("GenericParam") + 1):
            owner = a.row("GenericParam", i)[2]
            (self.generic_types if owner[0] == "TypeDef" else self.generic_methods).add(owner[1])
        self.forwards = None            # (namespace, name) -> AssemblyRef row, see find_type
        self.typedefs = {}
        for i in range(1, a.nrows("TypeDef") + 1):
            r = a.row("TypeDef", i)
            enc = self.enclosing.get(i)
            key = (r[2] if enc is None else None, r[1], enc)
            self.typedefs[(r[2], r[1]) if enc is None else ("/", enc, r[1])] = i
        self.method_owner = {}
        for i in range(1, a.nrows("TypeDef") + 1):
            for m in a.range_of("TypeDef", 5, i, "MethodDef"):
                self.method_owner[m] = i
        self.field_owner = {}
        for i in range(1, a.nrows("TypeDef") + 1):
            for f in a.range_of("TypeDef", 4, i, "Field"):
                self.field_owner[f] = i
        self.typespecs = {}
        for i in range(1, a.nrows("TypeSpec") + 1):
            self.typespecs.setdefault(bytes(a.blob(a.row("TypeSpec", i)[0])), i)
        self.layout = {}
        for i in range(1, a.nrows("ClassLayout") + 1):
            pk, size, parent = a.row("ClassLayout", i)
            self.layout[parent] = size

    # ---- names ----
    def td_name(self, i, ns=True, sep="/"):
        r = self.a.row("TypeDef", i)
        enc = self.enclosing.get(i)
        if enc:
            return self.td_name(enc, ns, sep) + sep + r[1]
        return (r[2] + "." if ns and r[2] else "") + r[1]

    def tr_name(self, i, ns=True):
        scope, name, nspace = self.a.row("TypeRef", i)
        if scope[0] == "TypeRef":
            return self.tr_name(scope[1], ns) + "/" + name
        return (nspace + "." if ns and nspace else "") + name

    # ---- typedef facts ----
    def td_extends(self, i):
        ext = self.a.row("TypeDef", i)[3]
        if ext[1] == 0:
            return None
        if ext[0] == "TypeRef":
            return self.tr_name(ext[1])
        if ext[0] == "TypeDef":
            return self.td_name(ext[1])
        return "?"

    def td_kind(self, i):
        """('enum', prim) | ('vt',) | ('class',)"""
        name = self.td_name(i)
        ext = self.td_extends(i)
        if self.a.row("TypeDef", i)[2] == "System" and self.a.row("TypeDef", i)[1] in SYS_PRIM and \
                self.enclosing.get(i) is None:
            return ("prim", SYS_PRIM[self.a.row("TypeDef", i)[1]])
        if ext == "System.Enum":
            for f in self.a.range_of("TypeDef", 4, i, "Field"):
                fl, fname, sig = self.a.row("Field", f)
                if not fl & 0x10:                 # instance field: value__
                    t = meta.field_sig(self.a.blob(sig))
                    if t[0] == "prim":
                        return ("enum", t[1])
            return ("enum", "i4")
        if ext == "System.ValueType" and name not in ("System.Enum",):
            return ("vt",)
        return ("class",)

    def resolve_tr(self, i):
        """TypeRef -> (AsmInfo, typedef row) or None"""
        scope, name, nspace = self.a.row("TypeRef", i)
        if scope[0] == "AssemblyRef":
            other = self.world.get(self.a.row("AssemblyRef", scope[1])[6])
            if not other:
                return None
            return other.find_type(nspace, name)
        if scope[0] == "TypeRef":
            outer = self.resolve_tr(scope[1])
            if not outer:
                return None
            o, orow = outer
            row = o.typedefs.get(("/", orow, name))
            return (o, row) if row else None
        if scope[0] in ("Module", "ModuleRef"):
            row = self.typedefs.get((nspace, name))
            return (self, row) if row else None
        return None

    def find_type(self, nspace, name, depth=0):
        """a top-level type of this assembly -> (AsmInfo, typedef row) or None.
        Follows type forwarders: netstandard.dll and the facade assemblies
        define nothing, they pass every type on (System.Func`2 -> mscorlib),
        and System.Core does the same for the types that moved to mscorlib."""
        row = self.typedefs.get((nspace, name))
        if row is not None:
            return self, row
        if depth > 8:
            return None
        if self.forwards is None:
            self.forwards = {}
            try:
                for i in range(1, self.a.nrows("ExportedType") + 1):
                    r = self.a.row("ExportedType", i)
                    if r[4][0] == "AssemblyRef" and r[4][1]:
                        self.forwards[(r[3], r[2])] = r[4][1]
            except (meta.MetaError, KeyError, IndexError):
                pass
        ref = self.forwards.get((nspace, name))
        if not ref:
            return None
        other = self.world.get(self.a.row("AssemblyRef", ref)[6])
        return other.find_type(nspace, name, depth + 1) if other else None

    def tok_kind(self, tdor):
        table, row = tdor
        if table == "TypeDef":
            return self.td_kind(row)
        if table == "TypeRef":
            scope, name, nspace = self.a.row("TypeRef", row)
            if nspace == "System" and name in SYS_PRIM and scope[0] != "TypeRef":
                return ("prim", SYS_PRIM[name])
            r = self.resolve_tr(row)
            if not r:
                full = self.tr_name(row)
                if full in CORLIB_CLASSES or (nspace.startswith("System") and re.match(r"I[A-Z]", name)):
                    return ("class",)             # well-known reference types / interfaces
                raise Unsupported(f"cannot resolve type {full}")
            return r[0].td_kind(r[1])
        raise Unsupported("typespec kind")


# reference types of corlib, for when mscorlib.dll is not next to the game's assemblies
CORLIB_CLASSES = set("""System.Object System.String System.Delegate System.MulticastDelegate System.Math
System.Mathf System.Console System.Exception System.Type System.Array System.Attribute System.Enum
System.ValueType System.Activator System.GC System.Environment System.Convert System.BitConverter
System.Buffer System.Random System.Text.StringBuilder System.Text.Encoding System.Threading.Monitor
System.Threading.Interlocked System.Threading.Thread System.Collections.ArrayList System.Collections.Hashtable
System.Collections.Generic.List`1 System.Collections.Generic.Dictionary`2 System.Collections.Generic.HashSet`1
System.Collections.Generic.Queue`1 System.Collections.Generic.Stack`1 System.Collections.Generic.Comparer`1
System.Collections.Generic.EqualityComparer`1 System.Action System.Action`1 System.Action`2 System.Action`3
System.Func`1 System.Func`2 System.Func`3 System.Func`4 System.Predicate`1 System.Comparison`1
System.EventHandler System.EventArgs System.InvalidOperationException System.ArgumentException
System.ArgumentNullException System.ArgumentOutOfRangeException System.NullReferenceException
System.IndexOutOfRangeException System.NotImplementedException System.NotSupportedException
System.OverflowException System.DivideByZeroException System.InvalidCastException System.FormatException
System.Runtime.CompilerServices.RuntimeHelpers System.IO.File System.IO.Path System.IO.Stream
System.Reflection.MethodInfo System.Reflection.FieldInfo System.Linq.Enumerable""".split())

TABLE_TOK = {"TypeDef": 0x02000000, "TypeRef": 0x01000000, "TypeSpec": 0x1B000000}


def encode_type(t):
    """inverse of meta.read_type, for finding a TypeSpec row of a generic type"""
    PRIM_CODE = {v: k for k, v in meta.PRIM.items()}

    def tdor(x):
        tab, row = x
        return enc_cint((row << 2) | ["TypeDef", "TypeRef", "TypeSpec"].index(tab))
    k = t[0]
    if k == "prim":
        return bytes([PRIM_CODE[t[1]]])
    if k == "tok":
        return bytes([0x11 if t[2] else 0x12]) + tdor(t[1])
    if k == "szarray":
        return b"\x1d" + encode_type(t[1])
    if k == "ginst":
        return bytes([0x15, 0x11 if t[2] else 0x12]) + tdor(t[1]) + enc_cint(len(t[3])) + \
            b"".join(encode_type(x) for x in t[3])
    if k == "var":
        return b"\x13" + enc_cint(t[1])
    if k == "mvar":
        return b"\x1e" + enc_cint(t[1])
    if k == "byref":
        return b"\x10" + encode_type(t[1])
    if k == "ptr":
        return b"\x0f" + encode_type(t[1])
    raise Unsupported(f"cannot encode {k}")


def enc_cint(v):
    if v < 0x80:
        return bytes([v])
    if v < 0x4000:
        return bytes([0x80 | (v >> 8), v & 0xFF])
    return bytes([0xC0 | (v >> 24), (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def subst(t, targs, margs):
    """replace VAR/MVAR with the generic arguments of the containing instance"""
    k = t[0]
    if k == "var":
        if targs is None or t[1] >= len(targs):
            raise Unsupported("open generic type")
        return targs[t[1]]
    if k == "mvar":
        if margs is None or t[1] >= len(margs):
            raise Unsupported("open generic method")
        return margs[t[1]]
    if k in ("szarray", "byref", "ptr"):
        return (k, subst(t[1], targs, margs)) + t[2:]
    if k == "array":
        return (k, subst(t[1], targs, margs), t[2])
    if k == "ginst":
        return (k, t[1], t[2], tuple(subst(x, targs, margs) for x in t[3]))
    return t


def has_generic(t):
    k = t[0]
    if k in ("var", "mvar"):
        return True
    if k in ("szarray", "byref", "ptr", "array"):
        return has_generic(t[1])
    if k == "ginst":
        return any(has_generic(x) for x in t[3])
    return False


# ---------------------------------------------------------------------------
class AsmCompiler:
    def __init__(self, ai, cname):
        self.ai, self.a = ai, ai.a
        self.cname = cname                    # C identifier for this assembly
        self.asm_c = f"ASM_{cname}"
        self.decls = {}                       # static cache variable declarations
        self.methods = {}                     # methoddef row -> info
        self.translated = {}                  # row -> info for translated ones
        self.skipped = {}                     # row -> reason

    # ---- caches ----
    def cache(self, kind, tok):
        """a per-site cache variable, shared by all C files of the assembly:
        decls[name] = (extern declaration, definition)"""
        nm = f"{kind}{self.cname}_{tok:08x}"
        ctype = {"K": "MonoClass *", "M": "MonoMethod *", "F": "MonoClassField *", "S": "MonoString *",
                 "SF": "uint8_t *", "CI": "int", "OF": "int32_t", "VS": "int32_t"}[kind]
        self.decls[nm] = (f"extern {ctype} {nm};", f"{ctype} {nm};")
        return nm

    def vsize(self, t):
        """C expression: size of struct type t (cached per class)"""
        tok = int(t.key[1:], 16)
        return f"cil_vt_size_c(&{self.cache('VS', tok)}, {t.cls})"

    def kls(self, tok):
        return f"cil_class(&{self.cache('K', tok)}, {self.asm_c}, {tok:#010x}u)"

    def mth(self, tok):
        return f"cil_method(&{self.cache('M', tok)}, {self.asm_c}, {tok:#010x}u)"

    def fld(self, tok):
        return f"cil_field(&{self.cache('F', tok)}, {self.asm_c}, {tok:#010x}u)"

    # ---- types ----
    def rtype(self, t, ctx_targs=None, ctx_margs=None):
        """signature type -> T"""
        k = t[0]
        if k == "prim":
            if t[1] in ("string", "object"):
                return T("obj")
            if t[1] == "void":
                return T("void")
            if t[1] == "typedref":
                raise Unsupported("typedref")
            return T("prim", t[1])
        if k in ("szarray", "array"):
            return T("obj")
        if k == "byref":
            return T("ptr", "byref")      # mono_runtime_invoke wants the address itself
        if k in ("ptr", "fnptr"):
            return T("ptr")
        if k in ("var", "mvar"):
            raise Unsupported("generic type parameter")
        if k == "tok":
            if not t[2]:
                return T("obj")
            kind = self.ai.tok_kind(t[1])
            if kind[0] in ("prim", "enum"):
                return T("prim", kind[1])
            if kind[0] == "class":
                return T("obj")
            tok = TABLE_TOK[t[1][0]] | t[1][1]
            return T("vt", cls=self.kls(tok), key=f"t{tok:08x}", sig=t)
        if k == "ginst":
            if not t[2]:
                return T("obj")
            row = self.ai.typespecs.get(encode_type(t))
            if row is None:
                raise Unsupported("generic struct type without a TypeSpec row")
            tok = 0x1B000000 | row
            return T("vt", cls=self.kls(tok), key=f"t{tok:08x}", sig=t)
        raise Unsupported(f"type {k}")

    def tok_type(self, tok):
        """a type token (TypeDef/TypeRef/TypeSpec) as T"""
        table = tok >> 24
        row = tok & 0xFFFFFF
        if table == 0x02:
            return self.rtype(("tok", ("TypeDef", row), self.ai.td_kind(row)[0] != "class"))
        if table == 0x01:
            kind = self.ai.tok_kind(("TypeRef", row))
            return self.rtype(("tok", ("TypeRef", row), kind[0] != "class"))
        if table == 0x1B:
            t = meta.typespec_sig(self.a.blob(self.a.row("TypeSpec", row)[0]))
            if has_generic(t):
                raise Unsupported("open generic type")
            if t[0] == "ginst" and t[2]:
                return T("vt", cls=self.kls(tok), key=f"t{tok:08x}", sig=t)
            return self.rtype(t)
        raise Unsupported("type token")

    # ---- methods ----
    def method_ref(self, tok):
        """call target -> dict(sig, hasthis, params[T], ret T, row (if our MethodDef), name, owner_vt,
        virtual, cls_tok, special)"""
        table, row = tok >> 24, tok & 0xFFFFFF
        targs = margs = None
        if table == 0x2B:                       # MethodSpec: generic method instance
            mrow = self.a.row("MethodSpec", row)
            margs = meta.methodspec_sig(self.a.blob(mrow[1]))
            if any(has_generic(x) for x in margs):
                raise Unsupported("call to an open generic method")
            base_tab, base_row = mrow[0]
            base_tok = (0x06000000 if base_tab == "MethodDef" else 0x0A000000) | base_row
            if base_tab == "MemberRef":
                r = self.method_ref_memberref(base_row, margs)
            else:
                r = self.method_ref_def(base_row, margs)
            r["row"] = None                     # generic instance: never a direct C call
            r["tok"] = tok
            return r
        if table == 0x06:
            return self.method_ref_def(row, None)
        if table == 0x0A:
            return self.method_ref_memberref(row, None)
        raise Unsupported("call token")

    def method_ref_def(self, row, margs):
        rva, iflags, flags, name, sig, plist = self.a.row("MethodDef", row)
        s = meta.method_sig(self.a.blob(sig))
        owner = self.ai.method_owner[row]
        kind = self.ai.td_kind(owner)
        return self._mref(s, None, margs, name, row, 0x06000000 | row, kind[0] != "class", flags,
                          self.ai.td_name(owner), 0x02000000 | owner)

    def method_ref_memberref(self, row, margs):
        parent, name, sig = self.a.row("MemberRef", row)
        s = meta.method_sig(self.a.blob(sig))
        targs, owner_vt, owner_name, cls_tok = None, False, "?", None
        if parent[0] == "TypeSpec":
            t = meta.typespec_sig(self.a.blob(self.a.row("TypeSpec", parent[1])[0]))
            if has_generic(t):
                raise Unsupported("member of an open generic type")
            cls_tok = 0x1B000000 | parent[1]
            if t[0] == "ginst":
                targs, owner_vt = t[3], t[2]
                owner_name = self._tdor_name(t[1])
            else:
                owner_name = "array" if t[0] in ("szarray", "array") else "?"
                if t[0] == "array" and name in (".ctor", "Get", "Set", "Address"):
                    raise Unsupported("multi-dimensional array method")
        elif parent[0] == "TypeRef":
            cls_tok = 0x01000000 | parent[1]
            owner_name = self.ai.tr_name(parent[1])
            owner_vt = self.ai.tok_kind(("TypeRef", parent[1]))[0] != "class"
        elif parent[0] == "TypeDef":
            cls_tok = 0x02000000 | parent[1]
            owner_name = self.ai.td_name(parent[1])
            owner_vt = self.ai.td_kind(parent[1])[0] != "class"
        else:
            raise Unsupported("vararg / module method reference")
        # is the target one of our own MethodDefs? (MemberRef to a TypeDef member)
        mrow = None
        if parent[0] == "TypeDef":
            for m in self.a.range_of("TypeDef", 5, parent[1], "MethodDef"):
                r = self.a.row("MethodDef", m)
                if r[3] == name and bytes(self.a.blob(r[4])) == bytes(self.a.blob(sig)):
                    mrow = m
        flags = self.a.row("MethodDef", mrow)[2] if mrow else None
        return self._mref(s, targs, margs, name, mrow, 0x0A000000 | row, owner_vt, flags, owner_name, cls_tok)

    def _tdor_name(self, tdor):
        return self.ai.td_name(tdor[1]) if tdor[0] == "TypeDef" else self.ai.tr_name(tdor[1])

    def _mref(self, s, targs, margs, name, row, tok, owner_vt, flags, owner_name, cls_tok):
        if s["vararg"]:
            raise Unsupported("vararg call")
        params = [self.rtype(subst(p, targs, margs)) for p in s["params"]]
        ret = self.rtype(subst(s["ret"], targs, margs))
        virtual = flags is None or bool(flags & 0x40)    # unknown (external): assume virtual
        if flags is not None and flags & 0x20 and not flags & 0x40:
            virtual = False                               # final non-virtual
        return {"hasthis": s["hasthis"], "params": params, "ret": ret, "row": row, "tok": tok,
                "name": name, "owner_vt": owner_vt, "virtual": virtual, "owner": owner_name,
                "cls_tok": cls_tok, "static": not s["hasthis"]}

    def field_ref(self, tok):
        """(T of the field, static?, owner is valuetype?)"""
        table, row = tok >> 24, tok & 0xFFFFFF
        if table == 0x04:
            fl, name, sig = self.a.row("Field", row)
            t = meta.field_sig(self.a.blob(sig))
            owner = self.ai.field_owner[row]
            if owner in self.ai.generic_types:
                raise Unsupported("field of a generic type")
            return self.rtype(t), bool(fl & 0x10), self.ai.td_kind(owner)[0] != "class", row
        if table == 0x0A:
            parent, name, sig = self.a.row("MemberRef", row)
            t = meta.field_sig(self.a.blob(sig))
            targs, owner_vt = None, False
            if parent[0] == "TypeSpec":
                ts = meta.typespec_sig(self.a.blob(self.a.row("TypeSpec", parent[1])[0]))
                if has_generic(ts) or ts[0] != "ginst":
                    raise Unsupported("field of an open generic type")
                targs, owner_vt = ts[3], ts[2]
            elif parent[0] == "TypeRef":
                owner_vt = self.ai.tok_kind(("TypeRef", parent[1]))[0] != "class"
            elif parent[0] == "TypeDef":
                owner_vt = self.ai.td_kind(parent[1])[0] != "class"
            ft = self.rtype(subst(t, targs, None))
            # static-ness of an external field is not in the MemberRef; the
            # opcode (ldsfld vs ldfld) tells it, so callers pass it themselves
            return ft, None, owner_vt, None
        raise Unsupported("field token")

    # ---- per method ----
    def method_info(self, row):
        rva, iflags, flags, name, sig, plist = self.a.row("MethodDef", row)
        owner = self.ai.method_owner[row]
        info = {"row": row, "tok": 0x06000000 | row, "name": name, "owner": owner, "rva": rva,
                "flags": flags, "iflags": iflags}
        why = None
        if not rva:
            why = "no IL body (abstract, extern, runtime)"
        elif iflags & 0x1000 or iflags & 0x3 or flags & 0x2000:
            why = "internal call / native / pinvoke"
        elif iflags & 0x20:
            why = "synchronized method"
        elif owner in self.ai.generic_types or self.enclosing_generic(owner):
            why = "method of a generic class"
        elif row in self.ai.generic_methods:
            why = "generic method"
        if why:
            raise Unsupported(why)
        s = meta.method_sig(self.a.blob(sig))
        if s["vararg"]:
            raise Unsupported("vararg method")
        if s["generic"]:
            raise Unsupported("generic method")
        kind = self.ai.td_kind(owner)
        info["owner_vt"] = kind[0] != "class"
        info["params"] = [self.rtype(p) for p in s["params"]]
        info["ret"] = self.rtype(s["ret"])
        info["hasthis"] = s["hasthis"]
        info["sig"] = s
        info["virtual"] = bool(flags & 0x40)
        info["cname"] = f"cil_{self.cname}_{row:x}"
        return info

    def enclosing_generic(self, td):
        e = self.ai.enclosing.get(td)
        while e:
            if e in self.ai.generic_types:
                return True
            e = self.ai.enclosing.get(e)
        return False

    def c_params(self, info):
        ps = []
        if info["hasthis"]:
            ps.append(("void *" if info["owner_vt"] else "MonoObject *", "a0"))
        off = 1 if info["hasthis"] else 0
        for k, t in enumerate(info["params"]):
            ps.append((t.ctype, f"a{k + off}"))
        if info["ret"].kind == "vt":
            ps.insert(0, ("void *", "retp"))
        return ps

    def proto(self, info, name=None):
        ret = "void" if info["ret"].kind == "vt" else info["ret"].ctype
        ps = self.c_params(info) or [("void", "")]
        return f"{ret} {name or info['cname']}({', '.join((t + ' ' + n).strip() for t, n in ps)})"

    def exposable(self, info):
        """can Mono call it as an internal call? (no struct this/args/return)"""
        if info["owner_vt"] and info["hasthis"]:
            return False
        if info["ret"].kind == "vt" or any(p.kind == "vt" for p in info["params"]):
            return False
        return True

    def icall_names(self, info):
        """the strings Mono looks internal calls up by: Ns.Class::Method(sig);
        registered with and without namespaces in the signature (Mono versions differ)"""
        s = info["sig"]
        cls = self.ai.td_name(info["owner"])
        out = []
        for ns in (True, False):
            d = ",".join(self.desc(p, ns) for p in s["params"])
            out.append(f"{cls}::{info['name']}({d})")
        same = [m for m in self.a.range_of("TypeDef", 5, info["owner"], "MethodDef")
                if self.a.row("MethodDef", m)[3] == info["name"]]
        if len(same) == 1:
            out.append(f"{cls}::{info['name']}")
        return list(dict.fromkeys(out))

    def desc(self, t, ns):
        k = t[0]
        if k == "prim":
            return DESC[t[1]]
        if k == "szarray":
            return self.desc(t[1], ns) + "[]"
        if k == "array":
            return self.desc(t[1], ns) + "[" + "," * (t[2] - 1) + "]"
        if k == "byref":
            return self.desc(t[1], ns) + "&"
        if k == "ptr":
            return self.desc(t[1], ns) + "*"
        if k == "tok":
            return self._tdor_name_ns(t[1], ns)
        if k == "ginst":
            return self._tdor_name_ns(t[1], ns) + "<" + ",".join(self.desc(x, ns) for x in t[3]) + ">"
        if k == "fnptr":
            return "*()"
        raise Unsupported("desc")

    def _tdor_name_ns(self, tdor, ns):
        tab, row = tdor
        if tab == "TypeDef":
            full = self.ai.td_name(row, True)
            short = self.ai.td_name(row, False)
        elif tab == "TypeRef":
            full = self.ai.tr_name(row, True)
            short = self.ai.tr_name(row, False)
        else:
            raise Unsupported("typespec in signature")
        return full if ns else short

    # -----------------------------------------------------------------------
    def compile(self):
        rows = range(1, self.a.nrows("MethodDef") + 1)
        for r in rows:
            try:
                self.methods[r] = self.method_info(r)
            except Unsupported as e:
                self.skipped[r] = str(e)
            except meta.MetaError as e:
                self.skipped[r] = f"metadata: {e}"
        bodies = {}
        for r, info in list(self.methods.items()):
            try:
                bodies[r] = MethodCompiler(self, info).compile()
                self.translated[r] = info
            except Unsupported as e:
                self.skipped[r] = str(e)
            except (meta.MetaError, KeyError, IndexError, struct.error) as e:
                self.skipped[r] = f"translator: {type(e).__name__} {e}"
        # direct calls to methods that turned out untranslatable: recompile
        # those callers with invoke() instead (iterate until stable)
        changed = True
        while changed:
            changed = False
            for r in list(self.translated):
                mc = MethodCompiler(self, self.translated[r])
                try:
                    bodies[r] = mc.compile()
                except Unsupported as e:
                    self.skipped[r] = str(e)
                    del self.translated[r]
                    changed = True
        return bodies

    def method_label(self, r):
        info = self.methods.get(r)
        owner = self.ai.method_owner.get(r)
        return f"{self.ai.td_name(owner) if owner else '?'}::{self.a.row('MethodDef', r)[3]}"


class MethodCompiler:
    def __init__(self, ac, info):
        self.ac, self.info, self.a, self.ai = ac, info, ac.a, ac.ai
        self.lines = []
        self.slots = {}          # var name -> decl
        self.tmp = 0

    def un(self, why):
        raise Unsupported(why)

    def compile(self):
        info = self.info
        body = self.a.body(info["rva"])
        self.ins = decode(body["code"])
        self.by_off = {o: k for k, (o, *_r) in enumerate(self.ins)}
        self.code_len = len(body["code"])
        self.locals = []
        if body["locals"]:
            sig = self.a.row("StandAloneSig", body["locals"] & 0xFFFFFF)[0]
            self.locals = [self.ac.rtype(t) for t in meta.locals_sig(self.a.blob(sig))]
        self.args = []
        if info["hasthis"]:
            self.args.append(T("ptr") if info["owner_vt"] else T("obj"))
        self.args += info["params"]
        self.eh = body["eh"]
        for c in self.eh:
            if c[0] & 1:
                self.un("exception filter")
        self.has_eh = bool(self.eh)
        self.vol = "volatile " if self.has_eh else ""
        self.eh_groups = dict(self.groups())
        self.leave_id, self.fin_targets, self.constrained = 0, {}, None
        self.analyze()
        return self.generate()

    # ---- EH structure ----
    def groups(self):
        g = {}
        for c in self.eh:
            fl, to, tl, ho, hl, ct = c
            g.setdefault((to, tl), []).append(c)
        # outer (longer) groups first for the same start
        return sorted(g.items(), key=lambda kv: (kv[0][0], -kv[0][1]))

    def in_try(self, off, key):
        return key[0] <= off < key[0] + key[1]

    # ---- stack analysis ----
    def analyze(self):
        self.entry = {}
        work = [(0, ())]
        for (to, tl), cl in self.groups():
            for c in cl:
                st = (("o", None),) if c[0] == 0 else ()
                work.append((c[3], st))
        self.mode = "analyze"
        seen = 0
        while work:
            off, st = work.pop()
            if off in self.entry:
                if not self.same(self.entry[off], st):
                    self.un(f"stack shape differs at IL_{off:04x}")
                continue
            self.entry[off] = st
            k = self.by_off.get(off)
            if k is None:
                self.un(f"branch into the middle of an instruction at IL_{off:04x}")
            while True:
                seen += 1
                if seen > 200000:
                    self.un("method too large")
                o, name, arg, nxt = self.ins[k]
                st, succ, falls = self.sim(k, list(st))
                for s in succ:
                    work.append((s, tuple(st) if name not in ("leave", "leave.s") else ()))
                if not falls:
                    break
                if nxt >= self.code_len:
                    break
                if nxt in self.entry:
                    if not self.same(self.entry[nxt], tuple(st)):
                        self.un(f"stack shape differs at IL_{nxt:04x}")
                    break
                self.entry[nxt] = tuple(st)
                k += 1
                st = tuple(st)

    def same(self, a, b):
        if len(a) != len(b):
            return False
        for x, y in zip(a, b):
            if x[0] != y[0]:
                return False
            if x[0] == "vt" and x[1].key != y[1].key:
                return False
        return True

    # ---- helpers for generation ----
    def slot(self, d, t, vt=None):
        if t == "vt":
            nm = f"sv{d}_{vt.key}"
            self.slots[nm] = ("vt", vt)
            return nm
        if t in ("ftn", "fld", "typetok"):
            t = "i"
        nm = f"s{d}_{t}"
        self.slots[nm] = (t, None)
        return nm

    def emit(self, s):
        if self.mode == "gen":
            self.lines.append("    " + s)

    def newtmp(self, ctype):
        self.tmp += 1
        nm = f"t{self.tmp}"
        self.emit(f"{ctype} {nm};")
        return nm

    def label(self, off):
        return f"IL_{off:04x}"

    def target_label(self, src, dst):
        """branch target, skipping try-pushes of groups the source is already in"""
        lab = self.label(dst)
        for key, cl in self.groups():
            if key[0] == dst and self.in_try(src, key):
                lab = f"IL_{dst:04x}_in{key[0]:x}_{key[1]:x}"
        return lab

    def load(self, t, expr):
        """value of exact type t at expr -> (stack type, C expr)"""
        if t.kind == "prim":
            st = PRIM_STACK[t.p]
            return st, f"({STACK_C[st]})({expr})"
        if t.kind == "obj":
            return "o", expr
        if t.kind == "ptr":
            return "i", f"(intptr_t)({expr})"
        raise Unsupported("load vt")

    def conv_to(self, t, st_entry, var):
        """stack value -> C expression of exact type t"""
        # the stack value may be of another kind than t: IL written by other
        # compilers than C#'s uses 0 for null, object references as numbers...
        # C wants that said with a cast (gcc 14+ refuses it otherwise)
        if t.kind == "prim":
            if st_entry[0] in ("o", "vt"):
                return f"({PRIM_C[t.p]})(intptr_t)({var})"
            return f"({PRIM_C[t.p]})({var})"
        if t.kind == "obj":
            return var if st_entry[0] == "o" else f"({t.ctype})(intptr_t)({var})"
        if t.kind == "ptr":
            return f"(void *)({var})"
        if t.kind == "vt":
            return var
        raise Unsupported("conv")

    # ---- the simulator / generator ----
    def sim(self, k, st):
        """one instruction: returns (stack after, branch successors, falls through)"""
        o, name, arg, nxt = self.ins[k]
        D = len(st)
        emit = self.emit
        info = self.info
        succ, falls = [], True

        def pop():
            if not st:
                self.un(f"stack underflow at IL_{o:04x}")
            e = st.pop()
            return e, self.slot(len(st), e[0], e[1])

        def push(t, expr, vt=None):
            nm = self.slot(len(st), t, vt)
            if t == "vt":
                emit(f"memcpy({nm}, {expr}, {self.ac.vsize(vt)});")
            else:
                emit(f"{nm} = {expr};")
            st.append((t, vt))
            return nm

        def push_t(t, expr):
            """push a value of exact type t that lives at expr (an lvalue / address for vt)"""
            if t.kind == "vt":
                return push("vt", expr, t)
            s, e = self.load(t, expr)
            return push(s, e)

        def binop_type(a, b, opn):
            ta, tb = a[0], b[0]
            if ta == tb and ta in ("i4", "i8", "i", "r4", "r8"):
                return ta
            if {ta, tb} == {"i4", "i"}:
                return "i"
            if {ta, tb} <= {"r4", "r8"}:
                return "r8"
            if ta == "o" or tb == "o":
                if opn in ("ceq", "beq", "bne.un", "cgt.un", "clt.un"):
                    return "o"
            if {ta, tb} <= {"i", "o"} and opn in ("ceq", "beq", "bne.un", "cgt.un"):
                return "i"
            self.un(f"{name} on {ta},{tb}")

        def cast(stt, var):
            return f"({STACK_C[stt]})({var})" if stt != "o" else var

        if name in ("nop", "break") or name.endswith(".") and name not in ("constrained.",):
            return st, succ, True

        # ---- constants / args / locals ----
        if name == "ldnull":
            push("o", "NULL")
        elif name.startswith("ldc.i4"):
            v = arg if arg is not None else (-1 if name.endswith("m1") else int(name.split(".")[-1]))
            push("i4", f"(int32_t){v}" if v != -2147483648 else "INT32_MIN")
        elif name == "ldc.i8":
            push("i8", f"(int64_t){arg}LL" if arg != -9223372036854775808 else "INT64_MIN")
        elif name in ("ldc.r4", "ldc.r8"):
            v = arg
            if v != v:
                e = "NAN"
            elif v in (float("inf"), float("-inf")):
                e = "INFINITY" if v > 0 else "-INFINITY"
            else:
                e = repr(float(v))
            if name == "ldc.r4":
                push("r4", f"(float){e}")
            else:
                push("r8", e)
        elif name.startswith("ldarg") and not name.startswith("ldarga"):
            i = arg if arg is not None else int(name[-1])
            t = self.args[i]
            push_t(t, f"A{i}")
        elif name.startswith("ldarga"):
            push("i", f"(intptr_t){'' if self.args[arg].kind == 'vt' else '&'}A{arg}")
        elif name.startswith("starg"):
            e, v = pop()
            t = self.args[arg]
            self.store_var(f"A{arg}", t, e, v)
        elif name.startswith("ldloc") and not name.startswith("ldloca"):
            i = arg if arg is not None else int(name[-1])
            push_t(self.locals[i], f"L{i}")
        elif name.startswith("ldloca"):
            push("i", f"(intptr_t){'' if self.locals[arg].kind == 'vt' else '&'}L{arg}")
        elif name.startswith("stloc"):
            i = arg if arg is not None else int(name[-1])
            e, v = pop()
            self.store_var(f"L{i}", self.locals[i], e, v)
        elif name == "dup":
            e = st[-1]
            src = self.slot(D - 1, e[0], e[1])
            push(e[0], src, e[1])
        elif name == "pop":
            pop()
        # ---- arithmetic ----
        elif name in ("add", "sub", "mul", "and", "or", "xor", "div", "div.un", "rem", "rem.un",
                      "add.ovf", "add.ovf.un", "sub.ovf", "sub.ovf.un", "mul.ovf", "mul.ovf.un"):
            b, vb = pop()
            a, va = pop()
            t = binop_type(a, b, name)
            ca, cb = cast(t, va), cast(t, vb)
            sym = {"add": "+", "sub": "-", "mul": "*", "and": "&", "or": "|", "xor": "^"}
            if t in ("r4", "r8"):
                if name in ("div",):
                    e = f"{ca} / {cb}"
                elif name == "rem":
                    e = f"({STACK_C[t]})fmod({ca}, {cb})"
                elif name in sym and name not in ("and", "or", "xor"):
                    e = f"{ca} {sym[name]} {cb}"
                else:
                    self.un(f"{name} on floats")
            else:
                w = {"i4": "4", "i8": "8", "i": "8"}[t]
                u = {"i4": "uint32_t", "i8": "uint64_t", "i": "uintptr_t"}[t]
                sc = STACK_C[t]
                if name in sym:
                    e = f"({sc})(({u}){ca} {sym[name]} ({u}){cb})"     # wrap around, no UB
                elif name == "div":
                    e = f"({sc})cil_div{w}({ca}, {cb})"
                elif name == "rem":
                    e = f"({sc})cil_rem{w}({ca}, {cb})"
                elif name == "div.un":
                    e = f"({sc})cil_divu{w}(({u}){ca}, ({u}){cb})"
                elif name == "rem.un":
                    e = f"({sc})cil_remu{w}(({u}){ca}, ({u}){cb})"
                else:
                    opn = name.split(".")[0]
                    un = name.endswith(".un")
                    e = f"({sc})cil_{opn}_ovf{'u' if un else ''}{w}(({u if un else sc}){ca}, ({u if un else sc}){cb})"
            push(t, e)
        elif name in ("shl", "shr", "shr.un"):
            b, vb = pop()
            a, va = pop()
            t = a[0]
            if t not in ("i4", "i8", "i") or b[0] not in ("i4", "i"):
                self.un("shift types")
            bits = 31 if t == "i4" else 63
            u = {"i4": "uint32_t", "i8": "uint64_t", "i": "uintptr_t"}[t]
            sc = STACK_C[t]
            if name == "shl":
                e = f"({sc})(({u}){va} << ((int){vb} & {bits}))"
            elif name == "shr":
                e = f"({sc})({va} >> ((int){vb} & {bits}))"
            else:
                e = f"({sc})(({u}){va} >> ((int){vb} & {bits}))"
            push(t, e)
        elif name in ("neg", "not"):
            a, va = pop()
            t = a[0]
            if t in ("r4", "r8") and name == "neg":
                push(t, f"-{va}")
            elif t in ("i4", "i8", "i"):
                u = {"i4": "uint32_t", "i8": "uint64_t", "i": "uintptr_t"}[t]
                push(t, f"({STACK_C[t]})(0 - ({u}){va})" if name == "neg" else f"~{va}")
            else:
                self.un(f"{name} on {t}")
        elif name.startswith("conv."):
            a, va = pop()
            self.conv(name, a, va, push)
        elif name == "ckfinite":
            a, va = pop()
            push(a[0], f"({STACK_C[a[0]]})cil_ckfinite({va})")
        # ---- comparisons / branches ----
        elif name in ("ceq", "cgt", "cgt.un", "clt", "clt.un"):
            b, vb = pop()
            a, va = pop()
            push("i4", self.compare(name, a, va, b, vb, binop_type(a, b, name)))
        elif name in ("br", "br.s"):
            succ.append(arg)
            emit(f"goto {self.target_label(o, arg)};")
            falls = False
        elif name in ("brtrue", "brtrue.s", "brfalse", "brfalse.s"):
            a, va = pop()
            neg = "!" if "false" in name else ""
            emit(f"if ({neg}({va})) goto {self.target_label(o, arg)};")
            succ.append(arg)
        elif name.split(".")[0] in ("beq", "bne", "bge", "bgt", "ble", "blt"):
            b, vb = pop()
            a, va = pop()
            base = name[:-2] if name.endswith(".s") else name
            cmpop = {"beq": "ceq", "bne.un": "bne", "bge": "cge", "bge.un": "cge.un", "bgt": "cgt",
                     "bgt.un": "cgt.un", "ble": "cle", "ble.un": "cle.un", "blt": "clt", "blt.un": "clt.un"}[base]
            cond = self.compare(cmpop, a, va, b, vb, binop_type(a, b, base))
            emit(f"if ({cond}) goto {self.target_label(o, arg)};")
            succ.append(arg)
        elif name == "switch":
            a, va = pop()
            if self.mode == "gen":
                emit(f"switch ((uint32_t){va}) {{")
                for i, tgt in enumerate(arg):
                    emit(f"  case {i}: goto {self.target_label(o, tgt)};")
                emit("}")
            succ += arg
        elif name == "ret":
            if info["ret"].kind != "void":
                e, v = pop()
                if info["ret"].kind == "vt":
                    emit(f"memcpy(retp, {v}, {self.ac.vsize(info['ret'])});")
                    emit("return;")
                else:
                    emit(f"return {self.conv_to(info['ret'], e, v)};")
            else:
                emit("return;")
            falls = False
        # ---- indirect ----
        elif name.startswith("ldind."):
            a, va = pop()
            p = {"i1": "i1", "u1": "u1", "i2": "i2", "u2": "u2", "i4": "i4", "u4": "u4", "i8": "i8",
                 "i": "i", "r4": "r4", "r8": "r8"}.get(name[6:])
            if name == "ldind.ref":
                push("o", f"*(MonoObject **)({va})")
            else:
                push_t(T("prim", p), f"*({PRIM_C[p]} *)({va})")
        elif name.startswith("stind."):
            v, vv = pop()
            a, va = pop()
            if name == "stind.ref":
                emit(f"cil_setref((void *)({va}), {vv});")
            else:
                p = {"i1": "i1", "i2": "i2", "i4": "i4", "i8": "i8", "i": "i", "r4": "r4", "r8": "r8"}[name[6:]]
                emit(f"*({PRIM_C[p]} *)({va}) = ({PRIM_C[p]})({vv});")
        # ---- objects ----
        elif name == "ldstr":
            push("o", f"(MonoObject *)cil_ldstr(&{self.ac.cache('S', arg)}, {self.ac.asm_c}, {arg:#010x}u)")
        elif name in ("ldfld", "ldflda", "stfld", "ldsfld", "ldsflda", "stsfld"):
            self.field_op(name, arg, st, pop, push, push_t)
        elif name in ("call", "callvirt"):
            self.call(name, arg, st, pop, push, push_t, k)
        elif name == "newobj":
            self.newobj(arg, st, pop, push, push_t)
        elif name == "newarr":
            n, vn = pop()
            et = self.ac.tok_type(arg)
            push("o", f"cil_newarr({self.ac.kls(arg)}, (intptr_t){vn})")
        elif name == "ldlen":
            a, va = pop()
            push("i", f"(intptr_t)cil_ldlen({va})")
        elif name.startswith("ldelem") or name.startswith("stelem") or name == "ldelema":
            self.elem_op(name, arg, st, pop, push, push_t)
        elif name in ("box",):
            a, va = pop()
            t = self.ac.tok_type(arg)
            if t.kind == "obj":
                push("o", va)
            elif t.kind == "vt":
                if self.is_nullable(arg):
                    self.un("box Nullable<T>")
                push("o", f"cil_box({self.ac.kls(arg)}, {va})")
            else:
                tmp = self.newtmp(t.ctype)
                emit(f"{tmp} = {self.conv_to(t, a, va)};")
                push("o", f"cil_box({self.ac.kls(arg)}, &{tmp})")
        elif name == "unbox":
            a, va = pop()
            push("i", f"(intptr_t)cil_unbox({va}, {self.ac.kls(arg)})")
        elif name == "unbox.any":
            a, va = pop()
            t = self.ac.tok_type(arg)
            if t.kind == "obj":
                push("o", f"cil_castclass({va}, {self.ac.kls(arg)})")
            elif t.kind == "vt":
                if self.is_nullable(arg):
                    self.un("unbox Nullable<T>")
                push("vt", f"cil_unbox({va}, {self.ac.kls(arg)})", t)
            else:
                push_t(t, f"*({t.ctype} *)cil_unbox({va}, {self.ac.kls(arg)})")
        elif name in ("isinst", "castclass"):
            a, va = pop()
            t = self.ac.tok_type(arg)
            if t.kind == "vt" and self.is_nullable(arg):
                self.un(f"{name} Nullable<T>")
            push("o", f"cil_{name}({va}, {self.ac.kls(arg)})")
        elif name == "initobj":
            a, va = pop()
            t = self.ac.tok_type(arg)
            if t.kind == "vt":
                emit(f"memset((void *)({va}), 0, {self.ac.vsize(t)});")
            elif t.kind == "obj":
                emit(f"cil_setref((void *)({va}), NULL);")
            else:
                emit(f"memset((void *)({va}), 0, sizeof({t.ctype}));")
        elif name == "ldobj":
            a, va = pop()
            push_t(self.ac.tok_type(arg), f"*({self.ac.tok_type(arg).ctype} *)({va})"
                   if self.ac.tok_type(arg).kind != "vt" else f"(void *)({va})")
        elif name == "stobj":
            v, vv = pop()
            a, va = pop()
            t = self.ac.tok_type(arg)
            if t.kind == "vt":
                emit(f"cil_vtcopy((void *)({va}), {vv}, {t.cls});")
            elif t.kind == "obj":
                emit(f"cil_setref((void *)({va}), {vv});")
            else:
                emit(f"*({t.ctype} *)({va}) = {self.conv_to(t, v, vv)};")
        elif name == "cpobj":
            s, vs = pop()
            d, vd = pop()
            t = self.ac.tok_type(arg)
            if t.kind == "vt":
                emit(f"cil_vtcopy((void *)({vd}), (void *)({vs}), {t.cls});")
            elif t.kind == "obj":
                emit(f"cil_setref((void *)({vd}), *(MonoObject **)({vs}));")
            else:
                emit(f"*({t.ctype} *)({vd}) = *({t.ctype} *)({vs});")
        elif name == "sizeof":
            t = self.ac.tok_type(arg)
            push("i4", f"(int32_t){self.ac.vsize(t)}" if t.kind == "vt" else f"(int32_t)sizeof({t.ctype})")
        elif name in ("ldftn", "ldvirtftn"):
            m = self.ac.method_ref(arg)
            if name == "ldvirtftn":
                a, va = pop()
                push("ftn", f"(intptr_t)cil_virtual({va}, {self.ac.mth(arg)})")
            else:
                push("ftn", f"(intptr_t){self.ac.mth(arg)}")
            st[-1] = ("i", None)
        elif name == "ldtoken":
            self.ldtoken(k, arg, push, st)
        # ---- exceptions ----
        elif name == "throw":
            e, v = pop()
            emit(f"cil_throw({v});")
            falls = False
        elif name == "rethrow":
            g = self.handler_group(o)
            if g is None:
                self.un("rethrow outside a catch handler")
            emit(f"cil_throw(CX_{g[0]:x}_{g[1]:x});")
            falls = False
        elif name in ("leave", "leave.s"):
            st.clear()
            self.leave(o, arg)
            succ.append(arg)
            falls = False
        elif name == "endfinally":
            g = self.handler_group(o, finally_=True)
            if g is None:
                self.un("endfinally outside a finally")
            emit(f"goto FE_{g[0]:x}_{g[1]:x};")
            falls = False
        elif name == "constrained.":
            self.constrained = arg
            return st, succ, True
        else:
            self.un(f"opcode {name}")
        return st, succ, falls

    def store_var(self, var, t, e, v):
        if t.kind == "vt":
            self.emit(f"memcpy({var}, {v}, {self.ac.vsize(t)});")
        else:
            self.emit(f"{var} = {self.conv_to(t, e, v)};")

    def is_nullable(self, tok):
        try:
            if tok >> 24 == 0x1B:
                t = meta.typespec_sig(self.a.blob(self.a.row("TypeSpec", tok & 0xFFFFFF)[0]))
                if t[0] == "ginst":
                    return self.ac._tdor_name(t[1]) == "System.Nullable`1"
        except meta.MetaError:
            pass
        return False

    def conv(self, name, a, va, push):
        t = a[0]
        if t == "o" and name in ("conv.u", "conv.i"):
            push("i", f"(intptr_t)({va})")     # `fixed`: address of a pinned object
            return
        if t in ("o", "vt"):
            self.un(f"{name} on {t}")
        ovf = ".ovf" in name
        un_src = name.endswith(".un")
        tgt = name.replace("conv.", "").replace("ovf.", "").replace(".un", "")
        fl = t in ("r4", "r8")
        rng = {"i1": (-128, 127), "u1": (0, 255), "i2": (-32768, 32767), "u2": (0, 65535),
               "i4": (-2147483648, 2147483647), "u4": (0, 4294967295),
               "i8": (-9223372036854775808, 9223372036854775807), "u8": (0, 18446744073709551615),
               "i": (-9223372036854775808, 9223372036854775807), "u": (0, 18446744073709551615)}
        if tgt in ("r4", "r8", "r"):
            if tgt == "r" or un_src:                  # conv.r.un: unsigned integer -> float
                u = {"i4": "uint32_t", "i8": "uint64_t", "i": "uint64_t"}.get(t)
                src = f"(double)({u}){va}" if u else f"(double){va}"
                push("r8", src)
            elif tgt == "r4":
                push("r4", f"(float){va}")
            else:
                push("r8", f"(double){va}")
            return
        p = tgt
        stt = PRIM_STACK[p]
        if not ovf:
            if fl:
                if p in ("i8", "i"):
                    e = f"cil_d2i8({va})"
                elif p in ("u8", "u"):
                    e = f"cil_d2u8({va})"
                elif p == "u4":
                    e = f"cil_d2u4({va})"
                else:
                    e = f"cil_d2i4({va})"
                push(stt, f"({STACK_C[stt]})({PRIM_C[p]})({e})")
            else:
                if p in ("u8", "u") and t == "i4":
                    # conv.u8 of an int32 zero-extends: `ldc.i4.m1; conv.u8` is
                    # how compilers write the long constant 0xFFFFFFFF
                    va = f"(uint32_t)({va})"
                push(stt, f"({STACK_C[stt]})({PRIM_C[p]})({va})")
            return
        lo, hi = rng[p]
        if fl and p in ("u8", "u"):
            push(stt, f"({STACK_C[stt]})({PRIM_C[p]})(cil_ovf_d2u8({va}))")
            return
        if fl:
            e = f"cil_ovf_d2i({va}, {float(lo)!r}, {float(hi)!r})"
            push(stt, f"({STACK_C[stt]})({PRIM_C[p]})({e})")
            return
        if un_src:
            u = {"i4": "uint32_t", "i8": "uint64_t", "i": "uint64_t"}[t]
            e = f"cil_ovf_urange((uint64_t)({u}){va}, {hi}ULL)"
        else:
            if p in ("u8", "u"):
                e = f"cil_ovf_range((int64_t){va}, 0, INT64_MAX)"
            elif p in ("i8", "i"):
                e = f"(int64_t){va}"
            else:
                e = f"cil_ovf_range((int64_t){va}, {lo}LL, {hi}LL)"
        push(stt, f"({STACK_C[stt]})({PRIM_C[p]})({e})")

    def compare(self, op, a, va, b, vb, t):
        if t in ("o", "i") and (a[0] == "o" or b[0] == "o"):
            va, vb = f"(intptr_t){va}", f"(intptr_t){vb}"
        fl = t in ("r4", "r8")
        u = {"i4": "uint32_t", "i8": "uint64_t", "i": "uintptr_t", "o": "uintptr_t"}.get(t)
        un = op.endswith(".un")
        base = op.replace(".un", "")
        sym = {"ceq": "==", "bne": "!=", "cgt": ">", "clt": "<", "cge": ">=", "cle": "<="}[base]
        if fl:
            if un:   # unordered: true if either is NaN
                inv = {"cgt": "<=", "clt": ">=", "cge": "<", "cle": ">"}[base]
                return f"(int32_t)!({va} {inv} {vb})"
            if base == "bne":
                return f"(int32_t)!({va} == {vb})"
            return f"(int32_t)({va} {sym} {vb})"
        if un and base != "bne":
            return f"(int32_t)(({u}){va} {sym} ({u}){vb})"
        if base in ("ceq", "bne"):
            return f"(int32_t)({va} {sym} {vb})"
        return f"(int32_t)(({STACK_C[t]}){va} {sym} ({STACK_C[t]}){vb})"

    # ---- fields ----
    def field_op(self, name, tok, st, pop, push, push_t):
        ft, is_static, owner_vt, frow = self.ac.field_ref(tok)
        static = name in ("ldsfld", "ldsflda", "stsfld")
        F = self.ac.fld(tok)
        OF = self.ac.cache("OF", tok)
        emit = self.emit
        if static:
            if frow is not None and self.thread_static(frow):
                self.un("thread-static field")
            addr = f"cil_sfield(&{self.ac.cache('SF', tok)}, {F})"
            if name == "ldsfld":
                push_t(ft, f"*({ft.ctype} *){addr}" if ft.kind != "vt" else addr)
            elif name == "ldsflda":
                push("i", f"(intptr_t){addr}")
            else:
                v, vv = pop()
                if ft.kind == "obj":
                    emit(f"cil_setref({addr}, {vv});")
                elif ft.kind == "vt":
                    emit(f"cil_vtcopy({addr}, {vv}, {ft.cls});")
                else:
                    emit(f"*({ft.ctype} *){addr} = {self.conv_to(ft, v, vv)};")
            return
        if name == "stfld":
            v, vv = pop()
        obj, vo = pop()
        if obj[0] == "o":
            base = f"(char *)cil_nn({vo})"
            off = f"cil_foff_c(&{OF}, {F})"
            in_obj = True
        elif obj[0] == "vt":
            base = f"(char *){vo}"
            off = f"(cil_foff_c(&{OF}, {F}) - (int32_t)sizeof(MonoObject))"
            in_obj = False
        elif obj[0] == "i":
            base = f"(char *)({vo})"
            off = f"(cil_foff_c(&{OF}, {F}) - (int32_t)sizeof(MonoObject))" if owner_vt else f"cil_foff_c(&{OF}, {F})"
            in_obj = False
        else:
            self.un(f"{name} on {obj[0]}")
        addr = f"({base} + {off})"
        if name == "ldfld":
            push_t(ft, f"*({ft.ctype} *){addr}" if ft.kind != "vt" else addr)
        elif name == "ldflda":
            push("i", f"(intptr_t){addr}")
        else:
            if ft.kind == "obj":
                if in_obj:
                    emit(f"cil_setref_field({vo}, {addr}, {vv});")
                else:
                    emit(f"cil_setref({addr}, {vv});")
            elif ft.kind == "vt":
                emit(f"cil_vtcopy({addr}, {vv}, {ft.cls});")
            else:
                emit(f"*({ft.ctype} *){addr} = {self.conv_to(ft, v, vv)};")

    def thread_static(self, frow):
        for i in range(1, self.a.nrows("CustomAttribute") + 1):
            parent, ctor, val = self.a.row("CustomAttribute", i)
            if parent == ("Field", frow):
                try:
                    m = self.ac.method_ref((0x0A000000 if ctor[0] == "MemberRef" else 0x06000000) | ctor[1])
                    if m["owner"] in ("System.ThreadStaticAttribute",):
                        return True
                except Unsupported:
                    pass
        return False

    # ---- arrays ----
    def elem_op(self, name, tok, st, pop, push, push_t):
        emit = self.emit
        kinds = {"i1": "i1", "u1": "u1", "i2": "i2", "u2": "u2", "i4": "i4", "u4": "u4", "i8": "i8",
                 "i": "i", "r4": "r4", "r8": "r8"}
        if name.startswith("stelem"):
            v, vv = pop()
        i, vi = pop()
        a, va = pop()
        if name in ("ldelem", "stelem", "ldelema"):
            t = self.ac.tok_type(tok)
        elif name.endswith(".ref"):
            t = T("obj")
        else:
            t = T("prim", kinds[name.split(".")[1]])
        size = f"{self.ac.vsize(t)}" if t.kind == "vt" else f"(int)sizeof({t.ctype})"
        if name == "ldelema":
            push("i", f"(intptr_t)cil_elem({va}, (intptr_t){vi}, {size})")
            return
        if name.startswith("ldelem"):
            addr = f"cil_elem({va}, (intptr_t){vi}, {size})"
            push_t(t, f"*({t.ctype} *){addr}" if t.kind != "vt" else addr)
            return
        if t.kind == "obj":
            emit(f"cil_stelem_ref({va}, (intptr_t){vi}, {vv});")
        elif t.kind == "vt":
            emit(f"cil_vtcopy(cil_elem({va}, (intptr_t){vi}, {size}), {vv}, {t.cls});")
        else:
            emit(f"*({t.ctype} *)cil_elem({va}, (intptr_t){vi}, {size}) = {self.conv_to(t, v, vv)};")

    # ---- calls ----
    def args_from_stack(self, m, pop):
        vals = []
        for p in reversed(m["params"]):
            e, v = pop()
            vals.append((p, e, v))
        vals.reverse()
        this = pop() if m["hasthis"] else None
        return this, vals

    def call(self, name, tok, st, pop, push, push_t, k):
        emit = self.emit
        m = self.ac.method_ref(tok)
        constrained = getattr(self, "constrained", None)
        self.constrained = None
        # special cases
        if m["owner"] == "System.Runtime.CompilerServices.RuntimeHelpers" and m["name"] == "InitializeArray":
            fe, fv = pop()
            ae, av = pop()
            if fe[0] != "fld":
                self.un("InitializeArray with a computed field handle")
            data = self.ac.field_data(fe[1])
            nm = f"D{self.ac.cname}_{fe[1]:x}"
            n = max(len(data), 1)
            self.ac.decls[nm] = (f"extern const unsigned char {nm}[{n}];",
                                 f"const unsigned char {nm}[{n}] = {{{','.join(str(b) for b in data) or '0'}}};")
            emit(f"{{ MonoArray *arr_ = (MonoArray *)cil_nn({av}); size_t n_ = (size_t)mono_array_length(arr_) * "
                 f"mono_array_element_size(mono_object_get_class((MonoObject *)arr_)); "
                 f"memcpy(mono_array_addr_with_size(arr_, 1, 0), {nm}, n_ < sizeof {nm} ? n_ : sizeof {nm}); }}")
            return
        if m["owner"] == "System.Type" and m["name"] == "GetTypeFromHandle" and st and st[-1][0] == "typetok":
            e, v = pop()
            push("o", f"cil_typeof({self.ac.kls(e[1])})")
            return
        this, vals = self.args_from_stack(m, pop)
        if any(e[0] in ("typetok", "fld") for _, e, _ in vals):
            self.un("ldtoken handle passed to a method")
        ret = m["ret"]
        # the object `this` refers to
        self_expr, self_kind = None, None
        boxback = None
        if this is not None:
            te, tv = this
            if constrained is not None:
                ct = self.ac.tok_type(constrained)
                if ct.kind == "obj":
                    self_expr, self_kind = f"*(MonoObject **)({tv})", "o"
                elif m["owner_vt"] and not m["virtual"] or (m["row"] and m["owner_vt"]):
                    self_expr, self_kind = f"(void *)({tv})", "ptr"
                else:
                    tmp = self.newtmp("MonoObject *")
                    emit(f"{tmp} = cil_box({ct.cls if ct.kind == 'vt' else self.ac.kls(constrained)}, (void *)({tv}));")
                    self_expr, self_kind = tmp, "o"
                    # the method runs on a boxed copy; what it changes in the
                    # value (an enumerator's MoveNext, a struct's own state)
                    # must end up in the original
                    boxback = f"cil_unbox_back({tmp}, (void *)({tv}));"
            elif te[0] == "o":
                self_expr, self_kind = tv, "o"
            elif te[0] in ("i", "vt"):
                self_expr, self_kind = f"(void *)({tv})", "ptr"
            else:
                self.un(f"call on {te[0]}")
        # return slot
        rslot = None
        if ret.kind == "vt":
            rslot = self.slot(len(st), "vt", ret)
        direct = m["row"] is not None and m["row"] in self.ac.translated
        if self.mode == "analyze":
            direct = m["row"] is not None and m["row"] in self.ac.methods
        is_virtual_call = name == "callvirt" and m["virtual"]
        if self_kind == "o" and (name == "callvirt"):
            self_expr = f"cil_nn({self_expr})"
        cargs = [self.conv_to(p, e, v) for p, e, v in vals]
        if direct and not is_virtual_call:
            info = self.ac.methods[m["row"]]
            args = ([rslot] if rslot else []) + ([self_expr] if this is not None else []) + cargs
            call = f"{info['cname']}({', '.join(args)})"
            self.finish_call(ret, call, rslot, push)
            if boxback:
                emit(boxback)
            if ret.kind == "vt":
                st.append(("vt", ret))
            return
        # through Mono: virtual dispatch to a translated override, else invoke
        M = self.ac.mth(m["tok"])
        tmpv = []
        argv = "NULL"
        if vals:
            self.tmp += 1
            argv = f"av{self.tmp}"
            emit(f"void *{argv}[{len(vals)}];")
            for i, (p, e, v) in enumerate(vals):
                if p.kind in ("obj", "vt") or (p.kind == "ptr" and p.p == "byref"):
                    emit(f"{argv}[{i}] = (void *)({v});")
                else:
                    t = self.newtmp(p.ctype)
                    emit(f"{t} = {self.conv_to(p, e, v)};")
                    emit(f"{argv}[{i}] = (void *)&{t};")
        mexpr = M
        if is_virtual_call and self_kind == "o":
            vm = self.newtmp("MonoMethod *")
            emit(f"{vm} = cil_virtual({self_expr}, {M});")
            mexpr = vm
            # fast path: the override was translated
            fp = self.newtmp("void *")
            emit(f"{fp} = cil_fn_for({vm});")
            rett = "void" if ret.kind == "vt" else ret.ctype
            ptypes = (["void *"] if rslot else []) + ["void *"] + [p.ctype for p, _, _ in vals]
            # the method found may belong to a value type (interface call on a
            # boxed struct, ToString() of a boxed struct...): such a method
            # takes the value itself as `this`, not the box around it - both
            # as translated C and through mono_runtime_invoke
            raw_self = f"(mono_class_is_valuetype(mono_method_get_class({vm})) ? mono_object_unbox({self_expr}) : (void *){self_expr})"
            fargs = ([rslot] if rslot else []) + [raw_self] + cargs
            fcall = f"(({rett} (*)({', '.join(ptypes)})){fp})({', '.join(fargs)})"
            if ret.kind in ("void", "vt"):
                emit(f"if ({fp}) {fcall}; else {{")
                self.invoke_part(ret, mexpr, raw_self, argv, rslot, push, into=None)
                emit("}")
                if boxback:
                    emit(boxback)
                if ret.kind == "vt":
                    st.append(("vt", ret))
            else:
                res = self.newtmp(ret.ctype)
                emit(f"if ({fp}) {res} = {fcall}; else {{")
                self.invoke_part(ret, mexpr, raw_self, argv, rslot, push, into=res)
                emit("}")
                if boxback:
                    emit(boxback)
                push_t(ret, res)
            return
        self.invoke_part(ret, mexpr, self_expr if this is not None else "NULL", argv, rslot, push, into=None,
                         push_t=push_t)
        if boxback:
            emit(boxback)
        if ret.kind == "vt":
            st.append(("vt", ret))

    def invoke_part(self, ret, mexpr, self_expr, argv, rslot, push, into=None, push_t=None):
        emit = self.emit
        call = f"cil_invoke({mexpr}, {self_expr}, {argv})"
        if ret.kind == "void":
            emit(f"{call};")
            return
        if ret.kind == "obj":
            if into:
                emit(f"{into} = {call};")
            else:
                push("o", call)
            return
        r = self.newtmp("MonoObject *")
        emit(f"{r} = {call};")
        if ret.kind == "vt":
            emit(f"memcpy({rslot}, mono_object_unbox({r}), {self.ac.vsize(ret)});")
            return
        if into:
            emit(f"{into} = *({ret.ctype} *)mono_object_unbox({r});")
        else:
            push_t(ret, f"*({ret.ctype} *)mono_object_unbox({r})")

    def finish_call(self, ret, call, rslot, push):
        if ret.kind == "void":
            self.emit(f"{call};")
        elif ret.kind == "vt":
            self.emit(f"{call};")
        else:
            s, e = self.load(ret, call)
            push(s, e)

    def newobj(self, tok, st, pop, push, push_t):
        emit = self.emit
        m = self.ac.method_ref(tok)
        if m["owner"] == "System.String":
            self.un("new string(...)")
        K = self.ac.kls(m["cls_tok"]) if m["cls_tok"] else None
        if K is None:
            self.un("constructor of unknown class")
        # delegates: (target, method)
        if self.is_delegate(m):
            fe, fv = pop()
            te, tv = pop()
            push("o", f"cil_delegate({K}, {tv}, (MonoMethod *)({fv}))")
            return
        vals = []
        for p in reversed(m["params"]):
            e, v = pop()
            vals.append((p, e, v))
        vals.reverse()
        cargs = [self.conv_to(p, e, v) for p, e, v in vals]
        direct = m["row"] is not None and (m["row"] in (self.ac.translated if self.mode == "gen" else self.ac.methods))
        if m["owner_vt"]:
            vt = self.ac.tok_type(m["cls_tok"])
            if vt.kind != "vt":
                # constructor of a primitive-like struct (rare): through Mono
                self.un("constructor of a primitive struct")
            slot = self.slot(len(st), "vt", vt)
            emit(f"memset({slot}, 0, {self.ac.vsize(vt)});")
            if direct:
                emit(f"{self.ac.methods[m['row']]['cname']}({', '.join([slot] + cargs)});")
            else:
                argv = self.argv(vals)
                emit(f"cil_invoke({self.ac.mth(m['tok'])}, {slot}, {argv});")
            st.append(("vt", vt))
            return
        obj = self.newtmp("MonoObject *")
        emit(f"{obj} = cil_new({K});")
        if direct:
            emit(f"{self.ac.methods[m['row']]['cname']}({', '.join([obj] + cargs)});")
        else:
            argv = self.argv(vals)
            emit(f"cil_invoke({self.ac.mth(m['tok'])}, {obj}, {argv});")
        push("o", obj)

    def argv(self, vals):
        if not vals:
            return "NULL"
        self.tmp += 1
        argv = f"av{self.tmp}"
        self.emit(f"void *{argv}[{len(vals)}];")
        for i, (p, e, v) in enumerate(vals):
            if p.kind in ("obj", "vt") or (p.kind == "ptr" and p.p == "byref"):
                self.emit(f"{argv}[{i}] = (void *)({v});")
            else:
                t = self.newtmp(p.ctype)
                self.emit(f"{t} = {self.conv_to(p, e, v)};")
                self.emit(f"{argv}[{i}] = (void *)&{t};")
        return argv

    def is_delegate(self, m):
        if m["name"] != ".ctor" or len(m["params"]) != 2 or m["params"][1].kind != "prim" or \
                m["params"][1].p not in ("i", "u"):
            return False
        tok = m["cls_tok"]
        try:
            if tok >> 24 == 0x1B:               # generic delegate: Action<int>, Func<...>
                t = meta.typespec_sig(self.a.blob(self.a.row("TypeSpec", tok & 0xFFFFFF)[0]))
                if t[0] != "ginst":
                    return False
                tab, row = t[1]
                tok = (0x02000000 if tab == "TypeDef" else 0x01000000) | row
            if tok >> 24 == 0x02:
                return self.ai.td_extends(tok & 0xFFFFFF) in ("System.MulticastDelegate", "System.Delegate")
            if tok >> 24 == 0x01:
                r = self.ai.resolve_tr(tok & 0xFFFFFF)
                if r:
                    return r[0].td_extends(r[1]) in ("System.MulticastDelegate", "System.Delegate")
                # A class this translator cannot look into (its assembly is
                # not there). A constructor (object, native int) is what
                # every delegate has and next to nothing else: taking it for
                # an ordinary constructor would hand Mono a method handle
                # where it expects code, and the first Invoke would jump
                # into data.
                return True
        except meta.MetaError:
            return True
        return False

    def ldtoken(self, k, tok, push, st):
        """only the two common uses: array initializers (field handle into
        InitializeArray) and typeof(T) (type handle into GetTypeFromHandle)"""
        table = tok >> 24
        if table == 0x04:
            st.append(("fld", tok & 0xFFFFFF))
            return
        if table in (0x01, 0x02, 0x1B):
            st.append(("typetok", tok))
            return
        self.un("ldtoken of a method")

    # ---- exceptions ----
    def handler_group(self, off, finally_=False):
        best = None
        for key, cl in self.groups():
            for c in cl:
                fl, to, tl, ho, hl, ct = c
                if ho <= off < ho + hl and (not finally_ or fl in (2, 4)) and (finally_ or fl == 0):
                    if best is None or hl < best[1]:
                        best = (key, hl)
        return best[0] if best else None

    def leave(self, src, dst):
        emit = self.emit
        exited = [key for key, cl in self.groups() if self.in_try(src, key) and not self.in_try(dst, key)]
        exited.sort(key=lambda kk: kk[1])          # innermost first
        for key in exited:
            g = f"{key[0]:x}_{key[1]:x}"
            emit(f"CIL_POP(T_{g});")
            fin = [c for c in self.eh_groups[key] if c[0] == 2]
            if fin:
                self.leave_id += 1
                rid = self.leave_id
                self.fin_targets.setdefault(key, []).append(rid)
                emit(f"FR_{g} = {rid}; goto IL_{fin[0][3]:04x};")
                emit(f"LR_{rid}:;")
        emit(f"goto {self.target_label(src, dst)};")

    # ---- generation ----
    def generate(self):
        info = self.info
        self.mode = "gen"
        self.lines = []
        self.slots = {}
        self.tmp = 0
        self.leave_id = 0
        self.fin_targets = {}
        self.eh_groups = dict(self.groups())
        self.constrained = None
        body_lines = []
        starts = {}
        for key, cl in self.groups():
            starts.setdefault(key[0], []).append(key)
        handler_starts = {}
        for key, cl in self.groups():
            for c in cl:
                handler_starts[c[3]] = (key, c)
        for k, (o, name, arg, nxt) in enumerate(self.ins):
            if o not in self.entry:
                continue                                 # unreachable
            self.lines = []
            self.emit(f"{self.label(o)}:;")
            for key in starts.get(o, []):
                g = f"{key[0]:x}_{key[1]:x}"
                self.emit(f"if (CIL_TRY(T_{g})) goto DS_{g};")
                self.emit(f"IL_{o:04x}_in{key[0]:x}_{key[1]:x}:;")
            st = list(self.entry[o])
            self.sim(k, st)
            body_lines += self.lines
        # exception dispatch per try group
        disp = []
        for key, cl in self.groups():
            g = f"{key[0]:x}_{key[1]:x}"
            disp.append(f"  DS_{g}: {{")
            disp.append(f"    MonoObject *ex_ = cil_thr()->exc; cil_thr()->exc = NULL;")
            for c in cl:
                fl, to, tl, ho, hl, ct = c
                if fl == 0:
                    K = self.ac.kls(ct)
                    disp.append(f"    if (cil_isinst(ex_, {K})) {{ CX_{g} = ex_; s0_o = ex_; goto IL_{ho:04x}; }}")
                    self.slots["s0_o"] = ("o", None)
                elif fl in (2, 4):
                    disp.append(f"    PX_{g} = ex_; FR_{g} = 0; goto IL_{ho:04x};")
            disp.append("    cil_throw(ex_);")
            disp.append("  }")
            fin = [c for c in cl if c[0] in (2, 4)]
            if fin:
                disp.append(f"  FE_{g}: switch (FR_{g}) {{")
                disp.append(f"    case 0: cil_throw(PX_{g});")
                for rid in self.fin_targets.get(key, []):
                    disp.append(f"    case {rid}: goto LR_{rid};")
                disp.append("    default: abort();")
                disp.append("  }")
        # declarations; with try blocks, every variable is volatile itself
        # (it lives across setjmp): `T *volatile x`, not `volatile T *x`
        V = self.vol

        def vd(ctype, name):
            if not V:
                return f"{ctype} {name}"
            if ctype.endswith("*"):
                return f"{ctype}volatile {name}"
            return f"volatile {ctype} {name}"
        out = [self.ac.proto(info) + " {"]
        ps = self.ac.c_params(info)
        for i, t in enumerate(self.args):
            if t.kind == "vt":
                out.append(f"  uint8_t *A{i} = alloca({self.ac.vsize(t)} + 16);")
                out.append(f"  memcpy(A{i}, a{i}, {self.ac.vsize(t)});")
            else:
                out.append(f"  {vd(t.ctype, 'A' + str(i))} = a{i};")
        for i, t in enumerate(self.locals):
            if t.kind == "vt":
                out.append(f"  uint8_t *L{i} = alloca({self.ac.vsize(t)} + 16);")
                out.append(f"  memset(L{i}, 0, {self.ac.vsize(t)});")
            else:
                out.append(f"  {vd(t.ctype, 'L' + str(i))} = 0;")
        for nm, (t, vt) in sorted(self.slots.items()):
            if t == "vt":
                out.append(f"  uint8_t *{nm} = alloca({self.ac.vsize(vt)} + 16);")
            else:
                out.append(f"  {vd(STACK_C[t], nm)} = 0;")
        for key, cl in self.groups():
            g = f"{key[0]:x}_{key[1]:x}"
            out.append(f"  cil_try T_{g};")
            if any(c[0] == 0 for c in cl):
                out.append(f"  {vd('MonoObject *', 'CX_' + g)} = NULL;")
            if any(c[0] in (2, 4) for c in cl):
                out.append(f"  {vd('MonoObject *', 'PX_' + g)} = NULL; {vd('int', 'FR_' + g)} = 0;")
        # catch handlers can also be found through rethrow in nested handlers
        cinit = self.class_init_needed()
        if cinit:
            out.append(f"  cil_class_init(&{self.ac.cache('CI', cinit)}, {self.ac.kls(cinit)});")
        out += body_lines
        out += disp
        out.append("}")
        return "\n".join(out)

    def class_init_needed(self):
        """static methods and constructors of a class with a static
        constructor (not beforefieldinit) run it first, like the JIT does"""
        info = self.info
        if info["hasthis"] and info["name"] != ".ctor":
            return None
        if info["name"] == ".cctor":
            return None
        owner = info["owner"]
        tflags = self.a.row("TypeDef", owner)[0]
        if tflags & 0x00100000:                   # beforefieldinit
            return None
        for m in self.a.range_of("TypeDef", 5, owner, "MethodDef"):
            if self.a.row("MethodDef", m)[3] == ".cctor":
                return 0x02000000 | owner
        return None


def field_data(self, frow):
    """bytes of a field with an RVA (array initializers)"""
    fl, name, sig = self.a.row("Field", frow)
    t = meta.field_sig(self.a.blob(sig))
    size = None
    if t[0] == "tok" and t[1][0] == "TypeDef":
        size = self.ai.layout.get(t[1][1])
    elif t[0] == "prim":
        size = {"i1": 1, "u1": 1, "i2": 2, "u2": 2, "i4": 4, "u4": 4, "i8": 8, "u8": 8, "r4": 4, "r8": 8}.get(t[1])
    if size is None:
        raise Unsupported("array initializer of unknown size")
    d = self.a.field_rva_data(frow, size)
    if d is None:
        raise Unsupported("array initializer without data")
    return d


AsmCompiler.field_data = field_data


# ---------------------------------------------------------------------------
def c_ident(name):
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


CIL_FILE_LINES = int(os.environ.get("RECOMP_FILE_LINES", "50000"))


def translate(path, outdir, search_dirs, log=print, patch=True, patched_path=None, avoid_names=()):
    """one assembly -> outdir/<name>_cil.c (+ patched copy of the assembly)
    returns a report dict"""
    world = World(search_dirs + [os.path.dirname(os.path.abspath(path))])
    ai = AsmInfo(meta.Assembly(path), world)
    cname = c_ident(ai.name)
    ac = AsmCompiler(ai, cname)
    bodies = ac.compile()
    os.makedirs(outdir, exist_ok=True)
    exposed = {r: info for r, info in ac.translated.items() if ac.exposable(info)}
    names = {r: ac.icall_names(exposed[r]) for r in exposed}
    if avoid_names:
        for r in list(exposed):
            if any(n in avoid_names for n in names[r]):
                del exposed[r]
                del names[r]
    # <asm>_cil.h: prototypes + shared caches; <asm>_cil_data.c: the caches;
    # <asm>_cil_N.c: the functions, split so no C file gets huge
    hfile = os.path.join(outdir, f"{cname}_cil.h")
    with open(hfile, "w") as f:
        f.write(f"/* {ai.name}: C translated from .NET IL by recomp cil2c */\n#pragma once\n")
        f.write('#include "cil_rt.h"\n')
        f.write(f'#define {ac.asm_c} "{ai.name}"\n')
        for nm in sorted(ac.decls):
            f.write(ac.decls[nm][0] + "\n")
        for r, info in sorted(ac.translated.items()):
            f.write(ac.proto(info) + ";\n")
    cfiles = []

    def newfile():
        p = os.path.join(outdir, f"{cname}_cil_{len(cfiles)}.c")
        cfiles.append(p)
        fh = open(p, "w")
        fh.write(f'#include "{cname}_cil.h"\n')
        return fh
    f = newfile()
    lines = 0
    for r, info in sorted(ac.translated.items()):
        if lines > CIL_FILE_LINES:
            f.close()
            f = newfile()
            lines = 0
        f.write(f"\n/* {ac.method_label(r)} */\n")
        f.write(bodies[r] + "\n")
        lines += bodies[r].count("\n") + 2
        if r in exposed:
            ps = ac.c_params(info)
            ret = info["ret"].ctype
            # internal-call entry point: exceptions stop here and go to Mono
            f.write(f"{ac.proto(info, info['cname'] + '_icall')} {{\n")
            f.write("  cil_try b_;\n  CIL_ENTER(b_);\n")
            call = f"{info['cname']}({', '.join(n for _, n in ps)})"
            if info["ret"].kind == "void":
                f.write(f"  {call};\n  CIL_LEAVE(b_);\n}}\n")
            else:
                f.write(f"  {ret} r_ = {call};\n  CIL_LEAVE(b_);\n  return r_;\n}}\n")
    f.close()
    dfile = os.path.join(outdir, f"{cname}_cil_data.c")
    with open(dfile, "w") as f:
        f.write(f'#include "{cname}_cil.h"\n')
        for nm in sorted(ac.decls):
            f.write(ac.decls[nm][1] + "\n")
        for r, info in sorted(exposed.items()):
            f.write(f"{ac.proto(info, info['cname'] + '_icall')};\n")
            f.write(f"static const char *const N_{r:x}[] = {{{', '.join(cstr(n) for n in names[r])}, 0}};\n")
        f.write(f"static const cil_entry E_{cname}[] = {{\n")
        for r, info in sorted(ac.translated.items()):
            if r in exposed:
                f.write(f"  {{{ac.asm_c}, {info['tok']:#010x}u, (void *){info['cname']}, "
                        f"(void *){info['cname']}_icall, N_{r:x}}},\n")
            else:
                f.write(f"  {{{ac.asm_c}, {info['tok']:#010x}u, (void *){info['cname']}, 0, 0}},\n")
        f.write("  {0, 0, 0, 0, 0}\n};\n")
        f.write(f"void cil_register_{cname}(void) {{ cil_register(E_{cname}, {len(ac.translated)}); }}\n")
    cfile = cfiles[0]
    patched = None
    if patch:
        patched = patched_path or os.path.join(outdir, os.path.basename(path))
        os.makedirs(os.path.dirname(patched), exist_ok=True)
        patch_assembly(ai, path, patched, sorted(exposed))
    total = ai.a.nrows("MethodDef")
    with_body = sum(1 for r in range(1, total + 1) if ai.a.row("MethodDef", r)[0])
    reasons = {}
    for r, why in ac.skipped.items():
        if ai.a.row("MethodDef", r)[0]:
            key = re.sub(r"IL_[0-9a-f]+", "IL_x", why)
            reasons[key] = reasons.get(key, 0) + 1
    rep = {"assembly": ai.name, "c_files": [os.path.basename(x) for x in cfiles + [dfile]],
           "patched": patched, "methods_with_il": with_body,
           "icall_names": sorted({n for r in exposed for n in names[r]}),
           "translated": len(ac.translated), "called_by_mono_directly": len(exposed),
           "kept_as_il": {why: n for why, n in sorted(reasons.items(), key=lambda kv: -kv[1])},
           "kept_list": [(ac.method_label(r), why) for r, why in sorted(ac.skipped.items())
                         if ai.a.row("MethodDef", r)[0]],
           "register": f"cil_register_{cname}"}
    log(f"   {ai.name}: {len(ac.translated)}/{with_body} methods translated to C "
        f"({len(exposed)} called by Mono directly)")
    return rep


def cstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def patch_assembly(ai, src, dst, rows):
    """copy of the assembly with the translated methods marked InternalCall
    (RVA 0): Mono then calls the registered C function instead of the IL"""
    shutil.copyfile(src, dst)
    a = ai.a
    o, rs, cols, cs, n = a.tab["MethodDef"]
    with open(dst, "r+b") as f:
        for r in rows:
            p = o + rs * (r - 1)
            f.seek(p)
            row = bytearray(f.read(rs))
            struct.pack_into("<I", row, 0, 0)                     # RVA
            iflags = struct.unpack_from("<H", row, 4)[0]
            struct.pack_into("<H", row, 4, iflags | 0x1000)       # InternalCall
            f.seek(p)
            f.write(row)
