"""ARM64 shared libraries (Android lib/arm64-v8a/*.so, Linux aarch64 .so):
everything the lifter does differently for them, and the files that turn a
lift output into a library that can be put back into the APK.

How a rebuilt library works (runtime/a64/):

  * The original image is part of the rebuilt library, segment by segment,
    with the access rights it had, and is relocated, imported into and
    exported from by the system loader exactly like the original (guest.o,
    see a64elf.py). Its symbols are the rebuilt library's symbols.
  * The code is position independent, so every address an instruction
    computes comes from its own address: ADR/ADRP, BL/BLR (the return
    address), literal loads and branch targets. Those become
    "start of the image + offset" in the C (GA(...)): the library runs
    wherever the loader puts it.
  * Integer, memory and control-flow instructions are translated from
    Ghidra's P-code to C. Floating-point/SIMD data-processing instructions,
    atomic instructions, pointer authentication and a few system
    instructions are run as themselves: the rebuilt library runs on the same
    kind of CPU, so the instruction is emitted again (as .inst, in a few
    lines of inline assembly) with its registers loaded from and stored to
    the register file. That is exact by construction, where Ghidra's model
    of them is not (FRINT*, FCVT*S with a rounding mode, FMADD, most of NEON
    through opaque ops).
  * Native code and recompiled code call each other without any help from
    the system. The addresses the program hands out are addresses of its
    original code, and the original code is still there and executable, but
    two kinds of places in it are replaced by a jump into the runtime:
      - the first instruction of every function that is certainly one (a
        symbol, the target of a call, something that starts like a
        function): a call from native code continues in the recompiled code
        (rt_a64_enter);
      - the instruction after every call: when a native function the
        program called returns, the recompiled code goes on from there
        (rt_a64_reenter). The return address native code sees is the
        original one, so stack unwinding (C++ exceptions, setjmp/longjmp,
        backtraces) works with the original's unwind tables.
    A function pointer that leads to none of these places (a small callback
    that is only ever called through its address and starts like no
    function) runs as the original machine code until its first call
    returns: correct, only not recompiled.
  * The whole register state moves between the CPU and the register file at
    those places (rt_a64_asm.S); the program's stack is the real stack.
"""
import os
import shutil
import struct
from array import array

from pypcode import OpCode as O

from . import a64elf as E

X_OFF, V_OFF, SP_OFF, FLAG_OFF = 0x4000, 0x5000, 0x8, 0x100
NOMAP = 0xFFFFFFFF

# imports the runtime answers itself (rt_w_<name> in rt_a64.c): functions that
# call back into the program a lot (each callback from native code would
# otherwise cost a signal), CPU feature queries, and signal handlers
WRAPPED = {"qsort", "bsearch", "dl_iterate_phdr", "getauxval", "sigaction", "sigaction64", "signal",
           "bsd_signal"}
# what the runtime itself imports from the C library (rt_a64.c); together
# with the original's imports these are the only undefined symbols a rebuilt
# library may have (android_cc.check_undefined)
RT_IMPORTS = ["mmap", "munmap", "mprotect", "write", "getenv", "vsnprintf", "snprintf", "abort", "syscall",
              "strlen", "strcmp", "strncmp", "strtol", "qsort", "bsearch", "getauxval", "pthread_key_create",
              "pthread_getspecific", "pthread_setspecific", "pthread_self", "pthread_getattr_np",
              "pthread_attr_getstack", "pthread_attr_destroy", "dl_iterate_phdr", "sigaction",
              "memcpy", "memset", "memcmp", "memmove", "__android_log_write"]
# system registers read / written on the real CPU (key = bits 19..5 of MRS/MSR)
SYS_NZCV = 0x5a10
SYS_READ = {0x5a20: "fpcr", 0x5a21: "fpsr", 0x5e82: "tpidr_el0", 0x5e83: "tpidrro_el0",
            0x5f00: "cntfrq_el0", 0x5f01: "cntpct_el0", 0x5f02: "cntvct_el0", 0x5801: "ctr_el0",
            0x5807: "dczid_el0"}
SYS_WRITE = {0x5a20: "fpcr", 0x5a21: "fpsr"}
# special ops that need nothing done
NOP_OPS = {"Hint_Prefetch", "Hint_Yield", "Hint_WFE", "Hint_WFI", "Hint_SEV", "Hint_SEVL",
           "SpeculationBarrier", "SpeculativeStoreBypassBarrier", "ConsumptionOfSpeculativeDataBarrier",
           "ClearExclusiveLocal", "LOAcquire", "LORelease"}


def is_fpsimd(w):
    """Data processing - scalar floating point and advanced SIMD (registers only)"""
    return (w >> 25) & 7 == 7


def is_simd_ldst(w):
    """AdvSIMD load/store (multiple / single structure): LD1..LD4, ST1..ST4, LDnR"""
    return w & 0xbe000000 == 0x0c000000 and not w & 0x80000000


def sx(v, bits):
    return v - (1 << bits) if v >> (bits - 1) & 1 else v


class A64:
    """per-lift state for an ARM64 shared object"""
    nop_ops = NOP_OPS

    def __init__(self, ctx, img):
        self.ctx, self.img = ctx, img
        reg = ctx.registers
        assert reg["x0"].offset == X_OFF and reg["q0"].offset == V_OFF and reg["sp"].offset == SP_OFF \
            and reg["NG"].offset == FLAG_OFF and reg["q1"].offset == V_OFF + 0x20, "unexpected register layout"
        end = max(v.offset + v.size for v in reg.values())
        assert end <= 0x7000, "register file larger than RT_R_SIZE (rt_a64.h)"
        self.flag_offs = {reg[n].offset for n in ("NG", "ZR", "CY", "OV")}
        self.native = {}        # kind -> number of instructions emitted as themselves
        # for the jumps into the runtime that are put into the original code
        # (write_outputs): addresses, 8 bytes each
        self.ret_sites = array("Q")     # the instruction after a call
        self.data_refs = array("Q")     # read as data by an instruction (literal pools)
        self.addr_refs = array("Q")     # an instruction computes this address (ADR, ADRP + ADD)
        self._adrp = {}                 # register -> page, within a run of instructions
        self._adrp_end = 0

    def count(self, kind):
        self.native[kind] = self.native.get(kind, 0) + 1

    # ---- what an instruction's constants mean -----------------------------
    def addr_consts(self, ins):
        """constants in this instruction's P-code that are addresses"""
        if len(ins.raw) < 4:
            return ()
        w, A = struct.unpack("<I", ins.raw[:4])[0], ins.addr
        if w & 0x9f000000 == 0x10000000:                       # ADR
            return (A + sx(((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3, 21),)
        if w & 0x9f000000 == 0x90000000:                       # ADRP
            return ((A & ~0xfff) + (sx(((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3, 21) << 12),)
        if w & 0x3b000000 == 0x18000000:                       # LDR (literal)
            return (A + (sx((w >> 5) & 0x7ffff, 19) << 2),)
        if any(op.opcode in (O.CALL, O.CALLIND) for op in ins.ops):   # BL, BLR: x30 = here + 4
            return (A,)
        return ()

    def flag_reads(self, ins):
        """flags an instruction reads that its P-code doesn't show (MRS NZCV)"""
        if len(ins.raw) >= 4:
            w = struct.unpack("<I", ins.raw[:4])[0]
            if w & 0xfff00000 == 0xd5300000 and (w >> 5) & 0x7fff == SYS_NZCV:
                return self.flag_offs
        return ()

    # ---- register file access ----------------------------------------------
    @staticmethod
    def xr(n, sp=False):
        """C expression: pointer to general register n (31 = SP when sp)"""
        return f"(R+{SP_OFF:#x})" if n == 31 and sp else f"(R+{X_OFF + 8 * n:#x})"

    def xval(self, n, sp=False):
        """value of general register n; 31 reads as zero unless it means SP"""
        return "0ULL" if n == 31 and not sp else f"L8({self.xr(n, sp)})"

    def _gprs(self, ins):
        """(general registers read or written, written, reads flags, writes flags) per the P-code"""
        gin, gout, fin, fout = set(), set(), False, False
        for op in ins.ops:
            for v in op.inputs:
                if v.space.name == "register":
                    if X_OFF <= v.offset < X_OFF + 31 * 8:
                        gin.add((v.offset - X_OFF) // 8)
                    elif FLAG_OFF <= v.offset < FLAG_OFF + 4:
                        fin = True
            o = op.output
            if o is not None and o.space.name == "register":
                if X_OFF <= o.offset < X_OFF + 31 * 8:
                    gout.add((o.offset - X_OFF) // 8)
                elif FLAG_OFF <= o.offset < FLAG_OFF + 4:
                    fout = True
        return gin | gout, gout, fin or fout, fout

    # ---- instructions emitted as themselves ---------------------------------
    def fp_simd(self, w, ins):
        """a floating-point / SIMD data-processing instruction, run on the CPU.
        Vector registers: the four register fields are loaded (a field that is
        not a register only costs a load) and Rd is stored. General registers
        and flags: the ones the P-code reads or writes."""
        rd, rn, rm, ra = w & 31, (w >> 5) & 31, (w >> 16) & 31, (w >> 10) & 31
        vs = {rd, rn, rm, ra}
        if w & 0xbf208c00 == 0x0e000000:                      # TBL / TBX: 1-4 consecutive table registers
            for k in range(((w >> 13) & 3) + 1):
                vs.add((rn + k) & 31)
        g, gout, f, fout = self._gprs(ins)
        # x18 and x29 can't be used inside the inline assembly (the compiler
        # keeps them for itself): the instruction gets another register in
        # that field, which is loaded from / stored to x18's or x29's slot.
        # (In these instructions a general register is only ever Rd or Rn.)
        slot = {n: n for n in g}
        for n in sorted(g & {18, 29}):
            free = next(s for s in range(9, 16) if s not in g and s not in slot.values())
            if rd == n and n in gout:
                w = (w & ~31) | free
            elif rn == n:
                w = (w & ~(31 << 5)) | (free << 5)
            else:
                return None
            del slot[n]
            slot[free] = n
        g = set(slot)
        gout = {s for s, n in slot.items() if n in gout}
        a = [f"ldr x{s},[%[r],#{X_OFF + 8 * slot[s]}]" for s in sorted(g)]
        a += [f"ldr q{v},[%[r],#{V_OFF + 32 * v}]" for v in sorted(vs)]
        if f:
            a.append("msr nzcv,%[f]")
        a.append(f".inst {w:#010x}")
        if fout:
            a.append("mrs %[f],nzcv")
        a.append(f"str q{rd},[%[r],#{V_OFF + 32 * rd}]")
        a += [f"str x{s},[%[r],#{X_OFF + 8 * slot[s]}]" for s in sorted(gout)]
        clob = [f'"x{n}"' for n in sorted(g)] + [f'"v{v}"' for v in sorted(vs)] + ['"cc"', '"memory"']
        s = '"' + "\\n".join(a) + '"'
        self.count("fp/simd")
        if f:
            return [f"{{ uint64_t f_ = NZ_G(); __asm__ volatile({s} : [f] \"+r\"(f_) : [r] \"r\"(R) : "
                    f"{','.join(clob)});{' NZ_S(f_);' if fout else ''} }}"]
        return [f"__asm__ volatile({s} : : [r] \"r\"(R) : {','.join(clob)});"]

    def simd_ldst(self, w):
        """LD1-LD4 / ST1-ST4 / LDnR: the base register goes to x9 (and a
        post-index register to x10), the vector registers are the real ones"""
        rt, rn, rm, post, load = w & 31, (w >> 5) & 31, (w >> 16) & 31, w >> 23 & 1, w >> 22 & 1
        if w & 0x01000000:                                    # single structure
            n = ((w >> 13 & 1) << 1 | (w >> 21 & 1)) + 1
        else:
            n = {0: 4, 2: 4, 4: 3, 6: 3, 7: 1, 8: 2, 10: 2}.get(w >> 12 & 15)
            if n is None:
                return None
        vs = [(rt + k) & 31 for k in range(n)]
        enc = (w & ~(31 << 5)) | (9 << 5)
        regs = [f'register uint64_t a9 __asm__("x9") = {self.xval(rn, sp=True)};']
        ins_ = ['[r] "r"(R)']
        if post and rm != 31:
            enc = (enc & ~(31 << 16)) | (10 << 16)
            regs.append(f'register uint64_t a10 __asm__("x10") = L8({self.xr(rm)});')
            ins_.append('"r"(a10)')
        a = [f"ldr q{v},[%[r],#{V_OFF + 32 * v}]" for v in vs] + [f".inst {enc:#010x}"]
        if load:
            a += [f"str q{v},[%[r],#{V_OFF + 32 * v}]" for v in vs]
        clob = [f'"v{v}"' for v in vs] + ['"memory"']
        s = '"' + "\\n".join(a) + '"'
        out = "{ " + " ".join(regs) + f' __asm__ volatile({s} : "+r"(a9) : {", ".join(ins_)} : {",".join(clob)});'
        if post:
            out += f" S8({self.xr(rn, sp=True)},a9);"
        self.count("simd load/store")
        return [out + " }"]

    def gpr_native(self, w, fields, kind):
        """An instruction that uses only general registers (and memory through
        one of them), run on the CPU with its register fields renamed to
        scratch registers. fields: [(bit position, "i" | "o" | "io", 31 means
        SP)]; a field that is 31 (zero register) stays as it is."""
        enc, decl, outs, ins_, post = w, [], [], [], []
        for k, (sh, mode, sp) in enumerate(fields):
            n = (w >> sh) & 31
            if n == 31 and not sp:
                continue
            s = 9 + k
            enc = (enc & ~(31 << sh)) | (s << sh)
            init = f" = {self.xval(n, sp)}" if "i" in mode else ""
            decl.append(f'register uint64_t a{s} __asm__("x{s}"){init};')
            if "o" in mode:
                outs.append(f'"{"+" if "i" in mode else "="}r"(a{s})')
                post.append(f"S8({self.xr(n, sp)},a{s});")
            else:
                ins_.append(f'"r"(a{s})')
        self.count(kind)
        return ["{ " + " ".join(decl) + f' __asm__ volatile(".inst {enc:#010x}" : {", ".join(outs)} : '
                f'{", ".join(ins_)} : "memory","cc"); ' + " ".join(post) + " }"]

    def exclusive(self, w):
        """load/store exclusive, ordered loads/stores, CAS"""
        size, o2, load, o1 = w >> 30, w >> 23 & 1, w >> 22 & 1, w >> 21 & 1
        rs, rt2, rn, rt = w >> 16 & 31, w >> 10 & 31, w >> 5 & 31, w & 31
        base = self.xval(rn, sp=True)
        if o2:
            if o1:                                            # CAS: compare value in Rs, old value out
                return self.gpr_native(w, [(5, "i", True), (16, "io", False), (0, "i", False)], "atomic")
            return self.gpr_native(w, [(5, "i", True), (0, "o" if load else "i", False)], "atomic")
        if o1 and size < 2:                                   # CASP: register pairs Rs,Rs+1 and Rt,Rt+1
            enc = (w & ~((31 << 16) | (31 << 5) | 31)) | (10 << 16) | (9 << 5) | 12
            self.count("atomic")
            return [f'{{ register uint64_t a9 __asm__("x9") = {base}; '
                    f'register uint64_t a10 __asm__("x10") = L8({self.xr(rs)}); '
                    f'register uint64_t a11 __asm__("x11") = L8({self.xr(rs + 1)}); '
                    f'register uint64_t a12 __asm__("x12") = L8({self.xr(rt)}); '
                    f'register uint64_t a13 __asm__("x13") = L8({self.xr(rt + 1)}); '
                    f'__asm__ volatile(".inst {enc:#010x}" : "+r"(a10), "+r"(a11) : "r"(a9), "r"(a12), "r"(a13) : "memory"); '
                    f'S8({self.xr(rs)},a10); S8({self.xr(rs + 1)},a11); }}']
        # the exclusive monitor: LDXR remembers address and value, STXR stores
        # only if the memory still holds that value (one compare-and-swap)
        self.count("exclusive")
        if o1:                                                # LDXP / STXP
            es = 4 << (size & 1)
            T = "uint32_t" if es == 4 else "uint64_t"
            if load:
                return [f"{{ uint64_t a_ = {base}; ctx->ex_addr = a_; ctx->ex_size = {0x100 | es}; "
                        f"ctx->ex_val[0] = __atomic_load_n(({T}*)a_, __ATOMIC_SEQ_CST); "
                        f"ctx->ex_val[1] = __atomic_load_n(({T}*)(a_+{es}), __ATOMIC_SEQ_CST); "
                        + (f"S8({self.xr(rt)},ctx->ex_val[0]); " if rt != 31 else "")
                        + (f"S8({self.xr(rt2)},ctx->ex_val[1]); " if rt2 != 31 else "") + "}"]
            v0, v1 = self.xval(rt), self.xval(rt2)
            if es == 8:
                cas = f"rt_a64_cas16((uint64_t*)a_, ctx->ex_val, {v0}, {v1})"
            else:
                cas = (f"__atomic_compare_exchange_n((uint64_t*)a_, &e_, (uint64_t)(uint32_t){v0} | "
                       f"((uint64_t)(uint32_t){v1} << 32), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)")
            return [f"{{ uint64_t a_ = {base}; uint64_t e_ = ctx->ex_val[0] | (ctx->ex_val[1] << 32); (void)e_; "
                    f"uint64_t ok_ = ctx->ex_addr == a_ && ctx->ex_size == {0x100 | es} && {cas}; "
                    f"ctx->ex_addr = ~0ULL; " + (f"S8({self.xr(rs)},!ok_); " if rs != 31 else "") + "}"]
        n = 1 << size
        T = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}[n]
        if load:
            return [f"{{ uint64_t a_ = {base}; ctx->ex_addr = a_; ctx->ex_size = {n}; "
                    f"ctx->ex_val[0] = __atomic_load_n(({T}*)a_, __ATOMIC_SEQ_CST); "
                    + (f"S8({self.xr(rt)},ctx->ex_val[0]); " if rt != 31 else "") + "}"]
        return [f"{{ uint64_t a_ = {base}; {T} e_ = ({T})ctx->ex_val[0]; "
                f"uint64_t ok_ = ctx->ex_addr == a_ && ctx->ex_size == {n} && "
                f"__atomic_compare_exchange_n(({T}*)a_, &e_, ({T}){self.xval(rt)}, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); "
                f"ctx->ex_addr = ~0ULL; " + (f"S8({self.xr(rs)},!ok_); " if rs != 31 else "") + "}"]

    def system(self, w, ins):
        A = ins.addr
        if w & 0xfffff01f == 0xd503301f:                      # CLREX, DSB, DMB, ISB, SB
            self.count("barrier")
            return ["ctx->ex_addr = ~0ULL;"] if (w >> 5) & 7 == 2 else [f'__asm__ volatile(".inst {w:#010x}");']
        if w & 0xffd00000 == 0xd5100000:                      # MSR / MRS <system register>
            read, key, rt = w >> 21 & 1, (w >> 5) & 0x7fff, w & 31
            if key == SYS_NZCV:
                if read:
                    return [f"S8({self.xr(rt)},NZ_G());"] if rt != 31 else [";"]
                return [f"{{ uint64_t f_ = {self.xval(rt)}; NZ_S(f_); }}"]
            if read and key in SYS_READ:
                self.count("system register")
                enc = (w & ~31) | 9
                return [f'{{ register uint64_t a9 __asm__("x9"); __asm__ volatile(".inst {enc:#010x}" : "=r"(a9)); '
                        + (f"S8({self.xr(rt)},a9); " if rt != 31 else "") + "}"]
            if not read and key in SYS_WRITE:
                self.count("system register")
                enc = (w & ~31) | 9
                return [f'{{ register uint64_t a9 __asm__("x9") = {self.xval(rt)}; '
                        f'__asm__ volatile(".inst {enc:#010x}" : : "r"(a9)); }}']
            return None
        if w & 0xfff80000 == 0xd5080000 and (w >> 16) & 7 == 3 and (w >> 12) & 15 == 7:
            # DC ZVA / CVAU / CVAC / CIVAC, IC IVAU: cache operations on an address
            self.count("cache op")
            enc = (w & ~31) | 9
            return [f'{{ register uint64_t a9 __asm__("x9") = {self.xval(w & 31)}; '
                    f'__asm__ volatile(".inst {enc:#010x}" : : "r"(a9) : "memory"); }}']
        if w & 0xffe0001f == 0xd4000001:                      # SVC
            return ["rt_a64_svc(ctx);"]
        if w & 0xffe0001f in (0xd4200000, 0xd4400000) or w >> 16 == 0:     # BRK, HLT, UDF
            return [f"rt_a64_trap(ctx,{A:#x}ULL,{w:#010x}U);"]
        return None

    def scan(self, ins, w):
        """remember what this instruction says about addresses in the code"""
        A = ins.addr
        if A != self._adrp_end:
            self._adrp.clear()
        self._adrp_end = A + 4
        if w & 0x9f000000 == 0x10000000:                       # ADR
            self.addr_refs.append(A + sx(((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3, 21))
        elif w & 0x9f000000 == 0x90000000:                     # ADRP
            self._adrp[w & 31] = (A & ~0xfff) + (sx(((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3, 21) << 12)
            return
        elif w & 0x3b000000 == 0x18000000:                     # LDR (literal): 4, 8 or 16 bytes of data
            t = A + (sx((w >> 5) & 0x7ffff, 19) << 2)
            n = 16 if w & 0x04000000 and w >> 30 == 2 else 8 if (w >> 30) & 1 or (w & 0x04000000 and w >> 30 == 1) else 4
            for k in range(0, n, 4):
                self.data_refs.append(t + k)
        elif w & 0xff800000 == 0x91000000 and (w >> 5) & 31 in self._adrp:    # ADD Xd, Xn, #imm after ADRP Xn
            self.addr_refs.append(self._adrp[(w >> 5) & 31] + ((w >> 10) & 0xfff))
        if any(op.opcode in (O.CALL, O.CALLIND) for op in ins.ops):
            self.ret_sites.append(A + 4)
            self._adrp.clear()
        elif self._adrp:
            # a register that is written no longer holds the page
            for op in ins.ops:
                o = op.output
                if o is not None and o.space.name == "register" and X_OFF <= o.offset < X_OFF + 31 * 8:
                    self._adrp.pop((o.offset - X_OFF) // 8, None)

    def pac(self, w, ins):
        """Pointer authentication, done by the CPU like in the original: the
        signed return address on the stack is what an unwinder (or original
        code that runs as itself) authenticates. The forms compilers use are
        hint instructions that sign x30 with sp; they are run as the 1716
        hints (pointer in x17, modifier in x16), which do nothing on a CPU
        without pointer authentication, like the originals."""
        hint = {0xd503233f: (8, True), 0xd503237f: (10, True), 0xd50323bf: (12, True), 0xd50323ff: (14, True),
                0xd503231f: (8, False), 0xd503235f: (10, False), 0xd503239f: (12, False), 0xd50323df: (14, False),
                0xd65f0bff: (12, True), 0xd65f0fff: (14, True)}.get(w)      # PACIASP PACIBSP AUTIASP AUTIBSP, ...Z, RETAA RETAB
        if hint is not None:
            n, sp = hint
            self.count("pointer authentication")
            c = ['{ register uint64_t a17 __asm__("x17") = L8(' + self.xr(30) + '); register uint64_t a16 __asm__("x16") = '
                 + (self.xval(31, sp=True) if sp else "0ULL") + f'; __asm__ volatile("hint #{n}" : "+r"(a17) : "r"(a16)); '
                 f'S8({self.xr(30)},a17); }}']
            if w >> 16 == 0xd65f:                              # RETAA / RETAB: then return
                c.append(f"xr = 1; pc = L8({self.xr(30)}); goto DISPATCH;")
            return c
        if w in (0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df):     # PACIA1716 PACIB1716 AUTIA1716 AUTIB1716
            self.count("pointer authentication")
            return ['{ register uint64_t a17 __asm__("x17") = L8(' + self.xr(17) + '); register uint64_t a16 __asm__("x16") = L8('
                    + self.xr(16) + f'); __asm__ volatile(".inst {w:#010x}" : "+r"(a17) : "r"(a16)); S8({self.xr(17)},a17); }}']
        if w == 0xd50320ff:                                    # XPACLRI: strip the signature from x30
            self.count("pointer authentication")
            return ['{ register uint64_t a30 __asm__("x30") = L8(' + self.xr(30) + '); __asm__ volatile("hint #7" : "+r"(a30)); '
                    f'S8({self.xr(30)},a30); }}']
        if w & 0xffffc000 == 0xdac10000:                       # PACIA..AUTDB Xd, Xn|SP and the Z / XPAC forms
            z = (w >> 13) & 1
            return self.gpr_native(w, [(0, "io", False)] + ([] if z else [(5, "i", True)]), "pointer authentication")
        return None

    def custom(self, ins):
        """C for an instruction that is not translated from its P-code, or None"""
        if len(ins.raw) < 4:
            return None
        w = struct.unpack("<I", ins.raw[:4])[0]
        self.scan(ins, w)
        if w & 0xfffff01f == 0xd503201f or w & 0xfffffbff == 0xd65f0bff or w & 0xffffc000 == 0xdac10000:
            c = self.pac(w, ins)
            if c is not None:
                return c
        if is_fpsimd(w):
            return self.fp_simd(w, ins)
        if is_simd_ldst(w):
            return self.simd_ldst(w)
        if w & 0x3f000000 == 0x08000000:
            return self.exclusive(w)
        if w & 0x3b200c00 == 0x38200000:                      # LDADD/LDCLR/LDEOR/LDSET/LD[SU]MAX/MIN, SWP
            return self.gpr_native(w, [(5, "i", True), (16, "i", False), (0, "o", False)], "atomic")
        if w & 0x3fe0fc00 == 0x38a0c000:                      # LDAPR
            return self.gpr_native(w, [(5, "i", True), (0, "o", False)], "atomic")
        if w & 0x3f200c00 == 0x19000000:                      # LDAPUR / STLUR
            return self.gpr_native(w, [(5, "i", True), (0, "o" if (w >> 22) & 3 else "i", False)], "atomic")
        if w & 0x7fe0e000 == 0x1ac04000:                      # CRC32*
            return self.gpr_native(w, [(0, "o", False), (5, "i", False), (16, "i", False)], "crc32")
        if w & 0xff000000 == 0xd5000000 or w & 0xff000000 == 0xd4000000 or w >> 16 == 0:
            return self.system(w, ins)
        return None


def synthetic_decode(win):
    """(length, text) for an instruction Ghidra can't decode but that can be
    run as itself: a SIMD/floating-point data-processing instruction of a
    newer extension that only uses vector registers."""
    if len(win) < 4:
        return None
    w = struct.unpack("<I", bytes(win[:4]))[0]
    if is_fpsimd(w) and w & 0xff000000 not in (0x1e000000, 0x9e000000) and w & 0x9fe08400 != 0x0e000400:
        return 4, f".inst {w:#010x}"
    return None


# --------------------------------------------------------------------------
# generated C: file header
# --------------------------------------------------------------------------
def header(compact_macros):
    return ('/* generated by recomp - do not edit, regenerate instead */\n#include "rt_a64.h"\n#include "regs.h"\n'
            '/* short forms (see compact_line in lift.py) */\n'
            '#define M memcpy\n#define A_ (void*)(uintptr_t)\n#define U_(o) (U+0x##o)\n'
            '#define C_(o) (ctx->cur=B_+0x##o)\n#define G_(a) {pc=GA(a##ULL);goto OUT;}\n'
            '#define FN_(n) __attribute__((noinline)) uint64_t n(uint64_t pc, rt_ctx *ctx) {\n'
            '#define RU_ uint8_t *const R = ctx->R, *const U = ctx->U; uint64_t pc_here = pc; unsigned xr = 0; '
            '(void)pc_here; (void)U;\n'
            '/* entry table: one entry per instruction slot (4 bytes); xr = leaving through a RET */\n'
            '#define TB_(n) { static const int T[n] = {\n'
            '#define TE_(n) }; uint64_t o = pc - GA(B_); if (o >= 4 * n##u || (o & 3)) return pc | xr; '
            'xr = 0; goto *(&&OUT + T[o >> 2]); }\n'
            '#define L1(p) L(p,1)\n#define L2(p) L(p,2)\n#define L4(p) L(p,4)\n#define L8(p) L(p,8)\n'
            '#define S1(p,v) S(p,v,1)\n#define S2(p,v) S(p,v,2)\n#define S4(p,v) S(p,v,4)\n'
            '#define S8(p,v) S(p,v,8)\n'
            '#define E(l) (&&I##l - &&OUT)\n#define N (&&X - &&OUT)\n')


# --------------------------------------------------------------------------
# loading: what the lifter needs to know about the file
# --------------------------------------------------------------------------
def load(img):
    """called by Image._elf for an ARM64 shared object: relocations, exports,
    imports, code pointers. Raises LiftError (through the caller) for what the
    runtime can't do."""
    e = img.dynelf = E.DynElf(img.raw)
    lo_hi = [(c[0], c[0] + c[2]) for c in img.code]
    in_code = lambda v: any(a <= v < b for a, b in lo_hi)
    kinds = {}
    for r_off, typ, si, add in e.relocs:
        kinds[typ] = kinds.get(typ, 0) + 1
        if typ == E.R_RELATIVE and in_code(add):
            img.code_ptrs.add(add)
        elif typ == E.R_IRELATIVE and in_code(add):
            img.funcs.setdefault(add, f"ifunc_resolver_{add:x}")
    bad = [E.R_NAMES.get(t, str(t)) for t in kinds
           if t not in (E.R_ABS64, E.R_GLOB_DAT, E.R_JUMP_SLOT, E.R_RELATIVE, E.R_TLSDESC, E.R_IRELATIVE)]
    if bad:
        return f"relocation type(s) the rebuilt library can't reproduce: {', '.join(sorted(bad))}"
    img.exports = []
    # addresses that are certainly the first instruction of a function
    ent = img.a64_entries = set(getattr(img, "func_syms", ()))
    for r_off, typ, si, add in e.relocs:
        if typ == E.R_IRELATIVE and in_code(add):
            ent.add(add)
    for s in e.syms:
        if not s.name or not s.defined or s.bind == E.STB_LOCAL:
            if s.defined and s.type == E.STT_FUNC and in_code(s.value):
                ent.add(s.value)
            continue
        if s.type == E.STT_GNU_IFUNC:
            return f"exports an indirect function ({s.name}, STT_GNU_IFUNC): not supported"
        if s.type in (E.STT_FUNC, E.STT_GNU_IFUNC) or (s.type == E.STT_NOTYPE and in_code(s.value)):
            img.funcs.setdefault(s.value, s.name)
            img.exports.append((0, s.name, s.value, None))
            if s.type == E.STT_FUNC:
                ent.add(s.value)
        elif s.type == E.STT_OBJECT and s.value:
            img.datasyms.setdefault(s.value, s.name)
    slots = {}
    for r_off, typ, si, add in e.relocs:
        if si and si < len(e.syms) and not e.syms[si].defined:
            slots.setdefault(e.syms[si].name, r_off)
            img.datasyms.setdefault(r_off, f"__got_{e.syms[si].name}")
    img.imports = [("", s.name, slots.get(s.name, 0)) for s in e.syms if s.name and not s.defined]
    for tag, stag, nm in ((E.DT_INIT_ARRAY, E.DT_INIT_ARRAYSZ, "init"), (E.DT_FINI_ARRAY, E.DT_FINI_ARRAYSZ, "fini")):
        va, n = e.array(tag, stag)
        rel = {r[0]: r[3] for r in e.relocs if r[1] == E.R_RELATIVE and va <= r[0] < va + 8 * n} if n else {}
        for i in range(n):
            f = rel.get(va + 8 * i, 0)
            if f and in_code(f):
                img.funcs.setdefault(f, f"{nm}_array_{i}")
                ent.add(f)
    for tag, nm in ((E.DT_INIT, "_init"), (E.DT_FINI, "_fini")):
        v = e.dyn.get(tag)
        if v and in_code(v):
            img.funcs.setdefault(v, nm)
            ent.add(v)
    img.notes.append(f"{len(img.exports)} exported functions, {len(img.imports)} imported symbols, "
                     f"{len(e.relocs)} dynamic relocations ({', '.join(sorted(e.reloc_format)) or 'none'}), "
                     f"{len(img.code_ptrs)} code pointers in data")
    return None


def platform_of(img):
    """"android" (bionic: libc.so) or "linux" (glibc/musl): which C library the
    runtime talks to"""
    need = img.dynelf.needed
    if any(n.startswith("libc.so.") or n.startswith("ld-linux") or n.startswith("libc.musl") for n in need):
        return "linux"
    return "android"


# --------------------------------------------------------------------------
# output files
# --------------------------------------------------------------------------
RT_FILES = ("rt_a64.h", "rt_a64.c", "rt_a64_asm.S")
# helper scripts every lift output gets (build_lift.py uses them)
TOOL_FILES = ("android_cc.py", "a64elf.py")
CFLAGS = ["-O1", "-w", "-ffreestanding", "-fPIC", "-fno-strict-aliasing", "-fwrapv", "-fvisibility=hidden",
          "-ffixed-x18", "-fno-stack-protector", "-mno-outline-atomics", "-fno-asynchronous-unwind-tables",
          "-fno-unwind-tables", "-fomit-frame-pointer", "-fno-math-errno"]


def quote_sym(n):
    return '"' + n.replace("\\", "\\\\").replace('"', '\\"') + '"'


def prologue_like(w):
    """does a function start with this instruction? (what compilers emit
    first: a landing pad, signing the return address, pushing registers,
    making the frame)"""
    return (w in (0xd503233f, 0xd503237f, 0xd503245f, 0xd50324df)      # PACIASP PACIBSP, BTI c / jc
            or w & 0xffc003e0 == 0xa98003e0                              # STP Xa, Xb, [sp, #-n]!
            or w & 0xffe00fe0 == 0xf8000fe0 and w & 0x00100000          # STR Xa, [sp, #-n]!
            or w & 0xff8003ff == 0xd10003ff)                             # SUB sp, sp, #n


STUB0 = 32      # .guest_stubs: two shared pieces of code, then 12 bytes per function start


def write_outputs(img, em, outdir, rt_dir, files, chunk_of, nchunks, cstring, write_build_manifest):
    """everything besides code_*.c: guest.o (the image, with the jumps into
    the runtime), guest.lds, tables.c, the runtime and the build manifest.
    chunk_of: (instruction address, chunk number) pairs."""
    e = img.dynelf
    lo = e.lo
    plat = platform_of(img)
    target = getattr(img, "target", os.path.basename(img.path))
    notes = []
    PF_X, PF_W = 1, 2

    # ---- the image: one section per loadable segment ------------------------
    segs = []
    for k, p in enumerate(sorted(e.loads, key=lambda p: p["vaddr"])):
        if segs and p["vaddr"] < segs[-1]["vaddr"] + segs[-1]["memsz"]:
            raise ValueError("loadable segments overlap")
        segs.append({"k": k, "vaddr": p["vaddr"], "filesz": p["filesz"], "memsz": p["memsz"], "flags": p["flags"],
                     "name": f".guest.{k}", "relocs": [],
                     "data": bytearray(img.raw[p["offset"]:p["offset"] + p["filesz"]])})

    def in_file(va, n):
        """(segment, offset) of n file-backed bytes at va"""
        for sg in segs:
            if sg["vaddr"] <= va and va + n <= sg["vaddr"] + sg["filesz"]:
                return sg, va - sg["vaddr"]
        return None, 0

    def in_mem(va):
        """(section name, offset) of an address of the image"""
        for sg in segs:
            if sg["vaddr"] <= va < sg["vaddr"] + sg["filesz"]:
                return sg["name"], va - sg["vaddr"]
            if sg["vaddr"] + sg["filesz"] <= va <= sg["vaddr"] + sg["memsz"] and sg["memsz"] > sg["filesz"]:
                return sg["name"] + ".bss", va - sg["vaddr"] - sg["filesz"]
        return None, 0

    # ---- symbols and relocations -----------------------------------------
    syms, seen = [], set()
    skipped_tls = lost = 0
    sym_ref = {}        # dynsym index -> name to relocate against
    for i, s in enumerate(e.syms):
        if not s.name:
            continue
        if not s.defined:
            if s.name in WRAPPED:
                sym_ref[i] = "rt_w_" + s.name
                continue
            sym_ref[i] = s.name
            if s.name not in seen:
                seen.add(s.name)
                syms.append((s.name, None, 0, 0, E.STT_NOTYPE, E.STB_WEAK if s.bind == E.STB_WEAK else E.STB_GLOBAL, 0))
            continue
        if s.bind == E.STB_LOCAL or s.shndx == E.SHN_ABS:
            continue
        if s.type == E.STT_TLS:
            skipped_tls += 1
            continue
        sec, off = in_mem(s.value)
        if sec is None:
            lost += 1
            continue
        sym_ref[i] = s.name
        if s.name in seen:
            continue
        seen.add(s.name)
        typ = s.type if s.type in (E.STT_OBJECT, E.STT_FUNC) else E.STT_NOTYPE
        syms.append((s.name, sec, off, s.size, typ, s.bind, s.vis))
    for n in sorted({v for v in sym_ref.values() if v.startswith("rt_w_")} | {"rt_guest", "rt_a64_enter", "rt_a64_reenter"}):
        if n not in seen:
            seen.add(n)
            syms.append((n, None, 0, 0, E.STT_NOTYPE, E.STB_GLOBAL, 2))
    tlsdesc, irel = [], []

    def place(r_off, n):
        sg, o = in_file(r_off, n)
        if sg is None:
            raise ValueError(f"relocation at {r_off:#x} is outside the file-backed image")
        if not sg["flags"] & PF_W:
            raise ValueError(f"relocation at {r_off:#x} is in read-only memory (text relocations)")
        sg["data"][o:o + n] = bytes(n)
        return sg, o
    for r_off, typ, si, add in e.relocs:
        if typ == E.R_RELATIVE:
            sg, o = place(r_off, 8)
            sg["relocs"].append((o, E.R_ABS64, "rt_guest", add - lo))
        elif typ in (E.R_ABS64, E.R_GLOB_DAT, E.R_JUMP_SLOT):
            sg, o = place(r_off, 8)
            if si == 0:
                sg["relocs"].append((o, E.R_ABS64, "rt_guest", add - lo))
            elif si in sym_ref:
                sg["relocs"].append((o, E.R_ABS64, sym_ref[si], add))
            else:
                s = e.syms[si] if si < len(e.syms) else None
                if s is not None and s.defined:            # a local or unnamed definition
                    sg["relocs"].append((o, E.R_ABS64, "rt_guest", s.value + add - lo))
                else:
                    raise ValueError(f"relocation at {r_off:#x} names symbol {si}, which the file doesn't have")
        elif typ == E.R_TLSDESC:
            # two words: resolver function, argument. Filled in by the runtime:
            # the offset of the variable in this library's thread-local block
            s = e.syms[si] if si and si < len(e.syms) else None
            if s is not None and not s.defined:
                raise ValueError(f"thread-local variable {s.name} is imported from another library "
                                 f"(TLS descriptor): not supported")
            place(r_off, 16)
            tlsdesc.append((r_off, (s.value if s is not None else 0) + add))
        elif typ == E.R_IRELATIVE:
            place(r_off, 8)
            irel.append((r_off, add))
    if skipped_tls:
        notes.append(f"{skipped_tls} exported thread-local variable(s) are not exported by the rebuilt library")
    if lost:
        notes.append(f"{lost} exported symbol(s) point outside the image and are not exported")

    # ---- address -> chunk maps, one per code region -----------------------
    regions = []
    for k, (base, foff, size, name) in enumerate(sorted(img.code)):
        if size < 4:
            continue
        n = size // 4
        m = array("I", [NOMAP]) * n
        regions.append((base, n, m, f"map_{k}.bin"))
    for a, cid in chunk_of:
        for base, n, m, _ in regions:
            i = a - base
            if 0 <= i < 4 * n and not i & 3:
                m[i >> 2] = cid
                break
    for base, n, m, fn in regions:
        with open(os.path.join(outdir, fn), "wb") as f:
            m.tofile(f)

    def is_insn(a):
        for base, n, m, _ in regions:
            i = a - base
            if 0 <= i < 4 * n:
                return not i & 3 and m[i >> 2] != NOMAP
        return False

    # ---- the jumps into the runtime ----------------------------------------
    # see the top of this file. Nothing that may be data is replaced: not
    # what an instruction reads as data, and not an address the program only
    # computes or stores (unless a function clearly starts there).
    a64 = em.a64
    data = set(a64.data_refs)
    sure = set(getattr(img, "a64_entries", ())) | set(em.cm.calls)
    maybe = (set(a64.addr_refs) | set(img.code_ptrs)) - sure

    def word(a):
        sg, o = in_file(a, 4)
        return struct.unpack_from("<I", sg["data"], o)[0] if sg is not None and sg["flags"] & PF_X else None
    entries = {a for a in sure if a not in data and is_insn(a) and word(a) is not None}
    unsure = set()
    for a in maybe:
        if a in data or not is_insn(a):
            continue
        w = word(a)
        if w is not None and prologue_like(w):
            entries.add(a)
        else:
            unsure.add(a)
    rets = set()
    kept = 0
    for a in a64.ret_sites:
        if a in entries or a in rets:
            continue
        if a in data or a in unsure or not is_insn(a):
            kept += 1
            continue
        w = word(a)
        if w is None:
            kept += 1
        elif prologue_like(w):
            entries.add(a)          # (maybe the next function, after a call that never returns)
        else:
            rets.add(a)
    # a jump reaches 128 MB: the code it goes to sits right in front of the image
    reach = 0x7f00000 - (STUB0 + 12 * len(entries)) - 0x20000
    far = sum(1 for a in entries if a - lo >= reach) + sum(1 for a in rets if a - lo >= reach)
    entries = sorted(a for a in entries if a - lo < reach)
    rets = sorted(a for a in rets if a - lo < reach)
    if far:
        notes.append(f"{far} place(s) are too far into the image (over 128 MB) for a jump into the runtime: "
                     f"code reached through them from native code runs as the original machine code")
    stub = bytearray(struct.pack("<8I", 0xa9bf47f0, 0x90000010, 0x91000210, 0xd61f0200,     # stp x16,x17,[sp,#-16]!; x16 = rt_a64_reenter; br x16
                                 0x90000011, 0x91000231, 0xd61f0220, 0xd503201f))           # x17 = rt_a64_enter; br x17
    stub_rel = [(4, E.R_ADR_PAGE, "rt_a64_reenter", 0), (8, E.R_ADD_LO12, "rt_a64_reenter", 0),
                (16, E.R_ADR_PAGE, "rt_a64_enter", 0), (20, E.R_ADD_LO12, "rt_a64_enter", 0)]
    one = struct.pack("<3I", 0x90000010, 0x91000210, 0x14000000)        # x16 = the function's address; b (x17 = rt_a64_enter; br x17)
    stub += one * len(entries)
    for i, a in enumerate(entries):
        so = STUB0 + 12 * i
        stub_rel += [(so, E.R_ADR_PAGE, "rt_guest", a - lo), (so + 4, E.R_ADD_LO12, "rt_guest", a - lo),
                     (so + 8, E.R_JUMP26, ("section", ".guest_stubs"), 16)]
        sg, o = in_file(a, 4)
        sg["data"][o:o + 4] = b"\x00\x00\x00\x14"                       # b <its stub>
        sg["relocs"].append((o, E.R_JUMP26, ("section", ".guest_stubs"), so))
    for a in rets:
        sg, o = in_file(a, 4)
        sg["data"][o:o + 4] = b"\x00\x00\x00\x94"                       # bl <rt_a64_reenter, through .guest_stubs>
        sg["relocs"].append((o, E.R_CALL26, ("section", ".guest_stubs"), 0))

    sections = [{"name": ".guest_stubs", "flags": E.SHF_ALLOC | E.SHF_EXEC, "align": 16, "data": bytes(stub),
                 "relocs": stub_rel}]
    align = max([0x10000] + [p["align"] for p in e.loads])
    lds = ["/* generated by recomp: where the original image goes in the rebuilt library.",
           " * Every segment of the original is one section, at the distance from the others",
           " * and with the access rights it had; rt_guest is where the original's address",
           f" * {lo:#x} is. In front of it: the code the jumps in the image go to. */",
           "SECTIONS", "{",
           f"  .guest_stubs : ALIGN({align:#x}) {{ KEEP(*(.guest_stubs)) . = ALIGN({align:#x}); HIDDEN(rt_guest = .); }}"]
    for sg in segs:
        fl = E.SHF_ALLOC | (E.SHF_WRITE if sg["flags"] & PF_W else 0) | (E.SHF_EXEC if sg["flags"] & PF_X else 0)
        sg["relocs"].sort()
        if sg["filesz"]:
            sections.append({"name": sg["name"], "flags": fl, "align": 1, "data": bytes(sg["data"]), "relocs": sg["relocs"]})
            lds.append(f"  {sg['name']} rt_guest + {sg['vaddr'] - lo:#x} : {{ KEEP(*({sg['name']})) }}")
        sg["data"] = None
        if sg["memsz"] > sg["filesz"]:
            sections.append({"name": sg["name"] + ".bss", "flags": E.SHF_ALLOC | E.SHF_WRITE, "align": 1,
                             "size": sg["memsz"] - sg["filesz"]})
            lds.append(f"  {sg['name']}.bss rt_guest + {sg['vaddr'] + sg['filesz'] - lo:#x} (NOLOAD) : "
                       f"{{ KEEP(*({sg['name']}.bss)) }}")
    lds += ["}", "INSERT AFTER .bss;", ""]
    with open(os.path.join(outdir, "guest.lds"), "w", encoding="utf-8") as f:
        f.write("\n".join(lds))
    E.write_object(os.path.join(outdir, "guest.o"), sections, syms)
    for fn in ("exports.S", "exports.o"):           # (from an older recomp)
        if os.path.exists(os.path.join(outdir, fn)):
            os.remove(os.path.join(outdir, fn))

    syms_all = {}
    syms_all.update(img.datasyms)
    syms_all.update(img.funcs)
    ia, ian = e.array(E.DT_INIT_ARRAY, E.DT_INIT_ARRAYSZ)
    fa, fan = e.array(E.DT_FINI_ARRAY, E.DT_FINI_ARRAYSZ)
    ro = [(p["vaddr"], p["memsz"]) for p in e.phdrs if p["type"] == 0x6474e552]     # PT_GNU_RELRO
    imported = {s.name for s in e.syms if s.name and not s.defined}
    with open(os.path.join(outdir, "tables.c"), "w", encoding="utf-8") as f:
        f.write('#include "rt_a64.h"\n')
        for base, n, m, fn in regions:
            k = fn[4:-4]
            f.write(f'__asm__(".section .rodata\\n.balign 4\\nt_map{k}:\\n.incbin \\"{fn}\\"\\n.text");\n'
                    f"extern const uint32_t t_map{k}[] __asm__(\"t_map{k}\");\n")
        f.write("static const rt_a64_region t_regions[] = {\n")
        for base, n, m, fn in regions:
            f.write(f"  {{{base - lo:#x}ULL,{4 * n:#x}ULL,t_map{fn[4:-4]}}},\n")
        f.write("};\n")
        for cid in range(nchunks):
            f.write(f"uint64_t c{cid}(uint64_t, rt_ctx*);\n")
        f.write("static rt_chunk_fn const t_chunks[] = {")
        for cid in range(nchunks):
            f.write(("," if cid else "") + ("\n" if cid % 16 == 0 else "") + f"c{cid}")
        f.write("};\n")
        f.write("static const char* const t_opnames[] = {")
        f.write(",".join(cstring(n) for n, _ in sorted(em.userops.items(), key=lambda kv: kv[1])) or "0")
        f.write("};\n")
        f.write("static const rt_sym t_syms[] = {\n")
        for a in sorted(syms_all):
            f.write(f"  {{{a:#x}ULL,{cstring(syms_all[a])}}},\n")
        f.write("  {0,0}};\n")
        f.write("static const uint64_t t_tlsdesc[] = {" +
                ",".join(f"{a:#x}ULL,{v:#x}ULL" for a, v in tlsdesc) + ("," if tlsdesc else "") + "0};\n")
        f.write("static const uint64_t t_irel[] = {" +
                ",".join(f"{a:#x}ULL,{v:#x}ULL" for a, v in irel) + ("," if irel else "") + "0};\n")
        f.write("static const uint64_t t_ro[] = {" +
                ",".join(f"{a:#x}ULL,{s:#x}ULL" for a, s in ro) + ("," if ro else "") + "0,0};\n")
        t = e.tls or {"vaddr": 0, "filesz": 0, "memsz": 0, "align": 1}
        f.write("const rt_a64_mod rt_mod = {\n")
        f.write(f"  .name = {cstring(target)}, .glo = {lo:#x}ULL, .gsize = {e.mem_end - lo:#x}ULL,\n")
        f.write(f"  .nregions = {len(regions)}, .regions = t_regions, .nchunks = {nchunks}, .chunks = t_chunks,\n")
        f.write(f"  .nops = {len(em.userops)}, .opnames = t_opnames, .nsyms = {len(syms_all)}, .syms = t_syms,\n")
        f.write(f"  .init = {e.dyn.get(E.DT_INIT, 0):#x}ULL, .fini = {e.dyn.get(E.DT_FINI, 0):#x}ULL,\n")
        f.write(f"  .init_array = {ia:#x}ULL, .init_n = {ian}, .fini_array = {fa:#x}ULL, .fini_n = {fan},\n")
        f.write(f"  .tls_vaddr = {t['vaddr']:#x}ULL, .tls_filesz = {t['filesz']:#x}ULL, "
                f".tls_memsz = {t['memsz']:#x}ULL, .tls_align = {max(1, t['align'])},\n")
        f.write(f"  .ntlsdesc = {len(tlsdesc)}, .tlsdesc = t_tlsdesc, .nirel = {len(irel)}, .irel = t_irel,\n")
        f.write(f"  .ro = t_ro, .usize = {em.max_unique + 64:#x}ULL,\n")
        f.write("};\n")

    for fn in RT_FILES:
        shutil.copyfile(os.path.join(rt_dir, "a64", fn), os.path.join(outdir, fn))
    for fn in TOOL_FILES:
        shutil.copyfile(os.path.join(os.path.dirname(os.path.abspath(__file__)), fn), os.path.join(outdir, fn))

    # ---- how to build it ----------------------------------------------------
    srcs = list(files) + ["tables.c", "rt_a64.c", "rt_a64_asm.S"]
    defs = ["-DRT_ANDROID"] if plat == "android" else ["-DRT_GLIBC"]
    compiles = []
    for s in srcs:
        obj = os.path.splitext(s)[0] + ".o"
        compiles.append({"obj": obj, "src": s, "flags": CFLAGS + defs + (["-O2"] if s == "rt_a64.c" else [])})
    needed = list(e.needed)
    extra = ["libc.so", "libdl.so", "liblog.so"] if plat == "android" else ["libc.so.6"]
    if plat == "linux" and not any(n.startswith("libc.so") for n in needed):
        extra = []                              # (musl: everything is in the one libc it already names)
    needed += [n for n in extra if n not in needed]
    packing = "android+relr" if {"android", "relr"} <= e.reloc_format else \
        "android" if "android" in e.reloc_format else "relr" if "relr" in e.reloc_format else "none"
    # the page size the original was made for: its segments keep their
    # distances, so they can only be mapped with that page size or a smaller one
    page = max([0x1000] + [p["align"] for p in e.loads if p["align"] <= 0x10000])
    link = ["-shared", "-nostdlib", f"-Wl,-soname,{e.soname or os.path.basename(target)}",
            f"-Wl,-z,max-page-size={page}", "-Wl,--hash-style=both", "-Wl,--eh-frame-hdr", "-Wl,-z,noexecstack",
            "-Wl,-z,now", "-Wl,--no-as-needed", f"-Wl,--pack-dyn-relocs={packing}", "-Wl,-T,guest.lds"]
    if E.DT_ANDROID_RELR in e.dyn:
        link.append("-Wl,--use-android-relr-tags")      # (Android 9 and 10 only know these)
    if e.symbolic:
        link.append("-Wl,-Bsymbolic")
    out = os.path.basename(target)
    objs = [c["obj"] for c in compiles] + ["guest.o"]
    first = next(sg for sg in segs if sg["filesz"])
    m = {"out": out, "cc": "a64:" + plat,
         "compiles": compiles,
         "stubs": needed,
         "link": {"prefix": link + ["-o", out], "objs": objs, "suffix": [f"stubs/{n}" for n in needed],
                  "deps": ["guest.lds"]},
         "post": {"eh_frame_hdr": [e.eh_frame_hdr["vaddr"] - lo, e.eh_frame_hdr["memsz"]] if e.eh_frame_hdr else None,
                  # a section of the image and its distance from rt_guest
                  "image": [first["name"], first["vaddr"] - lo]},
         # every other undefined symbol in the built library is a mistake
         # (a compiler support function, a typo): the build stops
         "undefined_ok": sorted(imported | set(RT_IMPORTS)),
         "clean": [out]}
    write_build_manifest(outdir, m)
    for fn in ("Makefile", "ANALYSIS_ONLY.txt"):
        p = os.path.join(outdir, fn)
        if os.path.exists(p):
            os.remove(p)
    return {"platform": plat, "relocations": len(e.relocs),
            "exported_symbols": sum(1 for s in syms if s[1] is not None), "imports": len(imported),
            "wrapped_imports": sorted(n for n in imported if n in WRAPPED),
            "tls_descriptors": len(tlsdesc), "ifunc_relocations": len(irel), "notes": notes,
            "function_entries": len(entries), "return_sites": len(rets), "return_sites_left_alone": kept,
            "native_instructions": dict(a64.native)}
