/* recomp runtime, Windows x64 guests - built once as recomp_rt.dll and
 * shared by every recompiled file of a program (exe + DLLs).
 *
 *  - each rebuilt .exe/.dll has a non-executable section `.guest` right after
 *    its headers, at the original ImageBase; its DllMain/main calls
 *    rt_module_dllmain/rt_module_exemain, which copies the original image
 *    there, resolves its imports and registers it here
 *  - one dispatcher for all modules: a call from one recompiled DLL into
 *    another is an ordinary jump, on the same guest stack
 *  - when recompiled code jumps to an address outside every image, that is a
 *    real DLL function: rt_native_call() calls it with the Win64 ABI using
 *    the guest's registers and stack arguments
 *  - when Windows (or a DLL) calls back into original code - window
 *    procedures, thread start routines, exports of a rebuilt DLL - the CPU
 *    faults because the page is not executable; the vectored exception
 *    handler runs the recompiled version instead
 *  - every guest thread gets one context, stack and fake TEB (gs:[...]); its
 *    TLS array has one slot per module (the module's guest _tls_index)
 *  - exceptions (C++ throw, SEH) are dispatched on the guest stack: rt_seh.c
 */
#define WIN32_LEAN_AND_MEAN
#include "rt_internal.h"
#include "rt_win.h"
#include <windows.h>
#include <winternl.h>

#define GUEST_STACK (8u << 20)

static DWORD tls_slot;
static FARPROC p_exit_process, p_get_proc_address, p_terminate_process;
static CRITICAL_SECTION rt_cs;            /* modules, thread list, names */
static int inited;

/* ---- names of native functions, for logs ---- */
typedef struct { uint64_t addr; char name[96]; } natname;
static natname *names; static int nnames, cap_names;

static void add_name(uint64_t a, const char *dll, const char *fn) {
    EnterCriticalSection(&rt_cs);
    if (nnames == cap_names) { cap_names = cap_names ? cap_names * 2 : 256; names = realloc(names, cap_names * sizeof *names); }
    names[nnames].addr = a;
    snprintf(names[nnames].name, sizeof names[nnames].name, "%s!%s", dll, fn);
    nnames++;
    LeaveCriticalSection(&rt_cs);
}
static const char *native_name(uint64_t a) {
    for (int i = 0; i < nnames; i++) if (names[i].addr == a) return names[i].name;
    return "?";
}

/* ---- per-thread context with a fake TEB ---- */
static rt_ctx **threads; static int nthreads, cap_threads;

static void alloc_tls_block(rt_ctx *c, rt_module *m) {
    if (!m->tls_template && !m->tls_zsize) return;
    uint64_t *arr = *(uint64_t **)((uint8_t *)c->platform + 0x58);
    if (arr[m->index]) return;
    uint8_t *blk = calloc(1, m->tls_tsize + m->tls_zsize + 16);
    if (m->tls_template) memcpy(blk, m->tls_template, m->tls_tsize);
    arr[m->index] = (uint64_t)(uintptr_t)blk;
}

rt_ctx *rt_win_thread_ctx(void) {
    rt_ctx *c = rt_new_ctx(GUEST_STACK);
    /* fake TEB: a copy of the real one, with our stack bounds and TLS array */
    uint8_t *teb = VirtualAlloc(0, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *real = (uint8_t *)NtCurrentTeb();
    size_t n = 0x1800;
    if (VirtualQuery(real, &mbi, sizeof mbi)) {   /* Wine allocates the TEB smaller */
        size_t avail = (uint8_t *)mbi.BaseAddress + mbi.RegionSize - real;
        if (avail < n) n = avail;
    }
    memcpy(teb, real, n);
    /* Commit the thread's real stack now. Code made at run time (Mono's JIT)
     * runs on it and calls a helper in the program to probe the stack before
     * it takes a large frame; that helper, recompiled, probes the program's
     * stack instead. Without this the large frame could land beyond the
     * guard page of the real stack: an access violation out of nowhere. */
    if (n >= 0x1480) {
        uint8_t *lo = *(uint8_t **)(real + 0x1478);      /* DeallocationStack: bottom of the reservation */
        uint8_t *lim = *(uint8_t **)(real + 0x10);       /* StackLimit: lowest committed page */
        if (lo && lim > lo + 0x8000 && (size_t)(lim - lo) <= ((size_t)64 << 20))
            for (volatile uint8_t *p = lim - 0x1000; p >= lo + 0x6000; p -= 0x1000) (void)*p;
    }
    *(uint64_t *)(teb + 0x08) = c->stack_hi;            /* NT_TIB.StackBase  */
    *(uint64_t *)(teb + 0x10) = c->stack_lo;            /* NT_TIB.StackLimit */
    *(uint64_t *)(teb + 0x30) = (uint64_t)(uintptr_t)teb; /* NT_TIB.Self     */
    *(uint64_t *)(teb + 0x58) = (uint64_t)(uintptr_t)calloc(RT_MAX_MODULES, 8); /* TLS array */
    REG64(c, RREG_GS_OFFSET) = (uint64_t)(uintptr_t)teb;
    c->platform = teb;
    TlsSetValue(tls_slot, c);
    EnterCriticalSection(&rt_cs);
    for (int i = 0; i < rt_nmods; i++) alloc_tls_block(c, rt_mods[i]);
    if (nthreads == cap_threads) { cap_threads = cap_threads ? 2 * cap_threads : 16; threads = realloc(threads, cap_threads * sizeof *threads); }
    threads[nthreads++] = c;
    LeaveCriticalSection(&rt_cs);
    rt_log(1, "t%d: new guest thread context, stack %#llx-%#llx, fake TEB %p", c->tid,
           (unsigned long long)c->stack_lo, (unsigned long long)c->stack_hi, teb);
    return c;
}

rt_ctx *rt_current_ctx(void) { return (rt_ctx *)TlsGetValue(tls_slot); }
rt_ctx *rt_win_ctx(void) { rt_ctx *c = rt_current_ctx(); return c ? c : rt_win_thread_ctx(); }

void rt_platform_syscall(rt_ctx *c) {
    rt_crash(c, "SYSCALL instruction in a Windows program", c->cur,
             "Windows programs call the kernel through ntdll.dll, never directly. A raw "
             "syscall here means anti-tamper/anti-debug code or hand-written stubs");
}

/* ---- calling native code with the Win64 ABI --------------------------
 * rt_native_call(fn, args[20], xmm_in[4], &xmm0_out)
 *   args[0..3] -> RCX RDX R8 R9, args[4..19] -> stack slots 5..20
 *   xmm_in[0..3] -> XMM0..XMM3 (float args go there in the Win64 ABI)   */
uint64_t rt_native_call(uint64_t fn, const uint64_t *args, const uint64_t *xmm, uint64_t *xmm0_out);
/* (with unwind info, so Windows can walk through it when native code
 * raises and handles its own exceptions internally) */
__asm__(
    ".text\n.globl rt_native_call\n.def rt_native_call; .scl 2; .type 32; .endef\n"
    ".seh_proc rt_native_call\nrt_native_call:\n"
    "  push %rbp\n  .seh_pushreg %rbp\n  push %rbx\n  .seh_pushreg %rbx\n"
    "  push %rsi\n  .seh_pushreg %rsi\n  push %rdi\n  .seh_pushreg %rdi\n"
    "  push %r12\n  .seh_pushreg %r12\n"
    "  sub $0xa0,%rsp\n  .seh_stackalloc 0xa0\n  .seh_endprologue\n"
    /* 0x20 shadow + 16 stack args; 5 pushes + 0xa0 keep 16-byte alignment */
    "  mov %rcx,%rbx\n  mov %rdx,%rsi\n  mov %r8,%rdi\n  mov %r9,%r12\n"
    "  xor %eax,%eax\n"
    "1: mov 32(%rsi,%rax,8),%rcx\n  mov %rcx,32(%rsp,%rax,8)\n  inc %rax\n  cmp $16,%rax\n  jb 1b\n"
    "  movq 0(%rdi),%xmm0\n  movq 8(%rdi),%xmm1\n  movq 16(%rdi),%xmm2\n  movq 24(%rdi),%xmm3\n"
    "  mov 0(%rsi),%rcx\n  mov 8(%rsi),%rdx\n  mov 16(%rsi),%r8\n  mov 24(%rsi),%r9\n"
    "  call *%rbx\n"
    "  movq %xmm0,(%r12)\n"
    "  add $0xa0,%rsp\n  pop %r12\n  pop %rdi\n  pop %rsi\n  pop %rbx\n  pop %rbp\n  ret\n"
    ".seh_endproc\n");

static void log_native(rt_ctx *c, uint64_t fn, const uint64_t *a, uint64_t ret, uint64_t caller) {
    fprintf(rt_logf, "[%s] t%d %s(%#llx, %#llx, %#llx, %#llx) = %#llx   from %#llx %s\n",
            rt_logtag, c->tid, native_name(fn), (unsigned long long)a[0], (unsigned long long)a[1],
            (unsigned long long)a[2], (unsigned long long)a[3], (unsigned long long)ret,
            (unsigned long long)caller, rt_symstr(caller));
    if (rt_loglevel == 2 && rt_logf != stderr) fflush(rt_logf);   /* see rt_log */
}

/* guest register <-> CONTEXT field, and the guest's XMM registers */
static const struct { int guest; int host; } gpr_map[] = {
    {RREG_RAX, offsetof(CONTEXT, Rax)}, {RREG_RCX, offsetof(CONTEXT, Rcx)}, {RREG_RDX, offsetof(CONTEXT, Rdx)},
    {RREG_RBX, offsetof(CONTEXT, Rbx)}, {RREG_RBP, offsetof(CONTEXT, Rbp)}, {RREG_RSI, offsetof(CONTEXT, Rsi)},
    {RREG_RDI, offsetof(CONTEXT, Rdi)}, {RREG_R8, offsetof(CONTEXT, R8)},   {RREG_R9, offsetof(CONTEXT, R9)},
    {RREG_R10, offsetof(CONTEXT, R10)}, {RREG_R11, offsetof(CONTEXT, R11)}, {RREG_R12, offsetof(CONTEXT, R12)},
    {RREG_R13, offsetof(CONTEXT, R13)}, {RREG_R14, offsetof(CONTEXT, R14)}, {RREG_R15, offsetof(CONTEXT, R15)}};
static const int xmm_map[16] = {RREG_XMM0, RREG_XMM1, RREG_XMM2, RREG_XMM3, RREG_XMM4, RREG_XMM5, RREG_XMM6,
                                RREG_XMM7, RREG_XMM8, RREG_XMM9, RREG_XMM10, RREG_XMM11, RREG_XMM12,
                                RREG_XMM13, RREG_XMM14, RREG_XMM15};

#define SAVE_DEPTHS 256
static DWORD save_tls = TLS_OUT_OF_INDEXES;

int rt_platform_unknown_target(rt_ctx *c, uint64_t *pc) {
    uint64_t fn = *pc;
    if (rt_module_of(fn)) return 0;                   /* inside an image but not lifted */
    uint64_t sp = REG64(c, RREG_RSP);
    uint64_t ret = *(uint64_t *)(uintptr_t)sp;          /* guest pushed its return address */
    uint64_t args[20], xmm[4], x0 = 0;
    args[0] = REG64(c, RREG_RCX); args[1] = REG64(c, RREG_RDX);
    args[2] = REG64(c, RREG_R8);  args[3] = REG64(c, RREG_R9);
    /* exception machinery works on the guest stack: emulated, not called */
    int h = rt_seh_intercept(c, fn, args, ret, pc);
    if (h) return h > 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void *)(uintptr_t)fn, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT ||
        !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return 0;                                       /* not code at all: let the crash report explain */
    for (int i = 0; i < 16; i++) args[4 + i] = *(uint64_t *)(uintptr_t)(sp + 0x28 + 8 * i);
    xmm[0] = L(c->R + RREG_XMM0, 8); xmm[1] = L(c->R + RREG_XMM1, 8);
    xmm[2] = L(c->R + RREG_XMM2, 8); xmm[3] = L(c->R + RREG_XMM3, 8);
    uint64_t caller = c->cur;
    if ((FARPROC)(uintptr_t)fn == p_exit_process || (FARPROC)(uintptr_t)fn == p_terminate_process) {
        rt_log(1, "program exits with code %llu after %llu control transfers",
               (unsigned long long)args[(FARPROC)(uintptr_t)fn == p_terminate_process ? 1 : 0],
               (unsigned long long)c->n_transfers);
        fflush(NULL);
        rt_dump_memory(0, 0);
    }
    /* What the called code must leave alone (the registers a Windows function
     * preserves) and where this thread stands, so both can be put back: code
     * made at run time (Mono's JIT) handles a C# exception by jumping straight
     * back into one of its own frames further up - past any callbacks into the
     * program that were still running below it. Those never get to restore
     * the registers or the callback depth; this frame, which the jump returns
     * to in the end, does it for them. */
    static const int keep[] = {RREG_RBX, RREG_RBP, RREG_RSI, RREG_RDI, RREG_R12, RREG_R13, RREG_R14, RREG_R15};
    uint64_t keep_gpr[8];
    uint8_t keep_xmm[10][16];
    for (int i = 0; i < 8; i++) keep_gpr[i] = REG64(c, keep[i]);
    for (int i = 0; i < 10; i++) memcpy(keep_xmm[i], c->R + xmm_map[6 + i], 16);
    int depth0 = c->depth;
    void *seh0 = c->seh;
    c->depth++;
    uint64_t r = rt_native_call(fn, args, xmm, &x0);
    if (c->depth != depth0 + 1) {
        rt_log(2, "t%d native code %#llx came back past %d callback(s) that never returned "
               "(an exception handled by generated code)", c->tid, (unsigned long long)fn,
               c->depth - depth0 - 1);
        c->seh = seh0;
    }
    c->depth = depth0;
    for (int i = 0; i < 8; i++) REG64(c, keep[i]) = keep_gpr[i];
    for (int i = 0; i < 10; i++) memcpy(c->R + xmm_map[6 + i], keep_xmm[i], 16);
    if ((FARPROC)(uintptr_t)fn == p_get_proc_address && r)
        add_name(r, "GetProcAddress", (args[1] >> 16) ? (const char *)(uintptr_t)args[1] : "#ordinal");
    if (rt_loglevel >= 2) log_native(c, fn, args, r, caller);
    REG64(c, RREG_RAX) = r;
    memset(c->R + RREG_XMM0, 0, 16);
    memcpy(c->R + RREG_XMM0, &x0, 8);
    REG64(c, RREG_RSP) = sp + 8;                        /* pop the return address */
    *pc = ret;
    c->cur = caller;
    return 1;
}

/* ---- host -> guest: run recompiled code as if it were called natively ----
 * Every call pushes a run record; an exception unwind that ends in frames of
 * this run jumps back here (rt_seh.c) and the run continues from there.
 * cont: for calls made by the exception machinery, the guest context the
 * stack logically continues with above this call (see rt_seh.c). */
/* Callbacks that come from machine code made at run time (Mono's JIT) do not
 * keep to the Windows calling convention: helpers get their argument in RAX
 * or R10/R11 (stack probes, trampolines) and give results back in any
 * register. With `hx` (the caller's CPU state) every register goes into the
 * recompiled code and comes back out, as if the caller had called it directly. */
static uint64_t call_guest(rt_ctx *c, uint64_t fn, const uint64_t *args4, const uint64_t *stackargs,
                           int nstack, const uint64_t *xmm4, uint64_t *xmm0_out, const void *cont, CONTEXT *hx);

uint64_t rt_call_guest(rt_ctx *c, uint64_t fn, const uint64_t *args4, const uint64_t *stackargs,
                       int nstack, const uint64_t *xmm4, uint64_t *xmm0_out, const void *cont) {
    return call_guest(c, fn, args4, stackargs, nstack, xmm4, xmm0_out, cont, 0);
}

static uint64_t call_guest(rt_ctx *c, uint64_t fn, const uint64_t *args4, const uint64_t *stackargs,
                           int nstack, const uint64_t *xmm4, uint64_t *xmm0_out, const void *cont, CONTEXT *hx) {
    uint8_t *saved = 0;
    uint64_t saved_cur = c->cur;
    int saved_heap = 0;
    if (c->depth > 0) {
        /* one buffer per callback depth and thread, reused: a callback that
         * never returns (see rt_platform_unknown_target) leaks nothing */
        uint8_t **bufs = save_tls != TLS_OUT_OF_INDEXES ? TlsGetValue(save_tls) : 0;
        if (!bufs && save_tls != TLS_OUT_OF_INDEXES) { bufs = calloc(SAVE_DEPTHS, sizeof *bufs); TlsSetValue(save_tls, bufs); }
        if (bufs && c->depth < SAVE_DEPTHS) {
            if (!bufs[c->depth]) bufs[c->depth] = malloc(0x10000);
            saved = bufs[c->depth];
        } else { saved = malloc(0x10000); saved_heap = 1; }
        memcpy(saved, c->R, 0x10000);
    }
    uint64_t sp = c->depth > 0 ? REG64(c, RREG_RSP) - 0x200 : c->stack_hi - 0x100;
    sp -= 0x20 + 8 * (nstack > 16 ? nstack : 16);
    sp &= ~15ULL;
    sp -= 8;                                             /* (rsp+8) % 16 == 0 at function entry */
    *(uint64_t *)(uintptr_t)sp = RT_SENTINEL;
    for (int i = 0; i < nstack; i++) *(uint64_t *)(uintptr_t)(sp + 0x28 + 8 * i) = stackargs[i];
    REG64(c, RREG_RSP) = sp;
    REG64(c, RREG_RCX) = args4[0]; REG64(c, RREG_RDX) = args4[1];
    REG64(c, RREG_R8) = args4[2];  REG64(c, RREG_R9) = args4[3];
    if (xmm4) {
        memcpy(c->R + RREG_XMM0, &xmm4[0], 8); memcpy(c->R + RREG_XMM1, &xmm4[1], 8);
        memcpy(c->R + RREG_XMM2, &xmm4[2], 8); memcpy(c->R + RREG_XMM3, &xmm4[3], 8);
    }
    if (hx) {
        for (unsigned i = 0; i < sizeof gpr_map / sizeof gpr_map[0]; i++)
            memcpy(c->R + gpr_map[i].guest, (uint8_t *)hx + gpr_map[i].host, 8);
        for (int i = 0; i < 16; i++) memcpy(c->R + xmm_map[i], (uint8_t *)&hx->Xmm0 + 16 * i, 16);
    }
    c->depth++;
    rt_run_rec rr = {0};
    rr.prev = c->seh;
    rr.entry_sp = sp;
    rr.depth = c->depth;
    rr.cont = cont;
    rr.pc = fn;
    c->seh = &rr;
    if (__builtin_setjmp(rr.jb)) {
        /* an exception unwind ended in this run: rt_seh.c set the registers */
        c = rt_current_ctx();
        c->seh = &rr;
        c->depth = rr.depth;
    }
    rt_run(c, rr.pc, RT_SENTINEL);
    c->seh = rr.prev;
    c->depth--;
    uint64_t r = REG64(c, RREG_RAX);
    if (xmm0_out) memcpy(xmm0_out, c->R + RREG_XMM0, 8);
    if (hx) {
        for (unsigned i = 0; i < sizeof gpr_map / sizeof gpr_map[0]; i++)
            memcpy((uint8_t *)hx + gpr_map[i].host, c->R + gpr_map[i].guest, 8);
        for (int i = 0; i < 16; i++) memcpy((uint8_t *)&hx->Xmm0 + 16 * i, c->R + xmm_map[i], 16);
    }
    if (saved) { memcpy(c->R, saved, 0x10000); if (saved_heap) free(saved); }
    c->cur = saved_cur;
    return r;
}

static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    CONTEXT *x = ep->ContextRecord;
    uint64_t rip = x->Rip;
    /* host code jumped into original code (non-executable): a callback */
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2 &&
        er->ExceptionInformation[0] == 8 && rt_module_of(rip)) {
        rt_ctx *c = rt_win_ctx();
        if (!rt_lookup(c, rip)) {
            rt_crash(c, "Windows called into the program at an address with no recompiled code",
                     rip, "a callback/thread start points into the middle of an instruction or "
                     "into data; check listing.tsv around this address");
        }
        uint64_t a4[4] = {x->Rcx, x->Rdx, x->R8, x->R9}, st[16], xm[4], x0;
        /* stack arguments 5..20 - but only as far as the caller's stack is mapped
         * (a new thread starts at the very top of its stack) */
        memset(st, 0, sizeof st);
        MEMORY_BASIC_INFORMATION mbi;
        uint64_t from = x->Rsp + 0x28;
        if (VirtualQuery((void *)(uintptr_t)from, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT) {
            uint64_t end = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            int n = (int)((end - from) / 8);
            for (int i = 0; i < 16 && i < n; i++) st[i] = *(uint64_t *)(uintptr_t)(from + 8 * i);
        }
        for (int i = 0; i < 4; i++) memcpy(&xm[i], (uint8_t *)&x->Xmm0 + 16 * i, 8);
        if (rt_loglevel >= 2)
            fprintf(rt_logf, "[%s] t%d callback into %#llx %s (rcx=%#llx rdx=%#llx) depth %d\n",
                    rt_logtag, c->tid, (unsigned long long)rip, rt_symstr(rip), (unsigned long long)x->Rcx,
                    (unsigned long long)x->Rdx, c->depth);
        if (rt_loglevel == 2 && rt_logf != stderr) fflush(rt_logf);   /* see rt_log */
        uint64_t r = call_guest(c, rip, a4, st, 16, xm, &x0, 0, x);
        x->Rax = r;
        x->Rip = *(uint64_t *)(uintptr_t)x->Rsp;     /* return to the native caller */
        x->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* a CPU exception inside recompiled code: give the original program's
     * own exception handlers (__try/__except, catch(...)) a chance */
    rt_ctx *c = rt_current_ctx();
    if (c && c->depth > 0 && (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
              er->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO ||
              er->ExceptionCode == EXCEPTION_INT_OVERFLOW ||
              er->ExceptionCode == EXCEPTION_STACK_OVERFLOW ||
              er->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION ||
              er->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)) {
        HMODULE owner = 0;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)(uintptr_t)rip, &owner);
        rt_module *m = 0;
        for (int i = 0; i < rt_nmods; i++) if (rt_mods[i]->host == owner) m = rt_mods[i];
        if (m && !(rip >= m->lo && rip < m->hi))      /* in recompiled code of a rebuilt file */
            return rt_seh_cpu_fault(c, er, x, m->name);
    }
    /* the program's own vectored handlers (kept by the runtime, see rt_seh.c):
     * e.g. Mono turns an access violation in the code it generated into a
     * NullReferenceException here */
    {
        rt_ctx *gc = rt_current_ctx();    /* (a thread that never ran the program has none) */
        if (gc && rt_guest_veh(gc, ep) == EXCEPTION_CONTINUE_EXECUTION)
            return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* An error exception this runtime does not handle itself. Whoever handles
     * it (the program's own filter, Windows) may end the process without a
     * word, so leave a trace in the log first: what, where, and what the
     * thread was running. (Not C++ exceptions: those are ordinary.) */
    if (er->ExceptionCode >= 0xC0000000u && !(er->ExceptionFlags & 2)) {
        static volatile LONG shown;
        if (InterlockedIncrement(&shown) <= 40) {
            char mod[MAX_PATH] = "?";
            HMODULE owner = 0;
            uint64_t off = rip;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)(uintptr_t)rip, &owner) && owner) {
                char full[MAX_PATH];
                DWORD n = GetModuleFileNameA(owner, full, sizeof full);
                while (n && full[n - 1] != '\\' && full[n - 1] != '/') n--;
                snprintf(mod, sizeof mod, "%s", full + n);
                off = rip - (uint64_t)(uintptr_t)owner;
            }
            char what[160] = "";
            if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
                snprintf(what, sizeof what, " (%s address %#llx)",
                         er->ExceptionInformation[0] == 1 ? "writing" :
                         er->ExceptionInformation[0] == 8 ? "executing" : "reading",
                         (unsigned long long)er->ExceptionInformation[1]);
            else if (er->ExceptionCode == EXCEPTION_STACK_OVERFLOW)
                snprintf(what, sizeof what, " (stack overflow)");
            FILE *out = rt_logf ? rt_logf : stderr;
            fprintf(out, "[%s] EXCEPTION %#lx%s at %#llx = %s+%#llx", rt_logtag, er->ExceptionCode, what,
                    (unsigned long long)rip, mod, (unsigned long long)off);
            if (c) {
                /* inside a Windows function c->cur is 0: the last place the
                 * program itself was is the newest entry of the transfer ring */
                uint64_t at = c->cur;
                if (!at && c->ring_pos) at = c->ring[(c->ring_pos - 1) % RT_RING].from;
                fprintf(out, "; thread t%d was last in the program at %#llx %s (depth %d, %llu transfers)",
                        c->tid, (unsigned long long)at, rt_symstr(at), c->depth,
                        (unsigned long long)c->n_transfers);
            }
            fprintf(out, ". If nothing follows, the program ended here.\n");
            fflush(out);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- loading one module -------------------------------------------- */
static void load_module(rt_module *m) {
    if ((uint64_t)(uintptr_t)m->guest != m->imagebase) {
        char d[300];
        snprintf(d, sizeof d, "%s was loaded at %p instead of %#llx, so the original image is at "
                 "%p instead of %#llx. Something else already used that address range; every "
                 "rebuilt file of a game needs its own (`recomp.py game` assigns them)",
                 m->name, m->host, (unsigned long long)m->hostbase,
                 (void *)m->guest, (unsigned long long)m->imagebase);
        rt_crash(0, "the rebuilt file is not at its fixed address", m->imagebase, d);
    }
    for (int i = 0; i < m->nsegs; i++) {
        memcpy((void *)(uintptr_t)m->segs[i].vaddr, m->image + m->segs[i].off, m->segs[i].filesz);
        rt_log(1, "%s section %d: %#llx-%#llx (%llu bytes from file) %c%c%c", m->name, i,
               (unsigned long long)m->segs[i].vaddr, (unsigned long long)(m->segs[i].vaddr + m->segs[i].memsz),
               (unsigned long long)m->segs[i].filesz, m->segs[i].flags & 4 ? 'r' : '-',
               m->segs[i].flags & 2 ? 'w' : '-', m->segs[i].flags & 1 ? 'x' : '-');
    }
    uint8_t *b = (uint8_t *)(uintptr_t)m->imagebase;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY *dd = nt->OptionalHeader.DataDirectory;

    /* exception tables: the guest's own unwind info, used by rt_seh.c */
    if (dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress) {
        m->pdata = b + dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        m->npdata = dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION);
    }
    /* imports: other rebuilt DLLs load (and register) themselves here */
    if (dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR *id = (void *)(b + dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; id->Name; id++) {
            const char *dll = (const char *)(b + id->Name);
            HMODULE h = LoadLibraryA(dll);
            if (!h) {
                char d[300];
                snprintf(d, sizeof d, "%s: LoadLibrary(\"%s\") failed with error %lu: the DLL is missing "
                         "(copy it next to the program) or one of its own dependencies is", m->name, dll,
                         GetLastError());
                rt_crash(0, "a DLL the program needs could not be loaded", 0, d);
            }
            IMAGE_THUNK_DATA64 *ot = (void *)(b + (id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk));
            IMAGE_THUNK_DATA64 *ft = (void *)(b + id->FirstThunk);
            int n = 0;
            for (; ot->u1.AddressOfData; ot++, ft++, n++) {
                FARPROC f;
                char nm[64];
                if (IMAGE_SNAP_BY_ORDINAL64(ot->u1.Ordinal)) {
                    f = GetProcAddress(h, (LPCSTR)(uintptr_t)IMAGE_ORDINAL64(ot->u1.Ordinal));
                    snprintf(nm, sizeof nm, "#%llu", (unsigned long long)IMAGE_ORDINAL64(ot->u1.Ordinal));
                } else {
                    IMAGE_IMPORT_BY_NAME *ibn = (void *)(b + ot->u1.AddressOfData);
                    f = GetProcAddress(h, ibn->Name);
                    snprintf(nm, sizeof nm, "%s", ibn->Name);
                }
                if (!f) {
                    char d[300];
                    snprintf(d, sizeof d, "%s does not export %s (wrong DLL version?), needed by %s",
                             dll, nm, m->name);
                    rt_crash(0, "an imported function could not be found", 0, d);
                }
                ft->u1.Function = (uint64_t)(uintptr_t)f;
                add_name((uint64_t)(uintptr_t)f, dll, nm);
            }
            rt_log(1, "%s imports: %s (%d functions)", m->name, dll, n);
        }
    }
    /* static TLS (__declspec(thread)): this module's slot in the TLS array */
    if (dd[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
        IMAGE_TLS_DIRECTORY64 *td = (void *)(b + dd[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        m->tls_template = (void *)(uintptr_t)td->StartAddressOfRawData;
        m->tls_tsize = td->EndAddressOfRawData - td->StartAddressOfRawData;
        m->tls_zsize = td->SizeOfZeroFill;
        if (td->AddressOfIndex) *(uint32_t *)(uintptr_t)td->AddressOfIndex = m->index;
        rt_log(1, "%s static TLS: index %d, %llu bytes template + %llu zero fill", m->name, m->index,
               (unsigned long long)m->tls_tsize, (unsigned long long)m->tls_zsize);
    }
    EnterCriticalSection(&rt_cs);
    for (int i = 0; i < nthreads; i++) alloc_tls_block(threads[i], m);
    LeaveCriticalSection(&rt_cs);
}

static void runtime_init(void) {
    if (inited) return;
    inited = 1;
    rt_log_init();
    InitializeCriticalSection(&rt_cs);
    tls_slot = TlsAlloc();
    save_tls = TlsAlloc();
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    p_exit_process = GetProcAddress(k32, "ExitProcess");
    p_terminate_process = GetProcAddress(k32, "TerminateProcess");
    p_get_proc_address = GetProcAddress(k32, "GetProcAddress");
    rt_seh_init();
    AddVectoredExceptionHandler(1, veh);
}

/* ---- Mono games: C translated from C# (recomp cil2c) ----------------------
 * The translated methods are internal calls of the (patched) assemblies.
 * They must be registered right after the game has started Mono, before any
 * script runs: we hook the recompiled Mono runtime's mono_jit_init(_version)
 * and, when it returns, load recomp_cil.dll and call its cil_register_all(). */
static uint64_t guest_export(rt_module *m, const char *name) {
    uint8_t *b = (uint8_t *)(uintptr_t)m->imagebase;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY *ed = (void *)(b + dd->VirtualAddress);
    uint32_t *names = (void *)(b + ed->AddressOfNames), *funcs = (void *)(b + ed->AddressOfFunctions);
    uint16_t *ords = (void *)(b + ed->AddressOfNameOrdinals);
    for (uint32_t i = 0; i < ed->NumberOfNames; i++)
        if (!strcmp((char *)b + names[i], name)) return m->imagebase + funcs[ords[i]];
    return 0;
}

static void mono_started(rt_ctx *c) {
    static volatile LONG done;
    if (InterlockedExchange(&done, 1)) return;
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, sizeof path);
    while (n && path[n - 1] != '\\' && path[n - 1] != '/') n--;
    snprintf(path + n, sizeof path - n, "recomp_cil.dll");
    HMODULE h = LoadLibraryA(path);
    if (!h) {
        rt_log(0, "Mono started, but %s could not be loaded (error %lu): the C# code runs as IL "
               "only where the assemblies were not patched", path, GetLastError());
        return;
    }
    void (*reg)(void) = (void (*)(void))GetProcAddress(h, "cil_register_all");
    rt_log(1, "Mono started: registering the C translated from C# (%s)", path);
    if (reg) reg();
}

static void hook_mono(rt_module *m) {
    const char *n = m->name;
    if (_stricmp(n, "mono-2.0-bdwgc.dll") && _stricmp(n, "mono-2.0-sgen.dll") && _stricmp(n, "mono.dll") &&
        _stricmp(n, "mono-2.0.dll") && _stricmp(n, "mono-2.0-boehm.dll"))
        return;
    const char *fns[] = {"mono_jit_init_version", "mono_jit_init"};
    for (int i = 0; i < 2; i++) {
        uint64_t a = guest_export(m, fns[i]);
        if (a && rt_add_hook(a, mono_started))
            rt_log(1, "%s: C# -> C registration hooked on %s", n, fns[i]);
    }
}

static rt_ctx *register_module(rt_module *m, HMODULE host) {
    runtime_init();
    m->host = host;
    EnterCriticalSection(&rt_cs);
    rt_add_module(m);
    LeaveCriticalSection(&rt_cs);
    rt_log(1, "recompiled %s %s registered: ImageBase %#llx, entry %#llx %s, %llu lifted instructions",
           m->is_dll ? "DLL" : "program", m->name, (unsigned long long)m->imagebase,
           (unsigned long long)m->entry, rt_symstr(m->entry), (unsigned long long)m->naddr);
    load_module(m);
    hook_mono(m);
    return rt_win_ctx();
}

static void run_tls_callbacks(rt_ctx *c, rt_module *m, uint64_t reason) {
    for (int i = 0; i < m->ntls; i++) {
        uint64_t a[4] = {(uint64_t)(uintptr_t)m->host, reason, 0, 0};
        rt_log(1, "%s: TLS callback %#llx (reason %llu)", m->name, (unsigned long long)m->tls_callbacks[i],
               (unsigned long long)reason);
        rt_call_guest(c, m->tls_callbacks[i], a, 0, 0, 0, 0, 0);
    }
}

/* called by every rebuilt DLL's DllMain. The module handle given to the
 * original DllMain is the rebuilt file's, so FindResource / GetModuleFileName
 * on it work (resources were copied in). */
BOOL rt_module_dllmain(rt_module *m, HINSTANCE h, DWORD reason, LPVOID reserved) {
    rt_ctx *c;
    if (reason == DLL_PROCESS_ATTACH) {
        c = register_module(m, h);
    } else {
        c = rt_current_ctx();
        if (!c) {
            if (reason == DLL_THREAD_DETACH) return TRUE;   /* thread never ran our code */
            c = rt_win_thread_ctx();
        }
    }
    run_tls_callbacks(c, m, reason);
    uint64_t r = 1;
    if (m->entry) {
        uint64_t a[4] = {(uint64_t)(uintptr_t)h, reason, (uint64_t)(uintptr_t)reserved, 0};
        r = rt_call_guest(c, m->entry, a, 0, 0, 0, 0, 0);
        rt_log(1, "%s: original DllMain(reason %lu) returned %llu", m->name, reason, (unsigned long long)r);
    }
    if (reason == DLL_PROCESS_ATTACH && !(uint32_t)r)
        rt_log(0, "%s: the original DllMain failed, so loading the DLL fails", m->name);
    if (reason == DLL_PROCESS_DETACH && rt_logf && rt_logf != stderr) fflush(rt_logf);
    return (BOOL)(uint32_t)r;
}

/* called by a rebuilt exe's main() */
int rt_module_exemain(rt_module *m) {
    rt_ctx *c = register_module(m, GetModuleHandleA(0));
    uint64_t zero[4] = {0};
    run_tls_callbacks(c, m, DLL_PROCESS_ATTACH);
    rt_log(1, "starting the program at %#llx", (unsigned long long)m->entry);
    uint64_t r = rt_call_guest(c, m->entry, zero, 0, 0, 0, 0, 0);
    rt_log(1, "entry point returned %llu", (unsigned long long)r);
    fflush(NULL);
    rt_dump_memory(0, 0);
    ExitProcess((UINT)r);
}
