/* recomp runtime, Windows 32-bit x86 guests - built once as recomp_rt.dll
 * (a 32-bit DLL) and shared by every recompiled file of a program.
 *
 * A 32-bit program is rebuilt as a 32-bit program, so the DLLs it calls are
 * the real 32-bit system DLLs and a pointer of the program is a pointer of
 * the process. What differs from the x64 runtime (rt_win.c) is how control
 * moves between recompiled code and native code:
 *
 *  - TWO STACKS PER THREAD. The original program's stack is the thread's real
 *    stack: the recompiled code reads and writes it through its ESP register,
 *    and native code (system DLLs) runs directly on it. The runtime itself
 *    (the dispatch loop and the C functions of the recompiled code) runs on a
 *    separate private "host" stack. Nothing of the runtime is ever on the
 *    program's stack, so that stack looks exactly like in the original.
 *
 *  - CALLING NATIVE CODE (rt32_go_native): the 32-bit calling conventions
 *    (stdcall, cdecl, fastcall, thiscall, varargs) differ in who removes the
 *    arguments, and nothing says which one a function uses. So no arguments
 *    are copied: the runtime loads the program's registers into the CPU,
 *    switches ESP to the program's stack and jumps to the function. Whatever
 *    convention it has, it finds its arguments where the program put them and
 *    leaves ESP where the program expects it. The return address on the stack
 *    is replaced by a small stub that switches back to the host stack. There
 *    is one stub per return address of the program, and the stub alone says
 *    where the program continues. That matters for native functions that
 *    keep their return address and use it later: setjmp/longjmp, and Windows
 *    capturing a context and resuming it.
 *
 *  - NATIVE CODE CALLING THE PROGRAM (callbacks, thread starts, DllMain,
 *    exports of a rebuilt DLL, exception handlers): the original image is
 *    not executable, so the jump faults; the vectored exception handler takes
 *    the CPU registers as the program's registers and continues in the
 *    dispatch loop on the host stack. When the recompiled function returns to
 *    its native caller, that is "calling native code" again (a jump this time).
 *    Control never nests on the host stack: it is one flat loop per thread.
 *
 *  - EXCEPTIONS need no code here. 32-bit Windows exceptions are frame based:
 *    the program links handler records at fs:[0] on its own stack. Because the
 *    program uses the real TEB and its real stack, Windows' own dispatcher
 *    (RaiseException, RtlUnwind, _except_handler3/4, __CxxFrameHandler3,
 *    longjmp) walks and unwinds it natively. Its calls to the program's
 *    handlers are ordinary callbacks. A CPU fault in recompiled code (NULL
 *    pointer, division by zero) is turned into the same exception at the
 *    program's instruction by calling RtlRaiseException with the program's
 *    registers.
 *
 *  - x87: the host FPU is the guest FPU. Its control word (precision,
 *    rounding) is kept equal to the program's, and values on the FPU stack
 *    (float/double results in ST0) move across every transition.
 *
 *  - STATIC TLS (__declspec(thread)): the runtime keeps its own array of TLS
 *    blocks per thread; `mov reg, fs:[0x2C]` in the program reads that array
 *    (lift.py), and each module's _tls_index is its number in it.
 */
#define WIN32_LEAN_AND_MEAN
#include "rt_internal.h"
#include <windows.h>
#include <winternl.h>

#ifndef RT_GUEST32
#error "rt_win32.c is the runtime for 32-bit programs: build it with a 32-bit compiler (i686-w64-mingw32-gcc)"
#endif

#define HOST_STACK (2u << 20)       /* private stack of the runtime, per thread */
#define NEVER 0x7fffffff00000001ULL /* rt_run's "stop" address: the loop never ends */

/* per-thread switch area. The first part is used by the assembly below:
 * DO NOT reorder it without changing the offsets there. */
typedef struct rt32_thr {
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;   /*   0: the program's registers       */
    uint32_t pc;                /*  32: target (going out) / where native code entered the   */
                                /*      program (coming back)                                */
    uint32_t host_sp;           /*  36: host stack pointer while native code runs            */
    uint32_t nfp;               /*  40: x87 values to load before going native               */
    uint32_t eflags;            /*  44                                                       */
    uint8_t fp[8][16];          /*  48: those values, fp[0] = ST0                            */
    uint8_t fx[512];            /* 176: FXSAVE image taken when native code comes back       */
    /* ---- C only ---- */
    rt_ctx *c;
    uint8_t *host_lo, *host_top;
    int in_native;              /* 1 while this thread executes native code */
    uint32_t gpa_ret, gpa_name; /* a GetProcAddress call in progress (function names for the log) */
    uint32_t last_fn;           /* the native function called last (log) */
    EXCEPTION_RECORD rec[4]; unsigned nrec;   /* CPU faults being delivered to the program */
} rt32_thr;

void rt32_go_native(rt32_thr *t);
void rt32_ret_thunk(void);
void rt32_back(void);
void rt32_boot(void);
void rt32_fault_boot(void);
void rt32_boot_c(rt32_thr *t) __attribute__((noreturn, used));
void rt32_fault_c(rt32_thr *t) __attribute__((noreturn, used));
uint32_t rt32_teb_off __attribute__((used));    /* offset of our TLS slot inside the TEB */

__asm__(
    ".text\n"
    /* ---- host -> native: load the program's registers and jump --------- */
    ".globl _rt32_go_native\n"
    "_rt32_go_native:\n"
    "  pushl %ebp\n  pushl %ebx\n  pushl %esi\n  pushl %edi\n"
    "  movl 20(%esp), %eax\n"                 /* t */
    "  movl %esp, 36(%eax)\n"                 /* host_sp */
    "  movl 40(%eax), %ecx\n"                 /* x87 values, deepest first */
    "1: testl %ecx, %ecx\n  jz 2f\n"
    "  decl %ecx\n  movl %ecx, %edx\n  shll $4, %edx\n"
    "  fldt 48(%eax,%edx)\n  jmp 1b\n"
    "2: cld\n"
    "  movl 16(%eax), %esp\n"                 /* the program's stack */
    "  pushl 32(%eax)\n"                      /* target (below ESP: free stack) */
    "  movl 4(%eax), %ecx\n  movl 8(%eax), %edx\n  movl 12(%eax), %ebx\n"
    "  movl 20(%eax), %ebp\n  movl 24(%eax), %esi\n  movl 28(%eax), %edi\n"
    "  movl 0(%eax), %eax\n"
    "  ret\n"                                 /* = jmp target, ESP = the program's ESP */
    /* ---- native function returned to the program: every return stub does
     *      push <the program's return address>; jmp here ------------------- */
    ".globl _rt32_ret_thunk\n"
    "_rt32_ret_thunk:\n"
    "  pushl %ecx\n"
    "  movl _rt32_teb_off, %ecx\n"
    "  movl %fs:(%ecx), %ecx\n"               /* rt32_thr of this thread */
    "  movl %eax, 0(%ecx)\n"
    "  popl %eax\n  movl %eax, 4(%ecx)\n"    /* ecx */
    "  popl %eax\n  movl %eax, 32(%ecx)\n"   /* pc = the return address the stub pushed */
    "  movl %edx, 8(%ecx)\n  movl %ebx, 12(%ecx)\n  movl %esp, 16(%ecx)\n"
    "  movl %ebp, 20(%ecx)\n  movl %esi, 24(%ecx)\n  movl %edi, 28(%ecx)\n"
    "  movl 36(%ecx), %esp\n"
    /* ---- back on the host stack: finish rt32_go_native ------------------ */
    ".globl _rt32_back\n"
    "_rt32_back:\n"
    "  movl 20(%esp), %eax\n"
    "  fxsave 176(%eax)\n"                    /* FPU stack + control words as native code left them */
    "  fninit\n  fldcw 176(%eax)\n  cld\n"
    "  popl %edi\n  popl %esi\n  popl %ebx\n  popl %ebp\n"
    "  ret\n"
    /* ---- a thread's first entry into the program (ESP = top of a new host stack) */
    ".globl _rt32_boot\n"
    "_rt32_boot:\n"
    "  movl _rt32_teb_off, %eax\n"
    "  movl %fs:(%eax), %eax\n"
    "  fxsave 176(%eax)\n"
    "  fninit\n  fldcw 176(%eax)\n  cld\n"
    "  subl $12, %esp\n  pushl %eax\n"
    "  call _rt32_boot_c\n  int3\n"
    /* ---- after a CPU fault in recompiled code (ESP = top of the host stack) */
    ".globl _rt32_fault_boot\n"
    "_rt32_fault_boot:\n"
    "  movl _rt32_teb_off, %eax\n"
    "  movl %fs:(%eax), %eax\n"
    "  fninit\n  cld\n"
    "  subl $12, %esp\n  pushl %eax\n"
    "  call _rt32_fault_c\n  int3\n");

static DWORD tls_slot = TLS_OUT_OF_INDEXES;
static FARPROC p_exit_process, p_get_proc_address, p_terminate_process, p_raise;
static CRITICAL_SECTION rt_cs;            /* modules, thread list, names */
static int inited;

static inline rt32_thr *cur_thr(void) {
    return *(rt32_thr **)((uint8_t *)NtCurrentTeb() + rt32_teb_off);
}
/* (not TlsGetValue: that one clears the thread's last-error value, which the
 * program is about to read with GetLastError) */
rt_ctx *rt_current_ctx(void) {
    if (!inited) return 0;
    rt32_thr *t = cur_thr();
    return t ? t->c : 0;
}

/* ---- names of native functions, for logs ---- */
typedef struct { uint32_t addr; char name[96]; } natname;
static natname *names; static int nnames, cap_names;

static void add_name(uint32_t a, const char *dll, const char *fn) {
    EnterCriticalSection(&rt_cs);
    if (nnames == cap_names) { cap_names = cap_names ? cap_names * 2 : 256; names = realloc(names, cap_names * sizeof *names); }
    names[nnames].addr = a;
    snprintf(names[nnames].name, sizeof names[nnames].name, "%s!%s", dll, fn);
    nnames++;
    LeaveCriticalSection(&rt_cs);
}
static const char *native_name(uint32_t a) {
    for (int i = 0; i < nnames; i++) if (names[i].addr == a) return names[i].name;
    return "?";
}

/* ---- threads -------------------------------------------------------- */
static rt32_thr **threads; static int nthreads, cap_threads;

static void alloc_tls_block(rt_ctx *c, rt_module *m) {
    if (!m->tls_template && !m->tls_zsize) return;
    uint32_t *arr = (uint32_t *)c->tls_array;
    if (arr[m->index]) return;
    uint8_t *blk = calloc(1, m->tls_tsize + m->tls_zsize + 16);
    if (m->tls_template) memcpy(blk, m->tls_template, m->tls_tsize);
    arr[m->index] = (uint32_t)(uintptr_t)blk;
}

static void x87_all_empty(rt_ctx *c) {
    for (int i = 0; i < 8; i++) memcpy(c->R + RREG_ST0 + (RREG_ST1 - RREG_ST0) * i, RT_X87_EMPTY, 10);
}

/* the host FPU follows the program's control words */
void rt_fpsync(rt_ctx *c) {
    uint16_t cw; uint32_t mx;
    memcpy(&cw, c->R + RREG_FPUControlWord, 2);
    memcpy(&mx, c->R + RREG_MXCSR, 4);
    mx &= 0xffff;                           /* reserved bits would fault */
    __asm__ volatile("fldcw %0" : : "m"(cw));
    __asm__ volatile("ldmxcsr %0" : : "m"(mx));
}

static rt32_thr *new_thr(void) {
    rt32_thr *t = VirtualAlloc(0, sizeof *t, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    rt_ctx *c = rt_new_ctx(0);              /* no guest stack: the thread's own is used */
    uint8_t *teb = (uint8_t *)NtCurrentTeb();
    if (!t) { fprintf(stderr, "[recomp] out of memory for a thread\n"); ExitProcess(127); }
    t->c = c;
    c->thr = t;
    c->depth = 1;
    t->host_lo = VirtualAlloc(0, HOST_STACK, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!t->host_lo) { fprintf(stderr, "[recomp] out of memory for a host stack\n"); ExitProcess(127); }
    t->host_top = t->host_lo + HOST_STACK;
    c->stack_hi = *(uint32_t *)(teb + 4);                   /* NT_TIB.StackBase */
    c->stack_lo = *(uint32_t *)(teb + 0xE0C);               /* TEB.DeallocationStack */
    if (!c->stack_lo || c->stack_lo > c->stack_hi) c->stack_lo = *(uint32_t *)(teb + 8);
    REGP(c, RREG_FS_OFFSET) = (uint32_t)(uintptr_t)teb;     /* the real TEB */
    c->tls_array = calloc(RT_MAX_MODULES, 4);
    c->platform = teb;
    x87_all_empty(c);
    {   /* the thread's FPU settings as they are now */
        uint16_t cw; uint32_t mx;
        __asm__ volatile("fnstcw %0" : "=m"(cw));
        __asm__ volatile("stmxcsr %0" : "=m"(mx));
        memcpy(c->R + RREG_FPUControlWord, &cw, 2);
        memcpy(c->R + RREG_MXCSR, &mx, 4);
    }
    *(rt32_thr **)(teb + rt32_teb_off) = t;
    EnterCriticalSection(&rt_cs);
    for (int i = 0; i < rt_nmods; i++) alloc_tls_block(c, rt_mods[i]);
    if (nthreads == cap_threads) { cap_threads = cap_threads ? 2 * cap_threads : 16; threads = realloc(threads, cap_threads * sizeof *threads); }
    threads[nthreads++] = t;
    LeaveCriticalSection(&rt_cs);
    rt_log(1, "t%d: new guest thread context, stack %#llx-%#llx, TEB %p, host stack %p-%p", c->tid,
           (unsigned long long)c->stack_lo, (unsigned long long)c->stack_hi, teb, t->host_lo, t->host_top);
    return t;
}

void rt_platform_syscall(rt_ctx *c) {
    rt_crash(c, "SYSCALL/SYSENTER instruction in a Windows program", c->cur,
             "Windows programs call the kernel through ntdll.dll, never directly. A raw "
             "syscall here means anti-tamper/anti-debug code or hand-written stubs");
}

/* ---- is this address native code? (cached per page) ---- */
#define XCACHE 1024
static volatile uint32_t xcache[XCACHE];

static int is_exec(uint32_t a) {
    uint32_t page = a >> 12, h = (page ^ (page >> 10)) & (XCACHE - 1);
    if (a < 0x10000) return 0;
    if (xcache[h] == page) return 1;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void *)(uintptr_t)a, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT ||
        !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return 0;
    xcache[h] = page;
    return 1;
}

/* registers: program <-> switch area */
static void regs_out(rt_ctx *c, rt32_thr *t) {
    t->eax = REGP(c, RREG_RAX); t->ecx = REGP(c, RREG_RCX); t->edx = REGP(c, RREG_RDX);
    t->ebx = REGP(c, RREG_RBX); t->esp = REGP(c, RREG_RSP); t->ebp = REGP(c, RREG_RBP);
    t->esi = REGP(c, RREG_RSI); t->edi = REGP(c, RREG_RDI);
    /* x87 values the program has on its FPU stack (a float result it returns) */
    const uint8_t *st = c->R + RREG_ST0;
    const int stride = RREG_ST1 - RREG_ST0;
    int n = 0;
    while (n < 8 && memcmp(st + stride * n, RT_X87_EMPTY, 10)) n++;
    for (int i = 0; i < n; i++) memcpy(t->fp[i], st + stride * i, 10);
    t->nfp = n;
}

static void regs_in(rt_ctx *c, rt32_thr *t) {
    REGP(c, RREG_RAX) = t->eax; REGP(c, RREG_RCX) = t->ecx; REGP(c, RREG_RDX) = t->edx;
    REGP(c, RREG_RBX) = t->ebx; REGP(c, RREG_RSP) = t->esp; REGP(c, RREG_RBP) = t->ebp;
    REGP(c, RREG_RSI) = t->esi; REGP(c, RREG_RDI) = t->edi;
    c->R[RREG_DF] = 0;
    /* FXSAVE image: control word at 0, status at 2 (TOP in bits 11-13), one tag
     * bit per physical register at 4, MXCSR at 24, ST0.. at 32 */
    uint16_t fsw; memcpy(&fsw, t->fx + 2, 2);
    int top = (fsw >> 11) & 7, n = 0;
    while (n < 8 && ((t->fx[4] >> ((top + n) & 7)) & 1)) n++;
    uint8_t *st = c->R + RREG_ST0;
    const int stride = RREG_ST1 - RREG_ST0;
    for (int i = 0; i < 8; i++)
        memcpy(st + stride * i, i < n ? (const void *)(t->fx + 32 + 16 * i) : (const void *)RT_X87_EMPTY, 10);
    memcpy(c->R + RREG_FPUControlWord, t->fx, 2);
    memcpy(c->R + RREG_MXCSR, t->fx + 24, 4);
}

/* ---- return stubs ------------------------------------------------------
 * stub_for(R) = address of   push R; jmp rt32_ret_thunk   for the program's
 * return address R. Made on first use, never freed; found without a lock. */
typedef struct { volatile uint32_t ret; uint8_t *volatile stub; } stub_ent;
typedef struct { uint32_t mask, shift; stub_ent e[1]; } stub_tab;
static stub_tab *volatile stubs;
static uint32_t stub_count;
static uint8_t *stub_mem; static uint32_t stub_left;

static stub_tab *stub_tab_new(uint32_t bits) {
    stub_tab *t = calloc(1, sizeof *t + sizeof(stub_ent) * ((size_t)1 << bits));
    if (!t) { fprintf(stderr, "[recomp] out of memory for return stubs\n"); ExitProcess(127); }
    t->mask = (1u << bits) - 1;
    t->shift = 32 - bits;
    return t;
}
static void stub_put(stub_tab *t, uint32_t ret, uint8_t *stub) {
    uint32_t h = (ret * 2654435761u) >> t->shift;
    while (t->e[h].ret) h = (h + 1) & t->mask;
    t->e[h].stub = stub;            /* the stub first: a reader matches on ret */
    t->e[h].ret = ret;
}
static uint8_t *stub_for(uint32_t ret) {
    stub_tab *t = stubs;
    for (uint32_t h = (ret * 2654435761u) >> t->shift; t->e[h].ret; h = (h + 1) & t->mask)
        if (t->e[h].ret == ret) return t->e[h].stub;
    EnterCriticalSection(&rt_cs);
    t = stubs;
    for (uint32_t h = (ret * 2654435761u) >> t->shift; t->e[h].ret; h = (h + 1) & t->mask)
        if (t->e[h].ret == ret) { LeaveCriticalSection(&rt_cs); return t->e[h].stub; }
    if (stub_left < 16) {
        stub_mem = VirtualAlloc(0, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!stub_mem) { fprintf(stderr, "[recomp] out of memory for return stubs\n"); ExitProcess(127); }
        stub_left = 0x10000;
    }
    uint8_t *s = stub_mem;
    stub_mem += 16; stub_left -= 16;
    s[0] = 0x68; memcpy(s + 1, &ret, 4);                                /* push imm32 */
    uint32_t rel = (uint32_t)(uintptr_t)rt32_ret_thunk - ((uint32_t)(uintptr_t)s + 10);
    s[5] = 0xE9; memcpy(s + 6, &rel, 4);                                /* jmp rel32 */
    if (++stub_count * 2 > t->mask) {       /* grow: readers keep using the old table until it is swapped */
        stub_tab *n = stub_tab_new(33 - t->shift);
        for (uint32_t i = 0; i <= t->mask; i++) if (t->e[i].ret) stub_put(n, t->e[i].ret, t->e[i].stub);
        stub_put(n, ret, s);
        stubs = n;                          /* (the old table is left allocated: a reader may be in it) */
    } else {
        stub_put(t, ret, s);
    }
    LeaveCriticalSection(&rt_cs);
    return s;
}

/* native code gave control back to the program (a function returned through
 * its stub, or native code called / returned into the image): where to? */
static uint64_t came_back(rt_ctx *c, rt32_thr *t) {
    regs_in(c, t);
    if (t->gpa_ret) {
        if (t->pc == t->gpa_ret && t->eax)
            add_name(t->eax, "GetProcAddress", (t->gpa_name >> 16) ? (const char *)(uintptr_t)t->gpa_name : "#ordinal");
        t->gpa_ret = 0;
    }
    if (rt_loglevel >= 2)
        fprintf(rt_logf, "[%s] t%d   native code -> %#x %s (eax=%#x esp=%#x, last call %s)\n",
                rt_logtag, c->tid, t->pc, rt_symstr(t->pc), t->eax, t->esp, native_name(t->last_fn));
    return t->pc;
}

int rt_platform_unknown_target(rt_ctx *c, uint64_t *pc) {
    uint32_t fn = (uint32_t)*pc;
    if (rt_module_of(fn)) return 0;                     /* inside an image but not lifted */
    if (!is_exec(fn)) return 0;                         /* not code at all: let the crash report explain */
    rt32_thr *t = c->thr;
    uint32_t sp = REGP(c, RREG_RSP);
    if (!c->xret) {
        /* a CALL (or the JMP of an import thunk): [esp] is the return address.
         * If it is in recompiled code, the function returns through the thunk
         * instead of faulting on the non-executable image. */
        uint32_t ra = *(uint32_t *)(uintptr_t)sp;
        const uint32_t *a = (const uint32_t *)(uintptr_t)(sp + 4);
        if ((FARPROC)(uintptr_t)fn == p_exit_process || (FARPROC)(uintptr_t)fn == p_terminate_process) {
            rt_log(1, "program exits with code %u after %llu control transfers",
                   a[(FARPROC)(uintptr_t)fn == p_terminate_process ? 1 : 0], (unsigned long long)c->n_transfers);
            fflush(NULL);
            rt_dump_memory(0, 0);
        }
        if (rt_loglevel >= 2)
            fprintf(rt_logf, "[%s] t%d %s(%#x, %#x, %#x, %#x)   from %#llx %s\n", rt_logtag, c->tid,
                    native_name(fn), a[0], a[1], a[2], a[3], (unsigned long long)c->cur, rt_symstr(c->cur));
        t->last_fn = fn;
        if (rt_module_of(ra)) {
            if ((FARPROC)(uintptr_t)fn == p_get_proc_address) { t->gpa_ret = ra; t->gpa_name = a[1]; }
            *(uint32_t *)(uintptr_t)sp = (uint32_t)(uintptr_t)stub_for(ra);
        }
    } else if (rt_loglevel >= 2) {
        fprintf(rt_logf, "[%s] t%d the program returns to native code at %#x (eax=%#x)\n", rt_logtag,
                c->tid, fn, (uint32_t)REGP(c, RREG_RAX));
    }
    uint64_t caller = c->cur;
    regs_out(c, t);
    t->pc = fn;
    t->in_native = 1;
    rt32_go_native(t);
    t->in_native = 0;
    *pc = came_back(c, t);
    c->cur = caller;
    return 1;
}

/* the flat dispatch loop of a thread: never returns */
static void host_loop(rt_ctx *c, uint64_t pc) __attribute__((noreturn));
static void host_loop(rt_ctx *c, uint64_t pc) {
    for (;;) rt_run(c, pc, NEVER);
}

/* first entry of a thread into the program (from rt32_boot, on the new host stack) */
void rt32_boot_c(rt32_thr *t) {
    t->in_native = 0;
    host_loop(t->c, came_back(t->c, t));
}

/* a CPU fault in recompiled code becomes the program's exception: call
 * RtlRaiseException(record) as the program, "from" the faulting instruction.
 * Windows captures the program's registers there and dispatches to the
 * handlers on the program's stack; an unwinding handler never comes back, a
 * handler that says "continue" resumes at that instruction. */
void rt32_fault_c(rt32_thr *t) {
    rt_ctx *c = t->c;
    rt_fpsync(c);
    if (c->lock_depth > 0) { c->lock_depth = 1; rt_unlock(); }   /* fault inside a LOCKed instruction */
    EXCEPTION_RECORD *r = &t->rec[(t->nrec - 1) & 3];
    r->ExceptionAddress = (void *)(uintptr_t)(uint32_t)c->cur;
    r->ExceptionRecord = 0;
    uint32_t sp = REGP(c, RREG_RSP) - 8;
    ((uint32_t *)(uintptr_t)sp)[0] = (uint32_t)c->cur;            /* "return address": the instruction */
    ((uint32_t *)(uintptr_t)sp)[1] = (uint32_t)(uintptr_t)r;
    REGP(c, RREG_RSP) = sp;
    rt_log(1, "t%d: CPU exception %#lx at %#llx %s (address %#lx): raised as the program's exception",
           c->tid, r->ExceptionCode, (unsigned long long)c->cur, rt_symstr(c->cur),
           r->NumberParameters >= 2 ? (unsigned long)r->ExceptionInformation[1] : 0ul);
    /* RETFLAG: a plain jump - the return address stays the program's own */
    host_loop(c, (uint64_t)(uintptr_t)p_raise | RT_RETFLAG);
}

static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    CONTEXT *x = ep->ContextRecord;
    DWORD code = er->ExceptionCode;
    rt32_thr *t = cur_thr();
    /* native code jumped into the original image (not executable): a callback,
     * a thread start, or a return into the program */
    /* (not: a CPU fault of recompiled code that rt32_fault_c is raising as the
     * program's exception - its context has a guest EIP too, but the address
     * it faulted on is data) */
    if (t && er >= t->rec && er < t->rec + 4) return EXCEPTION_CONTINUE_SEARCH;
    if (code == EXCEPTION_ACCESS_VIOLATION && rt_module_of(x->Eip) &&
        (er->NumberParameters < 2 || er->ExceptionInformation[1] == x->Eip)) {
        if (t && !t->in_native)
            rt_crash(t->c, "the runtime itself jumped into the original image", x->Eip,
                     "host code must never execute guest addresses directly: bug in rt_win32.c");
        int fresh = !t;
        if (fresh) t = new_thr();
        t->eax = x->Eax; t->ecx = x->Ecx; t->edx = x->Edx; t->ebx = x->Ebx;
        t->esp = x->Esp; t->ebp = x->Ebp; t->esi = x->Esi; t->edi = x->Edi;
        t->eflags = x->EFlags;
        t->pc = x->Eip;
        if (fresh || !t->host_sp) {
            x->Esp = (DWORD)(uintptr_t)(t->host_top - 64);
            x->Eip = (DWORD)(uintptr_t)rt32_boot;
        } else {
            x->Esp = t->host_sp;                    /* into the waiting rt32_go_native */
            x->Eip = (DWORD)(uintptr_t)rt32_back;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* a CPU exception while recompiled code runs: the program's own exception */
    if (t && !t->in_native &&
        (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_INT_DIVIDE_BY_ZERO ||
         code == EXCEPTION_INT_OVERFLOW || code == EXCEPTION_ILLEGAL_INSTRUCTION ||
         code == EXCEPTION_PRIV_INSTRUCTION || code == EXCEPTION_IN_PAGE_ERROR ||
         code == EXCEPTION_GUARD_PAGE || code == EXCEPTION_DATATYPE_MISALIGNMENT ||
         code == EXCEPTION_FLT_DIVIDE_BY_ZERO || code == EXCEPTION_FLT_INVALID_OPERATION ||
         code == EXCEPTION_FLT_OVERFLOW || code == EXCEPTION_FLT_UNDERFLOW ||
         code == EXCEPTION_FLT_INEXACT_RESULT || code == EXCEPTION_FLT_DENORMAL_OPERAND ||
         code == EXCEPTION_FLT_STACK_CHECK)) {
        uint32_t ip = x->Eip;
        if (ip >= (uint32_t)(uintptr_t)t->host_lo && ip < (uint32_t)(uintptr_t)t->host_top)
            return EXCEPTION_CONTINUE_SEARCH;       /* (never: the host stack is not code) */
        /* which instruction of the program it was: every instruction that can
         * fault stores its address in ctx->cur first (lift.py) */
        t->rec[t->nrec++ & 3] = *er;
        x->Esp = (DWORD)(uintptr_t)(t->host_top - 64);
        x->Eip = (DWORD)(uintptr_t)rt32_fault_boot;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* no handler of the program took an exception: crash report, then end the
 * process with the exception code (what Windows does for the original) */
static LONG WINAPI unhandled(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    rt32_thr *t = inited ? cur_thr() : 0;
    char d[400];
    DWORD code = er->ExceptionCode;
    const char *what = code == EXCEPTION_ACCESS_VIOLATION ?
                           (er->NumberParameters && er->ExceptionInformation[0] == 1 ? "write to invalid memory"
                            : er->NumberParameters && er->ExceptionInformation[0] == 8 ? "jump to invalid memory"
                            : "read from invalid memory")
                     : code == EXCEPTION_INT_DIVIDE_BY_ZERO ? "integer divide by zero"
                     : code == EXCEPTION_STACK_OVERFLOW ? "stack overflow"
                     : code == EXCEPTION_ILLEGAL_INSTRUCTION ? "illegal instruction"
                     : code == 0xE06D7363 ? "C++ exception that nothing caught"
                     : "exception";
    snprintf(d, sizeof d, "%s (exception code %#lx at %p) and no exception handler of the program took it. "
             "If the original program does not crash here, an earlier instruction computed a wrong "
             "value: look at the registers and transfers", what, code, er->ExceptionAddress);
    rt_crash_exit_code = (int)code;
    if (t) {
        /* the report shows the program as it was when the exception happened,
         * not as it is now (inside the exception filters) */
        CONTEXT *x = ep->ContextRecord;
        rt_ctx *c = t->c;
        REGP(c, RREG_RAX) = x->Eax; REGP(c, RREG_RCX) = x->Ecx; REGP(c, RREG_RDX) = x->Edx;
        REGP(c, RREG_RBX) = x->Ebx; REGP(c, RREG_RSP) = x->Esp; REGP(c, RREG_RBP) = x->Ebp;
        REGP(c, RREG_RSI) = x->Esi; REGP(c, RREG_RDI) = x->Edi;
        if (rt_module_of((uint32_t)(uintptr_t)er->ExceptionAddress))
            c->cur = (uint32_t)(uintptr_t)er->ExceptionAddress;
    }
    rt_crash(t ? t->c : 0, "unhandled exception in the recompiled program",
             er->NumberParameters >= 2 ? er->ExceptionInformation[1] : (uintptr_t)er->ExceptionAddress, d);
    return EXCEPTION_EXECUTE_HANDLER;
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
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY *dd = nt->OptionalHeader.DataDirectory;

    /* imports: other rebuilt DLLs load (and register) themselves here */
    if (dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR *id = (void *)(b + dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; id->Name; id++) {
            const char *dll = (const char *)(b + id->Name);
            HMODULE h = LoadLibraryA(dll);
            if (!h) {
                char d[300];
                snprintf(d, sizeof d, "%s: LoadLibrary(\"%s\") failed with error %lu: the DLL is missing "
                         "(copy it next to the program), is a 64-bit DLL, or one of its own dependencies "
                         "is missing", m->name, dll, GetLastError());
                rt_crash(0, "a DLL the program needs could not be loaded", 0, d);
            }
            IMAGE_THUNK_DATA32 *ot = (void *)(b + (id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk));
            IMAGE_THUNK_DATA32 *ft = (void *)(b + id->FirstThunk);
            int n = 0;
            for (; ot->u1.AddressOfData; ot++, ft++, n++) {
                FARPROC f;
                char nm[64];
                if (IMAGE_SNAP_BY_ORDINAL32(ot->u1.Ordinal)) {
                    f = GetProcAddress(h, (LPCSTR)(uintptr_t)IMAGE_ORDINAL32(ot->u1.Ordinal));
                    snprintf(nm, sizeof nm, "#%lu", (unsigned long)IMAGE_ORDINAL32(ot->u1.Ordinal));
                } else {
                    IMAGE_IMPORT_BY_NAME *ibn = (void *)(b + ot->u1.AddressOfData);
                    f = GetProcAddress(h, (const char *)ibn->Name);
                    snprintf(nm, sizeof nm, "%s", (const char *)ibn->Name);
                }
                if (!f) {
                    char d[300];
                    snprintf(d, sizeof d, "%s does not export %s (wrong DLL version?), needed by %s",
                             dll, nm, m->name);
                    rt_crash(0, "an imported function could not be found", 0, d);
                }
                ft->u1.Function = (uint32_t)(uintptr_t)f;
                add_name((uint32_t)(uintptr_t)f, dll, nm);
            }
            rt_log(1, "%s imports: %s (%d functions)", m->name, dll, n);
        }
    }
    /* static TLS (__declspec(thread)): this module's slot in the runtime's TLS array */
    if (dd[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
        IMAGE_TLS_DIRECTORY32 *td = (void *)(b + dd[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        m->tls_template = (void *)(uintptr_t)td->StartAddressOfRawData;
        m->tls_tsize = td->EndAddressOfRawData - td->StartAddressOfRawData;
        m->tls_zsize = td->SizeOfZeroFill;
        if (td->AddressOfIndex) *(uint32_t *)(uintptr_t)td->AddressOfIndex = m->index;
        rt_log(1, "%s static TLS: index %d, %llu bytes template + %llu zero fill", m->name, m->index,
               (unsigned long long)m->tls_tsize, (unsigned long long)m->tls_zsize);
    }
    EnterCriticalSection(&rt_cs);
    for (int i = 0; i < nthreads; i++) alloc_tls_block(threads[i]->c, m);
    LeaveCriticalSection(&rt_cs);
}

static void runtime_init(void) {
    if (inited) return;
    rt_log_init();
    InitializeCriticalSection(&rt_cs);
    tls_slot = TlsAlloc();
    if (tls_slot >= 64) {
        fprintf(stderr, "[recomp] no free TLS slot below 64 (got %lu): recomp_rt.dll must be loaded "
                "early in the process\n", tls_slot);
        ExitProcess(127);
    }
    rt32_teb_off = 0xE10 + 4 * tls_slot;        /* TEB.TlsSlots[tls_slot] */
    stubs = stub_tab_new(12);
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    p_exit_process = GetProcAddress(k32, "ExitProcess");
    p_terminate_process = GetProcAddress(k32, "TerminateProcess");
    p_get_proc_address = GetProcAddress(k32, "GetProcAddress");
    p_raise = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlRaiseException");
    /* the original code must fault when native code jumps to it: needs DEP.
     * The rebuilt exe is linked NX-compatible; this covers a rebuilt DLL in a
     * program that is not (fails harmlessly if DEP is already permanent). */
    {
        BOOL (WINAPI *setdep)(DWORD) = (void *)GetProcAddress(k32, "SetProcessDEPPolicy");
        if (setdep) setdep(1 /* PROCESS_DEP_ENABLE */);
    }
    inited = 1;
    AddVectoredExceptionHandler(1, veh);
    SetUnhandledExceptionFilter(unhandled);
}

static void register_module(rt_module *m, HMODULE host) {
    runtime_init();
    m->host = host;
    EnterCriticalSection(&rt_cs);
    rt_add_module(m);
    LeaveCriticalSection(&rt_cs);
    rt_log(1, "recompiled %s %s registered: ImageBase %#llx, entry %#llx %s, %llu lifted instructions",
           m->is_dll ? "DLL" : "program", m->name, (unsigned long long)m->imagebase,
           (unsigned long long)m->entry, rt_symstr(m->entry), (unsigned long long)m->naddr);
    load_module(m);
}

/* The functions below run as NATIVE code on the thread's real stack (they are
 * called by Windows' loader / the rebuilt file's start-up code). Calling a
 * function of the program from here is simply a call through its address:
 * it faults on the non-executable image and the handler above takes over. */
typedef void (WINAPI *tls_cb_t)(void *, DWORD, void *);
typedef BOOL (WINAPI *dllmain_t)(HINSTANCE, DWORD, LPVOID);

static void run_tls_callbacks(rt_module *m, DWORD reason) {
    for (int i = 0; i < m->ntls; i++) {
        rt_log(1, "%s: TLS callback %#llx (reason %lu)", m->name, (unsigned long long)m->tls_callbacks[i], reason);
        ((tls_cb_t)(uintptr_t)m->tls_callbacks[i])(m->host, reason, 0);
    }
}

/* called by every rebuilt DLL's DllMain. The module handle given to the
 * original DllMain is the rebuilt file's, so FindResource / GetModuleFileName
 * on it work (resources were copied in). */
BOOL rt_module_dllmain(rt_module *m, HINSTANCE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) register_module(m, h);
    else if (reason == DLL_THREAD_DETACH && !cur_thr()) return TRUE;   /* thread never ran our code */
    run_tls_callbacks(m, reason);
    BOOL r = TRUE;
    if (m->entry) {
        r = ((dllmain_t)(uintptr_t)m->entry)(h, reason, reserved);
        rt_log(1, "%s: original DllMain(reason %lu) returned %d", m->name, reason, (int)r);
    }
    if (reason == DLL_PROCESS_ATTACH && !r)
        rt_log(0, "%s: the original DllMain failed, so loading the DLL fails", m->name);
    if (reason == DLL_PROCESS_DETACH && rt_logf && rt_logf != stderr) fflush(rt_logf);
    return r;
}

/* called by a rebuilt exe's main() */
int rt_module_exemain(rt_module *m) {
    register_module(m, GetModuleHandleA(0));
    {   /* the FPU as Windows hands it to a new process (the start-up code of the
         * rebuilt file itself has changed it): 53-bit precision, all masked */
        uint16_t cw = 0x27f; uint32_t mx = 0x1f80;
        __asm__ volatile("fninit\n\tfldcw %0" : : "m"(cw));
        __asm__ volatile("ldmxcsr %0" : : "m"(mx));
    }
    run_tls_callbacks(m, DLL_PROCESS_ATTACH);
    rt_log(1, "starting the program at %#llx", (unsigned long long)m->entry);
    /* the entry point of a Windows program gets the PEB as its only argument */
    void *peb = *(void **)((uint8_t *)NtCurrentTeb() + 0x30);
    int r = ((int (__cdecl *)(void *))(uintptr_t)m->entry)(peb);
    rt_log(1, "entry point returned %d", r);
    fflush(NULL);
    rt_dump_memory(0, 0);
    ExitProcess((UINT)r);
}

/* recomp_rt.dll itself: free a thread's runtime state when the thread ends
 * (this runs on the dying thread's real stack, so its host stack is idle) */
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)h; (void)reserved;
    if (reason == DLL_THREAD_DETACH && inited) {
        rt32_thr *t = cur_thr();
        if (t) {
            EnterCriticalSection(&rt_cs);
            for (int i = 0; i < nthreads; i++)
                if (threads[i] == t) { threads[i] = threads[--nthreads]; break; }
            LeaveCriticalSection(&rt_cs);
            *(rt32_thr **)((uint8_t *)NtCurrentTeb() + rt32_teb_off) = 0;
            VirtualFree(t->host_lo, 0, MEM_RELEASE);
            /* (the rt_ctx stays: the watchdog and crash reports may still look at it) */
            VirtualFree(t, 0, MEM_RELEASE);
        }
    }
    return TRUE;
}
