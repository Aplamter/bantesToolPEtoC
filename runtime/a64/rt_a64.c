/* recomp runtime for ARM64 shared libraries (Android, Linux aarch64).
 *
 * The rebuilt library holds the original image (rt_guest: data and code,
 * where the system loader relocated it) and the recompiled code as C
 * functions ("chunks"). This file is the part that runs them:
 *
 *   rt_a64_run     the loop: address in the program -> chunk -> next address,
 *                  until the program goes to an address outside the image.
 *                  That is native code (an imported function, a callback of
 *                  another library, the caller): the registers move to the
 *                  CPU and the jump is made (rt_a64_asm.S).
 *   coming back    happens by itself: the first instruction of the
 *                  program's functions and the instruction after each of
 *                  its calls are, in the image, jumps into rt_a64_enter /
 *                  rt_a64_reenter (a64.py). No signal handler, no table of
 *                  callbacks, and nothing of the runtime stays on a stack
 *                  while native code runs.
 *   wrapped imports
 *                  qsort, bsearch and dl_iterate_phdr call the program's
 *                  function directly (rt_a64_call) instead of through its
 *                  address; getauxval hides CPU features the lifter has no
 *                  instructions for; sigaction/signal give the program's
 *                  signal handlers the stack and the registers of the
 *                  program when the signal interrupts recompiled code.
 *
 * Build: -DRT_ANDROID (bionic) or -DRT_GLIBC. No headers besides the
 * compiler's own are used; the C library functions are declared below. */
#include "rt_a64.h"

#if !defined(RT_ANDROID) && !defined(RT_GLIBC)
#error "build with -DRT_ANDROID or -DRT_GLIBC"
#endif

/* ------------------------------------------------------------------ */
/* the C library, declared by hand                                      */
/* ------------------------------------------------------------------ */
typedef long ssize_t;
typedef __builtin_va_list va_list;
#define va_start __builtin_va_start
#define va_end __builtin_va_end
void *mmap(void *, size_t, int, int, int, long);
int munmap(void *, size_t);
int mprotect(void *, size_t, int);
ssize_t write(int, const void *, size_t);
int open(const char *, int, ...);
int close(int);
char *getenv(const char *);
int vsnprintf(char *, size_t, const char *, va_list);
int snprintf(char *, size_t, const char *, ...);
void abort(void) __attribute__((noreturn));
void _exit(int) __attribute__((noreturn));
long syscall(long, ...);

size_t strlen(const char *);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
long strtol(const char *, char **, int);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
void *bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));
unsigned long getauxval(unsigned long);
typedef unsigned int pthread_key_t;
int pthread_key_create(pthread_key_t *, void (*)(void *));
void *pthread_getspecific(pthread_key_t);
int pthread_setspecific(pthread_key_t, const void *);
struct dl_phdr_info;
int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);
#ifdef RT_ANDROID
int __android_log_write(int, const char *, const char *);
#endif

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)

/* struct sigaction: the two C libraries lay it out differently */
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SA_RESTART 0x10000000
#define SA_NODEFER 0x40000000
#define SA_RESETHAND 0x80000000u
#define RT_NSIG 65
#ifdef RT_ANDROID
typedef struct { unsigned long bits[1]; } rt_sigset;
typedef struct { int sa_flags; uint64_t handler; rt_sigset sa_mask; void *sa_restorer; } rt_sigaction;
#else
typedef struct { unsigned long bits[16]; } rt_sigset;
typedef struct { uint64_t handler; rt_sigset sa_mask; int sa_flags; void *sa_restorer; } rt_sigaction;
#endif
int sigaction(int, const rt_sigaction *, rt_sigaction *);
#define SIG_DFL_ 0
#define SIG_IGN_ 1

/* the kernel's signal frame (struct ucontext, struct sigcontext): the same
 * with every C library */
#define UC_SIZE 4560
#define UC_REGS 184             /* x0..x30 */
#define UC_SP 432
#define UC_PC 440
#define UC_PSTATE 448
#define UC_RESERVED 464         /* records: fpsimd_context = magic 0x46508001, size, fpsr, fpcr, v0..v31 */
#define UCR(uc, o) (*(uint64_t *)((uint8_t *)(uc) + (o)))
#define SI_ADDR(si) (*(uint64_t *)((uint8_t *)(si) + 16))

/* asm */
uint64_t rt_a64_run(rt_ctx *c, uint64_t pc);
void rt_a64_tlsdesc(void);
uint64_t rt_a64_call(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t rt_a64_call_sp(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t sp);

#define NOMAP 0xFFFFFFFFu
#define X(c, n) (*(uint64_t *)((c)->R + RT_R_X + 8 * (n)))
#define SPR(c) (*(uint64_t *)((c)->R + RT_R_SP))

/* ------------------------------------------------------------------ */
/* state of this library                                                */
/* ------------------------------------------------------------------ */
static uint64_t g_base, g_size;         /* rt_guest, size in memory */
static uint64_t g_delta;                /* run-time address = original address + g_delta */
static const rt_a64_region *g_r0;       /* the biggest code region (checked first) */
static pthread_key_t g_key;
static int g_ready, g_loglevel;
static size_t g_stack_size = 4u << 20;
/* signal handlers the program installed: called through rt_sig_dispatch */
static struct { uint64_t handler; int flags; rt_sigset mask; int set; } g_sig[RT_NSIG];
static int *g_opkind;
static volatile int g_crashing;

/* ------------------------------------------------------------------ */
/* log                                                                  */
/* RECOMP_LOG=1 start-up and threads, 2 + calls into/out of native code */
/* ------------------------------------------------------------------ */
static void rt_out(const char *s) {
#ifdef RT_ANDROID
    __android_log_write(g_crashing ? 7 : 4, "recomp", s);
#endif
    write(2, s, strlen(s));
}

__attribute__((format(printf, 2, 3)))
static void rt_log(int level, const char *fmt, ...) {
    if (level > g_loglevel) return;
    char b[1024];
    int n = snprintf(b, sizeof b, "[recomp %s] ", rt_mod.name);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b + n, sizeof b - n - 2, fmt, ap);
    va_end(ap);
    n = (int)strlen(b);
    b[n] = '\n'; b[n + 1] = 0;
    rt_out(b);
}

static int in_image(uint64_t a) { return a - g_base < g_size; }

/* "name+0x12" for an address of the program (original addresses) */
static const char *symstr(uint64_t orig, char *buf, size_t n) {
    int lo = 0, hi = rt_mod.nsyms - 1, best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (rt_mod.syms[mid].addr <= orig) { best = mid; lo = mid + 1; } else hi = mid - 1;
    }
    if (best >= 0 && orig - rt_mod.syms[best].addr < 0x100000)
        snprintf(buf, n, "%s+0x%llx", rt_mod.syms[best].name, (unsigned long long)(orig - rt_mod.syms[best].addr));
    else
        snprintf(buf, n, "?");
    return buf;
}

__attribute__((noreturn, cold))
static void rt_crash(rt_ctx *c, const char *what, uint64_t a) {
    char s[160];
    g_crashing = 1;
    g_loglevel = 9;
    rt_log(0, "*** %s (0x%llx)", what, (unsigned long long)a);
    if (c) {
        rt_log(0, "    last instruction: 0x%llx  %s  (address in the original %s)",
               (unsigned long long)c->cur, symstr(c->cur, s, sizeof s), rt_mod.name);
        for (int i = 0; i < 31; i += 4)
            rt_log(0, "    x%-2d %016llx  x%-2d %016llx  x%-2d %016llx  x%-2d %016llx", i,
                   (unsigned long long)X(c, i), i + 1, (unsigned long long)X(c, i + 1), i + 2,
                   (unsigned long long)(i + 2 < 31 ? X(c, i + 2) : SPR(c)), i + 3,
                   (unsigned long long)(i + 3 < 31 ? X(c, i + 3) : 0));
        rt_log(0, "    sp  %016llx  image at %016llx (original address 0x%llx)", (unsigned long long)SPR(c),
               (unsigned long long)g_base, (unsigned long long)rt_mod.glo);
        rt_ctx *b = c->base ? c->base : c;
        for (unsigned i = 0; i < 16; i++) {
            uint64_t p = b->last[(b->last_pos - 1 - i) & 15];
            if (!p) break;
            if (in_image(p))
                rt_log(0, "    came through 0x%llx  %s", (unsigned long long)(p - g_delta), symstr(p - g_delta, s, sizeof s));
            else
                rt_log(0, "    came through native code at %p", (void *)p);
        }
    }
    abort();
}

void rt_unsupported(rt_ctx *c, const char *what, uint64_t pc) {
    c->cur = pc;
    rt_log(0, "instruction that could not be translated: %s", what);
    rt_crash(c, "untranslated instruction", pc);
}

void rt_a64_trap(rt_ctx *c, uint64_t addr, uint32_t insn) {
    c->cur = addr;
    /* BRK / UDF: what compilers put where the program must not get
     * (__builtin_trap, a failed assertion) */
    rt_log(0, "trap instruction 0x%08x", insn);
    rt_crash(c, "the program ran a trap instruction (BRK/HLT/UDF)", addr);
}

/* ------------------------------------------------------------------ */
/* per-thread context                                                   */
/* ------------------------------------------------------------------ */
static size_t page_up(size_t n) { return (n + 0xffff) & ~(size_t)0xffff; }

static void *map(size_t n) {
    void *p = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? 0 : p;
}

static void ctx_free(void *p) {
    rt_ctx *c = p;
    if (!c) return;
    rt_log(1, "thread %d ends (%llu chunks run)", c->tid, (unsigned long long)c->n_run);
    if (c->tls_mem) munmap(c->tls_mem, page_up(rt_mod.tls_memsz + rt_mod.tls_align + 64));
    size_t ru = page_up(sizeof(rt_ctx) + RT_R_SIZE + rt_mod.usize);
    munmap(c->stack_lo - 0x10000, 0x10000 + g_stack_size + ru);
}

static rt_ctx *ctx_new(void) {
    /* one mapping: guard | runtime stack | context, register file, temporaries */
    size_t ru = page_up(sizeof(rt_ctx) + RT_R_SIZE + rt_mod.usize);
    uint8_t *m = map(0x10000 + g_stack_size + ru);
    if (!m) { rt_log(0, "out of memory for a thread context"); abort(); }
    mprotect(m, 0x10000, PROT_NONE);
    rt_ctx *c = (rt_ctx *)(m + 0x10000 + g_stack_size);
    c->base = c;
    c->stack_lo = m + 0x10000;
    c->stack_hi = (uint8_t *)c;
    c->R = (uint8_t *)(c + 1);
    c->U = c->R + RT_R_SIZE;
    c->ex_addr = ~0ULL;
    c->tid = (int)syscall(178);             /* gettid */
    pthread_setspecific(g_key, c);
    rt_log(1, "thread %d: context %p, runtime stack %p-%p", c->tid, (void *)c, (void *)c->stack_lo, (void *)c->stack_hi);
    return c;
}

static rt_ctx *ctx_base(void) {
    rt_ctx *c = pthread_getspecific(g_key);
    return c ? c : ctx_new();
}

/* Native code enters the program (rt_a64_enter / rt_a64_reenter, still on
 * the native stack; sp = the program's stack pointer). Returns the context
 * to run with and where on the runtime stack the run goes.
 *
 * Normally that is the thread's context and the top of its runtime stack:
 * between two runs nothing is kept there. But if recompiled code of this
 * thread is in the middle of running - a signal interrupted it, and the
 * handler (or something it called) now enters the program - its register
 * file and its part of the runtime stack must stay as they are: the new run
 * gets a context of its own, carved out of the runtime stack below. */
struct rt_begin { rt_ctx *c; uint8_t *sp; };
struct rt_begin rt_a64_begin(uint64_t sp) {
    rt_ctx *b = ctx_base();
    uint8_t *floor = 0;
    if (sp - (uint64_t)b->stack_lo < (uint64_t)(b->stack_hi - b->stack_lo))
        floor = (uint8_t *)(sp - 0x10000);      /* the caller itself is on the runtime stack: leave it room */
    if (b->sig_floor && (!floor || b->sig_floor < floor)) floor = b->sig_floor;
    if (!floor) {
        SPR(b) = sp;
        return (struct rt_begin){b, b->stack_hi};
    }
    size_t need = sizeof(rt_ctx) + RT_R_SIZE + ((rt_mod.usize + 15) & ~(size_t)15);
    uint8_t *p = (uint8_t *)(((uint64_t)floor & ~15ULL) - need);
    if (p < b->stack_lo + 0x10000 || p > b->stack_hi)
        rt_crash(b, "the runtime stack is full (signal handlers of the program nest too deep; "
                    "RECOMP_RT_STACK_KB makes it bigger)", sp);
    rt_ctx *c = (rt_ctx *)p;
    memset(c, 0, sizeof *c);
    c->base = b;
    c->R = (uint8_t *)(c + 1);
    c->U = c->R + RT_R_SIZE;
    memset(c->R, 0, RT_R_SIZE);
    c->ex_addr = ~0ULL;
    c->tid = b->tid;
    SPR(c) = sp;
    return (struct rt_begin){c, p};
}

/* rt_a64_reenter: everything the CPU had -> register file. frame: x0..x30,
 * NZCV, v0..v31 (16 bytes each); above it the two words the code in front
 * of the image pushed. Returns where the program goes on: the instruction
 * whose place the jump took. */
uint64_t rt_a64_take(rt_ctx *c, const uint64_t *frame) {
    uint8_t *R = c->R;
    uint64_t pc = frame[30] - 4, f = frame[31];
    memcpy(R + RT_R_X, frame, 30 * 8);
    X(c, 30) = pc;                  /* (what a function that returns leaves in x30) */
    NZ_S(f);
    for (int i = 0; i < 32; i++) memcpy(R + RT_R_V + 32 * i, (const uint8_t *)frame + 0x100 + 16 * i, 16);
    SPR(c) = (uint64_t)frame + 0x330;
    return pc;
}

/* this library's thread-local variables, for this thread */
static uint8_t *tls_block(rt_ctx *c) {
    c = c->base;
    if (!c->tls) {
        size_t al = rt_mod.tls_align > 16 ? rt_mod.tls_align : 16;
        uint8_t *m = map(page_up(rt_mod.tls_memsz + al + 64));
        if (!m) rt_crash(c, "out of memory for thread-local variables", rt_mod.tls_memsz);
        c->tls_mem = m;
        /* same alignment as in the original: the address of the block has
         * the remainder the segment's address has */
        uint64_t want = rt_mod.tls_vaddr & (al - 1), a = (uint64_t)m;
        a += (want - a) & (al - 1);
        c->tls = (uint8_t *)a;
        memcpy(c->tls, rt_guest + (rt_mod.tls_vaddr - rt_mod.glo), rt_mod.tls_filesz);
    }
    return c->tls;
}

/* ------------------------------------------------------------------ */
/* the run loop                                                         */
/* ------------------------------------------------------------------ */
static inline rt_chunk_fn lookup(uint64_t pc) {
    uint64_t off = pc - g_base;
    const rt_a64_region *r = g_r0;
    if (off - r->off < r->size) {
        uint32_t k = r->map[(off - r->off) >> 2];
        return k != NOMAP ? rt_mod.chunks[k] : 0;
    }
    if (off < g_size)
        for (int i = 0; i < rt_mod.nregions; i++) {
            r = &rt_mod.regions[i];
            if (off - r->off < r->size) {
                uint32_t k = r->map[(off - r->off) >> 2];
                return k != NOMAP ? rt_mod.chunks[k] : 0;
            }
        }
    return 0;
}

/* TLS descriptor, called by original code that runs as itself (rt_a64_asm.S) */
uint64_t rt_a64_tls_offset(const uint64_t *desc) {
    uint64_t tp;
    __asm__("mrs %0, tpidr_el0" : "=r"(tp));
    return (uint64_t)tls_block(ctx_base()) + desc[1] - tp;
}

/* Runs the program from pc until it goes to native code: returns that
 * address (rt_a64_asm.S jumps there with the program's registers). */
uint64_t rt_a64_run(rt_ctx *c, uint64_t pc) {
    rt_ctx *b = c->base, *outer = b->active;
    b->active = c;
    for (;;) {
        /* bit 0: the chunk left through a RET */
        rt_chunk_fn fn = lookup(pc & ~1ULL);
        if (__builtin_expect(fn != 0, 1)) {
            b->last[b->last_pos++ & 15] = pc & ~1ULL;
            b->n_run++;
            pc = fn(pc & ~1ULL, c);
            continue;
        }
        pc &= ~1ULL;
        if (in_image(pc) || (pc & 3))
            rt_crash(c, in_image(pc) ? "jump to an address of the program that is not code recomp translated"
                                     : "jump to an address that cannot be code", in_image(pc) ? pc - g_delta : pc);
        if (pc == (uint64_t)rt_a64_tlsdesc) {
            /* TLS descriptor call: x0 = address of the descriptor; returns
             * in x0 the offset of the variable from the thread pointer.
             * Changes no other register. */
            uint64_t tp, off = ((uint64_t *)X(c, 0))[1];
            __asm__("mrs %0, tpidr_el0" : "=r"(tp));
            X(c, 0) = (uint64_t)tls_block(c) + off - tp;
            pc = X(c, 30);
            continue;
        }
        /* native code: a call (it returns to the instruction after the
         * call, which is a jump back into the runtime), a return to the
         * native caller, or a jump */
        if (g_loglevel >= 2) rt_log(2, "to native code at %p (from 0x%llx)", (void *)pc, (unsigned long long)c->cur);
        b->last[b->last_pos++ & 15] = pc;
        c->ex_addr = ~0ULL;
        b->active = outer;
        return pc;
    }
}

/* ------------------------------------------------------------------ */
/* signals                                                              */
/* ------------------------------------------------------------------ */
static uint8_t *uc_fpsimd(void *uc) {
    uint8_t *p = (uint8_t *)uc + UC_RESERVED, *end = (uint8_t *)uc + UC_SIZE;
    while (p + 8 <= end) {
        uint32_t magic, size;
        memcpy(&magic, p, 4); memcpy(&size, p + 4, 4);
        if (magic == 0x46508001u) return p;
        if (!magic || size < 8) break;
        p += size;
    }
    return 0;
}

/* Signal handlers of the program are installed through this function
 * (rt_w_sigaction). If the signal interrupted native code, the handler is
 * simply called. If it interrupted recompiled code, the real registers and
 * the real stack are the runtime's: the handler then gets the program's
 * stack and a signal frame that describes the program - a handler that
 * looks at the interrupted registers or scans the stack (garbage
 * collectors stop threads this way) sees what it would see in the
 * original. */
static void rt_sig_dispatch(int sig, void *si, void *uc) {
    if (sig <= 0 || sig >= RT_NSIG || !g_sig[sig].set) return;
    uint64_t fn = g_sig[sig].handler;
    if (g_sig[sig].flags & SA_RESETHAND) g_sig[sig].set = 0;
    rt_ctx *b = ctx_base();
    uint64_t sp = UCR(uc, UC_SP);
    if (sp - (uint64_t)b->stack_lo >= (uint64_t)(b->stack_hi - b->stack_lo)) {
        rt_a64_call(fn, (uint64_t)sig, (uint64_t)si, (uint64_t)uc, 0);
        return;
    }
    rt_ctx *g = b->active ? b->active : b;      /* the interrupted run */
    /* on the program's stack: the frame, the signal info, and the runtime's
     * own registers (a collector that scans the stack for pointers finds
     * there what the compiled C held in registers) */
    uint64_t gsp = (SPR(g) - 0x100 - 31 * 8 - 128 - UC_SIZE) & ~15ULL;
    uint8_t *g_uc = (uint8_t *)gsp, *g_si = g_uc + UC_SIZE;
    memcpy(g_uc, uc, UC_SIZE);
    memcpy(g_si, si, 128);
    memcpy(g_si + 128, (uint8_t *)uc + UC_REGS, 31 * 8);
    memcpy(g_uc + UC_REGS, g->R + RT_R_X, 31 * 8);
    UCR(g_uc, UC_SP) = SPR(g);
    UCR(g_uc, UC_PC) = g->cur + g_delta;
    { uint8_t *R = g->R; UCR(g_uc, UC_PSTATE) = NZ_G(); }
    uint8_t *fp = uc_fpsimd(g_uc);
    if (fp)
        for (int i = 0; i < 32; i++) memcpy(fp + 16 + 16 * i, g->R + RT_R_V + 32 * i, 16);
    uint8_t *ofloor = b->sig_floor;
    rt_ctx *oactive = b->active;
    b->sig_floor = (uint8_t *)(((uint64_t)__builtin_frame_address(0) - 0x2000) & ~15ULL);
    rt_a64_call_sp(fn, (uint64_t)sig, (uint64_t)g_si, (uint64_t)g_uc, gsp);
    b->sig_floor = ofloor;
    b->active = oactive;
}

static void set_handler(rt_sigaction *a, uint64_t h, int flags) {
    memset(a, 0, sizeof *a);
    a->handler = h;
    a->sa_flags = flags;
}

/* the program's sigaction() */
int rt_w_sigaction(int sig, const rt_sigaction *act, rt_sigaction *old) {
    if (sig <= 0 || sig >= RT_NSIG) return sigaction(sig, act, old);
    rt_sigaction prev;
    int was = g_sig[sig].set;
    uint64_t was_h = g_sig[sig].handler;
    int was_f = g_sig[sig].flags;
    rt_sigset was_m = g_sig[sig].mask;
    if (act && act->handler > SIG_IGN_ && in_image(act->handler)) {
        rt_sigaction a = *act;
        a.handler = (uint64_t)rt_sig_dispatch;
        a.sa_flags = (act->sa_flags | SA_SIGINFO) & ~SA_RESETHAND;
        g_sig[sig].handler = act->handler;
        g_sig[sig].flags = act->sa_flags;
        g_sig[sig].mask = act->sa_mask;
        g_sig[sig].set = 1;
        if (sigaction(sig, &a, &prev)) return -1;
    } else {
        if (sigaction(sig, act, &prev)) return -1;
        if (act) g_sig[sig].set = 0;
    }
    if (old) {
        *old = prev;
        if (was && prev.handler == (uint64_t)rt_sig_dispatch) {
            memset(old, 0, sizeof *old);
            old->handler = was_h;
            old->sa_flags = was_f;
            old->sa_mask = was_m;
        }
    }
    return 0;
}

int rt_w_sigaction64(int sig, const rt_sigaction *act, rt_sigaction *old) {
    return rt_w_sigaction(sig, act, old);       /* (the same structure on 64-bit Android) */
}

uint64_t rt_w_signal(int sig, uint64_t handler) {
    rt_sigaction a, o;
    set_handler(&a, handler, SA_RESTART);
    if (rt_w_sigaction(sig, &a, &o)) return ~0ULL;      /* SIG_ERR */
    return o.handler;
}

uint64_t rt_w_bsd_signal(int sig, uint64_t handler) { return rt_w_signal(sig, handler); }

/* ------------------------------------------------------------------ */
/* imports the runtime answers itself                                   */
/* ------------------------------------------------------------------ */
/* qsort / bsearch: the C library's own (same order of equal elements as in
 * the original), with a comparison function that enters the program
 * directly */
static uint64_t *cmp_slot(void) { return &ctx_base()->cb; }

static int cmp_shim(const void *a, const void *b) {
    return (int)rt_a64_call(*cmp_slot(), (uint64_t)a, (uint64_t)b, 0, 0);
}

void rt_w_qsort(void *base, size_t n, size_t size, uint64_t cmp) {
    uint64_t *s = cmp_slot(), old = *s;
    *s = cmp;
    qsort(base, n, size, in_image(cmp) ? cmp_shim : (int (*)(const void *, const void *))cmp);
    *cmp_slot() = old;
}

void *rt_w_bsearch(const void *key, const void *base, size_t n, size_t size, uint64_t cmp) {
    uint64_t *s = cmp_slot(), old = *s;
    *s = cmp;
    void *r = bsearch(key, base, n, size, in_image(cmp) ? cmp_shim : (int (*)(const void *, const void *))cmp);
    *cmp_slot() = old;
    return r;
}

struct dlit { uint64_t cb, data; };
static int dlit_shim(struct dl_phdr_info *info, size_t size, void *p) {
    struct dlit *d = p;
    return (int)rt_a64_call(d->cb, (uint64_t)info, size, d->data, 0);
}

int rt_w_dl_iterate_phdr(uint64_t cb, uint64_t data) {
    struct dlit d = {cb, data};
    if (!in_image(cb)) return dl_iterate_phdr((int (*)(struct dl_phdr_info *, size_t, void *))cb, (void *)data);
    return dl_iterate_phdr(dlit_shim, &d);
}

/* CPU features the program is told about: the ones whose instructions the
 * lifter knows (translated, or run as themselves because they only use
 * vector registers). Not SVE/SME, pointer authentication, memory tagging:
 * a program that is told they are missing takes its ordinary code path. */
unsigned long rt_w_getauxval(unsigned long type) {
    unsigned long v = getauxval(type);
    if (type == 16) {           /* AT_HWCAP */
        /* fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc
         * dcpop sha3 sm3 sm4 asimddp sha512 | asimdfhm (23) | uscat (25) ilrcpc (26) */
        v &= 0x003fffffUL | (1UL << 23) | (1UL << 25) | (1UL << 26);
        v &= ~(1UL << 11);      /* cpuid: the ID registers are not there for the program */
    } else if (type == 26) {    /* AT_HWCAP2: SVE2, memory tagging, ... */
        v = 0;
    }
    return v;
}

/* ------------------------------------------------------------------ */
/* special CPU operations                                               */
/* ------------------------------------------------------------------ */
enum { OP_UNKNOWN, OP_NOP, OP_ZERO };

static void resolve_ops(void) {
    g_opkind = map(page_up(sizeof(int) * (rt_mod.nops + 1)));
    for (int i = 0; i < rt_mod.nops && g_opkind; i++) {
        const char *s = rt_mod.opnames[i];
        int k = OP_UNKNOWN;
        if (!strncmp(s, "Hint_", 5) || !strcmp(s, "SpeculationBarrier") || !strcmp(s, "DataMemoryBarrier") ||
            !strcmp(s, "DataSynchronizationBarrier") || !strcmp(s, "InstructionSynchronizationBarrier") ||
            !strcmp(s, "ClearExclusiveLocal") || !strcmp(s, "LOAcquire") || !strcmp(s, "LORelease") ||
            !strcmp(s, "SysOp_W") || !strcmp(s, "SysOp_R"))
            k = OP_NOP;
        g_opkind[i] = k;
    }
}

void rt_callother(rt_ctx *c, int id, uint64_t pc, uint8_t *out, int osz, int n,
                  const uint8_t *const *in, const int *sz) {
    (void)n; (void)in; (void)sz;
    switch (g_opkind ? g_opkind[id] : OP_UNKNOWN) {
    case OP_NOP:
        if (out && osz) memset(out, 0, osz);
        return;
    default:
        c->cur = pc;
        rt_log(0, "special CPU instruction the runtime does not implement: %s", rt_mod.opnames[id]);
        rt_crash(c, "unimplemented special CPU instruction", pc);
    }
}

/* SVC: the program makes a system call itself (x8 = number, x0-x5) */
void rt_a64_svc(rt_ctx *c) {
    switch (X(c, 8)) {
    case 220: case 435:     /* clone, clone3: the new thread would share this C stack */
    case 139:               /* rt_sigreturn */
        rt_crash(c, "system call made directly by the program that the runtime cannot pass on", X(c, 8));
    }
    register uint64_t x8 __asm__("x8") = X(c, 8);
    register uint64_t x0 __asm__("x0") = X(c, 0);
    register uint64_t x1 __asm__("x1") = X(c, 1);
    register uint64_t x2 __asm__("x2") = X(c, 2);
    register uint64_t x3 __asm__("x3") = X(c, 3);
    register uint64_t x4 __asm__("x4") = X(c, 4);
    register uint64_t x5 __asm__("x5") = X(c, 5);
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
    X(c, 0) = x0;
}

/* shifts of values wider than 16 bytes (kind: 0 left, 1 right, 2 arithmetic right) */
void WSHIFT(uint8_t *o, const uint8_t *a, int n, uint64_t s, int kind) {
    uint8_t t[64], fill = (kind == 2 && (a[n - 1] & 0x80)) ? 0xff : 0;
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++) {
        long bit = kind == 0 ? (long)i * 8 - (long)s : (long)i * 8 + (long)s;
        unsigned v = 0;
        for (int k = 0; k < 8; k++) {
            long b = bit + k;
            unsigned x;
            if (b < 0) x = 0;
            else if (b >= (long)n * 8) x = kind == 0 ? 0 : (fill & 1);
            else x = (a[b >> 3] >> (b & 7)) & 1;
            v |= x << k;
        }
        t[i] = (uint8_t)v;
    }
    memcpy(o, t, n);
}

#ifdef RECOMP_TRACE_INSN
void rt_trace_insn(rt_ctx *c, uint64_t a) {
    if (g_loglevel >= 4) rt_log(4, "%d: 0x%llx", c->tid, (unsigned long long)a);
}
#endif

/* ------------------------------------------------------------------ */
/* loading and unloading                                                */
/* ------------------------------------------------------------------ */
__attribute__((constructor))
static void rt_a64_init(int argc, char **argv, char **envp) {
    const char *e = getenv("RECOMP_LOG");
    g_loglevel = e ? (int)strtol(e, 0, 10) : 0;
    e = getenv("RECOMP_RT_STACK_KB");
    if (e && strtol(e, 0, 10) >= 256) g_stack_size = page_up((size_t)strtol(e, 0, 10) << 10);
    g_base = (uint64_t)rt_guest;
    g_size = rt_mod.gsize;
    g_delta = g_base - rt_mod.glo;
    g_r0 = &rt_mod.regions[0];
    for (int i = 1; i < rt_mod.nregions; i++)
        if (rt_mod.regions[i].size > g_r0->size) g_r0 = &rt_mod.regions[i];
    resolve_ops();
    pthread_key_create(&g_key, ctx_free);
    rt_log(1, "loaded: image at %p (%llu KB), %d chunks", (void *)g_base, (unsigned long long)(g_size >> 10),
           rt_mod.nchunks);

    /* thread-local variables are reached through descriptors: (function, argument) */
    for (int i = 0; i < rt_mod.ntlsdesc; i++) {
        uint64_t *d = (uint64_t *)(g_base + (rt_mod.tlsdesc[2 * i] - rt_mod.glo));
        d[0] = (uint64_t)rt_a64_tlsdesc;
        d[1] = rt_mod.tlsdesc[2 * i + 1];
    }
    g_ready = 1;

    /* indirect functions: the resolver's result goes into the slot */
    for (int i = 0; i < rt_mod.nirel; i++) {
        uint64_t *slot = (uint64_t *)(g_base + (rt_mod.irel[2 * i] - rt_mod.glo));
        *slot = rt_a64_call(rt_mod.irel[2 * i + 1] + g_delta, getauxval(16), 0, 0, 0);
    }
    /* what the original made read-only after loading is read-only again (whole pages only) */
    unsigned long pg = getauxval(6);        /* AT_PAGESZ */
    if (!pg) pg = 4096;
    for (const uint64_t *r = rt_mod.ro; r && r[1]; r += 2) {
        uint64_t lo = (r[0] + g_delta + pg - 1) & ~(pg - 1), hi = (r[0] + r[1] + g_delta) & ~(pg - 1);
        if (hi > lo) mprotect((void *)lo, hi - lo, PROT_READ);
    }
    /* the program's own initialisation: DT_INIT, then DT_INIT_ARRAY */
    if (rt_mod.init) rt_a64_call(rt_mod.init + g_delta, (uint64_t)argc, (uint64_t)argv, (uint64_t)envp, 0);
    for (int i = 0; i < rt_mod.init_n; i++) {
        uint64_t f = *(uint64_t *)(g_base + (rt_mod.init_array - rt_mod.glo) + 8 * i);
        if (f && f != ~0ULL) rt_a64_call(f, (uint64_t)argc, (uint64_t)argv, (uint64_t)envp, 0);
    }
}

__attribute__((destructor))
static void rt_a64_fini(void) {
    if (!g_ready) return;
    for (int i = rt_mod.fini_n - 1; i >= 0; i--) {
        uint64_t f = *(uint64_t *)(g_base + (rt_mod.fini_array - rt_mod.glo) + 8 * i);
        if (f && f != ~0ULL) rt_a64_call(f, 0, 0, 0, 0);
    }
    if (rt_mod.fini) rt_a64_call(rt_mod.fini + g_delta, 0, 0, 0, 0);
}
