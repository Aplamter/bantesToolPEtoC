/* recomp runtime: shared core
 *   - address -> recompiled chunk lookup and the main dispatch loop
 *   - symbols, logging, crash reports
 *   - special CPU instructions (cpuid, rdtsc, SSE ops Ghidra leaves opaque)
 */
#define _GNU_SOURCE
#include "rt_internal.h"
#include <stdarg.h>
#include <math.h>
#include <signal.h>
#include <cpuid.h>
#include <x86intrin.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#endif

/* one stack slot / pointer of the program */
#ifdef RT_GUEST32
typedef uint32_t gptr_t;
#else
typedef uint64_t gptr_t;
#endif

int rt_loglevel = 0;
FILE *rt_logf;
static const char *crashpath;
/* a game is several rebuilt files in one process, each with its own runtime:
 * DLLs append to the shared log and tag their lines with their name */
int rt_log_append = 0;
const char *rt_logtag = "recomp";

/* ------------------------------------------------------------------ */
/* watchdog: RECOMP_WATCH=N writes where every guest thread is, every   */
/* N seconds, to the log. For hangs: shows which threads still make     */
/* progress (spinning / just slow) and which sit still (blocked).       */
/* ------------------------------------------------------------------ */
#define RT_MAX_CTX 4096
static rt_ctx *volatile all_ctx[RT_MAX_CTX];
/* the global lock for LOCK-prefixed instructions (see rt_lock) and its stats */
static volatile int g_lock;
static uint64_t g_lock_n;                 /* acquisitions (written while holding it) */
static volatile uint64_t g_lock_waits;    /* acquisitions that had to wait */
static volatile uint64_t g_lock_yields;   /* times a waiter gave its CPU to others */
static volatile int n_ctx;

static void watch_once(int secs) {
    static uint64_t last_tr[RT_MAX_CTX], last_cur[RT_MAX_CTX];
    static unsigned round_no;
    int n = __atomic_load_n(&n_ctx, __ATOMIC_ACQUIRE);
    if (n > RT_MAX_CTX) n = RT_MAX_CTX;
    int busy = 0;
    for (int i = 0; i < n; i++) {
        rt_ctx *c = all_ctx[i];
        if (c && c->n_transfers != last_tr[i]) busy++;
    }
    static uint64_t last_ln, last_lw, last_ly;
    uint64_t ln = g_lock_n, lw = g_lock_waits, ly = g_lock_yields;
    fprintf(rt_logf, "[%s] === watch #%u (+%ds): %d guest threads, %d made progress ===\n",
            rt_logtag, ++round_no, secs, n, busy);
    fprintf(rt_logf, "[%s]   atomic-instruction lock: %llu uses, %llu had to wait, %llu yields\n",
            rt_logtag, (unsigned long long)(ln - last_ln), (unsigned long long)(lw - last_lw),
            (unsigned long long)(ly - last_ly));
    last_ln = ln; last_lw = lw; last_ly = ly;
    for (int i = 0; i < n; i++) {
        rt_ctx *c = all_ctx[i];
        if (!c) continue;
        uint64_t t = c->n_transfers, cur = c->cur, d = t - last_tr[i];
        const char *st = d ? "RUNNING" : (cur == last_cur[i] ? "STILL  " : "moved  ");
        fprintf(rt_logf, "[%s]   t%-4d %s at %#llx %-48s +%llu transfers (total %llu) depth %d\n",
                rt_logtag, c->tid, st, (unsigned long long)cur, rt_symstr(cur),
                (unsigned long long)d, (unsigned long long)t, c->depth);
        last_tr[i] = t;
        last_cur[i] = cur;
    }
    fflush(rt_logf);
}

#ifdef _WIN32
static DWORD WINAPI watch_thread(LPVOID p) {
    int secs = (int)(intptr_t)p;
    for (;;) { Sleep(secs * 1000); watch_once(secs); }
    return 0;
}
#else
static void *watch_thread(void *p) {
    int secs = (int)(intptr_t)p;
    for (;;) { sleep(secs); watch_once(secs); }
    return 0;
}
#endif

static void watch_start(void) {
    static int started;
    const char *w = getenv("RECOMP_WATCH");
    int secs = w ? atoi(w) : 0;
    if (secs <= 0 || started) return;
    started = 1;
#ifdef _WIN32
    HANDLE h = CreateThread(NULL, 0, watch_thread, (LPVOID)(intptr_t)secs, 0, NULL);
    if (h) CloseHandle(h);
#else
    pthread_t th;
    if (!pthread_create(&th, 0, watch_thread, (void *)(intptr_t)secs)) pthread_detach(th);
#endif
    rt_log(0, "watchdog: thread positions every %d s (RECOMP_WATCH)", secs);
}

/* ------------------------------------------------------------------ */
/* logging                                                             */
/* ------------------------------------------------------------------ */
void rt_log_init(void) {
    const char *l = getenv("RECOMP_LOG");
    rt_loglevel = l ? atoi(l) : 0;
    rt_logf = stderr;
    const char *f = getenv("RECOMP_LOGFILE");
    if (f && *f) {
        /* Programs the game starts (e.g. UnityCrashHandler64.exe) inherit the
         * environment: they append instead of wiping the game's log. */
        const char *started = getenv("RECOMP_LOG_STARTED");
        int append = rt_log_append || (started && *started == '1');
        /* always in append mode, so every write goes to the end: the game's
         * own lines must not overwrite what programs it started have written */
        if (!append) { FILE *t = fopen(f, "w"); if (t) fclose(t); }
        FILE *x = fopen(f, "a");
        /* (no line buffering on Windows: _IOLBF means full buffering there.
         * rt_log flushes instead) */
        if (x) {
            rt_logf = x;
#ifndef _WIN32
            setvbuf(x, 0, _IOLBF, 0);
#endif
        }
#ifdef _WIN32
        SetEnvironmentVariableA("RECOMP_LOG_STARTED", "1");
        _putenv("RECOMP_LOG_STARTED=1");
#else
        setenv("RECOMP_LOG_STARTED", "1", 1);
#endif
    }
    const char *cf = getenv("RECOMP_CRASHFILE");
    if (cf && *cf) crashpath = cf;   /* opened only when there is a crash */
#ifndef RECOMP_TRACE_INSN
    if (rt_loglevel >= 4)
        rt_log(0, "RECOMP_LOG=4 needs a trace build: run `make clean; make TRACE=1` in the output dir");
#endif
    watch_start();
}

void rt_log(int level, const char *fmt, ...) {
    if (level > rt_loglevel) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(rt_logf, "[%s] ", rt_logtag);
    vfprintf(rt_logf, fmt, ap);
    fputc('\n', rt_logf);
    va_end(ap);
    /* a log is for finding out where a program stopped: when it hangs or is
     * killed, lines still sitting in a buffer are exactly the ones needed.
     * (At RECOMP_LOG=3 and up only the important lines are flushed: speed.) */
    if (rt_logf != stderr && (level <= 1 || rt_loglevel <= 2)) fflush(rt_logf);
}

void rt_trace_insn(rt_ctx *c, uint64_t a) {
    c->iring[c->iring_pos++ % RT_IRING] = a;
    if (rt_loglevel >= 4) fprintf(rt_logf, "[recomp] t%d insn %#llx %s\n", c->tid,
                                   (unsigned long long)a, rt_symstr(a));
}

/* ------------------------------------------------------------------ */
/* symbols                                                             */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* module registry                                                     */
/* ------------------------------------------------------------------ */
rt_module *rt_mods[RT_MAX_MODULES];
volatile int rt_nmods;
static uint64_t max_usize = 64;
static void resolve_ops(rt_module *m);

void rt_add_module(rt_module *m) {
    m->lo = ~0ULL; m->hi = 0;
    for (int i = 0; i < m->nsegs; i++) {
        if (m->segs[i].vaddr < m->lo) m->lo = m->segs[i].vaddr;
        if (m->segs[i].vaddr + m->segs[i].memsz > m->hi) m->hi = m->segs[i].vaddr + m->segs[i].memsz;
    }
    if (m->format == 1 && m->sizeofimage) { m->lo = m->imagebase; m->hi = m->imagebase + m->sizeofimage; }
    resolve_ops(m);
    if (m->usize > max_usize) max_usize = m->usize;
    if (rt_nmods >= RT_MAX_MODULES) { fprintf(stderr, "[recomp] too many modules\n"); exit(127); }
    m->index = rt_nmods;
    rt_mods[rt_nmods] = m;
    __atomic_store_n(&rt_nmods, rt_nmods + 1, __ATOMIC_RELEASE);
}

rt_module *rt_module_of(uint64_t a) {
    int n = __atomic_load_n(&rt_nmods, __ATOMIC_ACQUIRE);
    for (int i = 0; i < n; i++)
        if (a >= rt_mods[i]->lo && a < rt_mods[i]->hi) return rt_mods[i];
    return 0;
}

const rt_regdesc *rt_regdescs(int *n) {
    *n = rt_nmods ? rt_mods[0]->nregs : 0;
    return rt_nmods ? rt_mods[0]->regs : 0;
}

const char *rt_symname(uint64_t a, uint64_t *off) {
    rt_module *m = rt_module_of(a);
    if (!m) return 0;
    int lo = 0, hi = m->nsyms;
    while (lo < hi) {               /* last symbol with addr <= a */
        int mid = (lo + hi) / 2;
        if (m->syms[mid].addr <= a) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) return 0;
    *off = a - m->syms[lo - 1].addr;
    if (*off > 0x100000) return 0;
    return m->syms[lo - 1].name;
}

/* No thread-local variables anywhere in the runtime: with MinGW they are
 * emulated (malloc'd per thread, freed by a destructor at thread exit), and
 * touching them from a DLL's DllMain during thread attach corrupts the
 * loader's TLS bookkeeping. Per-thread state lives in rt_ctx instead. */
const char *rt_symstr(uint64_t a) {
    static char buf[64][160];          /* only used for log text */
    static volatile int k;
    char *b = buf[__atomic_fetch_add(&k, 1, __ATOMIC_RELAXED) & 63];
    uint64_t off;
    const char *n = rt_in_image(a) ? rt_symname(a, &off) : 0;
    if (!n) { b[0] = 0; return b; }
    if (off) snprintf(b, 160, "<%s+%#llx>", n, (unsigned long long)off);
    else snprintf(b, 160, "<%s>", n);
    return b;
}

int rt_in_image(uint64_t a) { return rt_module_of(a) != 0; }

/* ------------------------------------------------------------------ */
/* execution                                                           */
/* ------------------------------------------------------------------ */
#define CACHE 8192

rt_ctx *rt_new_ctx(uint64_t stack_size) {
    static int next_tid;
    rt_ctx *c = calloc(1, sizeof *c);
    c->R = calloc(1, 0x10000);
    c->usize = max_usize;
    c->U = calloc(1, c->usize);
    c->cache_pc = calloc(CACHE, sizeof(uint64_t));
    c->cache_fn = calloc(CACHE, sizeof(void *));
    c->cache_mod = calloc(CACHE, sizeof(void *));
    c->tid = __sync_fetch_and_add(&next_tid, 1);
    {   /* for the watchdog */
        int k = __atomic_fetch_add(&n_ctx, 1, __ATOMIC_ACQ_REL);
        if (k < RT_MAX_CTX) all_ctx[k] = c;
    }
    if (stack_size) {
        uint8_t *s = malloc(stack_size);
        if (!s) { fprintf(stderr, "[recomp] out of memory for guest stack\n"); exit(127); }
        c->stack_lo = (uint64_t)(uintptr_t)s;
        c->stack_hi = c->stack_lo + stack_size;
    }
    *(uint16_t *)(c->R + RREG_FPUControlWord) = 0x37f;   /* initial FPU state */
    *(uint32_t *)(c->R + RREG_MXCSR) = 0x1f80;
    return c;
}

/* address -> recompiled chunk, in whichever module contains it; sets c->mod */
rt_chunk_fn rt_lookup(rt_ctx *c, uint64_t pc) {
    unsigned h = (unsigned)((pc ^ (pc >> 13)) & (CACHE - 1));
    if (c->cache_pc[h] == pc && c->cache_fn[h]) {
        c->mod = c->cache_mod[h];
        return (rt_chunk_fn)c->cache_fn[h];
    }
    rt_module *m = rt_module_of(pc);
    if (!m) return 0;
    uint64_t lo = 0, hi = m->naddr;
    while (lo < hi) {
        uint64_t mid = (lo + hi) / 2;
        if (m->addrs[mid] < pc) lo = mid + 1; else hi = mid;
    }
    if (lo >= m->naddr || m->addrs[lo] != pc) return 0;
    if (c->usize < m->usize) {          /* a module with more temporaries was loaded later */
        free(c->U);
        c->usize = m->usize;
        c->U = calloc(1, c->usize);
    }
    c->cache_pc[h] = pc;
    c->cache_fn[h] = (void *)m->chunks[m->addr_chunk[lo]];
    c->cache_mod[h] = m;
    c->mod = m;
    return m->chunks[m->addr_chunk[lo]];
}

static void explain_bad_target(rt_ctx *c, uint64_t pc, char *out, size_t n) {
    /* nearest lifted instruction below the target */
    rt_module *mm = rt_module_of(pc);
    uint64_t prev = 0;
    if (mm) {
        uint64_t lo = 0, hi = mm->naddr;
        while (lo < hi) { uint64_t m = (lo + hi) / 2; if (mm->addrs[m] < pc) lo = m + 1; else hi = m; }
        prev = lo ? mm->addrs[lo - 1] : 0;
    }
    if (pc == 0)
        snprintf(out, n, "target is 0: the program called a NULL function pointer");
    else if (rt_in_image(pc) && prev && pc - prev < 16)
        snprintf(out, n, "target is inside the program image, %llu bytes after the lifted "
                 "instruction at %#llx: either the jump lands in the middle of an instruction "
                 "(overlapping/obfuscated code) or a register held a wrong value earlier",
                 (unsigned long long)(pc - prev), (unsigned long long)prev);
    else if (rt_in_image(pc))
        snprintf(out, n, "target is inside the program image but not in any executable "
                 "section that was lifted: code in a data section, packed/encrypted code "
                 "that is decrypted at runtime, or self-modifying code");
    else
        snprintf(out, n, "target is outside the program image: a corrupted return address "
                 "or function pointer (check the stack dump), or code the program generated "
                 "at runtime (JIT)");
}

static uint64_t hook_pc[8];
static void (*hook_fn[8])(rt_ctx *);
static volatile int nhooks;

int rt_add_hook(uint64_t pc, void (*fn)(rt_ctx *)) {
    if (nhooks >= 8) return 0;
    hook_pc[nhooks] = pc;
    hook_fn[nhooks] = fn;
    __atomic_add_fetch(&nhooks, 1, __ATOMIC_RELEASE);
    return 1;
}

void rt_run(rt_ctx *c, uint64_t pc, uint64_t stop) {
    for (;;) {
        if (pc == stop) return;
        /* 32-bit programs: a RET instruction marks its target (lift.py) */
        c->xret = (pc & RT_RETFLAG) != 0;
        pc &= ~RT_RETFLAG;
        if (nhooks) {
            if (pc == (gptr_t)RT_HOOK_RET && c->hook_n > 0) {      /* a hooked function returned */
                int k = --c->hook_n;
                pc = c->hook_ret[k];
                hook_fn[c->hook_idx[k]](c);
                continue;
            }
            for (int i = 0; i < nhooks; i++)
                if (pc == hook_pc[i] && c->hook_n < 8) {   /* entering it: catch the return */
                    gptr_t *sp = (gptr_t *)(uintptr_t)REGP(c, RREG_RSP);
                    c->hook_ret[c->hook_n] = *sp;
                    c->hook_idx[c->hook_n++] = i;
                    *sp = (gptr_t)RT_HOOK_RET;
                }
        }
        rt_chunk_fn f = rt_lookup(c, pc);
        c->ring[c->ring_pos++ % RT_RING].from = c->cur;
        c->ring[(c->ring_pos - 1) % RT_RING].to = pc;
        c->n_transfers++;
        if (!f) {
            uint64_t from = c->cur;
            if (rt_platform_unknown_target(c, &pc)) continue;
            char why[512];
            explain_bad_target(c, pc, why, sizeof why);
            c->cur = from;
#ifdef RT_GUEST32
            rt_crash_exit_code = (int)0xC0000005;   /* how Windows ends the original: access violation */
#endif
            rt_crash(c, "program jumped to an address that has no recompiled code", pc, why);
        }
        if (rt_loglevel >= 3) {
            uint64_t off;
            const char *n = rt_symname(pc, &off);
            if (n && off == 0)
                fprintf(rt_logf, "[%s] t%d %#llx %s -> %#llx <%s>\n", rt_logtag, c->tid,
                        (unsigned long long)c->cur, rt_symstr(c->cur), (unsigned long long)pc, n);
        }
        pc = f(pc, c);
    }
}

/* ------------------------------------------------------------------ */
/* crash report                                                        */
/* ------------------------------------------------------------------ */
static void classify(rt_ctx *c, uint64_t a, char *out, size_t n) {
    if (a < 0x10000) snprintf(out, n, "NULL pointer (+%#llx)", (unsigned long long)a);
    else if (c && a >= c->stack_lo - 0x10000 && a < c->stack_lo)
        snprintf(out, n, "just below the guest stack: STACK OVERFLOW (deep/infinite recursion?)");
    else if (c && a >= c->stack_lo && a < c->stack_hi + 0x1000) snprintf(out, n, "guest stack");
    else if (rt_in_image(a)) snprintf(out, n, "program image %s", rt_symstr(a));
    else if (sizeof(gptr_t) == 8 && a >= 0x0000800000000000ULL)
        snprintf(out, n, "non-canonical address: garbage pointer");
    else snprintf(out, n, "heap or unmapped memory");
}

static void report(FILE *f, rt_ctx *c, const char *reason, uint64_t fault, const char *detail) {
    char cls[256];
    fprintf(f, "=== RECOMP CRASH REPORT ===\n");
    fprintf(f, "reason: %s\n", reason);
    if (detail && *detail) fprintf(f, "detail: %s\n", detail);
    if (!c) { fprintf(f, "(no guest context on this thread)\n=== END ===\n"); return; }
    fprintf(f, "thread: %d   callback_depth: %d   control_transfers: %llu\n", c->tid, c->depth,
            (unsigned long long)c->n_transfers);
    fprintf(f, "instruction: %#llx %s\n", (unsigned long long)c->cur, rt_symstr(c->cur));
    if (!c->cur && !c->n_transfers)
        fprintf(f, "note: no guest instruction has run on this thread yet - the crash is in the "
                "recomp RUNTIME itself (setup code), not in the translated program. Bug in rt_*.c\n");
    classify(c, fault, cls, sizeof cls);
    fprintf(f, "address: %#llx  [%s]\n", (unsigned long long)fault, cls);
    fprintf(f, "registers:\n");
    int col = 0, rt_nregs;
    const rt_regdesc *rt_regs = rt_regdescs(&rt_nregs);
    for (int i = 0; i < rt_nregs; i++) {
        const rt_regdesc *r = &rt_regs[i];
        if (r->size == 8) {
            uint64_t v = L(c->R + r->off, 8);
            fprintf(f, "  %-9s 0x%016llx %s\n", r->name, (unsigned long long)v,
                    rt_in_image(v) ? rt_symstr(v) : "");
        } else if (r->size == 4) {
            uint64_t v = L(c->R + r->off, 4);
            fprintf(f, "  %-9s 0x%08llx %s\n", r->name, (unsigned long long)v,
                    rt_in_image(v) ? rt_symstr(v) : "");
        } else if (r->size == 1) {
            fprintf(f, "%s%s=%d", col++ ? " " : "  flags: ", r->name, c->R[r->off] & 1);
        }
    }
    if (col) fprintf(f, "\n");
    for (int i = 0; i < rt_nregs; i++) {
        const rt_regdesc *r = &rt_regs[i];
        if (r->size == 16) {
            int nz = 0;
            for (int k = 0; k < 16; k++) nz |= c->R[r->off + k];
            if (!nz) continue;          /* only non-zero vector registers */
            fprintf(f, "  %-6s ", r->name);
            for (int k = 15; k >= 0; k--) fprintf(f, "%02x", c->R[r->off + k]);
            double d; memcpy(&d, c->R + r->off, 8);
            fprintf(f, "  (low double %g)\n", d);
        }
    }
    uint64_t sp = REGP(c, RREG_RSP);
    const int W = (int)sizeof(gptr_t);      /* size of a stack slot */
    fprintf(f, "stack (%s=%#llx, guest stack %#llx-%#llx):\n", W == 8 ? "RSP" : "ESP", (unsigned long long)sp,
            (unsigned long long)c->stack_lo, (unsigned long long)c->stack_hi);
    if (sp >= c->stack_lo && sp + W <= c->stack_hi) {
        for (int i = 0; i < 32 && sp + W * i + W <= c->stack_hi; i++) {
            uint64_t v = *(gptr_t *)(uintptr_t)(sp + W * i);
            fprintf(f, W == 8 ? "  [rsp+0x%03x] 0x%016llx %s\n" : "  [esp+0x%03x] 0x%08llx %s\n", W * i,
                    (unsigned long long)v, rt_in_image(v) ? rt_symstr(v) : "");
        }
    } else fprintf(f, "  %s is outside the guest stack - not dumping\n", W == 8 ? "RSP" : "ESP");
    fprintf(f, "recent control transfers (oldest first, from -> to):\n");
    unsigned n = c->ring_pos < RT_RING ? c->ring_pos : RT_RING;
    for (unsigned i = 0; i < n; i++) {
        unsigned k = (c->ring_pos - n + i) % RT_RING;
        fprintf(f, "  %#llx %s -> %#llx %s\n", (unsigned long long)c->ring[k].from,
                rt_symstr(c->ring[k].from), (unsigned long long)c->ring[k].to,
                rt_symstr(c->ring[k].to));
    }
    if (c->iring_pos) {
        fprintf(f, "recent instructions (oldest first):\n");
        unsigned m = c->iring_pos < RT_IRING ? c->iring_pos : RT_IRING;
        for (unsigned i = 0; i < m; i++)
            fprintf(f, "  %#llx\n", (unsigned long long)c->iring[(c->iring_pos - m + i) % RT_IRING]);
    }
    fprintf(f, "=== END ===\n");
    fflush(f);
}

int rt_crash_signal;   /* set by the Linux signal handler: die by the same signal */
int rt_crash_exit_code = 127;

void rt_crash(rt_ctx *c, const char *reason, uint64_t fault, const char *detail) {
    fflush(stdout);
    report(stderr, c, reason, fault, detail);
    FILE *crashf = crashpath ? fopen(crashpath, "w") : 0;
    if (crashf) { report(crashf, c, reason, fault, detail); fclose(crashf); }
    if (rt_logf && rt_logf != stderr) fflush(rt_logf);
#ifdef _WIN32
#ifdef RT_GUEST32
    TerminateProcess(GetCurrentProcess(), (UINT)rt_crash_exit_code);   /* (no DLL detach code: the state is broken) */
#endif
    ExitProcess((UINT)rt_crash_exit_code);
#else
    if (rt_crash_signal) { signal(rt_crash_signal, SIG_DFL); raise(rt_crash_signal); }
    _exit(127);
#endif
}

void rt_unsupported(rt_ctx *c, const char *what, uint64_t pc) {
    char d[512];
    snprintf(d, sizeof d, "the lifter could not translate this instruction (%s). "
             "See lift_report.txt for every place this happens; fix it in lift.py", what);
    c->cur = pc;
    rt_crash(c, "reached an instruction the generator could not translate", pc, d);
}

/* RECOMP_DUMP=file : save the program's memory (image + heap) */
void rt_dump_memory(uint64_t heap_lo, uint64_t heap_hi) {
    const char *path = getenv("RECOMP_DUMP");
    if (!path) return;
    FILE *f = fopen(path, "wb");
    if (!f) return;
    for (int k = 0; k < rt_nmods; k++)
        for (int i = 0; i < rt_mods[k]->nsegs; i++) {
            uint64_t v = rt_mods[k]->segs[i].vaddr, n = rt_mods[k]->segs[i].memsz;
            fwrite(&v, 8, 1, f); fwrite(&n, 8, 1, f); fwrite((void *)(uintptr_t)v, 1, n, f);
        }
    if (heap_hi > heap_lo) {
        uint64_t n = heap_hi - heap_lo;
        fwrite(&heap_lo, 8, 1, f); fwrite(&n, 8, 1, f); fwrite((void *)(uintptr_t)heap_lo, 1, n, f);
    }
    fclose(f);
    rt_log(1, "memory dumped to %s", path);
}

/* ------------------------------------------------------------------ */
/* special CPU instructions                                            */
/* ------------------------------------------------------------------ */
enum { K_UNKNOWN, K_SYSCALL, K_CPUID, K_RDTSC, K_XGETBV, K_NOP, K_HLT, K_INT3,
       K_MOVMSKPS, K_MOVMSKPD, K_PSHUFB, K_SWI,
       K_LOCK, K_UNLOCK,
       K_AESENC, K_AESENCLAST, K_AESDEC, K_AESDECLAST, K_AESIMC, K_AESKEYGEN, K_PCLMUL,
       K_RSQRTPS, K_RSQRTSS, K_RCPPS, K_RCPSS,
       K_IN, K_OUT, K_DESCR, K_PRIV, K_FROMBCD, K_TOBCD, K_ZERO, K_CLZERO,
       K_SIMD = 1000 /* K_SIMD + S_xxx: packed SSE/AVX ops, see simd_op() */ };

/* SSE/MMX/AVX ops Ghidra leaves as CALLOTHER. AVX names ("vdivps_avx",
 * "vpermd_avx2", "vpmullq_avx512vl") map to the same entry as the SSE name. */
#define SIMD_OPS(X) \
    X(divps) X(divpd) X(sqrtps) X(sqrtpd) X(maxps) X(minps) X(subps) \
    X(cmpps) X(cmpsd) X(cvtps2dq) X(cvtdq2ps) X(cvtdq2pd) X(cvtpd2dq) X(cvtps2pd) \
    X(roundps) X(roundsd) X(blendvps) \
    X(pmulhw) X(pmulhuw) X(pmulld) X(pmuldq) X(pmullq) X(pmaddwd) X(pmaddubsw) \
    X(psadbw) X(mpsadbw) X(pavgb) X(pabsw) \
    X(paddsb) X(paddsw) X(paddusb) X(paddusw) X(psubsb) X(psubsw) X(psubusb) X(psubusw) \
    X(packsswb) X(packssdw) \
    X(psllw) X(psrlw) X(psraw) X(pslld) X(psrld) X(psrad) X(psllq) X(psrlq) X(psrldq) X(pslldq) \
    X(paddq) X(psubd) X(psubq) X(pand) X(por) X(pcmpeqb) X(pcmpeqw) X(pcmpeqd) \
    X(pshufw) X(pshuflw) X(pshufhw) X(pshufd) X(pshufb) X(permilps) X(shufps) X(permq) X(permd) \
    X(unpcklps) X(unpckhps) X(unpcklpd) X(punpckldq) X(punpcklqdq) \
    X(pmovsxdq) X(pmovzxwd) X(lddqu) X(movntdq) X(movdq2q) X(PackedIntToFloatingDwordConv) \
    X(pcmpistri) X(stmxcsr) X(ldmxcsr) \
    X(pblendvb) X(blendvpd) X(punpcklwd) X(psllvq) X(psrlvq) X(psllvd) X(psrlvd) X(psravd) \
    X(pmovzxdq) X(pmovzxbd) X(pmovzxbw) X(pmovzxbq) X(pmovzxwq) X(pmovsxbw) X(pmovsxbd) X(pmovsxwd) \
    X(pmaxuq) X(pminuq) X(pmaskmovd) X(pmaskmovq) X(maskmovps) X(maskmovpd) X(roundss) \
    X(pcmpestri) X(movntpd) X(movntps) \
    X(insertps) X(extractps) X(blendps) X(blendpd) X(pblendw) X(dpps) X(dppd) X(cmppd) X(cmpss) \
    X(maxpd) X(minpd) X(movntdqa) X(pabsb) X(pabsd) X(packusdw) X(pavgw) \
    X(phaddw) X(phaddd) X(phaddsw) X(phsubw) X(phsubd) X(phsubsw) X(phminposuw) \
    X(pmovsxbq) X(pmovsxwq) X(pmulhrsw) X(psignb) X(psignw) X(psignd) X(roundpd) X(crc32) \
    X(pcmpistrm) X(pcmpestrm) X(haddps) X(haddpd) X(hsubps) X(hsubpd) X(perm2f128) X(perm2i128) \
    X(pmullw) X(punpcklbw) X(punpckhbw) X(punpckhwd) X(punpckhdq) X(punpckhqdq) X(pmaxub) X(pminub) \
    X(pmaxsw) X(pminsw) X(palignr) X(sha1rnds4) X(sha1nexte) X(sha1msg1) X(sha1msg2) X(sha256rnds2) \
    X(sha256msg1) X(sha256msg2) X(cvtps2ph) X(cvtph2ps) \
    X(addsubps) X(addsubpd) X(subpd) X(cvtpd2ps) X(movshdup) X(movsldup) X(packuswb) X(pandn) X(pblendd) \
    X(pcmpgtb) X(pcmpgtw) X(pcmpgtd) X(pcmpgtq) X(permilpd) X(permpd) X(permps) X(pmaxsb) X(pmaxsd) \
    X(pmaxud) X(pmaxuw) X(pminsb) X(pminsd) X(pminud) X(pminuw) X(pmuludq) X(psubb) X(psubw) X(shufpd) \
    X(unpckhpd) X(movhpd) X(movhps) X(movlpd) X(movlps) X(pinsrb) X(pinsrw)
#define S_ENUM(x) S_##x,
#define S_NAME(x) #x,
enum { SIMD_OPS(S_ENUM) S_COUNT };
static const char *const simd_names[] = { SIMD_OPS(S_NAME) };

static int simd_lookup(const char *s) {
    char b[64];
    snprintf(b, sizeof b, "%s", s);
    /* VEX forms are named "v<op>_avx"/"v<op>_avx2", others "<op>_sha", "v<op>_f16c" */
    char *u = strstr(b, "_avx");
    if (!u) u = strstr(b, "_sha");
    if (!u) u = strstr(b, "_f16c");
    const char *p = b;
    if (u) { *u = 0; if (b[0] == 'v') p = b + 1; }
    for (int i = 0; i < S_COUNT; i++)
        if (!strcmp(p, simd_names[i])) return i;
    return -1;
}
static void resolve_ops(rt_module *m) {
    int *op_kind = m->opkind = calloc(m->nops + 1, sizeof(int));
    for (int i = 0; i < m->nops; i++) {
        const char *s = m->opnames[i];
        if (!strcmp(s, "syscall")) op_kind[i] = K_SYSCALL;
        else if (!strncmp(s, "cpuid", 5)) op_kind[i] = K_CPUID;
        else if (!strcmp(s, "rdtsc") || !strcmp(s, "rdtscp")) op_kind[i] = K_RDTSC;
        else if (!strcmp(s, "xgetbv") || !strcmp(s, "xinuse")) op_kind[i] = K_XGETBV;
        else if (!strcmp(s, "LOCK")) op_kind[i] = K_LOCK;
        else if (!strcmp(s, "UNLOCK")) op_kind[i] = K_UNLOCK;
        else if (!strcmp(s, "pause") ||
                 !strcmp(s, "lfence") || !strcmp(s, "mfence") || !strcmp(s, "sfence") ||
                 !strncmp(s, "prefetch", 8) || !strcmp(s, "clflush") || !strcmp(s, "endbr64") ||
                 !strcmp(s, "ShadowStackPush8B") || !strcmp(s, "ShadowStackPush4B") ||
                 !strcmp(s, "monitorx") || !strcmp(s, "mwaitx") || !strcmp(s, "ffree") ||
                 !strcmp(s, "FastExitMediaState") || !strcmp(s, "cldemote") ||
                 !strcmp(s, "xend"))  /* TSX commit: XBEGIN is treated as "transaction started" */
            op_kind[i] = K_NOP;
        else if (!strcmp(s, "hlt")) op_kind[i] = K_HLT;
        else if (!strcmp(s, "int3") || !strcmp(s, "invalidInstructionException")) op_kind[i] = K_INT3;
        else if (!strcmp(s, "swi")) op_kind[i] = K_SWI;
        else if (!strcmp(s, "movmskps") || !strncmp(s, "vmovmskps", 9)) op_kind[i] = K_MOVMSKPS;
        else if (!strcmp(s, "movmskpd") || !strncmp(s, "vmovmskpd", 9)) op_kind[i] = K_MOVMSKPD;
        else if (!strcmp(s, "pshufb")) op_kind[i] = K_PSHUFB;
        else if (!strcmp(s, "aesenc")) op_kind[i] = K_AESENC;
        else if (!strcmp(s, "aesenclast")) op_kind[i] = K_AESENCLAST;
        else if (!strcmp(s, "aesdec")) op_kind[i] = K_AESDEC;
        else if (!strcmp(s, "aesdeclast")) op_kind[i] = K_AESDECLAST;
        else if (!strcmp(s, "aesimc")) op_kind[i] = K_AESIMC;
        else if (!strcmp(s, "aeskeygenassist")) op_kind[i] = K_AESKEYGEN;
        else if (!strcmp(s, "pclmulqdq")) op_kind[i] = K_PCLMUL;
        /* approximate reciprocal / reciprocal sqrt (SSE and AVX "v..." forms) */
        else if (!strncmp(s, "rsqrtps", 7) || !strncmp(s, "vrsqrtps", 8)) op_kind[i] = K_RSQRTPS;
        else if (!strncmp(s, "rsqrtss", 7) || !strncmp(s, "vrsqrtss", 8)) op_kind[i] = K_RSQRTSS;
        else if (!strncmp(s, "rcpps", 5) || !strncmp(s, "vrcpps", 6)) op_kind[i] = K_RCPPS;
        else if (!strncmp(s, "rcpss", 5) || !strncmp(s, "vrcpss", 6)) op_kind[i] = K_RCPSS;
        /* system-level instructions: no meaning for a recompiled user program */
        else if (!strcmp(s, "in")) op_kind[i] = K_IN;
        else if (!strcmp(s, "out")) op_kind[i] = K_OUT;
        else if (!strcmp(s, "LocalDescriptorTableRegister") ||
                 !strcmp(s, "GlobalDescriptorTableRegister") ||
                 !strcmp(s, "InterruptDescriptorTableRegister") ||
                 !strcmp(s, "SegmentLimit") || !strcmp(s, "TaskRegister") ||
                 !strcmp(s, "verr") || !strcmp(s, "verw")) op_kind[i] = K_DESCR;
        else if (!strcmp(s, "sysret") || !strncmp(s, "enclv", 5) || !strncmp(s, "enclu", 5) ||
                 !strcmp(s, "wrmsr") || !strcmp(s, "rdmsr") || !strcmp(s, "invlpg") ||
                 !strcmp(s, "stgi") || !strcmp(s, "clgi") || !strcmp(s, "wbinvd") || !strcmp(s, "invd"))
            op_kind[i] = K_PRIV;
        else if (!strncmp(s, "rdpkru", 6)) op_kind[i] = K_ZERO;   /* protection keys: all access allowed */
        else if (!strcmp(s, "clzero")) op_kind[i] = K_CLZERO;
        else if (!strcmp(s, "from_bcd")) op_kind[i] = K_FROMBCD;
        else if (!strcmp(s, "to_bcd")) op_kind[i] = K_TOBCD;
        else {
            int k = simd_lookup(s);
            if (k >= 0) op_kind[i] = K_SIMD + k;
        }
    }
}

/* x86 LOCK prefix: Ghidra marks it with LOCK()/UNLOCK() but the read-modify-write
 * in between is ordinary p-code. With real threads that must be atomic, so all
 * locked instructions take one global spinlock (they are short).
 * A game has far more threads than CPU cores: when the OS pauses the thread
 * holding the lock, pure spinning makes every waiter burn its whole time slice
 * (that is a multi-second freeze with ~100 threads). So a waiter spins only
 * briefly and then gives its CPU away, letting the holder finish. */
static void rt_yield(void) {
#ifdef _WIN32
    if (!SwitchToThread()) Sleep(0);
#else
    sched_yield();
#endif
}
/* re-entrant per thread (rt_ctx.lock_depth): safe if a lock is ever nested */
void rt_lock(void) {
    rt_ctx *c = rt_current_ctx();
    if (c && c->lock_depth++) return;
    if (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE)) {
        __atomic_fetch_add(&g_lock_waits, 1, __ATOMIC_RELAXED);
        for (unsigned spins = 0;; spins++) {
            if (!__atomic_load_n(&g_lock, __ATOMIC_RELAXED) &&
                !__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE))
                break;
            if (spins < 100) {
                __builtin_ia32_pause();
            } else {
                __atomic_fetch_add(&g_lock_yields, 1, __ATOMIC_RELAXED);
                rt_yield();
            }
        }
    }
    g_lock_n++;
}
void rt_unlock(void) {
    rt_ctx *c = rt_current_ctx();
    if (!c || (c->lock_depth > 0 && --c->lock_depth == 0)) __atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE);
}

/* CVTPS2DQ/CVTSS2SI/CVTSD2SI/CVTPD2DQ: round by the guest's MXCSR mode
 * (lift.py emits this; Ghidra itself treats them as truncation).
 * Done explicitly, independent of the host's own rounding mode. */
long double rt_rint_mx(long double x, uint32_t mxcsr) {
    if (x != x) return x;
    switch ((mxcsr >> 13) & 3) {
    case 1: return floorl(x);
    case 2: return ceill(x);
    case 3: return truncl(x);
    default: {                      /* round to nearest, ties to even */
        long double f = floorl(x), d = x - f;
        if (d > 0.5L) return f + 1;
        if (d < 0.5L) return f;
        return fmodl(f, 2.0L) == 0 ? f : f + 1;
    }
    }
}

/* CMPXCHG16B for the generated code (lift.py emits these for 16-byte atomics):
 * a real cmpxchg16b on the host, so 16-byte lock-free stacks/queues stay
 * lock-free. The guest's own CMPXCHG16B already needs 16-byte alignment. */
#ifdef __SIZEOF_INT128__
__attribute__((target("cx16")))
int rt_cas16(void *p, void *expected, const void *desired) {
    unsigned __int128 e, d, old;
    memcpy(&e, expected, 16);
    memcpy(&d, desired, 16);
    old = __sync_val_compare_and_swap((volatile unsigned __int128 *)p, e, d);
    memcpy(expected, &old, 16);
    return old == e;
}
__attribute__((target("cx16")))
void rt_atomic_load16(const void *p, void *out) {
    /* compare-with-0/swap-with-0: an atomic 16-byte read that changes nothing */
    unsigned __int128 v = __sync_val_compare_and_swap((volatile unsigned __int128 *)p, 0, 0);
    memcpy(out, &v, 16);
}
#endif

/* AES-NI / PCLMUL: run them on the host CPU's own AES unit */
#include <wmmintrin.h>
__attribute__((target("aes,pclmul,sse4.1")))
static void aes_op(int kind, uint8_t *out, int osz, int n, const uint8_t *const *in, const int *sz) {
    __m128i a = _mm_loadu_si128((const __m128i *)in[0]), b = _mm_setzero_si128(), r;
    if (n > 1 && sz[1] >= 16) b = _mm_loadu_si128((const __m128i *)in[1]);
    int imm = n > 2 ? (int)L(in[n - 1], sz[n - 1]) : (n > 1 && sz[1] < 16 ? (int)L(in[1], sz[1]) : 0);
    switch (kind) {
    case K_AESENC: r = _mm_aesenc_si128(a, b); break;
    case K_AESENCLAST: r = _mm_aesenclast_si128(a, b); break;
    case K_AESDEC: r = _mm_aesdec_si128(a, b); break;
    case K_AESDECLAST: r = _mm_aesdeclast_si128(a, b); break;
    case K_AESIMC: r = _mm_aesimc_si128(a); break;
    case K_AESKEYGEN:
        switch (imm & 0xff) {   /* the immediate must be a compile-time constant */
#define K(i) case i: r = _mm_aeskeygenassist_si128(a, i); break;
        K(0x01) K(0x02) K(0x04) K(0x08) K(0x10) K(0x20) K(0x40) K(0x80) K(0x1b) K(0x36)
#undef K
        default: r = _mm_aeskeygenassist_si128(a, 0); break;
        }
        break;
    default:
        switch (imm & 0x11) {
        case 0x00: r = _mm_clmulepi64_si128(a, b, 0x00); break;
        case 0x01: r = _mm_clmulepi64_si128(a, b, 0x01); break;
        case 0x10: r = _mm_clmulepi64_si128(a, b, 0x10); break;
        default: r = _mm_clmulepi64_si128(a, b, 0x11); break;
        }
    }
    if (out) memcpy(out, &r, osz < 16 ? osz : 16);
}

/* RSQRTPS/RCPPS and the scalar SS forms. Run on the host's own instructions so the
 * approximate results are bit-identical to what the original program got.
 * Packed: every float lane of the source (last input), 16/32/64-byte registers.
 * Scalar: only lane 0 is computed; if the output is wider than 4 bytes the upper
 * lanes come from the first input (destination / AVX src1), as on real hardware. */
static void rsqrt_rcp_op(int kind, uint8_t *out, int osz, int n,
                         const uint8_t *const *in, const int *sz) {
    uint8_t r[64] = {0};
    const uint8_t *x = in[n - 1];
    int w = sz[n - 1] < 64 ? sz[n - 1] : 64;
    int rs = kind == K_RSQRTPS || kind == K_RSQRTSS;
    if (kind == K_RSQRTSS || kind == K_RCPSS) {
        if (n > 1 && osz > 4) memcpy(r, in[0], sz[0] < 64 ? sz[0] : 64);
        float f; memcpy(&f, x, 4);
        __m128 v = _mm_set_ss(f);
        v = rs ? _mm_rsqrt_ss(v) : _mm_rcp_ss(v);
        f = _mm_cvtss_f32(v);
        memcpy(r, &f, 4);
        w = osz < 64 ? osz : 64;
    } else {
        for (int k = 0; k < w; k += 16) {
            float t[4] = {0};
            int cnt = w - k < 16 ? w - k : 16;
            memcpy(t, x + k, cnt);
            __m128 v = _mm_loadu_ps(t);
            v = rs ? _mm_rsqrt_ps(v) : _mm_rcp_ps(v);
            _mm_storeu_ps(t, v);
            memcpy(r + k, t, cnt);
        }
    }
    if (out) { memset(out, 0, osz); memcpy(out, r, osz < w ? osz : w); }
}

/* ------------------------------------------------------------------ */
/* packed SSE / MMX / AVX ops                                          */
/* ------------------------------------------------------------------ */
typedef int8_t   s8a  __attribute__((may_alias));
typedef int16_t  s16a __attribute__((may_alias));
typedef uint16_t u16a __attribute__((may_alias));
typedef int32_t  s32a __attribute__((may_alias));
typedef uint32_t u32a __attribute__((may_alias));
typedef int64_t  s64a __attribute__((may_alias));
typedef uint64_t u64a __attribute__((may_alias));
typedef float    f32a __attribute__((may_alias));
typedef double   f64a __attribute__((may_alias));

static inline int sat8(int v)   { return v < -128 ? -128 : v > 127 ? 127 : v; }
static inline int usat8(int v)  { return v < 0 ? 0 : v > 255 ? 255 : v; }
static inline int sat16(int v)  { return v < -32768 ? -32768 : v > 32767 ? 32767 : v; }
static inline int usat16(int v) { return v < 0 ? 0 : v > 65535 ? 65535 : v; }

/* CMPPS/CMPSD predicate (0-31; 16-31 are the signalling twins of 0-15) */
static int fcmp(double a, double b, int p) {
    int un = a != a || b != b;
    switch (p & 15) {
    case 0: return !un && a == b;   case 1: return a < b;
    case 2: return a <= b;          case 3: return un;
    case 4: return un || a != b;    case 5: return !(a < b);
    case 6: return !(a <= b);       case 7: return !un;
    case 8: return un || a == b;    case 9: return !(a >= b);
    case 10: return !(a > b);       case 11: return 0;
    case 12: return !un && a != b;  case 13: return a >= b;
    case 14: return a > b;          default: return 1;
    }
}

/* rounding mode 0 nearest-even, 1 down, 2 up, 3 truncate (MXCSR / ROUNDxx encoding) */
__attribute__((target("sse4.1")))
static __m128 rnd_ps(__m128 v, int m) {
    switch (m & 3) {
    case 0: return _mm_round_ps(v, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC);
    case 1: return _mm_round_ps(v, _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC);
    case 2: return _mm_round_ps(v, _MM_FROUND_TO_POS_INF | _MM_FROUND_NO_EXC);
    default: return _mm_round_ps(v, _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC);
    }
}
__attribute__((target("sse4.1")))
static __m128d rnd_pd(__m128d v, int m) {
    switch (m & 3) {
    case 0: return _mm_round_pd(v, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC);
    case 1: return _mm_round_pd(v, _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC);
    case 2: return _mm_round_pd(v, _MM_FROUND_TO_POS_INF | _MM_FROUND_NO_EXC);
    default: return _mm_round_pd(v, _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC);
    }
}

/* PCMPISTRI on the host's SSE4.2 unit (the immediate must be a constant) */
__attribute__((target("sse4.2")))
static void pcmpistri_host(const uint8_t *pa, const uint8_t *pb, int imm, int *f) {
    __m128i a = _mm_loadu_si128((const __m128i *)pa), b = _mm_loadu_si128((const __m128i *)pb);
    switch (imm & 0x7f) {
#define PI1(i) case (i): f[0] = _mm_cmpistri(a, b, (i)); f[1] = _mm_cmpistrc(a, b, (i)); \
        f[2] = _mm_cmpistrz(a, b, (i)); f[3] = _mm_cmpistrs(a, b, (i)); f[4] = _mm_cmpistro(a, b, (i)); break;
#define PI4(i) PI1(i) PI1((i) + 1) PI1((i) + 2) PI1((i) + 3)
#define PI16(i) PI4(i) PI4((i) + 4) PI4((i) + 8) PI4((i) + 12)
#define PI64(i) PI16(i) PI16((i) + 16) PI16((i) + 32) PI16((i) + 48)
    PI64(0) PI64(64)
#undef PI1
#undef PI4
#undef PI16
#undef PI64
    }
}

/* PCMPESTRI on the host's SSE4.2 unit (explicit lengths) */
__attribute__((target("sse4.2")))
static void pcmpestri_host(const uint8_t *pa, int la, const uint8_t *pb, int lb, int imm, int *f) {
    __m128i a = _mm_loadu_si128((const __m128i *)pa), b = _mm_loadu_si128((const __m128i *)pb);
    switch (imm & 0x7f) {
#define PE1(i) case (i): f[0] = _mm_cmpestri(a, la, b, lb, (i)); f[1] = _mm_cmpestrc(a, la, b, lb, (i)); \
        f[2] = _mm_cmpestrz(a, la, b, lb, (i)); f[3] = _mm_cmpestrs(a, la, b, lb, (i)); \
        f[4] = _mm_cmpestro(a, la, b, lb, (i)); break;
#define PE4(i) PE1(i) PE1((i) + 1) PE1((i) + 2) PE1((i) + 3)
#define PE16(i) PE4(i) PE4((i) + 4) PE4((i) + 8) PE4((i) + 12)
#define PE64(i) PE16(i) PE16((i) + 16) PE16((i) + 32) PE16((i) + 48)
    PE64(0) PE64(64)
#undef PE1
#undef PE4
#undef PE16
#undef PE64
    }
}

/* write a 1-byte flag register (CF, ZF, ...) by name, if the module has it */
static void set_flag(rt_ctx *c, const char *name, int v) {
    rt_module *m = (rt_module *)c->mod;
    if (!m) return;
    for (int i = 0; i < m->nregs; i++)
        if (m->regs[i].size == 1 && !strcmp(m->regs[i].name, name)) { c->R[m->regs[i].off] = v != 0; return; }
}

/* Operand convention (Ghidra x86 CALLOTHERs): inputs are the destination /
 * VEX.vvvv source first, then the r/m source, then an imm8 (size <= 4).
 * Two-source ops use the last two data inputs (A, B); one-source ops use the
 * last data input (B). Works for 8-byte MMX, 16-byte XMM and 32-byte YMM. */
/* PCMPISTRM / PCMPESTRM on the host's SSE4.2 unit: mask -> XMM0, flags */
__attribute__((target("sse4.2")))
static void pcmpistrm_host(const uint8_t *pa, const uint8_t *pb, int imm, uint8_t *r, int *f) {
    __m128i a = _mm_loadu_si128((const __m128i *)pa), b = _mm_loadu_si128((const __m128i *)pb), m = _mm_setzero_si128();
    switch (imm & 0x7f) {
#define PM1(i) case (i): m = _mm_cmpistrm(a, b, (i)); f[1] = _mm_cmpistrc(a, b, (i)); \
        f[2] = _mm_cmpistrz(a, b, (i)); f[3] = _mm_cmpistrs(a, b, (i)); f[4] = _mm_cmpistro(a, b, (i)); break;
#define PM4(i) PM1(i) PM1((i) + 1) PM1((i) + 2) PM1((i) + 3)
#define PM16(i) PM4(i) PM4((i) + 4) PM4((i) + 8) PM4((i) + 12)
    PM16(0) PM16(16) PM16(32) PM16(48) PM16(64) PM16(80) PM16(96) PM16(112)
#undef PM1
#undef PM4
#undef PM16
    }
    _mm_storeu_si128((__m128i *)r, m);
}
__attribute__((target("sse4.2")))
static void pcmpestrm_host(const uint8_t *pa, int la, const uint8_t *pb, int lb, int imm, uint8_t *r, int *f) {
    __m128i a = _mm_loadu_si128((const __m128i *)pa), b = _mm_loadu_si128((const __m128i *)pb), m = _mm_setzero_si128();
    switch (imm & 0x7f) {
#define PN1(i) case (i): m = _mm_cmpestrm(a, la, b, lb, (i)); f[1] = _mm_cmpestrc(a, la, b, lb, (i)); \
        f[2] = _mm_cmpestrz(a, la, b, lb, (i)); f[3] = _mm_cmpestrs(a, la, b, lb, (i)); \
        f[4] = _mm_cmpestro(a, la, b, lb, (i)); break;
#define PN4(i) PN1(i) PN1((i) + 1) PN1((i) + 2) PN1((i) + 3)
#define PN16(i) PN4(i) PN4((i) + 4) PN4((i) + 8) PN4((i) + 12)
    PN16(0) PN16(16) PN16(32) PN16(48) PN16(64) PN16(80) PN16(96) PN16(112)
#undef PN1
#undef PN4
#undef PN16
    }
    _mm_storeu_si128((__m128i *)r, m);
}
/* SHA extensions on the host's SHA unit (a program only uses them after
 * checking CPUID, and RECOMP_CPUID only reports SHA when the host has it) */
__attribute__((target("sha,sse4.1")))
static void sha_host(int op, const uint8_t *pa, const uint8_t *pb, const uint8_t *pc, int imm, uint8_t *r);
/* F16C conversions on the host */
__attribute__((target("f16c,avx")))
static void f16c_host(int to_half, const uint8_t *src, int ssz, int imm, uint8_t *r, int rsz) {
    if (to_half) {
        __m128i h = _mm_setzero_si128();
        if (ssz >= 32) {
            __m256 v = _mm256_loadu_ps((const float *)src);
            switch (imm & 7) {
            case 0: h = _mm256_cvtps_ph(v, 0); break; case 1: h = _mm256_cvtps_ph(v, 1); break;
            case 2: h = _mm256_cvtps_ph(v, 2); break; case 3: h = _mm256_cvtps_ph(v, 3); break;
            default: h = _mm256_cvtps_ph(v, 4); break;
            }
        } else {
            __m128 v = _mm_loadu_ps((const float *)src);
            switch (imm & 7) {
            case 0: h = _mm_cvtps_ph(v, 0); break; case 1: h = _mm_cvtps_ph(v, 1); break;
            case 2: h = _mm_cvtps_ph(v, 2); break; case 3: h = _mm_cvtps_ph(v, 3); break;
            default: h = _mm_cvtps_ph(v, 4); break;
            }
        }
        _mm_storeu_si128((__m128i *)r, h);
    } else {
        __m128i h = _mm_loadu_si128((const __m128i *)src);
        if (rsz >= 32) _mm256_storeu_ps((float *)r, _mm256_cvtph_ps(h));
        else _mm_storeu_ps((float *)r, _mm_cvtph_ps(h));
    }
}

static void simd_op(rt_ctx *ctx, int op, uint8_t *out, int osz, int n,
                    const uint8_t *const *in, const int *sz) {
    /* Which input is an immediate is a property of the op, not of its size:
     * Ghidra passes some immediates as 8-byte constants (roundps, pshuflw,
     * pcmpistri...), the same size as an MMX register. */
    int imm_last = 0;
    switch (op) {
    case S_pshufw: case S_pshuflw: case S_pshufhw: case S_pshufd: case S_shufps: case S_permq:
    case S_roundps: case S_roundsd: case S_roundss: case S_mpsadbw: case S_cmpps: case S_cmpsd:
    case S_pcmpistri: case S_psrldq: case S_pslldq:
    case S_insertps: case S_extractps: case S_blendps: case S_blendpd: case S_pblendw:
    case S_dpps: case S_dppd: case S_cmppd: case S_cmpss: case S_roundpd:
    case S_pcmpistrm: case S_perm2f128: case S_perm2i128: case S_palignr: case S_sha1rnds4:
    case S_cvtps2ph: case S_pblendd: case S_permpd: case S_shufpd: case S_pinsrb: case S_pinsrw:
        imm_last = n >= 2; break;
    case S_permilps: case S_permilpd:
        imm_last = n >= 2 && sz[n - 1] < 16; break;     /* imm form vs. register-control form */
    default: break;
    }
    const uint8_t *d[4]; int ds[4], nd = 0, imm = 0, has_imm = 0;
    for (int i = 0; i < n; i++) {
        if (i == n - 1 && imm_last) { imm = (int)L(in[i], sz[i] < 8 ? sz[i] : 8); has_imm = 1; }
        else if ((op == S_pcmpestri || op == S_pcmpestrm) && i >= 2) break;    /* (A, B, imm, EAX, EDX): handled below */
        else if (nd < 4) { d[nd] = in[i]; ds[nd++] = sz[i]; }
    }
    _Alignas(64) uint8_t A[64] = {0}, B[64] = {0}, M[64] = {0}, R[64] = {0};
    if (nd) {
        int ia = nd >= 2 ? nd - 2 : 0, ib = nd - 1;
        memcpy(A, d[ia], ds[ia] < 64 ? ds[ia] : 64);
        memcpy(B, d[ib], ds[ib] < 64 ? ds[ib] : 64);
    }
    int sb = nd ? ds[nd - 1] : 0;
    int W = osz < 64 ? osz : 64;
    uint32_t *mxcsr = (uint32_t *)(ctx->R + RREG_MXCSR);
    int rmode = (*mxcsr >> 13) & 3;
    s8a *A8 = (s8a *)A, *B8 = (s8a *)B, *R8 = (s8a *)R;
    s16a *A16 = (s16a *)A, *B16 = (s16a *)B, *R16 = (s16a *)R;
    u16a *uA16 = (u16a *)A, *uB16 = (u16a *)B, *uR16 = (u16a *)R;
    s32a *A32 = (s32a *)A, *B32 = (s32a *)B, *R32 = (s32a *)R;
    u32a *uA32 = (u32a *)A, *uB32 = (u32a *)B, *uR32 = (u32a *)R;
    s64a *B64s = (s64a *)B, *R64s = (s64a *)R;
    u64a *A64 = (u64a *)A, *B64 = (u64a *)B, *R64 = (u64a *)R;
    f32a *Af = (f32a *)A, *Bf = (f32a *)B, *Rf = (f32a *)R;
    f64a *Ad = (f64a *)A, *Bd = (f64a *)B, *Rd = (f64a *)R;
    (void)B64s;

    switch (op) {
    /* ---- float arithmetic: on the host unit, bit-exact ---- */
    case S_divps: case S_maxps: case S_minps: case S_subps:
        for (int k = 0; k < W; k += 16) {
            __m128 x = _mm_load_ps((float *)(A + k)), y = _mm_load_ps((float *)(B + k)), r;
            r = op == S_divps ? _mm_div_ps(x, y) : op == S_maxps ? _mm_max_ps(x, y) :
                op == S_minps ? _mm_min_ps(x, y) : _mm_sub_ps(x, y);
            _mm_store_ps((float *)(R + k), r);
        }
        break;
    case S_divpd:
        for (int k = 0; k < W; k += 16)
            _mm_store_pd((double *)(R + k), _mm_div_pd(_mm_load_pd((double *)(A + k)), _mm_load_pd((double *)(B + k))));
        break;
    case S_sqrtps:
        for (int k = 0; k < W; k += 16) _mm_store_ps((float *)(R + k), _mm_sqrt_ps(_mm_load_ps((float *)(B + k))));
        break;
    case S_sqrtpd:
        for (int k = 0; k < W; k += 16) _mm_store_pd((double *)(R + k), _mm_sqrt_pd(_mm_load_pd((double *)(B + k))));
        break;
    case S_cmpps:
        for (int i = 0; i < W / 4; i++) uR32[i] = fcmp(Af[i], Bf[i], imm) ? ~0u : 0;
        break;
    case S_cmpsd:
        memcpy(R, A, 64);
        R64[0] = fcmp(Ad[0], Bd[0], imm) ? ~0ull : 0;
        break;
    case S_roundps: {
        int m = (imm & 4) ? rmode : imm & 3;
        for (int k = 0; k < W; k += 16) _mm_store_ps((float *)(R + k), rnd_ps(_mm_load_ps((float *)(B + k)), m));
        break;
    }
    case S_roundsd: {
        int m = (imm & 4) ? rmode : imm & 3;
        memcpy(R, A, 64);
        Rd[0] = _mm_cvtsd_f64(rnd_pd(_mm_set_sd(Bd[0]), m));
        break;
    }
    case S_blendvps: case S_blendvpd: case S_pblendvb: {   /* (dest|src1, src2, mask) */
        if (nd >= 3) {
            memcpy(A, d[nd - 3], ds[nd - 3] < 64 ? ds[nd - 3] : 64);
            memcpy(B, d[nd - 2], ds[nd - 2] < 64 ? ds[nd - 2] : 64);
            memcpy(M, d[nd - 1], ds[nd - 1] < 64 ? ds[nd - 1] : 64);
        }
        int e = op == S_pblendvb ? 1 : op == S_blendvps ? 4 : 8;
        for (int i = 0; i < W; i += e)
            memcpy(R + i, (M[i + e - 1] & 0x80) ? B + i : A + i, e);
        break;
    }
    /* ---- conversions (MXCSR rounding mode honoured) ---- */
    case S_cvtps2dq:
        for (int k = 0; k < W; k += 16)
            _mm_store_si128((__m128i *)(R + k), _mm_cvttps_epi32(rnd_ps(_mm_load_ps((float *)(B + k)), rmode)));
        break;
    case S_cvtdq2ps:
        for (int k = 0; k < W; k += 16)
            _mm_store_ps((float *)(R + k), _mm_cvtepi32_ps(_mm_load_si128((__m128i *)(B + k))));
        break;
    case S_cvtdq2pd:
        for (int i = 0; i < W / 8; i++) Rd[i] = (double)B32[i];
        break;
    case S_cvtps2pd:
        for (int i = 0; i < W / 8; i++) Rd[i] = (double)Bf[i];
        break;
    case S_cvtpd2dq:
        for (int i = 0; i < sb / 8 && i < 8; i++)
            R32[i] = _mm_cvttsd_si32(rnd_pd(_mm_set_sd(Bd[i]), rmode));
        break;
    case S_PackedIntToFloatingDwordConv:   /* CVTPI2PS: 2 ints -> low 2 floats, rest kept */
        if (nd >= 2) memcpy(R, A, 64);
        Rf[0] = (float)B32[0]; Rf[1] = (float)B32[1];
        break;
    /* ---- integer arithmetic ---- */
    case S_paddsb:  for (int i = 0; i < W; i++) R8[i] = sat8(A8[i] + B8[i]); break;
    case S_psubsb:  for (int i = 0; i < W; i++) R8[i] = sat8(A8[i] - B8[i]); break;
    case S_paddusb: for (int i = 0; i < W; i++) R[i] = usat8(A[i] + B[i]); break;
    case S_psubusb: for (int i = 0; i < W; i++) R[i] = usat8(A[i] - B[i]); break;
    case S_paddsw:  for (int i = 0; i < W / 2; i++) R16[i] = sat16(A16[i] + B16[i]); break;
    case S_psubsw:  for (int i = 0; i < W / 2; i++) R16[i] = sat16(A16[i] - B16[i]); break;
    case S_paddusw: for (int i = 0; i < W / 2; i++) uR16[i] = usat16(uA16[i] + uB16[i]); break;
    case S_psubusw: for (int i = 0; i < W / 2; i++) uR16[i] = usat16(uA16[i] - uB16[i]); break;
    case S_pmulhw:  for (int i = 0; i < W / 2; i++) R16[i] = (int16_t)(((int32_t)A16[i] * B16[i]) >> 16); break;
    case S_pmulhuw: for (int i = 0; i < W / 2; i++) uR16[i] = (uint16_t)(((uint32_t)uA16[i] * uB16[i]) >> 16); break;
    case S_pmulld:  for (int i = 0; i < W / 4; i++) uR32[i] = uA32[i] * uB32[i]; break;
    case S_pmullq:  for (int i = 0; i < W / 8; i++) R64[i] = A64[i] * B64[i]; break;
    case S_pmuldq:  for (int i = 0; i < W / 8; i++) R64s[i] = (int64_t)A32[2 * i] * B32[2 * i]; break;
    case S_pmaddwd:
        for (int i = 0; i < W / 4; i++)
            uR32[i] = (uint32_t)((int64_t)A16[2 * i] * B16[2 * i] + (int64_t)A16[2 * i + 1] * B16[2 * i + 1]);
        break;
    case S_pmaddubsw:
        for (int i = 0; i < W / 2; i++)
            R16[i] = sat16(A[2 * i] * B8[2 * i] + A[2 * i + 1] * B8[2 * i + 1]);
        break;
    case S_psadbw:
        for (int g = 0; g < W / 8; g++) {
            int s = 0;
            for (int j = 0; j < 8; j++) { int t = A[g * 8 + j] - B[g * 8 + j]; s += t < 0 ? -t : t; }
            uR16[g * 4] = s;
        }
        break;
    case S_mpsadbw:
        for (int l = 0; l < W; l += 16) {
            int im = imm >> (3 * (l / 16)), ao = ((im >> 2) & 1) * 4, bo = (im & 3) * 4;
            for (int i = 0; i < 8; i++) {
                int s = 0;
                for (int j = 0; j < 4; j++) { int t = A[l + ao + i + j] - B[l + bo + j]; s += t < 0 ? -t : t; }
                uR16[l / 2 + i] = s;
            }
        }
        break;
    case S_pavgb:   for (int i = 0; i < W; i++) R[i] = (A[i] + B[i] + 1) >> 1; break;
    case S_pabsw:   for (int i = 0; i < W / 2; i++) uR16[i] = (uint16_t)(B16[i] < 0 ? -B16[i] : B16[i]); break;
    case S_paddq:   for (int i = 0; i < W / 8; i++) R64[i] = A64[i] + B64[i]; break;
    case S_psubq:   for (int i = 0; i < W / 8; i++) R64[i] = A64[i] - B64[i]; break;
    case S_psubd:   for (int i = 0; i < W / 4; i++) uR32[i] = uA32[i] - uB32[i]; break;
    case S_pand:    for (int i = 0; i < W; i++) R[i] = A[i] & B[i]; break;
    case S_por:     for (int i = 0; i < W; i++) R[i] = A[i] | B[i]; break;
    case S_pcmpeqb: for (int i = 0; i < W; i++) R[i] = A[i] == B[i] ? 0xff : 0; break;
    case S_pcmpeqw: for (int i = 0; i < W / 2; i++) uR16[i] = uA16[i] == uB16[i] ? 0xffff : 0; break;
    case S_pcmpeqd: for (int i = 0; i < W / 4; i++) uR32[i] = uA32[i] == uB32[i] ? ~0u : 0; break;
    case S_packsswb: {
        int Ln = W < 16 ? W : 16;
        for (int l = 0; l < W; l += Ln)
            for (int i = 0; i < Ln / 2; i++) {
                R8[l + i] = sat8(A16[l / 2 + i]);
                R8[l + Ln / 2 + i] = sat8(B16[l / 2 + i]);
            }
        break;
    }
    case S_packssdw: {
        int Ln = W < 16 ? W : 16;
        for (int l = 0; l < W; l += Ln)
            for (int i = 0; i < Ln / 4; i++) {
                R16[l / 2 + i] = sat16(A32[l / 4 + i]);
                R16[l / 2 + Ln / 4 + i] = sat16(B32[l / 4 + i]);
            }
        break;
    }
    /* ---- shifts: count from imm8 or from the low 64 bits of a register ---- */
    case S_psllw: case S_psrlw: case S_psraw: case S_pslld: case S_psrld:
    case S_psrad: case S_psllq: case S_psrlq: {
        /* legacy (dst/src, count) and VEX (src, count): source is the first
         * input, the count is the low 64 bits of the last (imm or register) */
        uint8_t S0[64] = {0};
        memcpy(S0, in[0], sz[0] < 64 ? sz[0] : 64);
        const uint8_t *src = S0;
        uint64_t cnt = n >= 2 ? L(in[n - 1], sz[n - 1] < 8 ? sz[n - 1] : 8) : 0;
        int e = (op == S_psllw || op == S_psrlw || op == S_psraw) ? 2 :
                (op == S_psllq || op == S_psrlq) ? 8 : 4;
        int left = op == S_psllw || op == S_pslld || op == S_psllq;
        int arith = op == S_psraw || op == S_psrad;
        int bits = e * 8;
        for (int i = 0; i < W / e; i++) {
            uint64_t v = 0, r;
            memcpy(&v, src + i * e, e);
            if (left) r = cnt >= (uint64_t)bits ? 0 : v << cnt;
            else if (!arith) r = cnt >= (uint64_t)bits ? 0 : v >> cnt;
            else {
                int64_t sv = (int64_t)(v << (64 - bits)) >> (64 - bits);
                r = (uint64_t)(sv >> (cnt >= (uint64_t)bits ? bits - 1 : (int)cnt));
            }
            memcpy(R + i * e, &r, e);
        }
        break;
    }
    case S_psrldq: case S_pslldq: {
        int sh = imm & 0xff;
        for (int l = 0; l < W; l += 16)
            for (int i = 0; i < 16 && l + i < W; i++) {
                int k = op == S_psrldq ? i + sh : i - sh;
                R[l + i] = (k >= 0 && k < 16) ? B[l + k] : 0;
            }
        break;
    }
    /* ---- shuffles / permutes ---- */
    case S_pshufw:
        for (int i = 0; i < 4; i++) uR16[i] = uB16[(imm >> (2 * i)) & 3];
        break;
    case S_pshuflw: case S_pshufhw:
        for (int l = 0; l < W; l += 16) {
            int w0 = l / 2;
            memcpy(R + l, B + l, 16);
            int base = op == S_pshuflw ? w0 : w0 + 4;
            for (int i = 0; i < 4; i++) uR16[base + i] = uB16[base + ((imm >> (2 * i)) & 3)];
        }
        break;
    case S_pshufd:
        for (int l = 0; l < W; l += 16)
            for (int i = 0; i < 4; i++) uR32[l / 4 + i] = uB32[l / 4 + ((imm >> (2 * i)) & 3)];
        break;
    case S_pshufb:
        for (int l = 0; l < W; l += 16)
            for (int i = 0; i < 16 && l + i < W; i++) {
                uint8_t c = B[l + i];
                R[l + i] = (c & 0x80) ? 0 : A[l + (c & 15)];
            }
        break;
    case S_permilps:
        for (int l = 0; l < W; l += 16)
            for (int i = 0; i < 4; i++)
                uR32[l / 4 + i] = has_imm ? uB32[l / 4 + ((imm >> (2 * i)) & 3)]
                                          : uA32[l / 4 + (uB32[l / 4 + i] & 3)];
        break;
    case S_shufps:
        for (int l = 0; l < W; l += 16) {
            int q = l / 4;
            uR32[q] = uA32[q + (imm & 3)];            uR32[q + 1] = uA32[q + ((imm >> 2) & 3)];
            uR32[q + 2] = uB32[q + ((imm >> 4) & 3)]; uR32[q + 3] = uB32[q + ((imm >> 6) & 3)];
        }
        break;
    case S_permq:
        for (int i = 0; i < 4; i++) R64[i] = B64[(imm >> (2 * i)) & 3];
        break;
    case S_permd:                    /* (index, source) */
        for (int i = 0; i < 8; i++) uR32[i] = uB32[uA32[i] & 7];
        break;
    case S_unpcklps: case S_punpckldq: case S_unpckhps:
        for (int l = 0; l < W; l += 16) {
            int q = l / 4, h = op == S_unpckhps ? 2 : 0;
            uR32[q] = uA32[q + h];     uR32[q + 1] = uB32[q + h];
            uR32[q + 2] = uA32[q + h + 1]; uR32[q + 3] = uB32[q + h + 1];
        }
        break;
    case S_unpcklpd: case S_punpcklqdq:
        for (int l = 0; l < W; l += 16) { R64[l / 8] = A64[l / 8]; R64[l / 8 + 1] = B64[l / 8]; }
        break;
    /* ---- moves / extends ---- */
    case S_pmovsxdq: for (int i = 0; i < W / 8; i++) R64s[i] = B32[i]; break;
    case S_pmovzxwd: for (int i = 0; i < W / 4; i++) uR32[i] = uB16[i]; break;
    case S_lddqu: case S_movntdq: case S_movdq2q: case S_movntdqa:
        memcpy(R, B, 64);
        break;
    /* ---- SSE3 / SSSE3 / SSE4.1 (Burst-compiled code uses these freely) ---- */
    case S_insertps: {              /* (dest, src xmm or m32, imm): one float in, some zeroed */
        int cs = sb <= 4 ? 0 : (imm >> 6) & 3, cd = (imm >> 4) & 3;
        memcpy(R, A, 64);
        uR32[cd] = uB32[cs];
        for (int i = 0; i < 4; i++) if (imm & (1 << i)) uR32[i] = 0;
        break;
    }
    case S_extractps:               /* (xmm, imm) -> one float's bits */
        uR32[0] = uB32[imm & 3];
        break;
    case S_blendps: for (int i = 0; i < W / 4; i++) uR32[i] = (imm >> (i & 7)) & 1 ? uB32[i] : uA32[i]; break;
    case S_blendpd: for (int i = 0; i < W / 8; i++) R64[i] = (imm >> (i & 3)) & 1 ? B64[i] : A64[i]; break;
    case S_pblendw: for (int i = 0; i < W / 2; i++) uR16[i] = (imm >> (i & 7)) & 1 ? uB16[i] : uA16[i]; break;
    case S_dpps:                    /* per 128-bit lane, as the CPU adds them: (0+1)+(2+3) */
        for (int l = 0; l < W / 4; l += 4) {
            float t[4];
            for (int i = 0; i < 4; i++) t[i] = (imm >> (4 + i)) & 1 ? Af[l + i] * Bf[l + i] : 0.0f;
            float sum = (t[0] + t[1]) + (t[2] + t[3]);
            for (int i = 0; i < 4; i++) Rf[l + i] = (imm >> i) & 1 ? sum : 0.0f;
        }
        break;
    case S_dppd: {
        double t0 = (imm >> 4) & 1 ? Ad[0] * Bd[0] : 0.0, t1 = (imm >> 5) & 1 ? Ad[1] * Bd[1] : 0.0;
        double sum = t0 + t1;
        Rd[0] = imm & 1 ? sum : 0.0; Rd[1] = imm & 2 ? sum : 0.0;
        break;
    }
    case S_cmppd:                   /* Ghidra calls it per 8-byte lane */
        for (int i = 0; i < (W >= 8 ? W / 8 : 1); i++) R64[i] = fcmp(Ad[i], Bd[i], imm) ? ~0ull : 0;
        break;
    case S_cmpss:
        memcpy(R, A, 64);
        uR32[0] = fcmp(Af[0], Bf[0], imm) ? ~0u : 0;
        break;
    case S_maxpd: case S_minpd:
        for (int k = 0; k < W; k += 16) {
            __m128d x = _mm_load_pd((double *)(A + k)), y = _mm_load_pd((double *)(B + k));
            _mm_store_pd((double *)(R + k), op == S_maxpd ? _mm_max_pd(x, y) : _mm_min_pd(x, y));
        }
        break;
    case S_roundpd: {
        int m = (imm & 4) ? rmode : imm & 3;
        for (int k = 0; k < W; k += 16) _mm_store_pd((double *)(R + k), rnd_pd(_mm_load_pd((double *)(B + k)), m));
        break;
    }
    case S_pabsb: for (int i = 0; i < W; i++) R[i] = (uint8_t)(B8[i] < 0 ? -B8[i] : B8[i]); break;
    case S_pabsd: for (int i = 0; i < W / 4; i++) uR32[i] = (uint32_t)(B32[i] < 0 ? -(int64_t)B32[i] : B32[i]); break;
    case S_pavgw: for (int i = 0; i < (W >= 2 ? W / 2 : 1); i++) uR16[i] = (uint16_t)((uA16[i] + uB16[i] + 1) >> 1); break;
    case S_packusdw:                /* per 128-bit lane: 4 dwords of A, then 4 of B, saturated to u16 */
        for (int l = 0; l < W; l += 16)
            for (int i = 0; i < 4; i++) {
                int32_t x = A32[l / 4 + i], y = B32[l / 4 + i];
                uR16[l / 2 + i] = (uint16_t)(x < 0 ? 0 : x > 65535 ? 65535 : x);
                uR16[l / 2 + 4 + i] = (uint16_t)(y < 0 ? 0 : y > 65535 ? 65535 : y);
            }
        break;
    case S_phaddw: case S_phsubw: case S_phaddsw: case S_phsubsw: {
        int lane = W >= 16 ? 16 : W;             /* MMX form: one 8-byte lane */
        for (int l = 0; l < W; l += lane)
            for (int i = 0; i < lane / 4; i++)
                for (int h = 0; h < 2; h++) {
                    const s16a *S = h ? B16 : A16;
                    int x = S[l / 2 + 2 * i], y = S[l / 2 + 2 * i + 1];
                    int v = (op == S_phaddw || op == S_phaddsw) ? x + y : x - y;
                    if (op == S_phaddsw || op == S_phsubsw) v = v > 32767 ? 32767 : v < -32768 ? -32768 : v;
                    R16[l / 2 + h * (lane / 4) + i] = (int16_t)v;
                }
        break;
    }
    case S_phaddd: case S_phsubd: {
        int lane = W >= 16 ? 16 : W;
        for (int l = 0; l < W; l += lane)
            for (int i = 0; i < lane / 8; i++)
                for (int h = 0; h < 2; h++) {
                    const u32a *S = h ? uB32 : uA32;
                    uint32_t x = S[l / 4 + 2 * i], y = S[l / 4 + 2 * i + 1];
                    uR32[l / 4 + h * (lane / 8) + i] = op == S_phaddd ? x + y : x - y;
                }
        break;
    }
    case S_phminposuw: {            /* (src): smallest word and its index */
        int best = 0;
        for (int i = 1; i < 8; i++) if (uB16[i] < uB16[best]) best = i;
        uR16[0] = uB16[best]; uR16[1] = (uint16_t)best;
        break;
    }
    case S_pmovsxbq: for (int i = 0; i < W / 8; i++) R64s[i] = B8[i]; break;
    case S_pmovsxwq: for (int i = 0; i < W / 8; i++) R64s[i] = B16[i]; break;
    case S_pmulhrsw:
        for (int i = 0; i < W / 2; i++) R16[i] = (int16_t)((((int32_t)A16[i] * B16[i] >> 14) + 1) >> 1);
        break;
    case S_psignb: for (int i = 0; i < W; i++) R8[i] = (int8_t)(B8[i] < 0 ? -A8[i] : B8[i] == 0 ? 0 : A8[i]); break;
    case S_psignw: for (int i = 0; i < W / 2; i++) R16[i] = (int16_t)(B16[i] < 0 ? -A16[i] : B16[i] == 0 ? 0 : A16[i]); break;
    case S_psignd: for (int i = 0; i < W / 4; i++) uR32[i] = B32[i] < 0 ? 0u - uA32[i] : B32[i] == 0 ? 0 : uA32[i]; break;
    case S_crc32: {                 /* (crc, value of 1/2/4/8 bytes): CRC-32C */
        uint32_t c = uA32[0];
        for (int i = 0; i < sb && i < 8; i++) {
            c ^= B[i];
            for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0x82F63B78u & (0u - (c & 1)));
        }
        R64[0] = c;
        break;
    }
    case S_punpcklwd:
        for (int l = 0; l < W; l += 16)
            for (int i = 0; i < 4; i++) { uR16[l / 2 + 2 * i] = uA16[l / 2 + i]; uR16[l / 2 + 2 * i + 1] = uB16[l / 2 + i]; }
        break;
    case S_psllvq: for (int i = 0; i < W / 8; i++) R64[i] = B64[i] > 63 ? 0 : A64[i] << B64[i]; break;
    case S_psrlvq: for (int i = 0; i < W / 8; i++) R64[i] = B64[i] > 63 ? 0 : A64[i] >> B64[i]; break;
    case S_psllvd: for (int i = 0; i < W / 4; i++) uR32[i] = uB32[i] > 31 ? 0 : uA32[i] << uB32[i]; break;
    case S_psrlvd: for (int i = 0; i < W / 4; i++) uR32[i] = uB32[i] > 31 ? 0 : uA32[i] >> uB32[i]; break;
    case S_psravd: for (int i = 0; i < W / 4; i++) R32[i] = A32[i] >> (uB32[i] > 31 ? 31 : uB32[i]); break;
    case S_pmovzxdq: for (int i = 0; i < W / 8; i++) R64[i] = uB32[i]; break;
    case S_pmovzxbd: for (int i = 0; i < W / 4; i++) uR32[i] = B[i]; break;
    case S_pmovzxbw: for (int i = 0; i < W / 2; i++) uR16[i] = B[i]; break;
    case S_pmovzxbq: for (int i = 0; i < W / 8; i++) R64[i] = B[i]; break;
    case S_pmovzxwq: for (int i = 0; i < W / 8; i++) R64[i] = uB16[i]; break;
    case S_pmovsxbw: for (int i = 0; i < W / 2; i++) R16[i] = B8[i]; break;
    case S_pmovsxbd: for (int i = 0; i < W / 4; i++) R32[i] = B8[i]; break;
    case S_pmovsxwd: for (int i = 0; i < W / 4; i++) R32[i] = B16[i]; break;
    case S_pmaxuq: for (int i = 0; i < W / 8; i++) R64[i] = A64[i] > B64[i] ? A64[i] : B64[i]; break;
    case S_pminuq: for (int i = 0; i < W / 8; i++) R64[i] = A64[i] < B64[i] ? A64[i] : B64[i]; break;
    case S_pmaskmovd: case S_maskmovps:     /* load form (mask, memory); lift.py does the store form */
        for (int i = 0; i < W / 4; i++) uR32[i] = (uA32[i] >> 31) ? uB32[i] : 0;
        break;
    case S_pmaskmovq: case S_maskmovpd:
        for (int i = 0; i < W / 8; i++) R64[i] = (A64[i] >> 63) ? B64[i] : 0;
        break;
    case S_roundss: {
        int m = (imm & 4) ? rmode : imm & 3;
        memcpy(R, A, 64);
        Rf[0] = _mm_cvtss_f32(rnd_ps(_mm_set_ss(Bf[0]), m));
        break;
    }
    case S_movntpd: case S_movntps:
        memcpy(R, B, 64);
        break;
    case S_pcmpestri: {             /* (A, B, imm, EAX = length of A, EDX = length of B) */
        int f[5] = {0};
        int la = n > 3 ? (int)(int32_t)L(in[3], sz[3] < 4 ? sz[3] : 4) : 16;
        int lb = n > 4 ? (int)(int32_t)L(in[4], sz[4] < 4 ? sz[4] : 4) : 16;
        int im = n > 2 ? (int)L(in[2], sz[2] < 8 ? sz[2] : 8) : 0;
        memcpy(A, in[0], sz[0] < 16 ? sz[0] : 16);
        memcpy(B, in[1], sz[1] < 16 ? sz[1] : 16);
        pcmpestri_host(A, la, B, lb, im, f);
        R32[0] = f[0];
        set_flag(ctx, "CF", f[1]); set_flag(ctx, "ZF", f[2]); set_flag(ctx, "SF", f[3]);
        set_flag(ctx, "OF", f[4]); set_flag(ctx, "AF", 0);     set_flag(ctx, "PF", 0);
        break;
    }
    /* ---- strings / control ---- */
    case S_pcmpistri: {
        int f[5] = {0};
        pcmpistri_host(A, B, imm, f);
        R32[0] = f[0];
        set_flag(ctx, "CF", f[1]); set_flag(ctx, "ZF", f[2]); set_flag(ctx, "SF", f[3]);
        set_flag(ctx, "OF", f[4]); set_flag(ctx, "AF", 0);     set_flag(ctx, "PF", 0);
        break;
    }
    case S_pcmpistrm: {             /* (A, B, imm): mask -> XMM0 */
        int f[5] = {0};
        pcmpistrm_host(A, B, imm, R, f);
        set_flag(ctx, "CF", f[1]); set_flag(ctx, "ZF", f[2]); set_flag(ctx, "SF", f[3]);
        set_flag(ctx, "OF", f[4]); set_flag(ctx, "AF", 0);     set_flag(ctx, "PF", 0);
        break;
    }
    case S_pcmpestrm: {             /* (A, B, imm, EAX, EDX) */
        int f[5] = {0};
        int la = n > 3 ? (int)(int32_t)L(in[3], sz[3] < 4 ? sz[3] : 4) : 16;
        int lb = n > 4 ? (int)(int32_t)L(in[4], sz[4] < 4 ? sz[4] : 4) : 16;
        int im = n > 2 ? (int)L(in[2], sz[2] < 8 ? sz[2] : 8) : 0;
        memcpy(A, in[0], sz[0] < 16 ? sz[0] : 16);
        memcpy(B, in[1], sz[1] < 16 ? sz[1] : 16);
        pcmpestrm_host(A, la, B, lb, im, R, f);
        set_flag(ctx, "CF", f[1]); set_flag(ctx, "ZF", f[2]); set_flag(ctx, "SF", f[3]);
        set_flag(ctx, "OF", f[4]); set_flag(ctx, "AF", 0);     set_flag(ctx, "PF", 0);
        break;
    }
    /* ---- AVX / AVX2: horizontal ops and byte-lane shuffles work per 128-bit lane ---- */
    case S_haddps: case S_hsubps:
        for (int l = 0; l < W / 4; l += 4) {
            int sub = op == S_hsubps;
            Rf[l]     = sub ? Af[l] - Af[l + 1] : Af[l] + Af[l + 1];
            Rf[l + 1] = sub ? Af[l + 2] - Af[l + 3] : Af[l + 2] + Af[l + 3];
            Rf[l + 2] = sub ? Bf[l] - Bf[l + 1] : Bf[l] + Bf[l + 1];
            Rf[l + 3] = sub ? Bf[l + 2] - Bf[l + 3] : Bf[l + 2] + Bf[l + 3];
        }
        break;
    case S_haddpd: case S_hsubpd:
        for (int l = 0; l < W / 8; l += 2) {
            int sub = op == S_hsubpd;
            Rd[l]     = sub ? Ad[l] - Ad[l + 1] : Ad[l] + Ad[l + 1];
            Rd[l + 1] = sub ? Bd[l] - Bd[l + 1] : Bd[l] + Bd[l + 1];
        }
        break;
    case S_perm2f128: case S_perm2i128:     /* (src1, src2, imm) */
        for (int h = 0; h < 2; h++) {
            int c = (imm >> (4 * h)) & 0xf;
            if (c & 8) memset(R + 16 * h, 0, 16);
            else memcpy(R + 16 * h, ((c & 2) ? B : A) + 16 * (c & 1), 16);
        }
        break;
    case S_pmullw:  for (int i = 0; i < W / 2; i++) uR16[i] = (uint16_t)(uA16[i] * uB16[i]); break;
    case S_pmaxub:  for (int i = 0; i < W; i++) R[i] = A[i] > B[i] ? A[i] : B[i]; break;
    case S_pminub:  for (int i = 0; i < W; i++) R[i] = A[i] < B[i] ? A[i] : B[i]; break;
    case S_pmaxsw:  for (int i = 0; i < W / 2; i++) R16[i] = A16[i] > B16[i] ? A16[i] : B16[i]; break;
    case S_pminsw:  for (int i = 0; i < W / 2; i++) R16[i] = A16[i] < B16[i] ? A16[i] : B16[i]; break;
    case S_punpcklbw: case S_punpckhbw:
        for (int l = 0; l < W; l += 16) {
            int h = op == S_punpckhbw ? 8 : 0;
            for (int i = 0; i < 8; i++) { R[l + 2 * i] = A[l + h + i]; R[l + 2 * i + 1] = B[l + h + i]; }
        }
        break;
    case S_punpckhwd:
        for (int l = 0; l < W; l += 16)
            for (int i = 0; i < 4; i++) { uR16[l / 2 + 2 * i] = uA16[l / 2 + 4 + i]; uR16[l / 2 + 2 * i + 1] = uB16[l / 2 + 4 + i]; }
        break;
    case S_punpckhdq:
        for (int l = 0; l < W; l += 16) {
            int q = l / 4;
            uR32[q] = uA32[q + 2]; uR32[q + 1] = uB32[q + 2]; uR32[q + 2] = uA32[q + 3]; uR32[q + 3] = uB32[q + 3];
        }
        break;
    case S_punpckhqdq:
        for (int l = 0; l < W; l += 16) { R64[l / 8] = A64[l / 8 + 1]; R64[l / 8 + 1] = B64[l / 8 + 1]; }
        break;
    case S_palignr: {               /* (high, low, imm): per lane, (high:low) >> imm bytes */
        int sh = imm & 0xff, Ln = W < 16 ? W : 16;
        for (int l = 0; l < W; l += Ln)
            for (int i = 0; i < Ln; i++) {
                int k = i + sh;
                R[l + i] = k < Ln ? B[l + k] : k < 2 * Ln ? A[l + k - Ln] : 0;
            }
        break;
    }
    /* ---- SHA ---- */
    case S_sha1rnds4: case S_sha1nexte: case S_sha1msg1: case S_sha1msg2:
    case S_sha256msg1: case S_sha256msg2:
        sha_host(op, A, B, 0, imm, R);
        break;
    case S_sha256rnds2: {           /* (dst, src, XMM0) */
        uint8_t X0[16] = {0};
        if (nd >= 3) {
            memcpy(A, d[nd - 3], 16); memcpy(B, d[nd - 2], 16); memcpy(X0, d[nd - 1], 16);
        }
        sha_host(op, A, B, X0, 0, R);
        break;
    }
    /* ---- F16C ---- */
    case S_cvtps2ph: f16c_host(1, B, sb, imm, R, W); break;
    case S_cvtph2ps: f16c_host(0, B, sb, 0, R, W); break;
    /* ---- more AVX / AVX2 ---- */
    case S_addsubps: for (int i = 0; i < W / 4; i++) Rf[i] = (i & 1) ? Af[i] + Bf[i] : Af[i] - Bf[i]; break;
    case S_addsubpd: for (int i = 0; i < W / 8; i++) Rd[i] = (i & 1) ? Ad[i] + Bd[i] : Ad[i] - Bd[i]; break;
    case S_subpd:    for (int i = 0; i < W / 8; i++) Rd[i] = Ad[i] - Bd[i]; break;
    case S_cvtpd2ps: for (int i = 0; i < sb / 8 && i < 8; i++) Rf[i] = (float)Bd[i]; break;
    case S_movshdup: for (int i = 0; i < W / 4; i += 2) uR32[i] = uR32[i + 1] = uB32[i + 1]; break;
    case S_movsldup: for (int i = 0; i < W / 4; i += 2) uR32[i] = uR32[i + 1] = uB32[i]; break;
    case S_packuswb: {
        int Ln = W < 16 ? W : 16;
        for (int l = 0; l < W; l += Ln)
            for (int i = 0; i < Ln / 2; i++) {
                R[l + i] = (uint8_t)usat8(A16[l / 2 + i]);
                R[l + Ln / 2 + i] = (uint8_t)usat8(B16[l / 2 + i]);
            }
        break;
    }
    case S_pandn:   for (int i = 0; i < W; i++) R[i] = (uint8_t)(~A[i] & B[i]); break;
    case S_pblendd: for (int i = 0; i < W / 4; i++) uR32[i] = (imm >> (i & 7)) & 1 ? uB32[i] : uA32[i]; break;
    case S_pcmpgtb: for (int i = 0; i < W; i++) R[i] = A8[i] > B8[i] ? 0xff : 0; break;
    case S_pcmpgtw: for (int i = 0; i < W / 2; i++) uR16[i] = A16[i] > B16[i] ? 0xffff : 0; break;
    case S_pcmpgtd: for (int i = 0; i < W / 4; i++) uR32[i] = A32[i] > B32[i] ? ~0u : 0; break;
    case S_pcmpgtq: for (int i = 0; i < W / 8; i++) R64[i] = (int64_t)A64[i] > (int64_t)B64[i] ? ~0ull : 0; break;
    case S_permilpd:
        for (int i = 0; i < W / 8; i++)
            R64[i] = has_imm ? B64[(i & ~1) + ((imm >> (i & 7)) & 1)] : A64[(i & ~1) + ((B64[i] >> 1) & 1)];
        break;
    case S_permpd:  for (int i = 0; i < 4; i++) R64[i] = B64[(imm >> (2 * i)) & 3]; break;
    case S_permps:  for (int i = 0; i < 8; i++) uR32[i] = uB32[uA32[i] & 7]; break;   /* (index, source) */
    case S_pmaxsb:  for (int i = 0; i < W; i++) R8[i] = A8[i] > B8[i] ? A8[i] : B8[i]; break;
    case S_pminsb:  for (int i = 0; i < W; i++) R8[i] = A8[i] < B8[i] ? A8[i] : B8[i]; break;
    case S_pmaxsd:  for (int i = 0; i < W / 4; i++) R32[i] = A32[i] > B32[i] ? A32[i] : B32[i]; break;
    case S_pminsd:  for (int i = 0; i < W / 4; i++) R32[i] = A32[i] < B32[i] ? A32[i] : B32[i]; break;
    case S_pmaxud:  for (int i = 0; i < W / 4; i++) uR32[i] = uA32[i] > uB32[i] ? uA32[i] : uB32[i]; break;
    case S_pminud:  for (int i = 0; i < W / 4; i++) uR32[i] = uA32[i] < uB32[i] ? uA32[i] : uB32[i]; break;
    case S_pmaxuw:  for (int i = 0; i < W / 2; i++) uR16[i] = uA16[i] > uB16[i] ? uA16[i] : uB16[i]; break;
    case S_pminuw:  for (int i = 0; i < W / 2; i++) uR16[i] = uA16[i] < uB16[i] ? uA16[i] : uB16[i]; break;
    case S_pmuludq: for (int i = 0; i < W / 8; i++) R64[i] = (uint64_t)uA32[2 * i] * uB32[2 * i]; break;
    case S_psubb:   for (int i = 0; i < W; i++) R[i] = (uint8_t)(A[i] - B[i]); break;
    case S_psubw:   for (int i = 0; i < W / 2; i++) uR16[i] = (uint16_t)(uA16[i] - uB16[i]); break;
    case S_shufpd:
        for (int l = 0; l < W / 8; l += 2) {
            R64[l] = A64[l + ((imm >> l) & 1)];
            R64[l + 1] = B64[l + ((imm >> (l + 1)) & 1)];
        }
        break;
    case S_unpckhpd:
        for (int l = 0; l < W; l += 16) { R64[l / 8] = A64[l / 8 + 1]; R64[l / 8 + 1] = B64[l / 8 + 1]; }
        break;
    /* VMOVHPD/VMOVHPS/VMOVLPD/VMOVLPS: load form (xmm, m64) -> 16 bytes, store form -> 8 */
    case S_movhpd: case S_movhps:
        if (W <= 8) R64[0] = B64[1];
        else { R64[0] = A64[0]; R64[1] = B64[0]; }
        break;
    case S_movlpd: case S_movlps:
        if (W <= 8) R64[0] = B64[0];
        else { R64[0] = B64[0]; R64[1] = A64[1]; }
        break;
    /* VPINSRB / VPINSRW: (src xmm, r32/m8/m16, imm) */
    case S_pinsrb: memcpy(R, A, 16); R[imm & 15] = B[0]; break;
    case S_pinsrw: memcpy(R, A, 16); uR16[imm & 7] = uB16[0]; break;
    case S_stmxcsr:
        uR32[0] = *mxcsr;
        break;
    case S_ldmxcsr:
        if (nd) *mxcsr = (uint32_t)L(d[nd - 1], ds[nd - 1] < 4 ? ds[nd - 1] : 4);
        else if (n) *mxcsr = (uint32_t)L(in[0], sz[0] < 4 ? sz[0] : 4);
        break;
    }
    if (out && osz > 0) { memset(out, 0, osz); memcpy(out, R, W); }
}

__attribute__((target("sha,sse4.1")))
static void sha_host(int op, const uint8_t *pa, const uint8_t *pb, const uint8_t *pc, int imm, uint8_t *r) {
    __m128i a = _mm_loadu_si128((const __m128i *)pa), b = _mm_loadu_si128((const __m128i *)pb), x = _mm_setzero_si128();
    switch (op) {
    case S_sha1rnds4:
        switch (imm & 3) {
        case 0: x = _mm_sha1rnds4_epu32(a, b, 0); break; case 1: x = _mm_sha1rnds4_epu32(a, b, 1); break;
        case 2: x = _mm_sha1rnds4_epu32(a, b, 2); break; default: x = _mm_sha1rnds4_epu32(a, b, 3); break;
        }
        break;
    case S_sha1nexte:  x = _mm_sha1nexte_epu32(a, b); break;
    case S_sha1msg1:   x = _mm_sha1msg1_epu32(a, b); break;
    case S_sha1msg2:   x = _mm_sha1msg2_epu32(a, b); break;
    case S_sha256msg1: x = _mm_sha256msg1_epu32(a, b); break;
    case S_sha256msg2: x = _mm_sha256msg2_epu32(a, b); break;
    case S_sha256rnds2: x = _mm_sha256rnds2_epu32(a, b, _mm_loadu_si128((const __m128i *)pc)); break;
    default: break;
    }
    _mm_storeu_si128((__m128i *)r, x);
}

/* FMA with a single rounding. The program only executes FMA instructions on
 * a CPU that has them, so the host's own FMA unit is used; the libm fallback
 * is only reached on a host without FMA. */
static int host_has_fma(void) {
    static int v = -1;
    if (v < 0) { unsigned a, b, c, d; __cpuid(1, a, b, c, d); v = (c >> 12) & 1; }
    return v;
}
__attribute__((target("fma"))) static float fmaf_hw(float a, float b, float c) {
    return _mm_cvtss_f32(_mm_fmadd_ss(_mm_set_ss(a), _mm_set_ss(b), _mm_set_ss(c)));
}
__attribute__((target("fma"))) static double fma_hw(double a, double b, double c) {
    return _mm_cvtsd_f64(_mm_fmadd_sd(_mm_set_sd(a), _mm_set_sd(b), _mm_set_sd(c)));
}
float rt_fmaf(float a, float b, float c) { return host_has_fma() ? fmaf_hw(a, b, c) : fmaf(a, b, c); }
double rt_fma(double a, double b, double c) { return host_has_fma() ? fma_hw(a, b, c) : fma(a, b, c); }

/* FBLD / FBSTP: 10-byte packed BCD <-> x87 value (80-bit long double when the
 * operand is 10 bytes, double when it is 8) */
static void bcd_op(int to, uint8_t *out, int osz, int n, const uint8_t *const *in, const int *sz) {
    if (!to) {
        int64_t v = 0;
        for (int i = 8; i >= 0; i--) v = v * 100 + (in[0][i] >> 4) * 10 + (in[0][i] & 15);
        long double x = (in[0][9] & 0x80) ? -(long double)v : (long double)v;
        if (!out) return;
        memset(out, 0, osz);
        if (osz >= 10) memcpy(out, &x, 10);
        else if (osz == 8) { double y = (double)x; memcpy(out, &y, 8); }
        else { memcpy(out, &v, osz < 8 ? osz : 8); }
        return;
    }
    long double x = 0;
    if (sz[n - 1] >= 10) memcpy(&x, in[n - 1], 10);
    else if (sz[n - 1] == 8) { double y; memcpy(&y, in[n - 1], 8); x = y; }
    else if (sz[n - 1] == 4) { float y; memcpy(&y, in[n - 1], 4); x = y; }
    uint8_t r[10] = {0};
    if (x != x || x >= 1e18L || x <= -1e18L) {        /* BCD indefinite */
        r[9] = 0xff; r[8] = 0xff; r[7] = 0xc0;
    } else {
        int neg = x < 0;
        if (neg) x = -x;
        uint64_t v = (uint64_t)(x + 0.5L);
        if ((long double)v - x == 0.5L && (v & 1)) v--;  /* round half to even, like FISTP */
        for (int i = 0; i < 9; i++) { r[i] = (uint8_t)((v % 10) | ((v / 10 % 10) << 4)); v /= 100; }
        r[9] = neg ? 0x80 : 0;
    }
    if (out) { memset(out, 0, osz); memcpy(out, r, osz < 10 ? osz : 10); }
}

/* we report a baseline x86-64 CPU (SSE2 only) so libraries use plain code paths */

/* ------------------------------------------------------------------ */
/* What CPU the program is told it runs on (CPUID / XGETBV).           */
/*   RECOMP_CPUID=baseline (default) SSE2 only: programs that pick code */
/*                         paths at run time take the safest ones       */
/*   RECOMP_CPUID=verified the extensions tests/isa.c proves correct    */
/*                         (and that this CPU has)                      */
/*   RECOMP_CPUID=host     everything this CPU reports                  */
/* ------------------------------------------------------------------ */
enum { CPU_BASELINE, CPU_VERIFIED, CPU_HOST };
static int cpuid_mode(void) {
    static int mode = -1;
    if (mode < 0) {
        const char *e = getenv("RECOMP_CPUID");
        mode = !e || !*e || !strcmp(e, "baseline") ? CPU_BASELINE :
               !strcmp(e, "host") ? CPU_HOST : CPU_VERIFIED;
    }
    return mode;
}
/* leaf 1 ECX: SSE3 PCLMUL SSSE3 FMA CX16 SSE4.1 SSE4.2 MOVBE POPCNT AES OSXSAVE AVX F16C.
 * Not XSAVE (bit 26): a program told it exists may run XSAVE/XRSTOR itself,
 * which the runtime doesn't implement; AVX detection only needs OSXSAVE. */
#define VER_L1_ECX ((1u << 0) | (1u << 1) | (1u << 9) | (1u << 12) | (1u << 13) | (1u << 19) | \
                    (1u << 20) | (1u << 22) | (1u << 23) | (1u << 25) | (1u << 27) | \
                    (1u << 28) | (1u << 29))
/* leaf 7 EBX: BMI1 AVX2 BMI2 ERMS ADX SHA */
#define VER_L7_EBX ((1u << 3) | (1u << 5) | (1u << 8) | (1u << 9) | (1u << 19) | (1u << 29))
/* 0x80000001 ECX: LAHF ABM(LZCNT) */
#define VER_X1_ECX ((1u << 0) | (1u << 5))
void rt_cpuid_filter(uint32_t leaf, uint32_t sub, unsigned *a, unsigned *b, unsigned *c, unsigned *d) {
    (void)sub;
    int mode = cpuid_mode();
    if (mode == CPU_HOST) return;
    if (mode == CPU_BASELINE) {
        if (leaf == 1) { *c = 0; *b &= 0x0000ffff; }
        else if (leaf == 7 || leaf == 0xd || leaf == 0x14 || leaf == 0x19) { *a = *b = *c = *d = 0; }
        else if (leaf == 0x80000001) { *c &= 1; }
        return;
    }
    if (leaf == 1) { *c &= VER_L1_ECX; *b &= 0x0000ffff; }
    else if (leaf == 7) {
        if (sub == 0) { *a = 0; *b &= VER_L7_EBX; *c = 0; *d = 0; } else *a = *b = *c = *d = 0;
    }
    else if (leaf == 0xd) {     /* XSAVE layout: only x87, SSE and AVX state exist */
        if (sub == 0) { *a &= 7; *d = 0; }
        else if (sub > 2) *a = *b = *c = *d = 0;
    }
    else if (leaf == 0x14 || leaf == 0x19) { *a = *b = *c = *d = 0; }
    else if (leaf == 0x80000001) { *c &= VER_X1_ECX; }
}
uint64_t rt_xgetbv_value(void) {
    int mode = cpuid_mode();
    if (mode == CPU_BASELINE) return 3;          /* x87 + SSE state: "AVX is off" */
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    if (!(c & (1u << 27))) return 3;
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    uint64_t v = ((uint64_t)hi << 32) | lo;
    return mode == CPU_HOST ? v : (v & 7);       /* verified: no AVX-512 state */
}

void rt_callother(rt_ctx *ctx, int id, uint64_t pc, uint8_t *out, int osz, int n,
                  const uint8_t *const *in, const int *sz) {
    const int *op_kind = ((rt_module *)ctx->mod)->opkind;
    if (op_kind[id] >= K_SIMD) {
        simd_op(ctx, op_kind[id] - K_SIMD, out, osz, n, in, sz);
        return;
    }
    switch (op_kind[id]) {
    case K_SYSCALL:
        rt_platform_syscall(ctx);
        return;
    case K_CPUID: {
        uint32_t leaf = n ? (uint32_t)L(in[0], sz[0]) : (uint32_t)REG64(ctx, RREG_RAX);
        uint32_t sub = (uint32_t)REG64(ctx, RREG_RCX);
        unsigned a = 0, b = 0, c = 0, d = 0;
        __cpuid_count(leaf, sub, a, b, c, d);
        rt_cpuid_filter(leaf, sub, &a, &b, &c, &d);
        uint32_t *cpuid_buf = ctx->cpuid_buf;
        cpuid_buf[0] = a; cpuid_buf[1] = b; cpuid_buf[2] = d; cpuid_buf[3] = c;
        rt_log(2, "t%d cpuid leaf=%#x -> %08x %08x %08x %08x", ctx->tid, leaf, a, b, c, d);
        if (out) { uint64_t p = (uint64_t)(uintptr_t)cpuid_buf; memcpy(out, &p, osz > 8 ? 8 : osz); }
        return;
    }
    case K_RDTSC: {
        uint64_t t = __rdtsc();
        if (out) memcpy(out, &t, osz > 8 ? 8 : osz);
        return;
    }
    case K_XGETBV: {
        uint64_t v = rt_xgetbv_value();
        if (out) memcpy(out, &v, osz > 8 ? 8 : osz);
        return;
    }
    case K_NOP:
        return;
    case K_LOCK:
        rt_lock();
        return;
    case K_UNLOCK:
        rt_unlock();
        return;
    case K_HLT:
        ctx->cur = pc;
        rt_crash(ctx, "program executed HLT", pc, "HLT is privileged; in user programs it is used "
                 "as a deliberate crash, usually after abort() or a failed assertion");
    case K_INT3:
        ctx->cur = pc;
        rt_crash(ctx, "program executed a breakpoint / invalid instruction (INT3/UD2)", pc,
                 "compilers emit this for __builtin_trap(), unreachable code and failed "
                 "security checks (stack cookie, fortify). Look at the transfers above it");
    case K_MOVMSKPS:
    case K_MOVMSKPD: {
        const uint8_t *x = in[n - 1];
        int lane = op_kind[id] == K_MOVMSKPS ? 4 : 8, lanes = sz[n - 1] / lane;
        uint64_t m = 0;
        for (int k = 0; k < lanes; k++) m |= (uint64_t)(x[k * lane + lane - 1] >> 7) << k;
        if (out) { memset(out, 0, osz); memcpy(out, &m, osz > 8 ? 8 : osz); }
        return;
    }
    case K_PSHUFB: {
        uint8_t a[16] = {0}, b[16] = {0}, r[16];
        int w = sz[0] < 16 ? sz[0] : 16;
        memcpy(a, in[0], w); memcpy(b, in[1], sz[1] < 16 ? sz[1] : 16);
        for (int k = 0; k < w; k++) r[k] = (b[k] & 0x80) ? 0 : a[b[k] & (w - 1)];
        if (out) memcpy(out, r, osz < w ? osz : w);
        return;
    }
    case K_AESENC: case K_AESENCLAST: case K_AESDEC: case K_AESDECLAST:
    case K_AESIMC: case K_AESKEYGEN: case K_PCLMUL:
        aes_op(op_kind[id], out, osz, n, in, sz);
        return;
    case K_RSQRTPS: case K_RSQRTSS: case K_RCPPS: case K_RCPSS:
        rsqrt_rcp_op(op_kind[id], out, osz, n, in, sz);
        return;
    case K_FROMBCD: case K_TOBCD:
        bcd_op(op_kind[id] == K_TOBCD, out, osz, n, in, sz);
        return;
    case K_IN:          /* port I/O: no device answers; anti-VM probes see a real machine */
        rt_log(1, "t%d %#llx: IN from an I/O port, returning 0", ctx->tid, (unsigned long long)pc);
        if (out) memset(out, 0, osz);
        return;
    case K_OUT:
        rt_log(1, "t%d %#llx: OUT to an I/O port, ignored", ctx->tid, (unsigned long long)pc);
        return;
    case K_ZERO:
        if (out) memset(out, 0, osz);
        return;
    case K_CLZERO: {    /* AMD CLZERO: zero the 64-byte cache line at [RAX] */
        uint64_t a = REG64(ctx, RREG_RAX) & ~63ULL;
        memset((void *)(uintptr_t)a, 0, 64);
        return;
    }
    case K_DESCR:       /* SLDT/SGDT/SIDT/LSL/STR/VERR/VERW: 0 ("not accessible", "processor 0") */
        if (out) memset(out, 0, osz);
        return;
    case K_SWI: {       /* INT n (Ghidra lifts INT3 padding as swi(3) too) */
        int v = n ? (int)L(in[0], sz[0]) : 3;
        char d[256];
        if (v == 0x29)
            snprintf(d, sizeof d, "INT 0x29 is __fastfail: the program aborted itself on purpose "
                     "(failure code in RCX=%#llx; 7 = FAST_FAIL_FATAL_APP_EXIT, 2 = stack cookie)",
                     (unsigned long long)REG64(ctx, RREG_RCX));
        else if (v == 3)
            snprintf(d, sizeof d, "INT3: a breakpoint or padding between functions was executed - "
                     "usually a jump/return to a wrong address. Look at the transfers above it");
        else if (v == 0x2c)
            snprintf(d, sizeof d, "INT 0x2C is a Windows assertion failure (__assertfail)");
        else
            snprintf(d, sizeof d, "software interrupt INT %#x has no meaning in a recompiled program", v);
        ctx->cur = pc;
        rt_crash(ctx, "program executed a software interrupt", pc, d);
        return;
    }
    case K_PRIV: {
        char d[256];
        snprintf(d, sizeof d, "'%s' is a kernel/SGX instruction a user program cannot run; "
                 "this code is probably never reached normally", ((rt_module *)ctx->mod)->opnames[id]);
        ctx->cur = pc;
        rt_crash(ctx, "program executed a privileged instruction", pc, d);
        return;
    }
    default: {
        char d[256];
        snprintf(d, sizeof d, "CPU op '%s' is not implemented in the runtime. Add a case for "
                 "it in rt_callother() in runtime/rt_common.c", ((rt_module *)ctx->mod)->opnames[id]);
        ctx->cur = pc;
        rt_crash(ctx, "unimplemented special CPU instruction", pc, d);
    }
    }
}

/* shifts on 32/64-byte values (AVX/AVX-512 registers). kind: 0 left, 1 right, 2 arithmetic right */
void WSHIFT(uint8_t *o, const uint8_t *a, int n, uint64_t s, int kind) {
    uint8_t t[64] = {0};
    int bits = n * 8;
    int neg = kind == 2 && (a[n - 1] & 0x80);
    if (s >= (uint64_t)bits) { memset(o, neg ? 0xff : 0, n); return; }
    for (int i = 0; i < bits; i++) {
        int src = kind == 0 ? i - (int)s : i + (int)s;
        int bit = src < 0 ? 0 : src >= bits ? neg : (a[src >> 3] >> (src & 7)) & 1;
        t[i >> 3] |= (uint8_t)(bit << (i & 7));
    }
    memcpy(o, t, n);
}

/* ------------------------------------------------------------------ */
/* integer ops on values wider than 8 bytes without a 128-bit C type   */
/* (32-bit builds; lift.py emits rt_wide for them). Up to 64 bytes.    */
/* ------------------------------------------------------------------ */
#define WL 16                           /* 32-bit limbs */
static void w_load(uint32_t *x, const uint8_t *p, int n, int sext) {
    uint8_t t[4 * WL];
    if (n > 4 * WL) n = 4 * WL;
    memset(t, sext && n && (p[n - 1] & 0x80) ? 0xff : 0, sizeof t);
    memcpy(t, p, n);
    memcpy(x, t, sizeof t);
}
static void w_add(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint64_t c = 0;
    for (int i = 0; i < WL; i++) { c += (uint64_t)a[i] + b[i]; r[i] = (uint32_t)c; c >>= 32; }
}
static void w_sub(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint64_t c = 1;                     /* a + ~b + 1 */
    for (int i = 0; i < WL; i++) { c += (uint64_t)a[i] + (uint32_t)~b[i]; r[i] = (uint32_t)c; c >>= 32; }
}
static void w_mul(uint32_t *r, const uint32_t *a, const uint32_t *b) {
    uint32_t t[WL] = {0};
    for (int i = 0; i < WL; i++) {
        uint64_t c = 0;
        if (!a[i]) continue;
        for (int j = 0; i + j < WL; j++) {
            c += (uint64_t)a[i] * b[j] + t[i + j];
            t[i + j] = (uint32_t)c; c >>= 32;
        }
    }
    memcpy(r, t, sizeof t);
}
static int w_cmp(const uint32_t *a, const uint32_t *b) {      /* unsigned: -1, 0, 1 */
    for (int i = WL - 1; i >= 0; i--) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static int w_zero(const uint32_t *a) { for (int i = 0; i < WL; i++) if (a[i]) return 0; return 1; }
static void w_neg(uint32_t *r, const uint32_t *a) { uint32_t z[WL] = {0}; w_sub(r, z, a); }
/* keep the low n bytes, the rest zero */
static void w_trunc(uint32_t *x, int n) { if (n < 4 * WL) memset((uint8_t *)x + n, 0, 4 * WL - n); }
/* q = a / b, r = a % b (unsigned, b != 0), bits = width of a */
static void w_divmod(uint32_t *q, uint32_t *r, const uint32_t *a, const uint32_t *b, int bits) {
    uint32_t Q[WL] = {0}, Rm[WL] = {0};
    for (int i = bits - 1; i >= 0; i--) {
        for (int k = WL - 1; k > 0; k--) Rm[k] = (Rm[k] << 1) | (Rm[k - 1] >> 31);
        Rm[0] = (Rm[0] << 1) | ((a[i >> 5] >> (i & 31)) & 1);
        if (w_cmp(Rm, b) >= 0) { w_sub(Rm, Rm, b); Q[i >> 5] |= 1u << (i & 31); }
    }
    memcpy(q, Q, sizeof Q); memcpy(r, Rm, sizeof Rm);
}

void rt_wide(int op, uint8_t *o, int osz, const uint8_t *a, int asz, const uint8_t *b, int bsz) {
    uint32_t A[WL], B[WL], R[WL] = {0};
    int sgn = op == W_INT_SEXT || op == W_INT_SLESS || op == W_INT_SLESSEQUAL || op == W_INT_SDIV ||
              op == W_INT_SREM;
    int bits = asz * 8, flag = -1;
    w_load(A, a, asz, sgn);
    w_load(B, b, bsz, sgn);
    switch (op) {
    case W_INT_ADD: w_add(R, A, B); break;
    case W_INT_SUB: w_sub(R, A, B); break;
    case W_INT_MULT: w_mul(R, A, B); break;
    case W_INT_AND: for (int i = 0; i < WL; i++) R[i] = A[i] & B[i]; break;
    case W_INT_OR:  for (int i = 0; i < WL; i++) R[i] = A[i] | B[i]; break;
    case W_INT_XOR: for (int i = 0; i < WL; i++) R[i] = A[i] ^ B[i]; break;
    case W_INT_NEGATE: for (int i = 0; i < WL; i++) R[i] = ~A[i]; break;
    case W_INT_2COMP: w_neg(R, A); break;
    case W_INT_ZEXT: case W_INT_SEXT: memcpy(R, A, sizeof R); break;
    case W_INT_EQUAL: flag = w_cmp(A, B) == 0; break;
    case W_INT_NOTEQUAL: flag = w_cmp(A, B) != 0; break;
    case W_INT_LESS: flag = w_cmp(A, B) < 0; break;
    case W_INT_LESSEQUAL: flag = w_cmp(A, B) <= 0; break;
    case W_INT_SLESS: case W_INT_SLESSEQUAL: {
        /* sign-extended to the full width: compare as two's complement */
        int na = A[WL - 1] >> 31, nb = B[WL - 1] >> 31;
        int c = na != nb ? (na ? -1 : 1) : w_cmp(A, B);
        flag = op == W_INT_SLESS ? c < 0 : c <= 0;
        break;
    }
    case W_INT_DIV: case W_INT_REM: case W_INT_SDIV: case W_INT_SREM: {
        uint32_t Q[WL], Rm[WL];
        int na = 0, nb = 0;
        if (w_zero(B)) { volatile int z = 0; z = 1 / z; (void)z; }   /* the CPU's divide error */
        if (sgn) {
            na = A[WL - 1] >> 31; nb = B[WL - 1] >> 31;
            if (na) w_neg(A, A);
            if (nb) w_neg(B, B);
        }
        w_divmod(Q, Rm, A, B, 32 * WL);
        if (na != nb) w_neg(Q, Q);
        if (na) w_neg(Rm, Rm);
        memcpy(R, op == W_INT_DIV || op == W_INT_SDIV ? Q : Rm, sizeof R);
        break;
    }
    case W_INT_LEFT: case W_INT_RIGHT: case W_INT_SRIGHT: {
        uint8_t t[4 * WL] = {0};
        uint64_t cnt = 0;
        int big = 0;
        memcpy(&cnt, b, bsz < 8 ? bsz : 8);
        for (int i = 8; i < bsz; i++) big |= b[i];
        if (big) cnt = ~0ULL;
        memcpy(t, a, asz < 4 * WL ? asz : 4 * WL);
        WSHIFT(t, t, asz < 4 * WL ? asz : 4 * WL, cnt, op == W_INT_LEFT ? 0 : op == W_INT_RIGHT ? 1 : 2);
        memcpy(R, t, sizeof t);
        break;
    }
    case W_INT_CARRY: {                 /* carry out of an asz-byte addition */
        uint32_t S[WL];
        w_add(S, A, B); w_trunc(S, asz);
        flag = w_cmp(S, A) < 0;
        break;
    }
    case W_INT_SCARRY: case W_INT_SBORROW: {
        uint32_t S[WL];
        if (op == W_INT_SCARRY) w_add(S, A, B); else w_sub(S, A, B);
        int top = bits - 1, w = top >> 5, k = top & 31;
        uint32_t v = op == W_INT_SCARRY ? (A[w] ^ S[w]) & (B[w] ^ S[w]) : (A[w] ^ B[w]) & (A[w] ^ S[w]);
        flag = (v >> k) & 1;
        break;
    }
    case W_POPCOUNT: {
        int n = 0;
        for (int i = 0; i < WL; i++) n += __builtin_popcount(A[i]);
        R[0] = n;
        break;
    }
    case W_LZCOUNT: {
        int n = 0;
        for (int i = bits - 1; i >= 0 && !((A[i >> 5] >> (i & 31)) & 1); i--) n++;
        R[0] = n;
        break;
    }
    default: break;
    }
    if (flag >= 0) R[0] = flag;
    memset(o, 0, osz);
    memcpy(o, R, osz < 4 * WL ? osz : 4 * WL);
}

/* ------------------------------------------------------------------ */
/* x87 instructions that run on the host's FPU (32-bit programs)       */
/* ------------------------------------------------------------------ */
#define ST_PTR(c, i) ((c)->R + RREG_ST0 + (RREG_ST1 - RREG_ST0) * (i))
static void x87_push(rt_ctx *c, const void *v) {
    for (int i = 7; i > 0; i--) memcpy(ST_PTR(c, i), ST_PTR(c, i - 1), 10);
    memcpy(ST_PTR(c, 0), v, 10);
}
static void x87_pop(rt_ctx *c) {
    for (int i = 0; i < 7; i++) memcpy(ST_PTR(c, i), ST_PTR(c, i + 1), 10);
    memcpy(ST_PTR(c, 7), RT_X87_EMPTY, 10);
}
/* each template loads its operands from memory, runs the instruction, stores
 * the results and leaves the host's x87 stack as it found it. %1 = a (ST0),
 * %2 = b (ST1); the status word comes back in EAX. */
#define X87_ASM(tmpl) __asm__ volatile(tmpl : "=&a"(sw) : "r"(a), "r"(b) : "memory", "cc")
void rt_x87(rt_ctx *c, int op) {
    uint8_t a[16] = {0}, b[16] = {0};
    unsigned sw = 0;
    memcpy(a, ST_PTR(c, 0), 10);
    memcpy(b, ST_PTR(c, 1), 10);
    switch (op) {
    case X87_FSIN:    X87_ASM("fldt (%1)\n\tfsin\n\tfnstsw %%ax\n\tfstpt (%1)"); break;
    case X87_FCOS:    X87_ASM("fldt (%1)\n\tfcos\n\tfnstsw %%ax\n\tfstpt (%1)"); break;
    case X87_F2XM1:   X87_ASM("fldt (%1)\n\tf2xm1\n\tfnstsw %%ax\n\tfstpt (%1)"); break;
    case X87_FRNDINT: X87_ASM("fldt (%1)\n\tfrndint\n\tfnstsw %%ax\n\tfstpt (%1)"); break;
    case X87_FPREM:   X87_ASM("fldt (%2)\n\tfldt (%1)\n\tfprem\n\tfnstsw %%ax\n\tfstpt (%1)\n\tfstp %%st(0)"); break;
    case X87_FPREM1:  X87_ASM("fldt (%2)\n\tfldt (%1)\n\tfprem1\n\tfnstsw %%ax\n\tfstpt (%1)\n\tfstp %%st(0)"); break;
    case X87_FSCALE:  X87_ASM("fldt (%2)\n\tfldt (%1)\n\tfscale\n\tfnstsw %%ax\n\tfstpt (%1)\n\tfstp %%st(0)"); break;
    /* these pop: the result replaces ST1, which becomes the new ST0 */
    case X87_FYL2X:   X87_ASM("fldt (%2)\n\tfldt (%1)\n\tfyl2x\n\tfnstsw %%ax\n\tfstpt (%2)"); break;
    case X87_FYL2XP1: X87_ASM("fldt (%2)\n\tfldt (%1)\n\tfyl2xp1\n\tfnstsw %%ax\n\tfstpt (%2)"); break;
    case X87_FPATAN:  X87_ASM("fldt (%2)\n\tfldt (%1)\n\tfpatan\n\tfnstsw %%ax\n\tfstpt (%2)"); break;
    /* these push, unless the operand is out of range (C2 set: nothing happens) */
    case X87_FPTAN:   X87_ASM("fldt (%1)\n\tfptan\n\tfnstsw %%ax\n\ttestl $0x400, %%eax\n\tjnz 1f\n\t"
                              "fstpt (%2)\n1:\tfstpt (%1)"); break;      /* b = 1.0, a = tan */
    case X87_FSINCOS: X87_ASM("fldt (%1)\n\tfsincos\n\tfnstsw %%ax\n\ttestl $0x400, %%eax\n\tjnz 1f\n\t"
                              "fstpt (%2)\n1:\tfstpt (%1)"); break;      /* b = cos, a = sin */
    case X87_FXTRACT: X87_ASM("fldt (%1)\n\tfxtract\n\tfnstsw %%ax\n\tfstpt (%2)\n\tfstpt (%1)"); break; /* b = significand, a = exponent */
    case X87_FXAM:
        if (!memcmp(a, RT_X87_EMPTY, 10)) sw = 0x4100 | ((a[9] & 0x80) ? 0x200 : 0);   /* class "empty" */
        else X87_ASM("fldt (%1)\n\tfxam\n\tfnstsw %%ax\n\tfstp %%st(0)");
        break;
    default: break;
    }
    switch (op) {
    case X87_FYL2X: case X87_FYL2XP1: case X87_FPATAN:
        memcpy(ST_PTR(c, 1), b, 10);
        x87_pop(c);
        break;
    case X87_FPTAN: case X87_FSINCOS: case X87_FXTRACT:
        memcpy(ST_PTR(c, 0), a, 10);
        if (op == X87_FXTRACT || !(sw & 0x400)) x87_push(c, b);
        break;
    case X87_FXAM: break;
    default: memcpy(ST_PTR(c, 0), a, 10); break;
    }
    /* condition codes C0-C3, where the program's FNSTSW / SAHF look for them */
    c->R[RREG_C0] = (sw >> 8) & 1;  c->R[RREG_C1] = (sw >> 9) & 1;
    c->R[RREG_C2] = (sw >> 10) & 1; c->R[RREG_C3] = (sw >> 14) & 1;
    uint16_t fsw; memcpy(&fsw, c->R + RREG_FPUStatusWord, 2);
    fsw = (uint16_t)((fsw & ~0x4700) | (sw & 0x4700));
    memcpy(c->R + RREG_FPUStatusWord, &fsw, 2);
}
