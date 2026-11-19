/* recomp runtime, Linux x86-64 guests: map the image at its original
 * address, build the start-up stack, pass syscalls to the host kernel. */
#define _GNU_SOURCE
#include "rt_internal.h"
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <elf.h>
#include <sched.h>

static rt_ctx *main_ctx;
#define M (&rt_this_module)
static uint64_t brk_lo, brk_cur, brk_hi;

rt_ctx *rt_current_ctx(void) { return main_ctx; }

/* Linux has no native code outside the image to call into */
int rt_platform_unknown_target(rt_ctx *c, uint64_t *pc) { (void)c; (void)pc; return 0; }

static long raw6(long n, long a, long b, long c, long d, long e, long f) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}

static const char *sysname(long n) {
    switch (n) {
#define X(s) case SYS_##s: return #s;
    X(read) X(write) X(open) X(close) X(stat) X(fstat) X(lstat) X(poll) X(lseek) X(mmap)
    X(mprotect) X(munmap) X(brk) X(rt_sigaction) X(rt_sigprocmask) X(ioctl) X(pread64)
    X(pwrite64) X(readv) X(writev) X(access) X(pipe) X(select) X(sched_yield) X(mremap)
    X(madvise) X(dup) X(dup2) X(nanosleep) X(getpid) X(socket) X(connect) X(clone) X(fork)
    X(vfork) X(execve) X(exit) X(wait4) X(kill) X(uname) X(fcntl) X(fsync) X(getcwd)
    X(chdir) X(rename) X(mkdir) X(rmdir) X(unlink) X(readlink) X(gettimeofday) X(getuid)
    X(getgid) X(geteuid) X(getegid) X(sigaltstack) X(arch_prctl) X(gettid) X(futex)
    X(set_tid_address) X(clock_gettime) X(exit_group) X(openat) X(newfstatat) X(prlimit64)
    X(getrandom) X(rseq) X(set_robust_list) X(statx) X(clone3) X(getdents64) X(pipe2)
#undef X
    default: return "?";
    }
}

void rt_platform_syscall(rt_ctx *c) {
    long n = (long)REG64(c, RREG_RAX);
    long a = REG64(c, RREG_RDI), b = REG64(c, RREG_RSI), d3 = REG64(c, RREG_RDX);
    long d = REG64(c, RREG_R10), e = REG64(c, RREG_R8), f = REG64(c, RREG_R9);
    long r;
    const char *note = "";
    switch (n) {
    case SYS_exit:
    case SYS_exit_group:
        rt_log(1, "program exits with status %ld after %llu control transfers", a,
               (unsigned long long)c->n_transfers);
        fflush(NULL);
        rt_dump_memory(brk_lo, brk_cur);
        raw6(SYS_exit_group, a, 0, 0, 0, 0, 0);
        r = 0;
        break;
    case SYS_arch_prctl:
        note = " (emulated)";
        if (a == 0x1002) { REG64(c, RREG_FS_OFFSET) = b; r = 0; }
        else if (a == 0x1003) { *(uint64_t *)b = REG64(c, RREG_FS_OFFSET); r = 0; }
        else if (a == 0x1001) { REG64(c, RREG_GS_OFFSET) = b; r = 0; }
        else r = -EINVAL;
        break;
    case SYS_brk:                       /* private heap so we don't fight the host malloc */
        note = " (emulated heap)";
        if (a == 0) r = brk_cur;
        else if ((uint64_t)a >= brk_lo && (uint64_t)a <= brk_hi) r = brk_cur = a;
        else r = brk_cur;
        break;
    case SYS_rt_sigaction:
        note = " (IGNORED: guest signal handlers not supported yet)";
        if (d3) memset((void *)d3, 0, 32);
        r = 0;
        break;
    case SYS_sigaltstack:
        note = " (ignored)";
        r = 0;
        break;
    case SYS_rseq:
    case SYS_set_robust_list:
        note = " (refused on purpose)";
        r = -ENOSYS;
        break;
    case SYS_vfork:
        note = " (done as fork)";
        r = raw6(SYS_fork, 0, 0, 0, 0, 0, 0);
        break;
    case SYS_clone:
        if (a & CLONE_VM) {
            note = " (REFUSED: threads not supported on Linux guests yet)";
            r = -ENOSYS;
            break;
        }
        r = raw6(SYS_clone, a, 0, d3, d, e, f);
        break;
    case SYS_clone3:
        note = " (refused, libc falls back to clone)";
        r = -ENOSYS;
        break;
    default:
        r = raw6(n, a, b, d3, d, e, f);
    }
    if (rt_loglevel >= 2)
        fprintf(rt_logf, "[recomp] t%d syscall %s(%#lx, %#lx, %#lx, %#lx) = %ld%s%s  at %#llx %s\n",
                c->tid, sysname(n), a, b, d3, d, r,
                (r < 0 && r > -4096) ? " (error)" : "", note,
                (unsigned long long)c->cur, rt_symstr(c->cur));
    REG64(c, RREG_RAX) = (uint64_t)r;
}

static void on_signal(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    extern int rt_crash_signal;
    rt_crash_signal = sig;
    const char *what = sig == SIGSEGV ? "memory access violation (SIGSEGV)"
                     : sig == SIGBUS ? "bus error (SIGBUS)"
                     : sig == SIGFPE ? "arithmetic error, e.g. integer divide by zero (SIGFPE)"
                     : sig == SIGILL ? "illegal instruction in the runtime (SIGILL)"
                     : "signal";
    rt_crash(main_ctx, what, (uint64_t)(uintptr_t)si->si_addr,
             "the fault happened while running the recompiled instruction shown below. "
             "If the original program does NOT crash here, the translation of an earlier "
             "instruction produced a wrong value: look at the registers and transfers");
}

static void map_image(void) {
    uint64_t mapped_end = 0, top = 0;
    for (int i = 0; i < M->nsegs; i++) {
        const rt_seg *s = &M->segs[i];
        uint64_t start = s->vaddr & ~0xfffULL;
        uint64_t end = (s->vaddr + s->memsz + 0xfff) & ~0xfffULL;
        if (start < mapped_end) start = mapped_end;
        if (end > start) {
            void *p = mmap((void *)start, end - start, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (p == MAP_FAILED || (uint64_t)p != start) {
                char d[200];
                snprintf(d, sizeof d, "mmap at %#llx size %#llx failed: %s",
                         (unsigned long long)start, (unsigned long long)(end - start), strerror(errno));
                rt_crash(0, "cannot place the program at its original address", start, d);
            }
            mapped_end = end;
        }
        memcpy((void *)s->vaddr, M->image + s->off, s->filesz);
        rt_log(1, "segment %d: %#llx-%#llx (%llu bytes from file) flags=%c%c%c", i,
               (unsigned long long)s->vaddr, (unsigned long long)(s->vaddr + s->memsz),
               (unsigned long long)s->filesz, s->flags & 4 ? 'r' : '-', s->flags & 2 ? 'w' : '-',
               s->flags & 1 ? 'x' : '-');
        if (s->vaddr + s->memsz > top) top = s->vaddr + s->memsz;
    }
    brk_lo = brk_cur = (top + 0xfff) & ~0xfffULL;
    uint64_t size = 1ULL << 30;
    void *p = mmap((void *)brk_lo, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
    brk_hi = (p == MAP_FAILED) ? brk_lo : brk_lo + size;
    rt_log(1, "heap (brk) %#llx-%#llx", (unsigned long long)brk_lo, (unsigned long long)brk_hi);
}

static uint64_t build_stack(rt_ctx *c, int argc, char **argv, char **envp) {
    uint64_t *sp = (uint64_t *)(uintptr_t)(c->stack_hi - 256);
    static uint8_t rnd[16];
    for (int i = 0; i < 16; i++) rnd[i] = (uint8_t)(rand() ^ (i * 77));
    int envc = 0;
    while (envp[envc]) envc++;
    uint64_t aux[][2] = {
        {AT_PHDR, M->phdr}, {AT_PHENT, 56}, {AT_PHNUM, M->phnum}, {AT_PAGESZ, 4096},
        {AT_BASE, 0}, {AT_FLAGS, 0}, {AT_ENTRY, M->entry}, {AT_UID, getuid()},
        {AT_EUID, geteuid()}, {AT_GID, getgid()}, {AT_EGID, getegid()}, {AT_SECURE, 0},
        {AT_RANDOM, (uint64_t)(uintptr_t)rnd}, {AT_CLKTCK, 100}, {AT_HWCAP, 0},
        {AT_EXECFN, (uint64_t)(uintptr_t)argv[0]}, {AT_NULL, 0}};
    int naux = sizeof(aux) / sizeof(aux[0]);
    int words = 1 + argc + 1 + envc + 1 + naux * 2;
    sp -= words;
    sp = (uint64_t *)((uintptr_t)sp & ~15ULL);
    uint64_t *w = sp;
    *w++ = argc;
    for (int i = 0; i < argc; i++) *w++ = (uint64_t)(uintptr_t)argv[i];
    *w++ = 0;
    for (int i = 0; i < envc; i++) *w++ = (uint64_t)(uintptr_t)envp[i];
    *w++ = 0;
    for (int i = 0; i < naux; i++) { *w++ = aux[i][0]; *w++ = aux[i][1]; }
    return (uint64_t)(uintptr_t)sp;
}

int main(int argc, char **argv, char **envp) {
    rt_log_init();
    if (getenv("RECOMP_ARGV0")) argv[0] = getenv("RECOMP_ARGV0");
    static uint8_t altstack[65536];
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack};
    sigaltstack(&ss, 0);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESETHAND;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGFPE, &sa, 0);
    sigaction(SIGILL, &sa, 0);
    rt_add_module(M);
    rt_log(1, "recompiled Linux program, entry %#llx %s, %llu lifted instructions",
           (unsigned long long)M->entry, rt_symstr(M->entry), (unsigned long long)M->naddr);
    map_image();
    main_ctx = rt_new_ctx(8 << 20);
    REG64(main_ctx, RREG_RSP) = build_stack(main_ctx, argc, argv, envp);
    REG64(main_ctx, RREG_RDX) = 0;
    rt_run(main_ctx, M->entry, ~0ULL);
    return 0;
}
