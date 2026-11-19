/* shared between the runtime files (not used by generated code) */
#pragma once
#include "rt.h"
/* every system header the runtime uses comes BEFORE regs.h: regs.h defines a
 * macro per CPU register (r<name>), and one of those (rflags, ...) would
 * otherwise rewrite a field of the same name inside a system header */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <cpuid.h>
#include <x86intrin.h>
#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#endif
#define RT_RUNTIME          /* regs.h: the runtime needs no register macros */
#include "regs.h"

/* ---- one recompiled file (tables.c defines rt_this_module) ----
 * A game is several recompiled files in one process (exe + DLLs). On Windows
 * they all register with one shared runtime (recomp_rt.dll): one dispatcher,
 * one register file and guest stack per thread, so a call from one DLL into
 * another is an ordinary jump and the guest stack looks like a real one
 * (which is what exception unwinding needs). */
typedef struct { const char *name; int off, size; } rt_regdesc;
typedef struct rt_module {
    const char *name;
    int format, is_dll;                 /* format: 0 = ELF, 1 = PE */
    uint64_t imagebase, sizeofimage, hostbase, entry, phdr, phnum, usize;
    const uint8_t *image;               /* file bytes of the segments (image.bin) */
    int nsegs; const rt_seg *segs;
    int nops; const char *const *opnames;
    rt_chunk_fn const *chunks;
    uint64_t naddr; const uint64_t *addrs; const uint32_t *addr_chunk;
    int nsyms; const rt_sym *syms;
    int nregs; const rt_regdesc *regs;
    int ntls; const uint64_t *tls_callbacks;
    uint8_t *guest;                     /* PE: the .guest section of the rebuilt file */
    /* filled in by the runtime */
    int *opkind;
    uint64_t lo, hi;                    /* address range of the original image */
    void *host;                         /* HMODULE of the rebuilt file */
    int index;                          /* registration order = guest TLS index */
    void *tls_template; uint64_t tls_tsize, tls_zsize;
    const void *pdata; uint32_t npdata;  /* PE: RUNTIME_FUNCTION table (exceptions) */
} rt_module;
extern rt_module rt_this_module;        /* in each recompiled file's tables.c */

/* registry (rt_common.c) */
#define RT_MAX_MODULES 256
extern rt_module *rt_mods[RT_MAX_MODULES];
extern volatile int rt_nmods;
void rt_add_module(rt_module *m);       /* resolves its ops, appends it */
rt_module *rt_module_of(uint64_t a);    /* module whose image contains a, or 0 */
const rt_regdesc *rt_regdescs(int *n);

#define REG64(c, o) (*(uint64_t *)((c)->R + (o)))
/* a pointer-sized register of the program (RSP / ESP, ...) */
#ifdef RT_GUEST32
#define REGP(c, o) (*(uint32_t *)((c)->R + (o)))
#else
#define REGP(c, o) REG64(c, o)
#endif

/* ---- logging ----
 * RECOMP_LOG=0  errors + crash reports only (default)
 *            1  start-up info, memory map, exit
 *            2  + every syscall / Windows API call with arguments and result
 *            3  + every call/jump between functions, with symbol names
 *            4  + every instruction (only in builds made with `make TRACE=1`)
 * RECOMP_LOGFILE=path     write the log there instead of stderr
 * RECOMP_CRASHFILE=path   also write crash reports there                  */
extern int rt_loglevel;
extern FILE *rt_logf;
extern int rt_log_append;
extern const char *rt_logtag;
void rt_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void rt_log_init(void);

/* symbols: "name+0x12" for an address (static buffer per call slot) */
const char *rt_symstr(uint64_t a);
const char *rt_symname(uint64_t a, uint64_t *off);
int rt_in_image(uint64_t a);

/* execution */
rt_ctx *rt_new_ctx(uint64_t stack_size);
rt_chunk_fn rt_lookup(rt_ctx *c, uint64_t pc);
void rt_run(rt_ctx *c, uint64_t pc, uint64_t stop_pc);
/* after-call hooks: fn runs when the guest function at pc returns (used to
 * load the C translated from C# right after the game has started Mono) */
#define RT_HOOK_RET 0x00007FFFFFFD0000ULL      /* fake return address */
int rt_add_hook(uint64_t pc, void (*fn)(rt_ctx *));

/* crash report: never returns */
void rt_crash(rt_ctx *c, const char *reason, uint64_t fault_addr, const char *detail)
    __attribute__((noreturn));
void rt_dump_memory(uint64_t heap_lo, uint64_t heap_hi);
extern int rt_crash_exit_code;         /* exit code after a crash report (default 127) */

/* ---- implemented per platform (rt_linux.c / rt_win.c) ---- */
rt_ctx *rt_current_ctx(void);
void rt_platform_syscall(rt_ctx *c);                      /* the SYSCALL instruction */
int rt_platform_unknown_target(rt_ctx *c, uint64_t *pc);   /* 1 = handled, *pc = next */
