/* recomp runtime for ARM64 shared libraries (Android lib/arm64-v8a, Linux
 * aarch64) - what the generated code and tables.c use.
 *
 * Nothing here needs a C library header: the rebuilt library is compiled
 * with -ffreestanding and -nostdlib, so any clang or gcc that makes ARM64
 * code can build it (the Android NDK, a plain LLVM, a Linux cross gcc).
 * The few C library functions the runtime calls are declared in rt_a64.c. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define memcpy __builtin_memcpy
#define memset __builtin_memset
#define memcmp __builtin_memcmp

typedef unsigned __int128 u128;
typedef __int128 s128;

/* ------------------------------------------------------------------ */
/* register file (Ghidra's AARCH64 'register' space)                    */
/* ------------------------------------------------------------------ */
#define RT_R_SP    0x8          /* sp                                   */
#define RT_R_FLAGS 0x100        /* NG, ZR, CY, OV: one byte each        */
#define RT_R_X     0x4000       /* x0..x30, 8 bytes each                */
#define RT_R_V     0x5000       /* v0..v31, 32 bytes apart (16 used)    */
#define RT_R_SIZE  0x7000

/* CPU context. Every thread has one per rebuilt library; a signal handler of
 * the program that interrupts recompiled code runs with another one, made
 * for the time it runs (rt_a64_begin). The first fields are used by the
 * generated code, R also by rt_a64_asm.S. */
typedef struct rt_ctx {
    uint8_t *R;                 /* 0x00 register file                              */
    uint8_t *U;                 /* 0x08 p-code temporaries ('unique' space)        */
    uint64_t cur;               /* 0x10 address of the instruction being run (as in the original file) */
    uint64_t ex_addr, ex_size;  /* 0x18 exclusive monitor: LDXR remembers, STXR checks */
    uint64_t ex_val[2];         /* 0x28 */
    struct rt_ctx *base;        /* the thread's own context (itself, for that one) */
    /* ---- only in the thread's own context ---- */
    struct rt_ctx *active;      /* the context recompiled code is running with right now, or 0 */
    uint8_t *stack_hi;          /* the runtime's own stack (the generated C runs on it; */
    uint8_t *stack_lo;          /* the program's stack is the thread's real stack)      */
    uint8_t *sig_floor;         /* a signal handler of the program is running: runs go below this */
    uint8_t *tls;               /* this library's thread-local variables           */
    void *tls_mem;
    uint64_t cb;                /* comparison function of the qsort/bsearch in progress */
    uint64_t n_run;             /* chunks run (statistics)                         */
    int tid;
    uint64_t last[16];          /* recent transfers between chunks (crash reports) */
    unsigned last_pos;
} rt_ctx;

typedef uint64_t (*rt_chunk_fn)(uint64_t pc, rt_ctx *ctx);
typedef struct { uint64_t addr; const char *name; } rt_sym;
typedef struct { uint64_t off, size; const uint32_t *map; } rt_a64_region;

/* one rebuilt library (tables.c). Addresses are those of the original file;
 * glo is the lowest one, which is where rt_guest starts. */
typedef struct rt_a64_mod {
    const char *name;
    uint64_t glo, gsize;
    int nregions; const rt_a64_region *regions;     /* code: instruction slot -> chunk */
    int nchunks; rt_chunk_fn const *chunks;
    int nops; const char *const *opnames;           /* special CPU ops (rt_callother) */
    int nsyms; const rt_sym *syms;
    uint64_t init, fini, init_array; int init_n; uint64_t fini_array; int fini_n;
    uint64_t tls_vaddr, tls_filesz, tls_memsz; int tls_align;
    int ntlsdesc; const uint64_t *tlsdesc;          /* (address of the descriptor, offset of the variable) */
    int nirel; const uint64_t *irel;                /* (address, resolver function) */
    const uint64_t *ro;                             /* (address, size) of memory that is read-only after loading */
    uint64_t usize;
} rt_a64_mod;
extern const rt_a64_mod rt_mod;

/* the original image, loaded and relocated by the system (guest.o): where
 * the original's lowest address is (guest.lds) */
extern uint8_t rt_guest[] __attribute__((visibility("hidden")));
/* address at run time of an address of the original file */
#define GA(a) ((uint64_t)(uintptr_t)rt_guest + ((a) - RT_GLO))

/* ------------------------------------------------------------------ */
/* helpers of the generated code (the same as in rt.h)                  */
/* ------------------------------------------------------------------ */
#ifdef RECOMP_TRACE_INSN
void rt_trace_insn(rt_ctx *ctx, uint64_t a);
#define INSN(a) do { ctx->cur = (a); rt_trace_insn(ctx, (a)); } while (0)
#else
#define INSN(a) (ctx->cur = (a))
#endif

typedef struct { uint64_t v[8]; } rt_cbuf;
#define KP(x) ((uint8_t *)(rt_cbuf){{(x)}}.v)

static inline uint64_t L(const void *p, int n) { uint64_t v = 0; memcpy(&v, p, n); return v; }
static inline void S(void *p, uint64_t v, int n) { memcpy(p, &v, n); }
static inline u128 L16(const void *p, int n) { u128 v = 0; memcpy(&v, p, n); return v; }
static inline void S16(void *p, u128 v, int n) { memcpy(p, &v, n); }

static inline int64_t SX(uint64_t v, int n) {
    if (n >= 8) return (int64_t)v;
    int sh = 64 - 8 * n;
    return ((int64_t)(v << sh)) >> sh;
}
static inline s128 SX16(u128 v, int n) {
    if (n >= 16) return (s128)v;
    int sh = 128 - 8 * n;
    return ((s128)(v << sh)) >> sh;
}
#define MASK(n) ((n) >= 8 ? ~0ULL : ((1ULL << (8 * (n))) - 1))
#define MASK16(n) ((n) >= 16 ? ~(u128)0 : (((u128)1 << (8 * (n))) - 1))
static inline uint64_t CARRYS(uint64_t a, uint64_t b, int n) {
    uint64_t r = a + b; return (((a ^ r) & (b ^ r)) >> (8 * n - 1)) & 1;
}
static inline uint64_t BORROWS(uint64_t a, uint64_t b, int n) {
    uint64_t r = a - b; return (((a ^ b) & (a ^ r)) >> (8 * n - 1)) & 1;
}
static inline uint64_t CARRYS16(u128 a, u128 b, int n) {
    u128 r = a + b; return (uint64_t)((((a ^ r) & (b ^ r)) >> (8 * n - 1)) & 1);
}
static inline uint64_t BORROWS16(u128 a, u128 b, int n) {
    u128 r = a - b; return (uint64_t)((((a ^ b) & (a ^ r)) >> (8 * n - 1)) & 1);
}
#define POPC(x) ((uint64_t)__builtin_popcountll(x))
#define POPC16(x) ((uint64_t)(__builtin_popcountll((uint64_t)(x)) + __builtin_popcountll((uint64_t)((x) >> 64))))
static inline uint64_t LZC(uint64_t x, int n) {
    return x == 0 ? 8 * n : (uint64_t)(__builtin_clzll(x) - (64 - 8 * n));
}
static inline uint64_t LZC16(u128 x, int n) {
    uint64_t hi = (uint64_t)(x >> 64), lo = (uint64_t)x; uint64_t c;
    if (hi) c = __builtin_clzll(hi); else if (lo) c = 64 + __builtin_clzll(lo); else c = 128;
    return c - (128 - 8 * n);
}
void WSHIFT(uint8_t *o, const uint8_t *a, int n, uint64_t s, int kind);

/* NZCV <-> the four flag bytes of the register file */
#define NZ_G() (((uint64_t)(R[RT_R_FLAGS] & 1) << 31) | ((uint64_t)(R[RT_R_FLAGS + 1] & 1) << 30) | \
                ((uint64_t)(R[RT_R_FLAGS + 2] & 1) << 29) | ((uint64_t)(R[RT_R_FLAGS + 3] & 1) << 28))
#define NZ_S(f) (R[RT_R_FLAGS] = ((f) >> 31) & 1, R[RT_R_FLAGS + 1] = ((f) >> 30) & 1, \
                 R[RT_R_FLAGS + 2] = ((f) >> 29) & 1, R[RT_R_FLAGS + 3] = ((f) >> 28) & 1)

/* Floating point. Nearly every floating-point instruction is run as itself
 * (a64.py); these are for the few that are translated from P-code. No
 * long double: on ARM64 it is a 128-bit type that needs a support library. */
static inline float LF4(const void *p) { float f; memcpy(&f, p, 4); return f; }
static inline double LF8(const void *p) { double f; memcpy(&f, p, 8); return f; }
static inline void SF4(void *p, double v) { float f = (float)v; memcpy(p, &f, 4); }
static inline void SF8(void *p, double v) { memcpy(p, &v, 8); }
#define fabsl(x) __builtin_fabs(x)
#define ceill(x) __builtin_ceil(x)
#define floorl(x) __builtin_floor(x)
#define sqrt(x) __builtin_sqrt(x)
#define sqrtf(x) __builtin_sqrtf(x)
#define isnan(x) __builtin_isnan(x)
#define FROUND(x, x87) __builtin_rint(x)
/* float -> int the ARM way: saturating, NaN gives 0 */
static inline uint64_t TRUNCF(double x, int n) {
    if (x != x) return 0;
    if (n >= 8) {
        if (x >= 9223372036854775808.0) return 0x7fffffffffffffffULL;
        if (x < -9223372036854775808.0) return 0x8000000000000000ULL;
        return (uint64_t)(int64_t)x;
    }
    double lim = (double)(1ULL << (8 * n - 1));
    if (x >= lim) return (1ULL << (8 * n - 1)) - 1;
    if (x < -lim) return 1ULL << (8 * n - 1);
    return (uint64_t)(int64_t)x;
}

/* special CPU instructions and translation failures */
void rt_callother(rt_ctx *ctx, int id, uint64_t pc, uint8_t *out, int osz, int n,
                  const uint8_t *const *in, const int *sz);
void rt_unsupported(rt_ctx *ctx, const char *what, uint64_t pc) __attribute__((noreturn, cold));
int rt_a64_cas16(uint64_t *p, const uint64_t *expect, uint64_t lo, uint64_t hi);   /* 1 = stored */
void rt_a64_svc(rt_ctx *ctx);                                   /* SVC: a system call */
void rt_a64_trap(rt_ctx *ctx, uint64_t addr, uint32_t insn) __attribute__((cold));    /* BRK, HLT, UDF */
