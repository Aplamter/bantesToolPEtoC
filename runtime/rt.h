/* recomp runtime - helpers used by the generated code */
#pragma once
#include <stdint.h>
#include <string.h>
#include <math.h>

#ifdef __SIZEOF_INT128__    /* (not in 32-bit builds: those use rt_wide() below) */
typedef unsigned __int128 u128;
typedef __int128 s128;
#endif

/* ------------------------------------------------------------------ */
/* CPU context: one per guest thread                                   */
/* ------------------------------------------------------------------ */
#define RT_RING 64          /* recent control transfers kept for crash reports */
#define RT_IRING 256        /* recent instructions (trace builds only)          */

typedef struct rt_ctx {
    uint8_t *R;             /* register file (Ghidra 'register' space layout) */
    uint8_t *U;             /* p-code temporaries ('unique' space)             */
    uint64_t cur;           /* address of the instruction being executed       */
    uint64_t stack_lo, stack_hi;   /* guest stack bounds                       */
    int depth;              /* nesting depth of host->guest callbacks          */
    int tid;
    struct { uint64_t from, to; } ring[RT_RING];
    unsigned ring_pos;
    uint64_t iring[RT_IRING];
    unsigned iring_pos;
    uint64_t n_transfers;
    uint64_t *cache_pc;     /* per-thread address -> chunk cache */
    void **cache_fn;
    void *platform;         /* per-platform extras (fake TEB on Windows) */
    int lock_depth;         /* nesting of LOCK-prefixed instructions           */
    int hook_n;             /* pending after-call hooks (rt_add_hook)          */
    int hook_idx[8];
    uint64_t hook_ret[8];
    void *mod;              /* rt_module of the chunk being run (rt_internal.h) */
    uint64_t usize;         /* size of U                                       */
    void **cache_mod;       /* module of each cached chunk                     */
    void *seh;              /* exception dispatch state (Windows)              */
    uint32_t cpuid_buf[4] __attribute__((aligned(16)));  /* CPUID results     */
    /* ---- 32-bit Windows programs (rt_win32.c) ---- */
    void *thr;              /* the thread's switch area (rt32_thr)             */
    void *tls_array;        /* static TLS blocks, one per module: what the     */
                            /* program reads at fs:[0x2C]                      */
    int xret;               /* the transfer being made is a RET instruction    */
} rt_ctx;

/* 32-bit programs: a RET leaves its chunk with this bit set in the target
 * (a return to native code is handled differently from a call to it) */
#define RT_RETFLAG 0x4000000000000000ULL

typedef uint64_t (*rt_chunk_fn)(uint64_t pc, rt_ctx *ctx);
typedef struct { uint64_t vaddr, memsz, off, filesz; int flags; } rt_seg;
typedef struct { uint64_t addr; const char *name; } rt_sym;

/* every instruction starts with INSN(address) */
void rt_trace_insn(rt_ctx *ctx, uint64_t a);
#ifdef RECOMP_TRACE_INSN
#define INSN(a) do { ctx->cur = (a); rt_trace_insn(ctx, (a)); } while (0)
#else
#define INSN(a) (ctx->cur = (a))
#endif

/* pointer to a constant (for ops that want memory operands) */
typedef struct { uint64_t v[8]; } rt_cbuf;
#define KP(x) ((uint8_t *)(rt_cbuf){{(x)}}.v)

/* load / store N bytes (little endian guest == little endian host) */
static inline uint64_t L(const void *p, int n) { uint64_t v = 0; memcpy(&v, p, n); return v; }
static inline void S(void *p, uint64_t v, int n) { memcpy(p, &v, n); }
#ifdef __SIZEOF_INT128__
static inline u128 L16(const void *p, int n) { u128 v = 0; memcpy(&v, p, n); return v; }
static inline void S16(void *p, u128 v, int n) { memcpy(p, &v, n); }
#endif

/* sign extend an N byte value */
static inline int64_t SX(uint64_t v, int n) {
    if (n >= 8) return (int64_t)v;
    int sh = 64 - 8 * n;
    return ((int64_t)(v << sh)) >> sh;
}
#ifdef __SIZEOF_INT128__
static inline s128 SX16(u128 v, int n) {
    if (n >= 16) return (s128)v;
    int sh = 128 - 8 * n;
    return ((s128)(v << sh)) >> sh;
}
#endif
#define MASK(n) ((n) >= 8 ? ~0ULL : ((1ULL << (8 * (n))) - 1))
#ifdef __SIZEOF_INT128__
#define MASK16(n) ((n) >= 16 ? ~(u128)0 : (((u128)1 << (8 * (n))) - 1))
#endif

static inline uint64_t CARRYS(uint64_t a, uint64_t b, int n) {
    uint64_t r = a + b; return (((a ^ r) & (b ^ r)) >> (8 * n - 1)) & 1;
}
static inline uint64_t BORROWS(uint64_t a, uint64_t b, int n) {
    uint64_t r = a - b; return (((a ^ b) & (a ^ r)) >> (8 * n - 1)) & 1;
}
#ifdef __SIZEOF_INT128__
static inline uint64_t CARRYS16(u128 a, u128 b, int n) {
    u128 r = a + b; return (uint64_t)((((a ^ r) & (b ^ r)) >> (8 * n - 1)) & 1);
}
static inline uint64_t BORROWS16(u128 a, u128 b, int n) {
    u128 r = a - b; return (uint64_t)((((a ^ b) & (a ^ r)) >> (8 * n - 1)) & 1);
}
#endif
#define POPC(x) ((uint64_t)__builtin_popcountll(x))
#define POPC16(x) ((uint64_t)(__builtin_popcountll((uint64_t)(x)) + __builtin_popcountll((uint64_t)((x) >> 64))))
static inline uint64_t LZC(uint64_t x, int n) {
    return x == 0 ? 8 * n : (uint64_t)(__builtin_clzll(x) - (64 - 8 * n));
}
#ifdef __SIZEOF_INT128__
static inline uint64_t LZC16(u128 x, int n) {
    uint64_t hi = (uint64_t)(x >> 64), lo = (uint64_t)x; uint64_t c;
    if (hi) c = __builtin_clzll(hi); else if (lo) c = 64 + __builtin_clzll(lo); else c = 128;
    return c - (128 - 8 * n);
}
#endif

/* integer ops on values wider than 8 bytes, for builds without a 128-bit C
 * type (32-bit): o = a <op> b, each operand a little-endian byte string.
 * W_<name> is Ghidra's p-code op name. */
enum { W_INT_ADD, W_INT_SUB, W_INT_MULT, W_INT_AND, W_INT_OR, W_INT_XOR, W_INT_NEGATE, W_INT_2COMP,
       W_INT_ZEXT, W_INT_SEXT, W_INT_EQUAL, W_INT_NOTEQUAL, W_INT_LESS, W_INT_LESSEQUAL, W_INT_SLESS,
       W_INT_SLESSEQUAL, W_INT_DIV, W_INT_REM, W_INT_SDIV, W_INT_SREM, W_INT_LEFT, W_INT_RIGHT,
       W_INT_SRIGHT, W_INT_CARRY, W_INT_SCARRY, W_INT_SBORROW, W_POPCOUNT, W_LZCOUNT };
void rt_wide(int op, uint8_t *o, int osz, const uint8_t *a, int asz, const uint8_t *b, int bsz);

/* x87 (32-bit programs). The register file holds the x87 stack as ST0..ST7;
 * a register that holds no value has this bit pattern (a NaN no instruction
 * produces), which is how the runtime knows how many values are on the stack
 * when the program calls native code or returns a float to it. */
static const uint8_t rt_x87_empty[10] = {0x4f, 0x43, 0x45, 0x52, 0x79, 0x74, 0x70, 0xed, 0xff, 0xff};
/* fused multiply-add with one rounding (FMA instructions; libm's fma is not exact everywhere) */
float rt_fmaf(float a, float b, float c);
double rt_fma(double a, double b, double c);
#define RT_X87_EMPTY rt_x87_empty
/* instructions that run on the host's own FPU (exact results) */
enum { X87_FPREM, X87_FPREM1, X87_FYL2X, X87_FYL2XP1, X87_FSIN, X87_FCOS, X87_FSINCOS, X87_FPTAN,
       X87_FPATAN, X87_F2XM1, X87_FSCALE, X87_FXTRACT, X87_FXAM, X87_FRNDINT };
struct rt_ctx;
void rt_x87(struct rt_ctx *ctx, int op);
void rt_fpsync(struct rt_ctx *ctx);      /* host FPU control words := the program's */

/* floats: 4 = float, 8 = double, 10 = x87 80-bit */
static inline float LF4(const void *p) { float f; memcpy(&f, p, 4); return f; }
static inline double LF8(const void *p) { double f; memcpy(&f, p, 8); return f; }
static inline long double LF10(const void *p) { long double f = 0; memcpy(&f, p, 10); return f; }
static inline long double LF16(const void *p) { long double f = 0; memcpy(&f, p, 10); return f; }
static inline void SF4(void *p, long double v) { float f = (float)v; memcpy(p, &f, 4); }
static inline void SF8(void *p, long double v) { double f = (double)v; memcpy(p, &f, 8); }
static inline void SF10(void *p, long double v) { memcpy(p, &v, 10); }
static inline void SF16(void *p, long double v) { memset(p, 0, 16); memcpy(p, &v, 10); }
/* float -> int, x86 style: out of range / NaN gives the "integer indefinite" value */
static inline uint64_t TRUNCF(long double x, int n) {
    long double lim = ldexpl(1.0L, 8 * n - 1);
    if (x != x || x >= lim || x < -lim) return n >= 8 ? 0x8000000000000000ULL : (1ULL << (8 * n - 1));
    return (uint64_t)(int64_t)x;
}
/* round to integer using the guest's current rounding mode
 * (x87: control word bits 10-11, SSE: MXCSR bits 13-14).
 * Ghidra models FISTP/FRNDINT/CVTSD2SI as plain round(); real CPUs don't. */
static inline long double rt_fround(long double x, int mode) {
    switch (mode & 3) {
    case 0: return rintl(x);
    case 1: return floorl(x);
    case 2: return ceill(x);
    default: return truncl(x);
    }
}
#define FROUND(x, x87) rt_fround((x), (x87) ? (int)((L(R + RREG_FPUControlWord, 2) >> 10) & 3) \
                                             : (int)((L(R + RREG_MXCSR, 4) >> 13) & 3))

/* special CPU instructions and translation failures */
void rt_callother(rt_ctx *ctx, int id, uint64_t pc, uint8_t *out, int osz, int n,
                  const uint8_t *const *in, const int *sz);
void rt_unsupported(rt_ctx *ctx, const char *what, uint64_t pc);
void rt_lock(void);     /* atomic section for LOCK-prefixed / XCHG instructions */
void rt_unlock(void);
