/* test library for the ARM64 shared-library path: built as a normal ARM64
 * .so, lifted, rebuilt, and both are loaded by driver.c - the output has to
 * be the same. Each test prints what it computed. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#define EXPORT __attribute__((visibility("default")))

static int g_counter = 7;
static const char *g_names[] = {"zero", "one", "two", "three"};
static __thread int t_value = 41;
static __thread char t_buf[32] = "tls-init";
EXPORT int lib_global = 1234;
static int g_ctor_ran;

__attribute__((constructor)) static void ctor(void) { g_ctor_ran = 0x5a; }

/* ---- integers ---- */
static uint64_t mix(uint64_t x) {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL; x ^= x >> 33;
    return x;
}

__attribute__((noinline)) static int classify(int v) {
    switch (v) {
    case 0: return 10;
    case 1: return 21;
    case 2: return 32;
    case 3: return 43;
    case 4: return 54;
    case 5: return 65;
    case 6: return 76;
    case 7: return 87;
    default: return -1;
    }
}

__attribute__((noinline)) static uint64_t fib(unsigned n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

__attribute__((noinline)) static int many_args(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j,
                                               double x, long k, const char *s) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j + (int)x + (int)k + (int)strlen(s);
}

EXPORT void test_int(void) {
    uint64_t h = 0x1234;
    for (int i = 0; i < 1000; i++) h = mix(h + i);
    printf("int: mix=%016llx fib=%llu\n", (unsigned long long)h, (unsigned long long)fib(20));
    int64_t a = -1234567890123LL, b = 987654321;
    printf("int: div=%lld rem=%lld udiv=%llu\n", (long long)(a / b), (long long)(a % b),
           (unsigned long long)((uint64_t)a / (uint64_t)b));
    unsigned __int128 m = (unsigned __int128)h * 0x9e3779b97f4a7c15ULL;
    printf("int: mulhi=%016llx clz=%d ctz=%d pop=%d bswap=%08x\n", (unsigned long long)(m >> 64),
           __builtin_clzll(h | 1), __builtin_ctzll(h | (1ULL << 40)), __builtin_popcountll(h),
           __builtin_bswap32((uint32_t)h));
    int s = 0;
    for (int i = -2; i < 10; i++) s = s * 3 + classify(i);
    printf("int: switch=%d many=%d\n", s, many_args(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 2.5, 100, "abc"));
    volatile int sh = 70; volatile int32_t neg = -5;
    printf("int: shifts=%llx %x %d names=%s,%s\n", (unsigned long long)(1ULL << (sh & 63)), (unsigned)neg >> 3,
           neg >> 1, g_names[(h >> 7) & 3], g_names[g_counter & 3]);
    uint8_t ov = 250; ov += 10;
    int16_t sx = (int16_t)0x8001;
    printf("int: narrow=%u %d ctor=%x global=%d\n", ov, sx, g_ctor_ran, lib_global);
}

/* ---- floating point ---- */
__attribute__((noinline)) static double poly(double x) { return ((2.5 * x - 1.25) * x + 0.5) * x - 3.0; }

EXPORT void test_float(void) {
    double s = 0;
    float f = 0;
    for (int i = 1; i <= 100; i++) { s += sqrt((double)i) / (i + 0.5); f += 1.0f / (float)i; }
    printf("float: sum=%.12f fsum=%.6f poly=%.6f\n", s, (double)f, poly(1.75));
    volatile double big = 1e300, tiny = 1e-300, nan = NAN, x = -2.75;
    printf("float: conv=%d %lld %u %ld inf=%g nan=%d\n", (int)x, (long long)(x * 1e12), (unsigned)(-x),
           lround(x), big * big, isnan(nan + tiny));
    printf("float: fn=%.9f %.9f %.9f %.6f\n", sin(1.0), exp(-0.5), pow(2.0, 0.5), fmod(10.25, 3.0));
    printf("float: round=%.1f %.1f %.1f %.1f cmp=%d%d%d\n", floor(x), ceil(x), trunc(x), rint(2.5), x < 0, x > nan,
           tiny != 0);
    float v[8] = {1, 2, 3, 4, 5, 6, 7, 8}, w[8];
    for (int i = 0; i < 8; i++) w[i] = v[i] * 1.5f + v[7 - i];
    printf("float: vec=%.2f %.2f %.2f %.2f fma=%.6f\n", (double)w[0], (double)w[3], (double)w[4], (double)w[7],
           fma(1.5, 2.5, -0.125));
}

/* ---- vectors (the compiler turns these loops into NEON) ---- */
EXPORT void test_simd(void) {
    static uint8_t a[256], b[256];
    static int32_t c[64];
    static double d[32];
    for (int i = 0; i < 256; i++) a[i] = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < 256; i++) b[i] = (uint8_t)(a[i] ^ (a[255 - i] >> 1));
    uint32_t sum = 0;
    for (int i = 0; i < 256; i++) sum += b[i];
    for (int i = 0; i < 64; i++) c[i] = (int32_t)(b[i] * b[i + 64]) - 1000 * i;
    int32_t mx = c[0];
    for (int i = 1; i < 64; i++) mx = c[i] > mx ? c[i] : mx;
    for (int i = 0; i < 32; i++) d[i] = (double)c[i] * 0.25 + i;
    double ds = 0;
    for (int i = 0; i < 32; i++) ds += d[i];
    char buf[200];
    memset(buf, 'x', sizeof buf);
    memcpy(buf + 3, a, 100);
    memmove(buf + 10, buf + 3, 150);
    uint32_t cs = 0;
    for (unsigned i = 0; i < sizeof buf; i++) cs = cs * 31 + (uint8_t)buf[i];
    printf("simd: sum=%u max=%d dsum=%.3f mem=%08x\n", sum, mx, ds, cs);
}

/* ---- calls back from native code ---- */
static int cmp_int(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

typedef int (*lib_cb)(int, void *);
static lib_cb g_cb;
static void *g_cb_arg;

EXPORT void lib_set_callback(lib_cb cb, void *arg) { g_cb = cb; g_cb_arg = arg; }

static int add_ten(int v, void *arg) { return v + 10 + *(int *)arg; }

/* a function pointer of this library, called by the program that loaded it */
EXPORT lib_cb lib_get_function(void) { return add_ten; }

struct ops { int (*twice)(int); double (*half)(double); const char *name; };
static int twice(int v) { return 2 * v; }
static double half(double v) { return v / 2; }
static const struct ops g_ops = {twice, half, "ops-table"};
EXPORT const struct ops *lib_get_ops(void) { return &g_ops; }

EXPORT void test_callbacks(void) {
    int v[] = {42, -7, 19, 0, 1000, 3, -500, 77, 8, 8};
    qsort(v, 10, sizeof v[0], cmp_int);
    const char *s[] = {"pear", "apple", "fig", "banana"};
    qsort(s, 4, sizeof s[0], cmp_str);
    int key = 77, *hit = bsearch(&key, v, 10, sizeof v[0], cmp_int);
    printf("callbacks: sorted=%d,%d,%d,%d..%d strings=%s,%s found=%d\n", v[0], v[1], v[2], v[3], v[9], s[0], s[3],
           hit ? (int)(hit - v) : -1);
    if (g_cb) printf("callbacks: host says %d %d\n", g_cb(5, g_cb_arg), g_cb(-5, g_cb_arg));
}

/* ---- variadic ---- */
__attribute__((noinline)) static double vsum(const char *fmt, ...) {
    va_list ap;
    double s = 0;
    va_start(ap, fmt);
    for (; *fmt; fmt++) {
        if (*fmt == 'i') s += va_arg(ap, int);
        else if (*fmt == 'd') s += va_arg(ap, double);
        else if (*fmt == 'l') s += (double)va_arg(ap, long long);
    }
    va_end(ap);
    return s;
}

EXPORT void test_varargs(void) {
    char b[128];
    int n = snprintf(b, sizeof b, "%d|%5.2f|%s|%c|%lld|%x|%10s|%-6d|", -42, 3.14159, "str", 'Z', 1234567890123LL,
                     0xbeef, "right", 99);
    printf("varargs: %s n=%d sum=%.2f\n", b, n,
           vsum("idildidididid", 1, 2.5, 3, 1LL << 40, 4.25, 5, 6.5, 7, 8.5, 9, 10.5, 11, 12.75));
}

/* ---- setjmp / longjmp ---- */
static jmp_buf g_jb;
__attribute__((noinline)) static void deep(int n) {
    volatile char pad[64];
    pad[0] = (char)n;
    if (n == 0) longjmp(g_jb, 99);
    deep(n - 1);
    pad[1] = 0;
}

EXPORT void test_setjmp(void) {
    volatile int stage = 1;
    int r = setjmp(g_jb);
    if (r == 0) { stage = 2; deep(50); stage = 3; }
    printf("setjmp: r=%d stage=%d\n", r, stage);
}

/* ---- thread-local variables, threads, atomics ---- */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static long g_shared;
static _Atomic long g_atomic;
static int g_flag;

static void *worker(void *arg) {
    long id = (long)arg;
    t_value += (int)id;
    snprintf(t_buf, sizeof t_buf, "thread-%ld", id);
    for (int i = 0; i < 20000; i++) {
        pthread_mutex_lock(&g_mu);
        g_shared += id;
        pthread_mutex_unlock(&g_mu);
        g_atomic += 1;
        int e = 0;
        __atomic_compare_exchange_n(&g_flag, &e, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        __atomic_store_n(&g_flag, 0, __ATOMIC_SEQ_CST);
    }
    return (void *)(long)(t_value * 1000 + (int)strlen(t_buf));
}

EXPORT void test_threads(void) {
    pthread_t th[4];
    void *res[4];
    t_value++;
    for (long i = 0; i < 4; i++) pthread_create(&th[i], 0, worker, (void *)(i + 1));
    for (int i = 0; i < 4; i++) pthread_join(th[i], &res[i]);
    printf("threads: shared=%ld atomic=%ld results=%ld,%ld,%ld,%ld tls=%d,%s\n", g_shared, (long)g_atomic,
           (long)res[0], (long)res[1], (long)res[2], (long)res[3], t_value, t_buf);
}

/* ---- signals ---- */
static volatile int g_sig_seen, g_sig_info;
static void on_usr1(int sig, siginfo_t *si, void *uc) { g_sig_seen += sig; g_sig_info = si != 0 && uc != 0; }
static void on_usr2(int sig) { g_sig_seen += 1000 * sig; }
static volatile int g_spin;
static void *sig_target(void *arg) {
    (void)arg;
    uint64_t h = 1;
    while (!g_spin) h = mix(h);         /* interrupted in the middle of recompiled code */
    return (void *)(h | 1);
}

EXPORT void test_signals(void) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, &old);
    signal(SIGUSR2, on_usr2);
    raise(SIGUSR1);
    raise(SIGUSR2);
    pthread_t th;
    pthread_create(&th, 0, sig_target, 0);
    usleep(20000);
    for (int i = 0; i < 5; i++) { pthread_kill(th, SIGUSR1); usleep(2000); }
    g_spin = 1;
    void *r;
    pthread_join(th, &r);
    struct sigaction cur;
    sigaction(SIGUSR1, 0, &cur);
    printf("signals: seen=%d info=%d handler_kept=%d old_default=%d thread=%d\n", g_sig_seen, g_sig_info,
           cur.sa_sigaction == on_usr1, old.sa_handler == SIG_DFL, r != 0);
    signal(SIGUSR2, SIG_DFL);
    sigaction(SIGUSR1, &old, 0);
}

/* ---- memory, strings, errno ---- */
struct node { struct node *next; int v; char name[12]; };

EXPORT void test_memory(void) {
    struct node *head = 0;
    for (int i = 0; i < 100; i++) {
        struct node *n = malloc(sizeof *n);
        n->v = i * i;
        snprintf(n->name, sizeof n->name, "n%d", i);
        n->next = head;
        head = n;
    }
    long s = 0; int len = 0;
    while (head) { struct node *n = head; s += n->v; len += (int)strlen(n->name); head = n->next; free(n); }
    errno = 0;
    long bad = strtol("99999999999999999999", 0, 10);
    int e = errno;
    char *dup = strdup("duplicate me");
    for (char *p = dup; *p; p++) if (*p == 'e') *p = 'E';
    printf("memory: sum=%ld len=%d strtol=%ld errno=%d dup=%s\n", s, len, bad, e == ERANGE, dup);
    free(dup);
}
