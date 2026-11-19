/* 32-bit CPU details: 64-bit integer math on a 32-bit CPU, SSE2 / MMX
 * vectors, 8-byte atomics (CMPXCHG8B), string instructions, flags, static
 * thread-local storage (fs:[0x2C]) and x87 corner cases.
 * i686-w64-mingw32-gcc -O2 -msse2 -o cpu32.exe cpu32.c -lm */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <emmintrin.h>
#include <mmintrin.h>

static uint64_t seed = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed; }

/* ---- static TLS, the way MSVC's __declspec(thread) does it ---- */
extern unsigned _tls_index;
extern char _tls_start;
__attribute__((section(".tls$RCMP"))) int tls_counter = 1000;
__attribute__((section(".tls$RCMP"))) char tls_name[12] = "template";
static __attribute__((noinline)) char *tls_block(void) {
    char **arr;
    __asm__("movl %%fs:0x2c, %0" : "=r"(arr));
    return arr[_tls_index];
}
#define TLS(v) (*(__typeof__(v) *)(tls_block() + ((char *)&(v) - &_tls_start)))

static DWORD WINAPI tls_thread(LPVOID arg) {
    int k = (int)(INT_PTR)arg;
    for (int i = 0; i < 1000 * k; i++) TLS(tls_counter)++;
    TLS(tls_name)[0] = (char)('A' + k);
    return (DWORD)TLS(tls_counter) * 10 + (TLS(tls_name)[0] - 'A');
}

static volatile LONG64 shared64;
static DWORD WINAPI add64_thread(LPVOID arg) {
    (void)arg;
    for (int i = 0; i < 20000; i++) InterlockedExchangeAdd64(&shared64, 0x100000001LL);
    return 0;
}

int main(void) {
    /* 64-bit integers on a 32-bit CPU */
    uint64_t h = 0; int64_t sh = 0;
    for (int i = 0; i < 2000; i++) {
        uint64_t a = rnd(), b = rnd() | 1; int s = (int)(rnd() & 63);
        h ^= a * b; h += a / (b >> 20 | 1); h ^= a % (b >> 33 | 1);
        h += (a << s) | (a >> ((64 - s) & 63)); h ^= (uint64_t)((int64_t)a >> s);
        sh += (int64_t)a / (int64_t)(b >> 40 | 1) + (int64_t)a % 1000003;
        h += __builtin_popcountll(a) + __builtin_clzll(b) * 3 + __builtin_ctzll(b << 7) * 5 + __builtin_bswap64(a);
    }
    printf("int64: %016llx %lld\n", (unsigned long long)h, (long long)sh);

    /* SSE2 integer and float vectors */
    __m128i v = _mm_set_epi32(0x01234567, (int)0x89abcdef, 0x0fedcba9, 0x76543210), acc = _mm_setzero_si128();
    __m128d d = _mm_set_pd(1.25, -3.5);
    __m128 f = _mm_set_ps(0.5f, 1.5f, -2.5f, 100.0f);
    for (int i = 0; i < 64; i++) {
        __m128i t = (i & 1) ? _mm_xor_si128(_mm_slli_si128(v, 3), _mm_srli_si128(v, 5))
                            : _mm_xor_si128(_mm_slli_si128(v, 9), _mm_srli_si128(v, 1));
        t = _mm_add_epi64(t, _mm_mul_epu32(v, t));
        t = _mm_sub_epi16(_mm_unpacklo_epi8(t, v), _mm_packs_epi32(v, t));
        t = _mm_or_si128(_mm_slli_epi64(t, i & 31), _mm_srai_epi32(t, i & 15));
        acc = _mm_add_epi32(_mm_shuffle_epi32(acc, 0x1b), _mm_madd_epi16(t, v));
        acc = _mm_xor_si128(acc, _mm_cmpgt_epi32(t, acc));
        v = _mm_add_epi8(v, _mm_avg_epu8(acc, t));
        d = _mm_add_pd(_mm_mul_pd(d, _mm_set1_pd(1.0000001)), _mm_sqrt_pd(_mm_set_pd(i + 1.0, i + 2.0)));
        f = _mm_div_ps(_mm_add_ps(f, _mm_cvtepi32_ps(_mm_and_si128(t, _mm_set1_epi32(0xff)))), _mm_set1_ps(1.5f));
        f = _mm_max_ps(f, _mm_min_ps(_mm_sqrt_ps(_mm_mul_ps(f, f)), _mm_set1_ps(1e6f)));
    }
    uint32_t o[4]; double od[2]; float of[4];
    _mm_storeu_si128((__m128i *)o, acc); _mm_storeu_pd(od, d); _mm_storeu_ps(of, f);
    printf("sse2: %08x %08x %08x %08x mask %x | %.12f %.12f | %.5f %.5f %.5f %.5f | %d %d\n", o[0], o[1], o[2], o[3],
           _mm_movemask_epi8(v), od[0], od[1], of[0], of[1], of[2], of[3], _mm_cvtsd_si32(d), _mm_cvttss_si32(f));

    /* MMX, then EMMS before floating point again */
    __m64 m = _mm_set_pi16(1, 2, 3, 4), n = _mm_set_pi16(100, -200, 300, -400);
    for (int i = 0; i < 10; i++) { m = _mm_add_pi16(_mm_mullo_pi16(m, n), _mm_srli_pi16(n, 1)); n = _mm_xor_si64(n, _mm_slli_si64(m, 3)); }
    uint32_t mlo = (uint32_t)_mm_cvtsi64_si32(m), mhi = (uint32_t)_mm_cvtsi64_si32(_mm_srli_si64(m, 32));
    _mm_empty();
    volatile long double ld = 2.0L;
    printf("mmx: %08x%08x, x87 after emms: %.15Lf\n", mhi, mlo, sqrtl(ld) * atanl(ld) + powl(ld, 0.3L));

    /* x87 corner cases */
    volatile double big = 1e300, tiny = 1e-320, neg0 = -0.0, nan = NAN, inf = INFINITY;
    volatile long double e = expl(1.0L), t7 = tanl(0.7L);
    printf("x87: %g %g %g %d %d %d %.17g %.18Lg %.18Lg %ld %lld\n", big * big, tiny / 3, neg0 * 5, isnan(nan * 0), isinf(inf),
           fpclassify(tiny), fmod(1e20, 3.7), e, t7, lrint(-2.5), llrint(1e15 + 0.5));
    printf("x87: %.15g %.15g %.15g %.15g %d\n", ldexp(0.75, 40), frexp(12345.678, &(int){0}), cbrt(-27.0), hypot(3e200, 4e200),
           (int)floor(-0.5) + (int)ceil(2.1) * 10 + (int)trunc(-7.9) * 100 + (int)round(2.5) * 1000);

    /* string instructions and flags */
    char buf[300], buf2[300];
    for (int i = 0; i < 300; i++) buf[i] = (char)(i * 7 + 3);
    memmove(buf2, buf, 300); memmove(buf2 + 5, buf2, 200); memset(buf2 + 250, 0x5a, 37);
    unsigned sum = 0;
    for (int i = 0; i < 300; i++) sum = sum * 31 + (unsigned char)buf2[i];
    unsigned c = 0, x = 0xdeadbeef;
    for (int i = 0; i < 40; i++) {
        unsigned y = x + sum; c += y < x;                       /* carry */
        c += __builtin_add_overflow_p((int)x, (int)sum, (int)0) * 3;
        c += __builtin_mul_overflow_p((int)x, (int)i, (int)0) * 7;
        x = (x << (i & 31)) | (x >> ((32 - i) & 31)); x ^= y; sum += x / (i + 1) + x % (i + 3);
    }
    printf("strings/flags: %08x %08x %u memchr %d strcmp %d\n", sum, x, c, (int)((char *)memchr(buf, 0x5c, 300) - buf),
           strncmp(buf + 1, buf2 + 6, 50));

    /* 8-byte atomics across threads */
    HANDLE th[4];
    for (int i = 0; i < 4; i++) th[i] = CreateThread(0, 0, add64_thread, 0, 0, 0);
    WaitForMultipleObjects(4, th, TRUE, INFINITE);
    for (int i = 0; i < 4; i++) CloseHandle(th[i]);
    printf("atomic64: %llx\n", (unsigned long long)shared64);

    /* static TLS: every thread has its own copy of the template */
    DWORD code[3];
    TLS(tls_counter) += 5;
    for (int i = 0; i < 3; i++) th[i] = CreateThread(0, 0, tls_thread, (LPVOID)(INT_PTR)(i + 1), 0, 0);
    WaitForMultipleObjects(3, th, TRUE, INFINITE);
    for (int i = 0; i < 3; i++) { GetExitCodeThread(th[i], &code[i]); CloseHandle(th[i]); }
    printf("tls: main %d %s, threads %lu %lu %lu\n", TLS(tls_counter), TLS(tls_name), code[0], code[1], code[2]);
    return 7;
}
