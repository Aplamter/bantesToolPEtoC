/* SSE3/SSSE3/SSE4 instructions with awkward values: the recompiled program
 * must print exactly what the CPU computes */
#include <stdio.h>
#include <string.h>
#include <immintrin.h>
static void show(const char *n, __m128i v) {
    unsigned char b[16]; _mm_storeu_si128((__m128i *)b, v);
    printf("%-12s", n); for (int i = 15; i >= 0; i--) printf("%02x", b[i]); printf("\n");
}
#define NOINL __attribute__((noinline))
#define F(name, expr) NOINL static __m128i f_##name(__m128i a, __m128i b) { __m128 fa = _mm_castsi128_ps(a), fb = _mm_castsi128_ps(b); \
    __m128d da = _mm_castsi128_pd(a), db = _mm_castsi128_pd(b); (void)fa; (void)fb; (void)da; (void)db; return expr; }
F(insertps1, _mm_castps_si128(_mm_insert_ps(fa, fb, 0x9c)))
F(insertps2, _mm_castps_si128(_mm_insert_ps(fa, fb, 0x21)))
F(blendps, _mm_castps_si128(_mm_blend_ps(fa, fb, 0x6)))
F(blendpd, _mm_castpd_si128(_mm_blend_pd(da, db, 0x2)))
F(pblendw, _mm_blend_epi16(a, b, 0xa5))
F(dpps, _mm_castps_si128(_mm_dp_ps(fa, fb, 0x7b)))
F(dppd, _mm_castpd_si128(_mm_dp_pd(da, db, 0x31)))
F(cmppd, _mm_castpd_si128(_mm_cmplt_pd(da, db)))
F(cmpss, _mm_castps_si128(_mm_cmpneq_ss(fa, fb)))
F(maxpd, _mm_castpd_si128(_mm_max_pd(da, db)))
F(minpd, _mm_castpd_si128(_mm_min_pd(da, db)))
F(roundpd, _mm_castpd_si128(_mm_round_pd(db, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC)))
F(pabsb, _mm_abs_epi8(b))
F(pabsd, _mm_abs_epi32(b))
F(packusdw, _mm_packus_epi32(a, b))
F(pavgw, _mm_avg_epu16(a, b))
F(phaddw, _mm_hadd_epi16(a, b))
F(phaddd, _mm_hadd_epi32(a, b))
F(phaddsw, _mm_hadds_epi16(a, b))
F(phsubw, _mm_hsub_epi16(a, b))
F(phsubd, _mm_hsub_epi32(a, b))
F(phsubsw, _mm_hsubs_epi16(a, b))
F(phminposuw, _mm_minpos_epu16(b))
F(pmovsxbq, _mm_cvtepi8_epi64(b))
F(pmovsxwq, _mm_cvtepi16_epi64(b))
F(pmulhrsw, _mm_mulhrs_epi16(a, b))
F(psignb, _mm_sign_epi8(a, b))
F(psignw, _mm_sign_epi16(a, b))
F(psignd, _mm_sign_epi32(a, b))
NOINL static int f_extractps(__m128i a) { return _mm_extract_ps(_mm_castsi128_ps(a), 2); }
NOINL static unsigned f_crc8(unsigned c, unsigned char v) { return _mm_crc32_u8(c, v); }
NOINL static unsigned f_crc32(unsigned c, unsigned v) { return _mm_crc32_u32(c, v); }
NOINL static unsigned long long f_crc64(unsigned long long c, unsigned long long v) { return _mm_crc32_u64(c, v); }
NOINL static __m128i f_insertmem(__m128i a, const float *p) { return _mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(a), _mm_load_ss(p), 0x20)); }
int main(void) {
    static const unsigned char pa[3][16] = {
        {0x7e,0x2a,0x40,0x3d, 0xd7,0x9e,0x34,0xbf, 0x00,0x00,0x80,0x7f, 0x01,0x00,0x00,0x80},
        {0xff,0x7f,0x00,0x80, 0x34,0x12,0xff,0xff, 0x80,0x7f,0x01,0xfe, 0x00,0x00,0xf0,0x3f},
        {0x18,0x2d,0x44,0x54, 0xfb,0x21,0x09,0x40, 0x00,0x00,0x00,0x00, 0x00,0x00,0xf8,0xbf}};
    static const unsigned char pb[3][16] = {
        {0x00,0x00,0x80,0x3f, 0x00,0x00,0x20,0xc1, 0xcd,0xcc,0x4c,0x3e, 0x00,0x00,0xc0,0x7f},
        {0x00,0x80,0xff,0x7f, 0x80,0x00,0x81,0xff, 0x00,0x00,0x01,0x00, 0xfe,0xff,0x03,0x00},
        {0x00,0x00,0x00,0x00, 0x00,0x00,0x04,0x40, 0x9a,0x99,0x99,0x99, 0x99,0x99,0xe9,0xbf}};
    volatile int z = 0;
    for (int k = 0; k < 3; k++) {
        __m128i a = _mm_loadu_si128((const __m128i *)pa[k + z]), b = _mm_loadu_si128((const __m128i *)pb[k + z]);
        printf("-- set %d\n", k);
#define S(name) show(#name, f_##name(a, b));
        S(insertps1) S(insertps2) S(blendps) S(blendpd) S(pblendw) S(dppd)
        if (k != 1) S(dpps)   /* set 1 is two NaNs: which payload wins is the CPU's secret */ S(cmppd) S(cmpss)
        S(maxpd) S(minpd) S(roundpd) S(pabsb) S(pabsd) S(packusdw) S(pavgw) S(phaddw) S(phaddd)
        S(phaddsw) S(phsubw) S(phsubd) S(phsubsw) S(phminposuw) S(pmovsxbq) S(pmovsxwq) S(pmulhrsw)
        S(psignb) S(psignw) S(psignd)
        float fm = 3.5f + k;
        show("insertmem", f_insertmem(a, &fm));
        printf("extractps   %08x  crc %08x %08x %016llx\n", (unsigned)f_extractps(a), f_crc8(0x12345678u + k, pa[k][3]),
               f_crc32(~0u, 0xdeadbeefu + k), f_crc64(0x1234, 0x0123456789abcdefULL * (k + 1)));
    }
    return 0;
}
