/* Instruction-set coverage test: one mode per instruction family.
 *   isa FAMILY      prints a checksum of results computed with that family
 *   isa all         every family the CPU supports
 * The recompiled program must print exactly what the original prints.
 * Inputs come from volatile memory so the compiler can't fold the work away. */
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <cpuid.h>

static volatile uint64_t seedv = 0x9E3779B97F4A7C15ull;
static uint64_t rng(void) {
    uint64_t x = seedv;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    seedv = x;
    return x;
}
static uint64_t mix(uint64_t h, uint64_t v) { return (h ^ v) * 0x100000001B3ull + (h >> 29); }
static uint64_t mixv(uint64_t h, const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) h = mix(h, b[i]);
    return h;
}
static void fill(void *p, size_t n) { unsigned char *b = p; for (size_t i = 0; i < n; i++) b[i] = (unsigned char)rng(); }
static float frand(void) { return (float)((int64_t)(rng() % 20001) - 10000) / 97.0f; }

#define T(x) __attribute__((target(x), noinline))

T("sse4.2,popcnt") static uint64_t f_sse42(void) {
    uint64_t h = 0; uint32_t c = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t v = rng();
#ifdef __x86_64__
        c = (uint32_t)_mm_crc32_u64(c, v); h = mix(h, (uint64_t)_mm_popcnt_u64(v));
#else
        c = _mm_crc32_u32(c, (uint32_t)v); c = _mm_crc32_u32(c, (uint32_t)(v >> 32));
        h = mix(h, (uint64_t)_mm_popcnt_u32((uint32_t)v));
#endif
        c = _mm_crc32_u8(c, (uint8_t)v); c = _mm_crc32_u16(c, (uint16_t)v);
        h = mix(h, c);
    }
    char a[16], b[16]; fill(a, 16); fill(b, 16); a[5] = b[5];
    __m128i x = _mm_loadu_si128((void *)a), y = _mm_loadu_si128((void *)b);
    h = mix(h, (uint64_t)_mm_cmpistri(x, y, _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_EACH));
    h = mix(h, (uint64_t)_mm_cmpestri(x, 9, y, 12, _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY));
    __m128i m = _mm_cmpistrm(x, y, _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_EACH | _SIDD_UNIT_MASK);
    h = mixv(h, &m, 16);
    h = mix(h, (uint64_t)_mm_cmpgt_epi64(x, y)[0]);
    return h;
}

T("sse4.1") static uint64_t f_sse41(void) {
    uint64_t h = 0;
    for (int i = 0; i < 32; i++) {
        __m128 a = _mm_set_ps(frand(), frand(), frand(), frand()), b = _mm_set_ps(frand(), frand(), frand(), frand());
        __m128 d = _mm_dp_ps(a, b, 0xF1);
        __m128 r = _mm_round_ps(a, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC);
        __m128 fl = _mm_floor_ps(b), ce = _mm_ceil_ps(a);
        __m128 bl = _mm_blendv_ps(a, b, _mm_cmplt_ps(a, b));
        __m128i ia, ib; fill(&ia, 16); fill(&ib, 16);
        __m128i ml = _mm_mullo_epi32(ia, ib), mx = _mm_max_epi32(ia, ib), mn = _mm_min_epu16(ia, ib);
        __m128i pb = _mm_blendv_epi8(ia, ib, ia), ex = _mm_cvtepi8_epi32(ia), pk = _mm_packus_epi32(ia, ib);
        __m128i ins = _mm_insert_epi32(ia, (int)rng(), 2);
        h = mixv(h, &d, 16); h = mixv(h, &r, 16); h = mixv(h, &fl, 16); h = mixv(h, &ce, 16); h = mixv(h, &bl, 16);
        h = mixv(h, &ml, 16); h = mixv(h, &mx, 16); h = mixv(h, &mn, 16); h = mixv(h, &pb, 16);
        h = mixv(h, &ex, 16); h = mixv(h, &pk, 16); h = mixv(h, &ins, 16);
        h = mix(h, (uint64_t)_mm_testz_si128(ia, ib)); h = mix(h, (uint64_t)_mm_extract_epi8(ib, 7));
        __m128i mp = _mm_minpos_epu16(ia); h = mixv(h, &mp, 16);
        __m128i sad = _mm_mpsadbw_epu8(ia, ib, 5); h = mixv(h, &sad, 16);
    }
    return h;
}

T("ssse3") static uint64_t f_ssse3(void) {
    uint64_t h = 0;
    for (int i = 0; i < 32; i++) {
        __m128i a, b; fill(&a, 16); fill(&b, 16);
        __m128i s = _mm_shuffle_epi8(a, b), al = _mm_alignr_epi8(a, b, 5), ab = _mm_abs_epi16(a);
        __m128i hd = _mm_hadd_epi32(a, b), ma = _mm_maddubs_epi16(a, b), mr = _mm_mulhrs_epi16(a, b);
        __m128i sg = _mm_sign_epi8(a, b);
        h = mixv(h, &s, 16); h = mixv(h, &al, 16); h = mixv(h, &ab, 16); h = mixv(h, &hd, 16);
        h = mixv(h, &ma, 16); h = mixv(h, &mr, 16); h = mixv(h, &sg, 16);
    }
    return h;
}

T("bmi,bmi2,lzcnt") static uint64_t f_bmi(void) {
    uint64_t h = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t a = rng(), b = rng();
#ifdef __x86_64__
        unsigned long long hi;
        h = mix(h, _andn_u64(a, b)); h = mix(h, _blsr_u64(a)); h = mix(h, _blsi_u64(a)); h = mix(h, _blsmsk_u64(a));
        h = mix(h, _bextr_u64(a, (unsigned)(b & 63), (unsigned)((b >> 8) & 63)));
        h = mix(h, _tzcnt_u64(a & (b | 1))); h = mix(h, _lzcnt_u64(a >> (b & 63)));
        h = mix(h, _pdep_u64(a, b)); h = mix(h, _pext_u64(a, b)); h = mix(h, _bzhi_u64(a, (unsigned)(b & 127)));
        h = mix(h, _mulx_u64(a, b, &hi)); h = mix(h, hi);
        h = mix(h, a << (b & 63)); h = mix(h, (int64_t)a >> (b & 63));                 /* shlx/sarx */
        h = mix(h, (a >> 17) | (a << 47));                                              /* rorx */
#else
        uint32_t x = (uint32_t)a, y = (uint32_t)b, hi32;
        h = mix(h, _andn_u32(x, y)); h = mix(h, _blsr_u32(x)); h = mix(h, _blsi_u32(x)); h = mix(h, _blsmsk_u32(x));
        h = mix(h, _bextr_u32(x, y & 31, (y >> 8) & 31));
        h = mix(h, _tzcnt_u32(x & (y | 1))); h = mix(h, _lzcnt_u32(x >> (y & 31)));
        h = mix(h, _bzhi_u32(x, y & 63)); h = mix(h, _mulx_u32(x, y, &hi32)); h = mix(h, hi32);
        h = mix(h, x << (y & 31)); h = mix(h, (uint32_t)((int32_t)x >> (y & 31)));
        h = mix(h, (x >> 13) | (x << 19));
#endif
        h = mix(h, _pdep_u32((uint32_t)a, (uint32_t)b)); h = mix(h, _pext_u32((uint32_t)a, (uint32_t)b));
    }
    return h;
}

T("adx") static uint64_t f_adx(void) {
#ifdef __x86_64__
    typedef unsigned long long word;
#define ADCX _addcarryx_u64
#define ADC _addcarry_u64
#define SBB _subborrow_u64
#else
    typedef unsigned int word;
#define ADCX _addcarryx_u32
#define ADC _addcarry_u32
#define SBB _subborrow_u32
#endif
    word a[8], b[8], r[8]; uint64_t h = 0;
    for (int k = 0; k < 16; k++) {
        for (int i = 0; i < 8; i++) { a[i] = (word)rng(); b[i] = (word)rng(); }
        unsigned char c = 0, o = 0;
        for (int i = 0; i < 8; i++) { word t; c = ADCX(c, a[i], b[i], &t); o = ADC(o, t, a[i], &r[i]); }
        h = mixv(h, r, sizeof r); h = mix(h, c); h = mix(h, o);
        unsigned char bw = 0;
        for (int i = 0; i < 8; i++) bw = SBB(bw, a[i], b[i], &r[i]);
        h = mixv(h, r, sizeof r); h = mix(h, bw);
    }
#undef ADCX
#undef ADC
#undef SBB
    return h;
}

T("movbe") static uint64_t f_movbe(void) {
    uint64_t h = 0; uint64_t buf[4];
    for (int i = 0; i < 64; i++) {
        uint64_t v = rng(); uint32_t w; uint16_t s;
#ifdef __x86_64__
        __asm__ volatile("movbeq %1, %0" : "=m"(buf[0]) : "r"(v)); h = mix(h, buf[0]);
#else
        __asm__ volatile("movbel %1, %0" : "=m"(*(uint32_t *)buf) : "r"((uint32_t)v)); h = mix(h, buf[0] & 0xffffffff);
#endif
        __asm__ volatile("movbel %1, %0" : "=r"(w) : "m"(buf[0])); h = mix(h, w);
        __asm__ volatile("movbew %1, %0" : "=r"(s) : "m"(buf[0])); h = mix(h, s);
        h = mix(h, __builtin_bswap64(v)); h = mix(h, __builtin_bswap32((uint32_t)v));
    }
    return h;
}

T("aes,pclmul") static uint64_t f_aes(void) {
    uint64_t h = 0;
    __m128i k, s; fill(&k, 16); fill(&s, 16);
    for (int i = 0; i < 32; i++) {
        __m128i ka = _mm_aeskeygenassist_si128(k, 0x1b);
        s = _mm_aesenc_si128(s, k); s = _mm_aesenclast_si128(s, ka);
        __m128i d = _mm_aesdec_si128(s, k), dl = _mm_aesdeclast_si128(d, ka), im = _mm_aesimc_si128(k);
        __m128i c0 = _mm_clmulepi64_si128(s, k, 0x00), c1 = _mm_clmulepi64_si128(s, k, 0x11);
        h = mixv(h, &s, 16); h = mixv(h, &d, 16); h = mixv(h, &dl, 16); h = mixv(h, &im, 16);
        h = mixv(h, &c0, 16); h = mixv(h, &c1, 16); h = mixv(h, &ka, 16);
        k = _mm_xor_si128(k, d);
    }
    return h;
}

T("sha,sse4.1") static uint64_t f_sha(void) {
    uint64_t h = 0;
    __m128i a, b, c; fill(&a, 16); fill(&b, 16); fill(&c, 16);
    for (int i = 0; i < 32; i++) {
        __m128i r2 = _mm_sha256rnds2_epu32(a, b, c), m1 = _mm_sha256msg1_epu32(a, b), m2 = _mm_sha256msg2_epu32(b, c);
        __m128i s4 = _mm_sha1rnds4_epu32(a, b, 2), n = _mm_sha1nexte_epu32(a, b);
        __m128i q1 = _mm_sha1msg1_epu32(a, b), q2 = _mm_sha1msg2_epu32(b, c);
        h = mixv(h, &r2, 16); h = mixv(h, &m1, 16); h = mixv(h, &m2, 16); h = mixv(h, &s4, 16);
        h = mixv(h, &n, 16); h = mixv(h, &q1, 16); h = mixv(h, &q2, 16);
        a = _mm_xor_si128(r2, q2); b = _mm_add_epi32(b, s4); c = _mm_sub_epi32(c, m1);
    }
    return h;
}

T("avx") static uint64_t f_avx(void) {
    uint64_t h = 0;
    for (int i = 0; i < 32; i++) {
        float fa[8], fb[8]; for (int j = 0; j < 8; j++) { fa[j] = frand(); fb[j] = frand(); }
        __m256 a = _mm256_loadu_ps(fa), b = _mm256_loadu_ps(fb);
        __m256 s = _mm256_add_ps(a, b), m = _mm256_mul_ps(a, b), d = _mm256_div_ps(a, _mm256_set1_ps(3.0f));
        __m256 p = _mm256_permute2f128_ps(a, b, 0x21), sh = _mm256_shuffle_ps(a, b, 0x4e), bl = _mm256_blend_ps(a, b, 0x5a);
        __m256 mx = _mm256_max_ps(a, b), sq = _mm256_sqrt_ps(_mm256_mul_ps(a, a)), hd = _mm256_hadd_ps(a, b);
        __m256 bc = _mm256_broadcast_ss(&fa[3]), pv = _mm256_permutevar_ps(a, _mm256_set_epi32(3, 1, 2, 0, 0, 3, 1, 2));
        __m256 cm = _mm256_cmp_ps(a, b, _CMP_LT_OQ), rd = _mm256_round_ps(a, _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC);
        __m256d dd = _mm256_cvtps_pd(_mm256_castps256_ps128(a));
        __m256i ci = _mm256_cvttps_epi32(a);
        __m128 ex = _mm256_extractf128_ps(b, 1);
        h = mixv(h, &s, 32); h = mixv(h, &m, 32); h = mixv(h, &d, 32); h = mixv(h, &p, 32); h = mixv(h, &sh, 32);
        h = mixv(h, &bl, 32); h = mixv(h, &mx, 32); h = mixv(h, &sq, 32); h = mixv(h, &hd, 32); h = mixv(h, &bc, 32);
        h = mixv(h, &pv, 32); h = mixv(h, &cm, 32); h = mixv(h, &rd, 32); h = mixv(h, &dd, 32); h = mixv(h, &ci, 32);
        h = mixv(h, &ex, 16); h = mix(h, (uint64_t)_mm256_movemask_ps(cm)); h = mix(h, (uint64_t)_mm256_testz_ps(a, b));
    }
    _mm256_zeroupper();
    return h;
}

T("avx2") static uint64_t f_avx2(void) {
    uint64_t h = 0;
    int32_t table[64]; for (int j = 0; j < 64; j++) table[j] = (int32_t)rng();
    for (int i = 0; i < 32; i++) {
        __m256i a, b; fill(&a, 32); fill(&b, 32);
        __m256i ad = _mm256_add_epi32(a, b), ml = _mm256_mullo_epi16(a, b), sh = _mm256_shuffle_epi8(a, b);
        __m256i pm = _mm256_permutevar8x32_epi32(a, b), p4 = _mm256_permute4x64_epi64(a, 0x9c);
        __m256i sv = _mm256_sllv_epi32(a, _mm256_and_si256(b, _mm256_set1_epi32(31)));
        __m256i sr = _mm256_srav_epi32(a, _mm256_and_si256(b, _mm256_set1_epi32(31)));
        __m256i idx = _mm256_and_si256(b, _mm256_set1_epi32(63));
        __m256i g = _mm256_i32gather_epi32(table, idx, 4);
        __m256i mg = _mm256_mask_i32gather_epi32(a, table, idx, _mm256_srai_epi32(a, 31), 4);
        __m256i bc = _mm256_broadcastd_epi32(_mm256_castsi256_si128(a)), un = _mm256_unpacklo_epi8(a, b);
        __m256i pk = _mm256_packs_epi32(a, b), sa = _mm256_sad_epu8(a, b), mx = _mm256_max_epu8(a, b);
        __m256i cv = _mm256_cvtepu8_epi16(_mm256_castsi256_si128(b)), al = _mm256_alignr_epi8(a, b, 3);
        __m256i md = _mm256_madd_epi16(a, b), av = _mm256_avg_epu16(a, b), bl = _mm256_blendv_epi8(a, b, a);
        h = mixv(h, &ad, 32); h = mixv(h, &ml, 32); h = mixv(h, &sh, 32); h = mixv(h, &pm, 32); h = mixv(h, &p4, 32);
        h = mixv(h, &sv, 32); h = mixv(h, &sr, 32); h = mixv(h, &g, 32); h = mixv(h, &mg, 32); h = mixv(h, &bc, 32);
        h = mixv(h, &un, 32); h = mixv(h, &pk, 32); h = mixv(h, &sa, 32); h = mixv(h, &mx, 32); h = mixv(h, &cv, 32);
        h = mixv(h, &al, 32); h = mixv(h, &md, 32); h = mixv(h, &av, 32); h = mixv(h, &bl, 32);
        h = mix(h, (uint64_t)(uint32_t)_mm256_movemask_epi8(a));
    }
    _mm256_zeroupper();
    return h;
}

T("fma,avx") static uint64_t f_fma(void) {
    uint64_t h = 0;
    for (int i = 0; i < 32; i++) {
        float fa[8], fb[8], fc[8]; for (int j = 0; j < 8; j++) { fa[j] = frand(); fb[j] = frand(); fc[j] = frand(); }
        __m256 a = _mm256_loadu_ps(fa), b = _mm256_loadu_ps(fb), c = _mm256_loadu_ps(fc);
        __m256 r1 = _mm256_fmadd_ps(a, b, c), r2 = _mm256_fmsub_ps(a, b, c), r3 = _mm256_fnmadd_ps(a, b, c);
        __m256 r4 = _mm256_fmaddsub_ps(a, b, c);
        __m128d x = _mm_set_pd(fa[0], fb[1]), y = _mm_set_pd(fc[2], fa[3]), z = _mm_set_pd(fb[4], fc[5]);
        __m128d r5 = _mm_fmadd_sd(x, y, z), r6 = _mm_fnmsub_pd(x, y, z);
        h = mixv(h, &r1, 32); h = mixv(h, &r2, 32); h = mixv(h, &r3, 32); h = mixv(h, &r4, 32);
        h = mixv(h, &r5, 16); h = mixv(h, &r6, 16);
        h = mix(h, (uint64_t)(int64_t)(fmaf(fa[0], fb[0], fc[0]) * 1000.0f));
    }
    _mm256_zeroupper();
    return h;
}

T("f16c,avx") static uint64_t f_f16c(void) {
    uint64_t h = 0;
    for (int i = 0; i < 32; i++) {
        float fa[8]; for (int j = 0; j < 8; j++) fa[j] = frand();
        __m128i hp = _mm256_cvtps_ph(_mm256_loadu_ps(fa), _MM_FROUND_TO_NEAREST_INT);
        __m256 back = _mm256_cvtph_ps(hp);
        h = mixv(h, &hp, 16); h = mixv(h, &back, 32);
    }
    _mm256_zeroupper();
    return h;
}

#ifdef __x86_64__
T("avx512f,avx512bw,avx512vl") static uint64_t f_avx512(void) {
    uint64_t h = 0;
    for (int i = 0; i < 16; i++) {
        __m512i a, b; fill(&a, 64); fill(&b, 64);
        __m512i s = _mm512_add_epi32(a, b), x = _mm512_xor_si512(a, b), t = _mm512_ternarylogic_epi32(a, b, s, 0x96);
        __mmask16 k = _mm512_cmplt_epi32_mask(a, b);
        __m512i m = _mm512_mask_add_epi32(a, k, a, b), z = _mm512_maskz_sub_epi32(k, a, b);
        __m512i p = _mm512_permutexvar_epi32(b, a), r = _mm512_rol_epi32(a, 7), mn = _mm512_min_epu8(a, b);
        __m512i cp = _mm512_maskz_compress_epi32(k, a);
        h = mixv(h, &s, 64); h = mixv(h, &x, 64); h = mixv(h, &t, 64); h = mix(h, k);
        h = mixv(h, &m, 64); h = mixv(h, &z, 64); h = mixv(h, &p, 64); h = mixv(h, &r, 64); h = mixv(h, &mn, 64);
        h = mixv(h, &cp, 64); h = mix(h, (uint64_t)_mm512_reduce_add_epi32(a));
    }
    _mm256_zeroupper();
    return h;
}
#else
static uint64_t f_avx512(void) { return 0; }
#endif

/* x87 and scalar libm paths: transcendental instructions, long double */
__attribute__((noinline)) static uint64_t f_x87(void) {
    uint64_t h = 0;
    for (int i = 0; i < 32; i++) {
        long double v = (long double)frand() / 3.0L, r;
        __asm__("fsin" : "=t"(r) : "0"(v)); h = mix(h, (uint64_t)(int64_t)(r * 1e12L));
        __asm__("fcos" : "=t"(r) : "0"(v)); h = mix(h, (uint64_t)(int64_t)(r * 1e12L));
        __asm__("fsqrt" : "=t"(r) : "0"(v * v)); h = mix(h, (uint64_t)(int64_t)(r * 1e12L));
        __asm__("fyl2x" : "=t"(r) : "0"(fabsl(v) + 1.0L), "u"(2.0L) : "st(1)"); h = mix(h, (uint64_t)(int64_t)(r * 1e12L));
        __asm__("fpatan" : "=t"(r) : "0"(v), "u"(1.5L) : "st(1)"); h = mix(h, (uint64_t)(int64_t)(r * 1e12L));
        __asm__("frndint" : "=t"(r) : "0"(v * 7.3L)); h = mix(h, (uint64_t)(int64_t)r);
        __asm__("f2xm1" : "=t"(r) : "0"(v / 200.0L)); h = mix(h, (uint64_t)(int64_t)(r * 1e15L));
        long double x = v * 9.0L, y = 2.5L, q;
        __asm__("1: fprem\n fnstsw %%ax\n test $4, %%ah\n jnz 1b" : "=t"(q) : "0"(x), "u"(y) : "ax");
        h = mix(h, (uint64_t)(int64_t)(q * 1e12L));
    }
    return h;
}

/* integer odds and ends every compiler emits */
#ifdef __x86_64__
T("cx16") static uint64_t f_int(void) {
    uint64_t h = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t a = rng(), b = rng() | 1;
        unsigned __int128 p = (unsigned __int128)a * b; h = mix(h, (uint64_t)(p >> 64)); h = mix(h, (uint64_t)p);
        __int128 sp = (__int128)(int64_t)a * (int64_t)b; h = mix(h, (uint64_t)(sp >> 64));
        h = mix(h, a / b); h = mix(h, a % b); h = mix(h, (uint64_t)((int64_t)a / (int64_t)b));
        unsigned __int128 n = ((unsigned __int128)(b >> 1) << 64) | a; h = mix(h, (uint64_t)(n / b));
        h = mix(h, (uint64_t)__builtin_popcountll(a)); h = mix(h, (uint64_t)__builtin_ctzll(a | 1));
        h = mix(h, (uint64_t)__builtin_clzll(a | 1)); h = mix(h, __builtin_bswap64(a));
        uint64_t r; __asm__("bsfq %1, %0" : "=r"(r) : "r"(a | 2)); h = mix(h, r);
        __asm__("btcq $13, %0" : "+r"(a)); h = mix(h, a);
        uint8_t cf; __asm__("btq %2, %1; setc %0" : "=r"(cf) : "r"(a), "r"(b & 63)); h = mix(h, cf);
        uint64_t sh = a; __asm__("shldq $11, %1, %0" : "+r"(sh) : "r"(b)); h = mix(h, sh);
        sh = a; __asm__("shrdq %%cl, %1, %0" : "+r"(sh) : "r"(b), "c"(b & 63)); h = mix(h, sh);
        uint64_t rc = a; __asm__("stc; rclq $3, %0" : "+r"(rc)); h = mix(h, rc);
        uint64_t old = a, want = b, mem = a;
        __asm__ volatile("lock cmpxchgq %2, %1" : "+a"(old), "+m"(mem) : "r"(want)); h = mix(h, mem);
        unsigned __int128 m16 = ((unsigned __int128)b << 64) | a, cmp = m16, nv = ((unsigned __int128)a << 64) | b;
        __int128 *mp = (__int128 *)&m16;
        h = mix(h, (uint64_t)__sync_bool_compare_and_swap(mp, (__int128)cmp, (__int128)nv)); h = mix(h, (uint64_t)m16);
        int64_t x = (int64_t)a; h = mix(h, (uint64_t)(x < 0 ? -x : x));
    }
    return h;
}
#else
/* 32-bit: 64-bit arithmetic through register pairs, CMPXCHG8B, 32-bit bit ops */
__attribute__((noinline)) static uint64_t f_int(void) {
    uint64_t h = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t a = rng(), b = rng() | 1;
        h = mix(h, a * b); h = mix(h, a / b); h = mix(h, a % b); h = mix(h, (uint64_t)((int64_t)a / (int64_t)b));
        h = mix(h, a << (b & 63)); h = mix(h, a >> (b & 63)); h = mix(h, (uint64_t)((int64_t)a >> (b & 63)));
        uint32_t x = (uint32_t)a, y = (uint32_t)b, r;
        h = mix(h, (uint64_t)__builtin_popcountll(a)); h = mix(h, (uint64_t)__builtin_ctzll(a | 1));
        h = mix(h, (uint64_t)__builtin_clzll(a | 1)); h = mix(h, __builtin_bswap64(a));
        __asm__("bsfl %1, %0" : "=r"(r) : "r"(x | 2)); h = mix(h, r);
        __asm__("btcl $13, %0" : "+r"(x)); h = mix(h, x);
        uint32_t sh = x; __asm__("shldl $11, %1, %0" : "+r"(sh) : "r"(y)); h = mix(h, sh);
        sh = x; __asm__("shrdl %%cl, %1, %0" : "+r"(sh) : "r"(y), "c"(y & 31)); h = mix(h, sh);
        uint64_t mem = a;
        h = mix(h, (uint64_t)__sync_bool_compare_and_swap(&mem, a, b)); h = mix(h, mem);
        uint32_t old = x, m32 = x;
        __asm__ volatile("lock cmpxchgl %2, %1" : "+a"(old), "+m"(m32) : "r"(y)); h = mix(h, m32);
    }
    return h;
}
#endif

__attribute__((noinline)) static uint64_t f_string(void) {
    static unsigned char src[4096], dst[4096];
    fill(src, sizeof src);
    uint64_t h = 0;
    for (int i = 0; i < 16; i++) {
        size_t n = 100 + rng() % 3000;
        { void *d0 = dst; const void *s0 = src + i; size_t c0 = n;
          __asm__ volatile("rep movsb" : "+D"(d0), "+S"(s0), "+c"(c0) : : "memory"); }
        h = mixv(h, dst, n);
        { void *d0 = dst; size_t c0 = n / 8;
#ifdef __x86_64__
          __asm__ volatile("rep stosq" : "+D"(d0), "+c"(c0) : "a"(rng()) : "memory"); }
#else
          c0 *= 2; __asm__ volatile("rep stosl" : "+D"(d0), "+c"(c0) : "a"((uint32_t)rng()) : "memory"); }
#endif
        h = mixv(h, dst, n & ~7);
        size_t left; const unsigned char *p = src;
        __asm__ volatile("repne scasb" : "=c"(left), "+D"(p) : "a"(src[n]), "0"(n + 1) : "memory");
        h = mix(h, left);
    }
    return h;
}

struct fam { const char *name; uint64_t (*fn)(void); int (*ok)(void); };
static unsigned r_ecx, r_ebx7, r_ecx7;
static int have(void) { return 1; }
static int h_sse42(void) { return (r_ecx >> 20) & 1; }
static int h_sse41(void) { return (r_ecx >> 19) & 1; }
static int h_ssse3(void) { return (r_ecx >> 9) & 1; }
static int h_bmi(void) { return ((r_ebx7 >> 3) & 1) && ((r_ebx7 >> 8) & 1); }
static int h_adx(void) { return (r_ebx7 >> 19) & 1; }
static int h_movbe(void) { return (r_ecx >> 22) & 1; }
static int h_aes(void) { return ((r_ecx >> 25) & 1) && ((r_ecx >> 1) & 1); }
static int h_sha(void) { return (r_ebx7 >> 29) & 1; }
static int h_avx(void) { return (r_ecx >> 28) & 1; }
static int h_avx2(void) { return (r_ebx7 >> 5) & 1; }
static int h_fma(void) { return (r_ecx >> 12) & 1; }
static int h_f16c(void) { return (r_ecx >> 29) & 1; }
static int h_avx512(void) { return ((r_ebx7 >> 16) & 1) && ((r_ebx7 >> 30) & 1) && ((r_ebx7 >> 31) & 1); }

static const struct fam fams[] = {
    {"int", f_int, have}, {"string", f_string, have}, {"x87", f_x87, have},
    {"ssse3", f_ssse3, h_ssse3}, {"sse41", f_sse41, h_sse41}, {"sse42", f_sse42, h_sse42},
    {"bmi", f_bmi, h_bmi}, {"adx", f_adx, h_adx}, {"movbe", f_movbe, h_movbe},
    {"aes", f_aes, h_aes}, {"sha", f_sha, h_sha}, {"avx", f_avx, h_avx}, {"avx2", f_avx2, h_avx2},
    {"fma", f_fma, h_fma}, {"f16c", f_f16c, h_f16c}, {"avx512", f_avx512, h_avx512},
};

int main(int argc, char **argv) {
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d); r_ecx = c;
    __cpuid_count(7, 0, a, b, c, d); r_ebx7 = b; r_ecx7 = c;
    const char *want = argc > 1 ? argv[1] : "all";
    int found = 0;
    for (size_t i = 0; i < sizeof fams / sizeof fams[0]; i++) {
        if (strcmp(want, "all") && strcmp(want, fams[i].name)) continue;
        found = 1;
        seedv = 0x9E3779B97F4A7C15ull + i;
        if (!fams[i].ok()) { printf("%-7s not supported by this CPU\n", fams[i].name); continue; }
        printf("%-7s %016llx\n", fams[i].name, (unsigned long long)fams[i].fn());
        fflush(stdout);
    }
    if (!found) { printf("unknown family %s\n", want); return 2; }
    return 0;
}
