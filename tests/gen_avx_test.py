#!/usr/bin/env python3
"""Generate tests/avx_wide.c: one test per AVX/AVX2 (and VEX-encoded SSE)
intrinsic, each printing its own checksum line, so a recompiled program that
gets one instruction wrong names it.

    python3 tests/gen_avx_test.py > tests/avx_wide.c
    avx_wide GROUP        GROUP = avxf | avxi | avx2 | vex128 | gather | all
"""
import sys

I = "__m256i"; F = "__m256"; D = "__m256d"; X = "__m128i"; XF = "__m128"; XD = "__m128d"
tests = []   # (group, name, C body computing `h`)


def add(group, name, body):
    tests.append((group, name, body))


def bin_(group, fn, t, sz):
    add(group, fn, f"{t} r = {fn}(a{t2s(t)}, b{t2s(t)}); h = mixv(h, &r, {sz});")


def un(group, fn, t_in, t_out, sz):
    add(group, fn, f"{t_out} r = {fn}(a{t2s(t_in)}); h = mixv(h, &r, {sz});")


def t2s(t):
    return {I: "i", F: "f", D: "d", X: "x", XF: "xf", XD: "xd"}[t]


# ---- AVX float (256-bit) ----
for op in ["add", "sub", "mul", "div", "min", "max", "and", "or", "xor", "andnot", "addsub",
           "hadd", "hsub", "unpacklo", "unpackhi"]:
    bin_("avxf", f"_mm256_{op}_ps", F, 32)
    bin_("avxf", f"_mm256_{op}_pd", D, 32)
for op in ["sqrt", "rcp", "rsqrt"]:
    un("avxf", f"_mm256_{op}_ps", F, F, 32)
un("avxf", "_mm256_sqrt_pd", D, D, 32)
for op in ["floor", "ceil"]:
    un("avxf", f"_mm256_{op}_ps", F, F, 32)
    un("avxf", f"_mm256_{op}_pd", D, D, 32)
for m in [0, 1, 2, 3, 4, 8, 9, 10, 11, 12]:
    add("avxf", f"_mm256_round_ps/{m}", f"__m256 r = _mm256_round_ps(af, {m}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm256_round_pd/{m}", f"__m256d r = _mm256_round_pd(ad, {m}); h = mixv(h, &r, 32);")
for p in range(32):
    add("avxf", f"_mm256_cmp_ps/{p}", f"__m256 r = _mm256_cmp_ps(af, bf, {p}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm256_cmp_pd/{p}", f"__m256d r = _mm256_cmp_pd(ad, bd, {p}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm_cmp_ss/{p}", f"__m128 r = _mm_cmp_ss(axf, bxf, {p}); h = mixv(h, &r, 16);")
    add("avxf", f"_mm_cmp_sd/{p}", f"__m128d r = _mm_cmp_sd(axd, bxd, {p}); h = mixv(h, &r, 16);")
add("avxf", "_mm256_blendv_ps", "__m256 r = _mm256_blendv_ps(af, bf, cf); h = mixv(h, &r, 32);")
add("avxf", "_mm256_blendv_pd", "__m256d r = _mm256_blendv_pd(ad, bd, cd); h = mixv(h, &r, 32);")
for m in [0, 0x55, 0xa3, 0xff]:
    add("avxf", f"_mm256_blend_ps/{m:#x}", f"__m256 r = _mm256_blend_ps(af, bf, {m}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm256_dp_ps/{m:#x}", f"__m256 r = _mm256_dp_ps(af, bf, {m}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm256_shuffle_ps/{m:#x}", f"__m256 r = _mm256_shuffle_ps(af, bf, {m}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm256_permute_ps/{m:#x}", f"__m256 r = _mm256_permute_ps(af, {m}); h = mixv(h, &r, 32);")
for m in [0, 5, 10, 15]:
    add("avxf", f"_mm256_blend_pd/{m}", f"__m256d r = _mm256_blend_pd(ad, bd, {m}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm256_shuffle_pd/{m}", f"__m256d r = _mm256_shuffle_pd(ad, bd, {m}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm256_permute_pd/{m}", f"__m256d r = _mm256_permute_pd(ad, {m}); h = mixv(h, &r, 32);")
for m in [0x00, 0x01, 0x10, 0x20, 0x21, 0x31, 0x08, 0x83]:
    add("avxf", f"_mm256_permute2f128_ps/{m:#x}", f"__m256 r = _mm256_permute2f128_ps(af, bf, {m}); h = mixv(h, &r, 32);")
add("avxf", "_mm256_permutevar_ps", "__m256 r = _mm256_permutevar_ps(af, ai); h = mixv(h, &r, 32);")
add("avxf", "_mm256_permutevar_pd", "__m256d r = _mm256_permutevar_pd(ad, ai); h = mixv(h, &r, 32);")
add("avxf", "_mm_permutevar_ps", "__m128 r = _mm_permutevar_ps(axf, ax); h = mixv(h, &r, 16);")
for k in [0, 1]:
    add("avxf", f"_mm256_insertf128_ps/{k}", f"__m256 r = _mm256_insertf128_ps(af, bxf, {k}); h = mixv(h, &r, 32);")
    add("avxf", f"_mm256_extractf128_ps/{k}", f"__m128 r = _mm256_extractf128_ps(af, {k}); h = mixv(h, &r, 16);")
    add("avxf", f"_mm256_extractf128_pd/{k}", f"__m128d r = _mm256_extractf128_pd(ad, {k}); h = mixv(h, &r, 16);")
for fn, ti, to, sz in [("_mm256_cvtps_epi32", F, I, 32), ("_mm256_cvttps_epi32", F, I, 32),
                       ("_mm256_cvtepi32_ps", I, F, 32), ("_mm256_cvtpd_ps", D, XF, 16),
                       ("_mm256_cvtps_pd", XF, D, 32), ("_mm256_cvtpd_epi32", D, X, 16),
                       ("_mm256_cvttpd_epi32", D, X, 16), ("_mm256_cvtepi32_pd", X, D, 32),
                       ("_mm256_movehdup_ps", F, F, 32), ("_mm256_moveldup_ps", F, F, 32),
                       ("_mm256_movedup_pd", D, D, 32)]:
    un("avxf", fn, ti, to, sz)
add("avxf", "_mm256_movemask_ps", "h = mix(h, (uint64_t)_mm256_movemask_ps(af));")
add("avxf", "_mm256_movemask_pd", "h = mix(h, (uint64_t)_mm256_movemask_pd(ad));")
for fn in ["testz", "testc", "testnzc"]:
    add("avxf", f"_mm256_{fn}_ps", f"h = mix(h, (uint64_t)_mm256_{fn}_ps(af, bf));")
    add("avxf", f"_mm256_{fn}_si256", f"h = mix(h, (uint64_t)_mm256_{fn}_si256(ai, bi));")
add("avxf", "_mm256_broadcast_ss", "__m256 r = _mm256_broadcast_ss(&fbuf[3]); h = mixv(h, &r, 32);")
add("avxf", "_mm256_broadcast_sd", "__m256d r = _mm256_broadcast_sd(&dbuf[1]); h = mixv(h, &r, 32);")
add("avxf", "_mm256_broadcast_ps", "__m256 r = _mm256_broadcast_ps(&bxf); h = mixv(h, &r, 32);")
add("avxf", "_mm256_maskload_ps", "__m256 r = _mm256_maskload_ps(fbuf, ai); h = mixv(h, &r, 32);")
add("avxf", "_mm256_maskload_pd", "__m256d r = _mm256_maskload_pd(dbuf, ai); h = mixv(h, &r, 32);")
add("avxf", "_mm256_maskstore_ps", "float o[8]; memcpy(o, fbuf + 8, 32); _mm256_maskstore_ps(o, ai, af); h = mixv(h, o, 32);")
add("avxf", "_mm256_maskstore_pd", "double o[4]; memcpy(o, dbuf + 4, 32); _mm256_maskstore_pd(o, ai, ad); h = mixv(h, o, 32);")
add("avxf", "_mm256_zeroupper", "_mm256_zeroupper(); h = mix(h, 1);")

# ---- AVX2 integer (256-bit) ----
ints = []
for sfx in ["epi8", "epi16", "epi32", "epi64"]:
    ints += [f"add_{sfx}", f"sub_{sfx}", f"cmpeq_{sfx}", f"cmpgt_{sfx}", f"unpacklo_{sfx}", f"unpackhi_{sfx}"]
for sfx in ["epi8", "epi16", "epu8", "epu16"]:
    ints += [f"adds_{sfx}", f"subs_{sfx}"]
for sfx in ["epi8", "epi16", "epi32", "epu8", "epu16", "epu32"]:
    ints += [f"max_{sfx}", f"min_{sfx}"]
ints += ["mullo_epi16", "mullo_epi32", "mulhi_epi16", "mulhi_epu16", "mulhrs_epi16", "mul_epi32", "mul_epu32",
         "madd_epi16", "maddubs_epi16", "and_si256", "or_si256", "xor_si256", "andnot_si256", "avg_epu8",
         "avg_epu16", "packs_epi16", "packs_epi32", "packus_epi16", "packus_epi32", "shuffle_epi8",
         "sign_epi8", "sign_epi16", "sign_epi32", "hadd_epi16", "hadd_epi32", "hadds_epi16", "hsub_epi16",
         "hsub_epi32", "hsubs_epi16", "sad_epu8", "permutevar8x32_epi32"]
for op in ints:
    bin_("avx2", f"_mm256_{op}", I, 32)
add("avx2", "_mm256_permutevar8x32_ps", "__m256 r = _mm256_permutevar8x32_ps(af, bi); h = mixv(h, &r, 32);")
for op in ["sllv_epi32", "srlv_epi32", "srav_epi32", "sllv_epi64", "srlv_epi64"]:
    add("avx2", f"_mm256_{op}", f"__m256i c = _mm256_and_si256(bi, _mm256_set1_epi64x(0x3f0000003fLL)); "
        f"__m256i r = _mm256_{op}(ai, c); h = mixv(h, &r, 32); "
        f"r = _mm256_{op}(ai, bi); h = mixv(h, &r, 32);")
for op in ["sll_epi16", "sll_epi32", "sll_epi64", "srl_epi16", "srl_epi32", "srl_epi64", "sra_epi16", "sra_epi32"]:
    add("avx2", f"_mm256_{op}", f"__m128i c = _mm_and_si128(bx, _mm_set_epi64x(0, 0x3f)); "
        f"__m256i r = _mm256_{op}(ai, c); h = mixv(h, &r, 32);")
for n in [0, 1, 7, 15, 16, 31, 33, 63]:
    for op in ["slli_epi16", "slli_epi32", "slli_epi64", "srli_epi16", "srli_epi32", "srli_epi64",
               "srai_epi16", "srai_epi32"]:
        add("avx2", f"_mm256_{op}/{n}", f"__m256i r = _mm256_{op}(ai, {n}); h = mixv(h, &r, 32);")
for n in [0, 1, 5, 15, 16]:
    add("avx2", f"_mm256_slli_si256/{n}", f"__m256i r = _mm256_slli_si256(ai, {n}); h = mixv(h, &r, 32);")
    add("avx2", f"_mm256_srli_si256/{n}", f"__m256i r = _mm256_srli_si256(ai, {n}); h = mixv(h, &r, 32);")
for n in [0, 1, 5, 15, 16, 17, 31]:
    add("avx2", f"_mm256_alignr_epi8/{n}", f"__m256i r = _mm256_alignr_epi8(ai, bi, {n}); h = mixv(h, &r, 32);")
for m in [0x00, 0x1b, 0x4e, 0xb1, 0xe4, 0xff]:
    for op in ["shuffle_epi32", "shufflehi_epi16", "shufflelo_epi16", "permute4x64_epi64"]:
        add("avx2", f"_mm256_{op}/{m:#x}", f"__m256i r = _mm256_{op}(ai, {m}); h = mixv(h, &r, 32);")
    add("avx2", f"_mm256_permute4x64_pd/{m:#x}", f"__m256d r = _mm256_permute4x64_pd(ad, {m}); h = mixv(h, &r, 32);")
    add("avx2", f"_mm256_blend_epi16/{m:#x}", f"__m256i r = _mm256_blend_epi16(ai, bi, {m}); h = mixv(h, &r, 32);")
    add("avx2", f"_mm256_blend_epi32/{m:#x}", f"__m256i r = _mm256_blend_epi32(ai, bi, {m}); h = mixv(h, &r, 32);")
for m in [0, 1, 2, 3, 4, 5, 6, 7]:
    add("avx2", f"_mm256_mpsadbw_epu8/{m}", f"__m256i r = _mm256_mpsadbw_epu8(ai, bi, {m}); h = mixv(h, &r, 32);")
for m in [0x00, 0x01, 0x10, 0x20, 0x21, 0x31, 0x08, 0x83]:
    add("avx2", f"_mm256_permute2x128_si256/{m:#x}", f"__m256i r = _mm256_permute2x128_si256(ai, bi, {m}); h = mixv(h, &r, 32);")
for k in [0, 1]:
    add("avx2", f"_mm256_inserti128_si256/{k}", f"__m256i r = _mm256_inserti128_si256(ai, bx, {k}); h = mixv(h, &r, 32);")
    add("avx2", f"_mm256_extracti128_si256/{k}", f"__m128i r = _mm256_extracti128_si256(ai, {k}); h = mixv(h, &r, 16);")
for op in ["abs_epi8", "abs_epi16", "abs_epi32"]:
    un("avx2", f"_mm256_{op}", I, I, 32)
for op in ["cvtepi8_epi16", "cvtepi8_epi32", "cvtepi8_epi64", "cvtepi16_epi32", "cvtepi16_epi64", "cvtepi32_epi64",
           "cvtepu8_epi16", "cvtepu8_epi32", "cvtepu8_epi64", "cvtepu16_epi32", "cvtepu16_epi64", "cvtepu32_epi64"]:
    un("avx2", f"_mm256_{op}", X, I, 32)
for op in ["broadcastb_epi8", "broadcastw_epi16", "broadcastd_epi32", "broadcastq_epi64"]:
    un("avx2", f"_mm256_{op}", X, I, 32)
    un("vex128", f"_mm_{op}", X, X, 16)
un("avx2", "_mm256_broadcastss_ps", XF, F, 32)
un("avx2", "_mm256_broadcastsd_pd", XD, D, 32)
add("avx2", "_mm256_broadcastsi128_si256", "__m256i r = _mm256_broadcastsi128_si256(bx); h = mixv(h, &r, 32);")
add("avx2", "_mm256_movemask_epi8", "h = mix(h, (uint64_t)(uint32_t)_mm256_movemask_epi8(ai));")
add("avx2", "_mm256_blendv_epi8", "__m256i r = _mm256_blendv_epi8(ai, bi, ci); h = mixv(h, &r, 32);")
add("avx2", "_mm256_maskload_epi32", "__m256i r = _mm256_maskload_epi32(ibuf, ai); h = mixv(h, &r, 32);")
add("avx2", "_mm256_maskload_epi64", "__m256i r = _mm256_maskload_epi64((const long long *)ibuf, ai); h = mixv(h, &r, 32);")
add("avx2", "_mm256_maskstore_epi32", "int o[8]; memcpy(o, ibuf + 8, 32); _mm256_maskstore_epi32(o, ai, bi); h = mixv(h, o, 32);")
add("avx2", "_mm256_maskstore_epi64", "long long o[4]; memcpy(o, ibuf + 8, 32); _mm256_maskstore_epi64(o, ai, bi); h = mixv(h, o, 32);")
add("avx2", "_mm256_stream_load_si256", "__m256i r = _mm256_stream_load_si256((__m256i *)ibuf); h = mixv(h, &r, 32);")

# ---- VEX-encoded 128-bit (what SSE intrinsics become in AVX code) ----
for op in ["sllv_epi32", "srlv_epi32", "srav_epi32", "sllv_epi64", "srlv_epi64"]:
    add("vex128", f"_mm_{op}", f"__m128i r = _mm_{op}(ax, _mm_and_si128(bx, _mm_set1_epi32(0x3f))); h = mixv(h, &r, 16);")
for n in [0x4e, 0xb1]:
    add("vex128", f"_mm_shuffle_epi32/{n:#x}", f"__m128i r = _mm_shuffle_epi32(ax, {n}); h = mixv(h, &r, 16);")
for m in [0, 5, 10, 15]:
    add("vex128", f"_mm_blend_epi32/{m}", f"__m128i r = _mm_blend_epi32(ax, bx, {m}); h = mixv(h, &r, 16);")
for op in ["maskload_epi32", "maskload_epi64"]:
    cast = "(const long long *)" if op.endswith("64") else ""
    add("vex128", f"_mm_{op}", f"__m128i r = _mm_{op}({cast}ibuf, ax); h = mixv(h, &r, 16);")
add("vex128", "_mm_maskload_ps", "__m128 r = _mm_maskload_ps(fbuf, ax); h = mixv(h, &r, 16);")
add("vex128", "_mm_maskstore_ps", "float o[4]; memcpy(o, fbuf + 4, 16); _mm_maskstore_ps(o, ax, axf); h = mixv(h, o, 16);")
for op in ["add_ps", "mul_ps", "div_ps", "max_ps", "min_ps", "hadd_ps", "addsub_ps", "unpackhi_ps"]:
    bin_("vex128", f"_mm_{op}", XF, 16)
for op in ["add_pd", "mul_pd", "div_pd", "max_pd", "min_pd", "hadd_pd", "addsub_pd", "unpackhi_pd"]:
    bin_("vex128", f"_mm_{op}", XD, 16)
for op in ["add_epi16", "mullo_epi16", "mulhi_epi16", "packus_epi16", "unpackhi_epi8", "unpacklo_epi16",
           "shuffle_epi8", "max_epu8", "min_epi16", "sad_epu8", "madd_epi16", "cmpgt_epi8", "avg_epu8",
           "subs_epu8", "adds_epi16", "hadd_epi16", "hsubs_epi16", "sign_epi8", "packs_epi32", "packus_epi32",
           "mul_epu32", "mul_epi32", "max_epi32", "min_epu32", "cmpeq_epi64", "cmpgt_epi64"]:
    bin_("vex128", f"_mm_{op}", X, 16)

# ---- inserts / extracts (VPINSR*/VPEXTR* in AVX code), every lane ----
for k in range(16):
    add("vex128", f"_mm_insert_epi8/{k}", f"__m128i r = _mm_insert_epi8(ax, (int)rng(), {k}); h = mixv(h, &r, 16);")
    add("vex128", f"_mm_extract_epi8/{k}", f"h = mix(h, (uint64_t)_mm_extract_epi8(ax, {k}));")
for k in range(8):
    add("vex128", f"_mm_insert_epi16/{k}", f"__m128i r = _mm_insert_epi16(ax, (int)rng(), {k}); h = mixv(h, &r, 16);")
    add("vex128", f"_mm_extract_epi16/{k}", f"h = mix(h, (uint64_t)_mm_extract_epi16(ax, {k}));")
    add("avx2", f"_mm256_insert_epi32/{k}", f"__m256i r = _mm256_insert_epi32(ai, (int)rng(), {k}); h = mixv(h, &r, 32);")
    add("avx2", f"_mm256_extract_epi32/{k}", f"h = mix(h, (uint64_t)(uint32_t)_mm256_extract_epi32(ai, {k}));")
for k in range(4):
    add("vex128", f"_mm_insert_epi32/{k}", f"__m128i r = _mm_insert_epi32(ax, (int)rng(), {k}); h = mixv(h, &r, 16);")
    add("vex128", f"_mm_insert_epi32_mem/{k}", f"__m128i r = _mm_insert_epi32(ax, ibuf[{k} + 3], {k}); h = mixv(h, &r, 16);")
    add("vex128", f"_mm_extract_epi32/{k}", f"h = mix(h, (uint64_t)(uint32_t)_mm_extract_epi32(ax, {k}));")
    add("vex128", f"_mm_insert_ps/{k}", f"__m128 r = _mm_insert_ps(axf, bxf, {(k << 6) | (k << 4) | (1 << ((k + 1) & 3))}); h = mixv(h, &r, 16);")
    add("vex128", f"_mm_extract_ps/{k}", f"h = mix(h, (uint64_t)(uint32_t)_mm_extract_ps(axf, {k}));")
add("vex128", "int64_to_float_via_vpinsrd", "float o[4]; for (int q = 0; q < 4; q++) o[q] = (float)((int64_t)(rng() % 20001) - 10000) / 97.0f; h = mixv(h, o, 16);")
add("x64only", "_mm_insert_epi64/0", "__m128i r = _mm_insert_epi64(ax, (long long)rng(), 0); h = mixv(h, &r, 16);")
add("x64only", "_mm_insert_epi64/1", "__m128i r = _mm_insert_epi64(ax, (long long)rng(), 1); h = mixv(h, &r, 16);")
add("x64only", "_mm_extract_epi64/1", "h = mix(h, (uint64_t)_mm_extract_epi64(ax, 1));")

# ---- gathers ----
for scale in [1, 2, 4, 8]:
    add("gather", f"_mm256_i32gather_epi32/x{scale}",
        f"__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi32({256 // scale - 4})); "
        f"__m256i r = _mm256_i32gather_epi32((const int *)gbuf, ix, {scale}); h = mixv(h, &r, 32);")
add("gather", "_mm256_mask_i32gather_epi32",
    "__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi32(63)); "
    "__m256i r = _mm256_mask_i32gather_epi32(ci, (const int *)gbuf, ix, ai, 4); h = mixv(h, &r, 32);")
add("gather", "_mm256_i32gather_epi64",
    "__m128i ix = _mm_and_si128(bx, _mm_set1_epi32(31)); "
    "__m256i r = _mm256_i32gather_epi64((const long long *)gbuf, ix, 8); h = mixv(h, &r, 32);")
add("gather", "_mm256_i64gather_epi32",
    "__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi64x(63)); "
    "__m128i r = _mm256_i64gather_epi32((const int *)gbuf, ix, 4); h = mixv(h, &r, 16);")
add("gather", "_mm256_i64gather_epi64",
    "__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi64x(31)); "
    "__m256i r = _mm256_i64gather_epi64((const long long *)gbuf, ix, 8); h = mixv(h, &r, 32);")
add("gather", "_mm256_mask_i64gather_epi64",
    "__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi64x(31)); "
    "__m256i r = _mm256_mask_i64gather_epi64(ci, (const long long *)gbuf, ix, ai, 8); h = mixv(h, &r, 32);")
add("gather", "_mm256_i32gather_ps",
    "__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi32(63)); "
    "__m256 r = _mm256_i32gather_ps(fbuf, ix, 4); h = mixv(h, &r, 32);")
add("gather", "_mm256_i32gather_pd",
    "__m128i ix = _mm_and_si128(bx, _mm_set1_epi32(31)); "
    "__m256d r = _mm256_i32gather_pd(dbuf, ix, 8); h = mixv(h, &r, 32);")
add("gather", "_mm256_i64gather_ps",
    "__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi64x(63)); "
    "__m128 r = _mm256_i64gather_ps(fbuf, ix, 4); h = mixv(h, &r, 16);")
add("gather", "_mm256_i64gather_pd",
    "__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi64x(31)); "
    "__m256d r = _mm256_i64gather_pd(dbuf, ix, 8); h = mixv(h, &r, 32);")
add("gather", "_mm_i32gather_epi32",
    "__m128i ix = _mm_and_si128(bx, _mm_set1_epi32(63)); "
    "__m128i r = _mm_i32gather_epi32((const int *)gbuf, ix, 4); h = mixv(h, &r, 16);")
add("gather", "_mm_i64gather_epi32",
    "__m128i ix = _mm_and_si128(bx, _mm_set1_epi64x(63)); "
    "__m128i r = _mm_i64gather_epi32((const int *)gbuf, ix, 4); h = mixv(h, &r, 16);")
add("gather", "_mm_mask_i32gather_ps",
    "__m128i ix = _mm_and_si128(bx, _mm_set1_epi32(63)); "
    "__m128 r = _mm_mask_i32gather_ps(axf, fbuf, ix, _mm_castsi128_ps(ax), 4); h = mixv(h, &r, 16);")
add("gather", "_mm256_i32gather_epi32/disp",
    "__m256i ix = _mm256_and_si256(bi, _mm256_set1_epi32(31)); "
    "__m256i r = _mm256_i32gather_epi32((const int *)gbuf + 7, ix, 4); h = mixv(h, &r, 32);")

HEAD = r'''/* GENERATED by tests/gen_avx_test.py - one checksum line per intrinsic.
 *   avx_wide GROUP   (avxf | avx2 | vex128 | gather | all)
 * The recompiled program must print exactly the same lines. */
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cpuid.h>

static volatile uint64_t seedv;
static uint64_t rng(void) { uint64_t x = seedv; x ^= x << 13; x ^= x >> 7; x ^= x << 17; seedv = x; return x; }
static uint64_t mix(uint64_t h, uint64_t v) { return (h ^ v) * 0x100000001B3ull + (h >> 29); }
static uint64_t mixv(uint64_t h, const void *p, size_t n) {
    const unsigned char *b = p; for (size_t i = 0; i < n; i++) h = mix(h, b[i]); return h;
}
static void fill(void *p, size_t n) { unsigned char *b = p; for (size_t i = 0; i < n; i++) b[i] = (unsigned char)rng(); }
static float frand(void) {      /* mostly ordinary values, sometimes 0, -0, inf, nan, tiny */
    uint64_t r = rng();
    switch (r % 23) {
    case 0: return 0.0f; case 1: return -0.0f; case 2: return 1.0f / 0.0f; case 3: return 0.0f / 0.0f;
    case 4: return 1e-40f; case 5: return 2.5f; case 6: return -3.5f;
    default: return (float)((int64_t)(r % 200001) - 100000) / 37.0f;
    }
}
static float fbuf[64]; static double dbuf[32]; static int ibuf[64]; static int gbuf[256];
#define T __attribute__((target("avx2,fma"), noinline))
#define SETUP \
    float fa[8], fb[8], fc[8]; double da[4], db[4], dc[4]; \
    for (int j = 0; j < 8; j++) { fa[j] = frand(); fb[j] = frand(); fc[j] = frand(); } \
    for (int j = 0; j < 4; j++) { da[j] = frand() * 1.5; db[j] = frand() * 0.75; dc[j] = frand(); } \
    if (it & 1) memcpy(fb, fa, 16); \
    __m256 af = _mm256_loadu_ps(fa), bf = _mm256_loadu_ps(fb), cf = _mm256_loadu_ps(fc); \
    __m256d ad = _mm256_loadu_pd(da), bd = _mm256_loadu_pd(db), cd = _mm256_loadu_pd(dc); \
    __m256i ai, bi, ci; fill(&ai, 32); fill(&bi, 32); fill(&ci, 32); \
    if (it & 2) bi = _mm256_blend_epi32(bi, ai, 0x5a); \
    __m128i ax = _mm256_castsi256_si128(ai), bx = _mm256_castsi256_si128(bi); \
    __m128 axf = _mm256_castps256_ps128(af), bxf = _mm256_castps256_ps128(bf); \
    __m128d axd = _mm256_castpd256_pd128(ad), bxd = _mm256_castpd256_pd128(bd); \
    (void)af; (void)bf; (void)cf; (void)ad; (void)bd; (void)cd; (void)ai; (void)bi; (void)ci; \
    (void)ax; (void)bx; (void)axf; (void)bxf; (void)axd; (void)bxd;
'''

out = [HEAD]
names = []
for k, (g, name, body) in enumerate(tests):
    if g == "x64only":
        body = "\n#ifdef __x86_64__\n" + body + "\n#endif\n"
    out.append(f"T static uint64_t t{k}(void) {{ uint64_t h = 0; "
               f"for (int it = 0; it < 16; it++) {{ SETUP {body} }} _mm256_zeroupper(); return h; }}")
    names.append((g, name, k))
out.append("static const struct { const char *group, *name; uint64_t (*fn)(void); } tests[] = {")
for g, name, k in names:
    out.append(f'    {{"{g}", "{name}", t{k}}},')
out.append("};")
out.append(r'''
int main(int argc, char **argv) {
    unsigned a, b, c, d;
    __cpuid_count(7, 0, a, b, c, d);
    int avx2 = (b >> 5) & 1;
    __cpuid(1, a, b, c, d);
    int fma = (c >> 12) & 1;
    const char *want = argc > 1 ? argv[1] : "all";
    if (!avx2 || !fma) { printf("AVX2/FMA not reported by this CPU\n"); return 0; }
    int n = 0;
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        if (strcmp(want, "all") && strcmp(want, tests[i].group)) continue;
        seedv = 0x9E3779B97F4A7C15ull ^ (i * 0x632BE59BD9B4E019ull);
        for (int j = 0; j < 64; j++) { fbuf[j] = frand(); ibuf[j] = (int)rng(); }
        for (int j = 0; j < 32; j++) dbuf[j] = frand() * 3.0;
        for (int j = 0; j < 256; j++) gbuf[j] = (int)rng();
        printf("%-34s %016llx\n", tests[i].name, (unsigned long long)tests[i].fn());
        n++;
    }
    printf("%d tests\n", n);
    return 0;
}''')
sys.stdout.write("\n".join(out) + "\n")
print(f"{len(tests)} tests", file=sys.stderr)
