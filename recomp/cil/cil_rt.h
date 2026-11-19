/* cil2c runtime: what C translated from .NET IL (C#) needs to run inside a
 * Mono runtime. Objects, classes, strings, GC and reflection stay Mono's; the
 * translated code reaches them through Mono's public embedding API, exactly
 * like Unity's own engine code does.
 *
 *   - exceptions: a per-thread chain of setjmp handlers (one per try block);
 *     at the boundary to Mono (an internal call returning to managed code) an
 *     uncaught exception is handed to mono_raise_exception
 *   - calls to methods that were not translated go through mono_runtime_invoke
 *   - class/method/field handles are looked up once per site and cached
 */
#pragma once
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <setjmp.h>
#include <stdlib.h>
#include "mono_api.h"
#ifdef _WIN32
#include <malloc.h>
#else
#include <alloca.h>
#endif

/* ---- exceptions ---- */
typedef struct cil_try {
    struct cil_try *prev;
    void *jb[5];                       /* __builtin_setjmp buffer */
} cil_try;

typedef struct cil_thread {
    cil_try *top;
    MonoObject *exc;                   /* the exception being propagated */
} cil_thread;

cil_thread *cil_thr(void);
void cil_throw(MonoObject *e) __attribute__((noreturn));
void cil_throw_null(void) __attribute__((noreturn));
/* where a NullReferenceException comes from: Mono's stack trace does not show
 * translated C. With RECOMP_CIL_LOG=file every one is written there with the
 * C function and line that raised it (the method's name is in the comment
 * above that function in the *_cil_*.c file). */
void cil_throw_null_at(const char *fn, int line) __attribute__((noreturn));
#ifndef CIL_RT_ITSELF
#define cil_throw_null() cil_throw_null_at(__func__, __LINE__)
#endif
void cil_throw_div0(void) __attribute__((noreturn));
void cil_throw_overflow(void) __attribute__((noreturn));
void cil_throw_index(void) __attribute__((noreturn));
void cil_throw_cast(void) __attribute__((noreturn));
void cil_throw_arraytype(void) __attribute__((noreturn));
void cil_throw_arith(void) __attribute__((noreturn));
void cil_throw_name(const char *ns, const char *name) __attribute__((noreturn));

/* try { ... }: push before the protected code; returns nonzero when an
 * exception arrives (then cil_thr()->exc holds it and the record is popped) */
#define CIL_TRY(t) ((t).prev = cil_thr()->top, cil_thr()->top = &(t), __builtin_setjmp((t).jb))
#define CIL_POP(t) (cil_thr()->top = (t).prev)

/* the boundary of an internal call: exceptions don't go past it in C */
#define CIL_ENTER(t) if (__builtin_setjmp(((t).prev = cil_thr()->top, cil_thr()->top = &(t), (t).jb))) \
        { cil_thread *th_ = cil_thr(); MonoObject *e_ = th_->exc; th_->exc = 0; mono_raise_exception((MonoException *)e_); }
#define CIL_LEAVE(t) (cil_thr()->top = (t).prev)

/* ---- handles (cached per call site) ---- */
MonoImage *cil_image(const char *asmname);
MonoClass *cil_class(MonoClass **cache, const char *asmname, uint32_t token);
MonoMethod *cil_method(MonoMethod **cache, const char *asmname, uint32_t token);
MonoClassField *cil_field(MonoClassField **cache, const char *asmname, uint32_t token);
MonoString *cil_ldstr(MonoString **cache, const char *asmname, uint32_t token);
uint8_t *cil_sfield(uint8_t **cache, MonoClassField *f);   /* address of a static field */
void cil_class_init(int *done, MonoClass *k);
int32_t cil_vt_size(MonoClass *k);

/* field offsets and struct sizes never change: cached per site, so the hot
 * path makes no call into Mono (on Windows such a call is a trip into the
 * recompiled Mono DLL) */
static inline int32_t cil_foff_c(int32_t *cache, MonoClassField *f) {
    if (*cache <= 0) *cache = (int32_t)mono_field_get_offset(f);
    return *cache;
}
static inline int32_t cil_vt_size_c(int32_t *cache, MonoClass *k) {
    if (*cache <= 0) *cache = cil_vt_size(k);
    return *cache;
}

/* ---- objects ---- */
#ifdef CIL_TRACE_NULL
/* built with -DCIL_TRACE_NULL: every null check knows the translated function
 * it is in, for RECOMP_CIL_LOG (bigger and a little slower: only for finding
 * out where a NullReferenceException comes from) */
static inline MonoObject *cil_nn_at(MonoObject *o, const char *fn, int line) {
    if (!o) cil_throw_null_at(fn, line);
    return o;
}
#define cil_nn(o) cil_nn_at((o), __func__, __LINE__)
#else
static inline MonoObject *cil_nn(MonoObject *o) { if (!o) cil_throw_null(); return o; }
#endif
MonoObject *cil_new(MonoClass *k);
MonoObject *cil_newarr(MonoClass *elem, intptr_t n);
static inline int32_t cil_ldlen(MonoObject *a) { return (int32_t)mono_array_length((MonoArray *)cil_nn(a)); }
static inline char *cil_elem(MonoObject *a, intptr_t i, int size) {
    MonoArray *arr = (MonoArray *)cil_nn(a);
    if ((uintptr_t)i >= (uintptr_t)mono_array_length(arr)) cil_throw_index();
    return mono_array_addr_with_size(arr, size, i);
}
void cil_stelem_ref(MonoObject *a, intptr_t i, MonoObject *v);
static inline MonoObject *cil_isinst(MonoObject *o, MonoClass *k) { return o ? mono_object_isinst(o, k) : 0; }
static inline MonoObject *cil_castclass(MonoObject *o, MonoClass *k) {
    if (o && !mono_object_isinst(o, k)) cil_throw_cast();
    return o;
}
MonoObject *cil_box(MonoClass *k, void *v);
void *cil_unbox(MonoObject *o, MonoClass *k);

/* stores of references into the heap need the GC's write barrier */
static inline void cil_setref_field(MonoObject *o, void *slot, MonoObject *v) { mono_gc_wbarrier_set_field(o, slot, v); }
static inline void cil_setref(void *slot, MonoObject *v) { mono_gc_wbarrier_generic_store(slot, v); }
static inline void cil_vtcopy(void *dst, const void *src, MonoClass *k) {
    mono_gc_wbarrier_value_copy(dst, (void *)src, 1, k);
}

/* ---- calls into Mono ---- */
/* calls a method that was not translated; returns the boxed result (or the
 * object for reference types); exceptions become cil_throw */
MonoObject *cil_invoke(MonoMethod *m, void *self, void **args);
MonoMethod *cil_virtual(MonoObject *o, MonoMethod *m);
void *cil_fn_for(MonoMethod *m);       /* translated C function of a method, or 0 */
MonoObject *cil_delegate(MonoClass *dk, MonoObject *target, MonoMethod *m);
/* copy a boxed value back to where it was boxed from (constrained calls) */
void cil_unbox_back(MonoObject *boxed, void *dst);

/* ---- numbers: the same results as Mono's JIT on x86-64 ---- */
static inline int32_t cil_d2i4(double d) { return (d > -2147483649.0 && d < 2147483648.0) ? (int32_t)d : INT32_MIN; }
static inline int64_t cil_d2i8(double d) { return (d >= -9223372036854775808.0 && d < 9223372036854775808.0) ? (int64_t)d : INT64_MIN; }
static inline uint32_t cil_d2u4(double d) { return (uint32_t)cil_d2i8(d); }
static inline uint64_t cil_d2u8(double d) {
    if (d >= 9223372036854775808.0 && d < 18446744073709551616.0) return (uint64_t)d;
    return (uint64_t)cil_d2i8(d);
}
static inline double cil_u82d(uint64_t v) { return (double)v; }
static inline int32_t cil_div4(int32_t a, int32_t b) { if (!b) cil_throw_div0(); if (b == -1 && a == INT32_MIN) cil_throw_arith(); return a / b; }
static inline int32_t cil_rem4(int32_t a, int32_t b) { if (!b) cil_throw_div0(); if (b == -1) return 0; return a % b; }
static inline uint32_t cil_divu4(uint32_t a, uint32_t b) { if (!b) cil_throw_div0(); return a / b; }
static inline uint32_t cil_remu4(uint32_t a, uint32_t b) { if (!b) cil_throw_div0(); return a % b; }
static inline int64_t cil_div8(int64_t a, int64_t b) { if (!b) cil_throw_div0(); if (b == -1 && a == INT64_MIN) cil_throw_arith(); return a / b; }
static inline int64_t cil_rem8(int64_t a, int64_t b) { if (!b) cil_throw_div0(); if (b == -1) return 0; return a % b; }
static inline uint64_t cil_divu8(uint64_t a, uint64_t b) { if (!b) cil_throw_div0(); return a / b; }
static inline uint64_t cil_remu8(uint64_t a, uint64_t b) { if (!b) cil_throw_div0(); return a % b; }
static inline double cil_ckfinite(double d) { if (!isfinite(d)) cil_throw_arith(); return d; }
/* checked conversions (conv.ovf.*) */
static inline int64_t cil_ovf_range(int64_t v, int64_t lo, int64_t hi) { if (v < lo || v > hi) cil_throw_overflow(); return v; }
static inline uint64_t cil_ovf_urange(uint64_t v, uint64_t hi) { if (v > hi) cil_throw_overflow(); return v; }
static inline int64_t cil_ovf_d2i(double d, double lo, double hi) { if (!(d > lo - 1.0 && d < hi + 1.0)) cil_throw_overflow(); return (int64_t)d; }
/* checked float -> uint64: values from 2^63 up do not fit an int64 */
static inline uint64_t cil_ovf_d2u8(double d) { if (!(d > -1.0 && d < 18446744073709551616.0)) cil_throw_overflow(); return d >= 9223372036854775808.0 ? (uint64_t)d : (uint64_t)(int64_t)d; }
static inline int32_t cil_add_ovf4(int32_t a, int32_t b) { int32_t r; if (__builtin_add_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline int32_t cil_sub_ovf4(int32_t a, int32_t b) { int32_t r; if (__builtin_sub_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline int32_t cil_mul_ovf4(int32_t a, int32_t b) { int32_t r; if (__builtin_mul_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline uint32_t cil_add_ovfu4(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_add_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline uint32_t cil_sub_ovfu4(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_sub_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline uint32_t cil_mul_ovfu4(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_mul_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline int64_t cil_add_ovf8(int64_t a, int64_t b) { int64_t r; if (__builtin_add_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline int64_t cil_sub_ovf8(int64_t a, int64_t b) { int64_t r; if (__builtin_sub_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline int64_t cil_mul_ovf8(int64_t a, int64_t b) { int64_t r; if (__builtin_mul_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline uint64_t cil_add_ovfu8(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_add_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline uint64_t cil_sub_ovfu8(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_sub_overflow(a, b, &r)) cil_throw_overflow(); return r; }
static inline uint64_t cil_mul_ovfu8(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_mul_overflow(a, b, &r)) cil_throw_overflow(); return r; }

/* registration of translated methods (generated per assembly) */
/* fn: the translated function (called directly by other translated code);
 * icall: the same behind an exception boundary, registered with Mono under
 * names (0 when the method keeps its IL: struct `this`, struct arguments) */
typedef struct { const char *asmname; uint32_t token; void *fn; void *icall; const char *const *names; } cil_entry;
MonoClass *cil_local_class(MonoMethod *m, int i);
MonoClass *cil_param_class(MonoMethod *m, int i);
MonoObject *cil_typeof(MonoClass *k);
void cil_register(const cil_entry *e, int n);
