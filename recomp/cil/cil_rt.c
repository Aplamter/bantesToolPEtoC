/* cil2c runtime (see cil_rt.h). Portable C: Linux (libmono) and Windows
 * (Unity's mono-2.0-bdwgc.dll). No thread-local variables: per-thread state
 * goes through pthread keys / Win32 TLS slots. */
#define CIL_RT_ITSELF
#include "cil_rt.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static DWORD thr_key = TLS_OUT_OF_INDEXES;
static CRITICAL_SECTION lock;
static void lock_init(void) { InitializeCriticalSection(&lock); }
#define LOCK() EnterCriticalSection(&lock)
#define UNLOCK() LeaveCriticalSection(&lock)
#else
#include <pthread.h>
#include <dlfcn.h>
static pthread_key_t thr_key;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static void lock_init(void) {}
#define LOCK() pthread_mutex_lock(&lock)
#define UNLOCK() pthread_mutex_unlock(&lock)
#endif


static int inited;
static void init_once(void) {
    if (inited) return;
#ifdef _WIN32
    thr_key = TlsAlloc();
#else
    pthread_key_create(&thr_key, free);
#endif
    lock_init();
    inited = 1;
}

cil_thread *cil_thr(void) {
#ifdef _WIN32
    cil_thread *t = TlsGetValue(thr_key);
#else
    cil_thread *t = pthread_getspecific(thr_key);
#endif
    if (!t) {
        t = calloc(1, sizeof *t);
#ifdef _WIN32
        TlsSetValue(thr_key, t);
#else
        pthread_setspecific(thr_key, t);
#endif
    }
    return t;
}

/* ---- exceptions ---- */
void cil_throw(MonoObject *e) {
    cil_thread *t = cil_thr();
    cil_try *h = t->top;
    if (!e) e = (MonoObject *)mono_get_exception_null_reference();   /* throw null */
    if (!h) {
        /* no C handler at all: only possible if translated code runs
         * without an internal-call boundary; let Mono have it */
        mono_raise_exception((MonoException *)e);
    }
    t->exc = e;
    t->top = h->prev;
    __builtin_longjmp(h->jb, 1);
}
void cil_throw_null(void) { cil_throw((MonoObject *)mono_get_exception_null_reference()); }

void cil_throw_null_at(const char *fn, int line) {
    static int state;                   /* 0 not looked yet, 1 off, 2 on */
    static char path[1024];
    if (!state) {
        const char *p = getenv("RECOMP_CIL_LOG");
        if (p && *p && strlen(p) < sizeof path) { strcpy(path, p); state = 2; } else state = 1;
    }
    if (state == 2) {
        FILE *f = fopen(path, "a");
        if (f) { fprintf(f, "NullReferenceException raised in %s, line %d\n", fn, line); fclose(f); }
    }
    cil_throw((MonoObject *)mono_get_exception_null_reference());
}
void cil_throw_div0(void) { cil_throw((MonoObject *)mono_get_exception_divide_by_zero()); }
void cil_throw_overflow(void) { cil_throw((MonoObject *)mono_get_exception_overflow()); }
void cil_throw_index(void) { cil_throw((MonoObject *)mono_get_exception_index_out_of_range()); }
void cil_throw_cast(void) { cil_throw((MonoObject *)mono_get_exception_invalid_cast()); }
void cil_throw_arraytype(void) { cil_throw((MonoObject *)mono_get_exception_array_type_mismatch()); }
void cil_throw_arith(void) { cil_throw((MonoObject *)mono_get_exception_arithmetic()); }
void cil_throw_name(const char *ns, const char *name) {
    cil_throw((MonoObject *)mono_exception_from_name(mono_get_corlib(), ns, name));
}

/* ---- handles ---- */
MonoImage *cil_image(const char *asmname) {
    MonoImage *im = mono_image_loaded(asmname);
    if (!im) {
        MonoAssemblyName *an = mono_assembly_name_new(asmname);
        MonoImageOpenStatus st;
        MonoAssembly *a = an ? mono_assembly_load(an, NULL, &st) : NULL;
        if (an) mono_assembly_name_free(an);
        im = a ? mono_assembly_get_image(a) : NULL;
    }
    if (!im) {
        fprintf(stderr, "[cil2c] assembly %s is not loaded\n", asmname);
        abort();
    }
    return im;
}

MonoClass *cil_class(MonoClass **cache, const char *asmname, uint32_t token) {
    if (!*cache) {
        MonoClass *k = mono_class_get(cil_image(asmname), token);
        if (!k) { fprintf(stderr, "[cil2c] class %08x of %s not found\n", token, asmname); abort(); }
        mono_class_init(k);
        *cache = k;
    }
    return *cache;
}

MonoMethod *cil_method(MonoMethod **cache, const char *asmname, uint32_t token) {
    if (!*cache) {
        MonoMethod *m = mono_get_method(cil_image(asmname), token, NULL);
        if (!m) { fprintf(stderr, "[cil2c] method %08x of %s not found\n", token, asmname); abort(); }
        *cache = m;
    }
    return *cache;
}

MonoClassField *cil_field(MonoClassField **cache, const char *asmname, uint32_t token) {
    if (!*cache) {
        MonoClass *k = NULL;
        MonoClassField *f = mono_field_from_token(cil_image(asmname), token, &k, NULL);
        if (!f) { fprintf(stderr, "[cil2c] field %08x of %s not found\n", token, asmname); abort(); }
        mono_class_init(mono_field_get_parent(f));
        *cache = f;
    }
    return *cache;
}

MonoString *cil_ldstr(MonoString **cache, const char *asmname, uint32_t token) {
    if (!*cache) {
        MonoString *s = mono_ldstr(mono_domain_get(), cil_image(asmname), token & 0xFFFFFF);
        mono_gchandle_new((MonoObject *)s, 1);      /* pinned: the pointer stays valid */
        *cache = s;
    }
    return *cache;
}

/* Running a static constructor from translated C. The C runs as an internal
 * call, and Mono marks a thread that is inside an internal call as "blocking"
 * (GC-safe). mono_runtime_class_init does not switch it back before it runs
 * the constructor - unlike mono_runtime_invoke - so the constructor's own
 * internal-call wrapper finds the thread already blocking: Mono 6 aborts
 * ("Cannot transition thread ... from STATE_BLOCKING"), other builds may
 * silently run managed code in the wrong state. So switch to "running"
 * around it, with Mono's own API, where Mono has it. */
typedef void *(*gc_enter_fn)(void *);
typedef void (*gc_exit_fn)(void *, void *);
static gc_enter_fn gc_enter;
static gc_exit_fn gc_exit;
static int gc_looked;

static void find_gc_api(void) {
    if (gc_looked) return;
#ifdef _WIN32
    static const char *const names[] = {"mono-2.0-bdwgc.dll", "mono-2.0-sgen.dll", "mono-2.0-boehm.dll",
                                        "mono-2.0.dll", "mono.dll"};
    for (unsigned i = 0; i < sizeof names / sizeof names[0] && !gc_enter; i++) {
        HMODULE h = GetModuleHandleA(names[i]);
        if (!h) continue;
        gc_enter = (gc_enter_fn)(void *)GetProcAddress(h, "mono_threads_enter_gc_unsafe_region");
        gc_exit = (gc_exit_fn)(void *)GetProcAddress(h, "mono_threads_exit_gc_unsafe_region");
    }
#else
    gc_enter = (gc_enter_fn)dlsym(RTLD_DEFAULT, "mono_threads_enter_gc_unsafe_region");
    gc_exit = (gc_exit_fn)dlsym(RTLD_DEFAULT, "mono_threads_exit_gc_unsafe_region");
#endif
    if (!gc_enter || !gc_exit) gc_enter = NULL, gc_exit = NULL;
    gc_looked = 1;
}

static void class_init(MonoVTable *vt) {
    void *stackdata[4] = {0};
    void *cookie = NULL;
    find_gc_api();
    if (gc_enter) cookie = gc_enter(stackdata);
    mono_runtime_class_init(vt);
    if (gc_exit) gc_exit(cookie, stackdata);
}

uint8_t *cil_sfield(uint8_t **cache, MonoClassField *f) {
    if (!*cache) {
        MonoVTable *vt = mono_class_vtable(mono_domain_get(), mono_field_get_parent(f));
        class_init(vt);
        *cache = (uint8_t *)mono_vtable_get_static_field_data(vt) + mono_field_get_offset(f);
    }
    return *cache;
}

void cil_class_init(int *done, MonoClass *k) {
    if (*done) return;
    class_init(mono_class_vtable(mono_domain_get(), k));
    *done = 1;
}

int32_t cil_vt_size(MonoClass *k) {
    uint32_t align;
    return mono_class_value_size(k, &align);
}

/* ---- objects ---- */
MonoObject *cil_new(MonoClass *k) {
    MonoObject *o = mono_object_new(mono_domain_get(), k);
    if (!o) cil_throw_name("System", "OutOfMemoryException");
    return o;
}

MonoObject *cil_newarr(MonoClass *elem, intptr_t n) {
    if (n < 0) cil_throw_overflow();
    return (MonoObject *)mono_array_new(mono_domain_get(), elem, (uintptr_t)n);
}

void cil_stelem_ref(MonoObject *a, intptr_t i, MonoObject *v) {
    MonoArray *arr = (MonoArray *)cil_nn(a);
    if ((uintptr_t)i >= (uintptr_t)mono_array_length(arr)) cil_throw_index();
    if (v) {
        MonoClass *ek = mono_class_get_element_class(mono_object_get_class(a));
        if (!mono_object_isinst(v, ek)) cil_throw_arraytype();
    }
    mono_gc_wbarrier_set_arrayref(arr, mono_array_addr_with_size(arr, sizeof(void *), i), v);
}

MonoObject *cil_box(MonoClass *k, void *v) {
    return mono_value_box(mono_domain_get(), k, v);
}

void *cil_unbox(MonoObject *o, MonoClass *k) {
    cil_nn(o);
    MonoClass *ok = mono_object_get_class(o);
    if (ok != k) {
        /* an enum and its underlying type unbox into each other */
        MonoType *a = mono_class_enum_basetype(ok), *b = mono_class_enum_basetype(k);
        MonoClass *ua = a ? mono_class_from_mono_type(a) : ok, *ub = b ? mono_class_from_mono_type(b) : k;
        if (ua != ub) cil_throw_cast();
    }
    return mono_object_unbox(o);
}

/* ---- calls into Mono ---- */
MonoObject *cil_invoke(MonoMethod *m, void *self, void **args) {
    MonoObject *exc = NULL;
    MonoObject *r = mono_runtime_invoke(m, self, args, &exc);
    if (exc) cil_throw(exc);
    return r;
}

MonoMethod *cil_virtual(MonoObject *o, MonoMethod *m) {
    MonoMethod *v = mono_object_get_virtual_method(cil_nn(o), m);
    return v ? v : m;
}

/* translated methods: (assembly, token) -> C function; plus a cache by MonoMethod */
typedef struct { const char *asmname; uint32_t token; void *fn; } fn_ent;
static fn_ent *fns;
static int nfns, capfns;
#define PCACHE 4096
static struct { MonoMethod *m; void *fn; } pcache[PCACHE];

void cil_register(const cil_entry *e, int n) {
    init_once();
    LOCK();
    for (int i = 0; i < n; i++) {
        if (nfns == capfns) { capfns = capfns ? capfns * 2 : 1024; fns = realloc(fns, capfns * sizeof *fns); }
        fns[nfns].asmname = e[i].asmname; fns[nfns].token = e[i].token; fns[nfns].fn = e[i].fn;
        nfns++;
        for (const char *const *nm = e[i].names; nm && *nm; nm++)
            mono_add_internal_call(*nm, e[i].icall);
    }
    UNLOCK();
}

void *cil_fn_for(MonoMethod *m) {
    unsigned h = (unsigned)(((uintptr_t)m >> 4) & (PCACHE - 1));
    void *fn = NULL;
    LOCK();
    if (pcache[h].m == m) { fn = pcache[h].fn; UNLOCK(); return fn; }
    UNLOCK();
    MonoClass *k = mono_method_get_class(m);
    const char *im = mono_image_get_name(mono_class_get_image(k));
    uint32_t tok = mono_method_get_token(m);
    for (int i = 0; i < nfns; i++)
        if (fns[i].token == tok && !strcmp(fns[i].asmname, im)) { fn = fns[i].fn; break; }
    LOCK();
    pcache[h].m = m; pcache[h].fn = fn;
    UNLOCK();
    return fn;
}

MonoObject *cil_delegate(MonoClass *dk, MonoObject *target, MonoMethod *m) {
    static MonoMethod *create;
    MonoDomain *d = mono_domain_get();
    if (!create) {
        MonoClass *del = mono_class_from_name(mono_get_corlib(), "System", "Delegate");
        MonoMethodDesc *desc = mono_method_desc_new(
            "System.Delegate:CreateDelegate(System.Type,object,System.Reflection.MethodInfo)", 1);
        create = mono_method_desc_search_in_class(desc, del);
        mono_method_desc_free(desc);
    }
    void *args[3] = {mono_type_get_object(d, mono_class_get_type(dk)), target,
                     mono_method_get_object(d, m, NULL)};
    return cil_invoke(create, NULL, args);
}

void cil_unbox_back(MonoObject *boxed, void *dst) {
    if (!boxed || !dst) return;
    MonoClass *k = mono_object_get_class(boxed);
    if (!mono_class_is_valuetype(k)) return;
    memcpy(dst, mono_object_unbox(boxed), (size_t)mono_class_value_size(k, NULL));
}

MonoClass *cil_local_class(MonoMethod *m, int i) {
    MonoMethodHeader *h = mono_method_get_header(m);
    uint32_t n;
    mono_bool init;
    MonoType **t = mono_method_header_get_locals(h, &n, &init);
    return mono_class_from_mono_type(t[i]);
}

MonoClass *cil_param_class(MonoMethod *m, int i) {
    MonoMethodSignature *sig = mono_method_signature(m);
    void *it = NULL;
    MonoType *t = NULL;
    for (int k = 0; k <= i; k++) t = mono_signature_get_params(sig, &it);
    return mono_class_from_mono_type(t);
}

MonoObject *cil_typeof(MonoClass *k) {
    return (MonoObject *)mono_type_get_object(mono_domain_get(), mono_class_get_type(k));
}
