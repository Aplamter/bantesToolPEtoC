/* 32-bit specifics of the recompiler runtime (rt_win32.c):
 *   - every calling convention, program -> recompiled DLL, program -> native
 *     DLL and native DLL -> program (callbacks)
 *   - float/double results on the x87 stack, in both directions
 *   - frame-based exception handling: a hand-made handler record at fs:[0],
 *     CPU faults in recompiled code, RaiseException in native code,
 *     exceptions that pass through native frames, longjmp out of a handler,
 *     and a handler that repairs a register and continues
 *   - threads, last-error value, x87 precision control                      */
#include <windows.h>
#include <stdio.h>
#include <setjmp.h>
#include <math.h>
#include <float.h>

__declspec(dllimport) int __stdcall s_add(int, int);
__declspec(dllimport) int __fastcall f_mix(int, int, int);
__declspec(dllimport) long long __stdcall s_wide(long long, int);
__declspec(dllimport) float __stdcall s_flt(float);
__declspec(dllimport) double __cdecl c_avg(int, ...);
typedef struct { int x, y, z; double w; } vec_t;
__declspec(dllimport) vec_t c_vec(int, double);
typedef struct { int base; } obj_t;
__declspec(dllimport) int __thiscall o_method(obj_t *, int);

__declspec(dllimport) double n_call_dd(double (*)(double), double);
__declspec(dllimport) float n_call_ff(float (*)(float, float), float, float);
__declspec(dllimport) long long n_call_ll(long long (*)(long long, int), long long, int);
__declspec(dllimport) int n_call_std(int (__stdcall *)(int, int, int), int, int, int);
__declspec(dllimport) int n_call_fast(int (__fastcall *)(int, int, int, int), int, int, int, int);
__declspec(dllimport) int __stdcall n_std_sum(int, int, int, int, int);
__declspec(dllimport) int __fastcall n_fast_sum(int, int, int);
__declspec(dllimport) int n_vsum(int, ...);
__declspec(dllimport) int n_nest(int (*)(int), int);
__declspec(dllimport) void n_raise(DWORD, ULONG_PTR);
__declspec(dllimport) int n_call_void(void (*)(void *), void *);
typedef struct { int a; double b; char c[20]; } big_t;
__declspec(dllimport) big_t n_struct(int, double);

/* ---- callbacks ---- */
static double cb_dd(double x) { return sqrt(x) + 0.5; }
static float cb_ff(float a, float b) { return a / b; }
static long long cb_ll(long long a, int b) { return a * b + 0x100000000LL; }
static int __stdcall cb_std(int a, int b, int c) { return a * 100 + b * 10 + c; }
static int __fastcall cb_fast(int a, int b, int c, int d) { return ((a - b) * c) ^ d; }
static int cb_nest(int depth) { return n_nest(cb_nest, depth) * 2; }

/* ---- exceptions: a raw handler record on the stack, linked at fs:[0] ---- */
typedef struct frame {
    struct frame *next;             /* EXCEPTION_REGISTRATION_RECORD */
    void *handler;
    jmp_buf jb;
    DWORD code; ULONG_PTR info;
    int calls, unwinds, decline;
} frame_t;
static DWORD rd_fs0(void) { DWORD v; __asm__("movl %%fs:0, %0" : "=r"(v)); return v; }
static void wr_fs0(DWORD v) { __asm__("movl %0, %%fs:0" : : "r"(v)); }

static int repair_good;
static EXCEPTION_DISPOSITION __cdecl handler(EXCEPTION_RECORD *r, void *fr, CONTEXT *ctx, void *disp) {
    frame_t *f = fr;
    (void)disp;
    if (r->ExceptionFlags & 6) { f->unwinds++; return ExceptionContinueSearch; }   /* unwinding */
    f->calls++;
    f->code = r->ExceptionCode;
    f->info = r->NumberParameters >= 2 ? r->ExceptionInformation[1] : r->NumberParameters ? r->ExceptionInformation[0] : 0;
    if (r->ExceptionCode == 0xE0000042 && f->decline) return ExceptionContinueSearch;   /* next handler */
    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && ctx->Ecx == 0x30) {
        ctx->Ecx = (DWORD)&repair_good;                 /* repair the pointer, run the instruction again */
        return ExceptionContinueExecution;
    }
    longjmp(f->jb, 1);
}

/* runs fn(arg); returns the exception code if it raised one, else 0 */
static int decline_next;
static DWORD guarded(void (*fn)(void *), void *arg, ULONG_PTR *info, frame_t *out) {
    frame_t f;
    f.calls = f.unwinds = 0; f.code = 0; f.info = 0;
    f.decline = decline_next; decline_next = 0;
    f.next = (frame_t *)rd_fs0();
    f.handler = (void *)handler;
    if (setjmp(f.jb)) {
        wr_fs0((DWORD)f.next);
        if (info) *info = f.info;
        if (out) *out = f;
        return f.code;
    }
    wr_fs0((DWORD)&f);
    fn(arg);
    wr_fs0((DWORD)f.next);
    if (out) *out = f;
    return 0;
}

static volatile int steps;
static void do_null_write(void *p) { steps++; *(volatile int *)p = 1; steps += 100; }
static void do_div(void *p) { volatile int z = *(int *)p; steps++; steps += 1000 / z; }
static void do_native_raise(void *p) { steps++; n_raise(0xE0000001, (ULONG_PTR)p); steps += 100; }
static void do_through_native(void *p) { n_call_void(do_null_write, p); steps += 100; }
static void do_raise42(void *p) { n_raise(0xE0000042, (ULONG_PTR)p); }
static void do_nested(void *p) {            /* the inner handler declines, the outer one takes it */
    ULONG_PTR info = 0;
    DWORD c = guarded(do_native_raise, p, &info, 0);
    printf("  inner handler took %#lx (%lu)\n", c, (unsigned long)info);
    decline_next = 1;
    c = guarded(do_raise42, (void *)99, &info, 0);
    printf("  not reached %#lx\n", c);
}
static void do_repair(void *p) {
    int before = steps;
    (void)p;
    /* writes 77 through ECX = 0x30 (invalid): the handler points ECX at
     * repair_good and continues, so the same instruction runs again */
    __asm__ volatile("incl %0\n\tmovl $77, (%%ecx)\n\tincl %0" : "+m"(steps) : "c"((int *)0x30) : "memory");
    printf("  repaired write: value %d, steps +%d\n", repair_good, steps - before);
}

static DWORD WINAPI thread_fn(LPVOID arg) {
    ULONG_PTR info = 0;
    DWORD c = guarded(do_null_write, (void *)0x40, &info, 0);
    return (DWORD)(INT_PTR)arg + (c == EXCEPTION_ACCESS_VIOLATION ? 1000 : 0) + (DWORD)info;
}

int main(void) {
    /* 1. the recompiled DLL */
    obj_t o = {12};
    vec_t v = c_vec(7, 2.5);
    printf("dll: s_add %d f_mix %d s_wide %lld s_flt %.4f c_avg %.4f\n", s_add(3, 4), f_mix(10, 3, 5),
           s_wide(123456789012LL, 7), s_flt(2.5f), c_avg(4, 1.0, 2.5, 4.0, 8.5));
    printf("dll: c_vec %d %d %d %.3f o_method %d\n", v.x, v.y, v.z, v.w, o_method(&o, 5));

    /* 2. the native DLL and its callbacks into the program */
    big_t b = n_struct(21, 9.0);
    printf("native: std %d fast %d vsum %d struct %d %.2f %s\n", n_std_sum(1, 2, 3, 4, 5), n_fast_sum(7, 8, 9),
           n_vsum(5, 10, 20, 30, 40, 50), b.a, b.b, b.c);
    printf("callbacks: dd %.6f ff %.6f ll %lld std %d fast %d\n", n_call_dd(cb_dd, 2.0), n_call_ff(cb_ff, 1.0f, 3.0f),
           n_call_ll(cb_ll, 5000000000LL, 3), n_call_std(cb_std, 4, 5, 6), n_call_fast(cb_fast, 50, 8, 3, 0x55));
    printf("nested native<->program calls: %d\n", cb_nest(12));

    /* 3. exceptions */
    ULONG_PTR info = 0;
    frame_t f;
    DWORD c = guarded(do_null_write, (void *)0x10, &info, &f);
    printf("null write: code %#lx address %#lx steps %d (handler calls %d, unwinds %d)\n", c, (unsigned long)info,
           steps, f.calls, f.unwinds);
    int zero = 0;
    c = guarded(do_div, &zero, &info, 0);
    printf("divide by zero: code %#lx steps %d\n", c, steps);
    c = guarded(do_native_raise, (void *)1234, &info, 0);
    printf("RaiseException in a native DLL: code %#lx arg %lu steps %d\n", c, (unsigned long)info, steps);
    c = guarded(do_through_native, (void *)0x20, &info, 0);
    printf("fault below a native frame: code %#lx address %#lx steps %d\n", c, (unsigned long)info, steps);
    c = guarded(do_nested, (void *)55, &info, &f);
    printf("nested handlers: outer took %#lx (%lu), fs:[0] restored: %d\n", c, (unsigned long)info,
           rd_fs0() == (DWORD)f.next);
    c = guarded(do_repair, 0, &info, &f);
    printf("continue after repair: code %#lx handler calls %d\n", c, f.calls);
    for (int i = 0; i < 300; i++) c = guarded(do_null_write, (void *)0x10, &info, 0);   /* no leak of pending calls */
    printf("300 more faults: last code %#lx steps %d\n", c, steps);

    /* 4. threads with their own exception frames */
    HANDLE th[3]; DWORD code[3];
    for (int i = 0; i < 3; i++) th[i] = CreateThread(0, 0, thread_fn, (LPVOID)(INT_PTR)(i * 10), 0, 0);
    WaitForMultipleObjects(3, th, TRUE, INFINITE);
    for (int i = 0; i < 3; i++) { GetExitCodeThread(th[i], &code[i]); CloseHandle(th[i]); }
    printf("threads: %lu %lu %lu\n", code[0], code[1], code[2]);

    /* 5. the last-error value survives recompiled code (atomic ops, callbacks) */
    volatile LONG cnt = 0;
    SetLastError(1234);
    InterlockedIncrement(&cnt);
    double keep = n_call_dd(cb_dd, 9.0);
    DWORD le1 = GetLastError();
    CreateFileA("Z:\\no\\such\\file.bin", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    printf("last error: %lu then %lu (%.1f)\n", le1, GetLastError() != 0 ? 1ul : 0ul, keep);

    /* 6. x87 precision control: the same sum in 24-bit, 53-bit and 64-bit precision */
    static const unsigned pc[3] = {_PC_24, _PC_53, _PC_64};
    for (int k = 0; k < 3; k++) {
        _controlfp(pc[k], _MCW_PC);
        volatile long double acc = 0, third = 1.0L / 3.0L;
        for (int i = 0; i < 1000; i++) acc = acc * 1.0000001L + third;
        printf("x87 precision %d: %.20Lg  ", k, acc);
        long double s = sinl(1.0L + k), l = log2l(10.0L + k), a = atan2l(1.0L, 3.0L + k);
        printf("sin %.18Lg log2 %.18Lg atan2 %.18Lg fmod %.18Lg\n", s, l, a, fmodl(1e18L + k, 7.25L));
    }
    _controlfp(_PC_64, _MCW_PC);
    _controlfp(_RC_DOWN, _MCW_RC);
    printf("round down: %ld %ld %.17g\n", lrint(2.7), lrint(-2.7), 1.0 / 3.0);
    _controlfp(_RC_NEAR, _MCW_RC);
    return 33;
}
