/* native.dll: stays NATIVE in the test (recomp.py game --keep native.dll).
 * It plays the role of a system DLL that calls back into the program with
 * every 32-bit calling convention, returns floats on the x87 stack, raises
 * exceptions and recurses through the program's callbacks. */
#include <windows.h>

__declspec(dllexport) double n_call_dd(double (*f)(double), double x) { return f(x) * 2.0 + 1.0; }
__declspec(dllexport) float n_call_ff(float (*f)(float, float), float a, float b) { return f(a, b) - 0.5f; }
__declspec(dllexport) long long n_call_ll(long long (*f)(long long, int), long long a, int b) { return f(a, b) + 1; }
__declspec(dllexport) int n_call_std(int (__stdcall *f)(int, int, int), int a, int b, int c) {
    /* a stdcall callee removes its own arguments: the locals around the call
     * only survive if the stack pointer comes back exactly right */
    volatile int guard1 = 0x1111, r = f(a, b, c), guard2 = 0x2222;
    return guard1 == 0x1111 && guard2 == 0x2222 ? r : -999;
}
__declspec(dllexport) int n_call_fast(int (__fastcall *f)(int, int, int, int), int a, int b, int c, int d) {
    volatile int guard = 0x3333, r = f(a, b, c, d);
    return guard == 0x3333 ? r : -999;
}
__declspec(dllexport) int __stdcall n_std_sum(int a, int b, int c, int d, int e) { return a + 2 * b + 3 * c + 4 * d + 5 * e; }
__declspec(dllexport) int __fastcall n_fast_sum(int a, int b, int c) { return a * 100 + b * 10 + c; }
__declspec(dllexport) int n_vsum(int n, ...) {
    va_list ap; int s = 0;
    va_start(ap, n);
    for (int i = 0; i < n; i++) s += va_arg(ap, int) * (i + 1);
    va_end(ap);
    return s;
}
/* native -> program -> native -> program ... */
__declspec(dllexport) int n_nest(int (*f)(int), int depth) { return depth <= 0 ? 1 : f(depth - 1) + depth; }
__declspec(dllexport) void n_raise(DWORD code, ULONG_PTR arg) { RaiseException(code, 0, 1, &arg); }
/* calls the program, which raises: the exception passes through this frame */
__declspec(dllexport) int n_call_void(void (*f)(void *), void *arg) { f(arg); return 7; }
typedef struct { int a; double b; char c[20]; } big_t;
__declspec(dllexport) big_t n_struct(int a, double b) { big_t r = {a * 2, b * 0.5, "native struct"}; return r; }
