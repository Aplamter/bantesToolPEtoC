/* conv.dll: recompiled. Exports with decorated names (stdcall: name@8,
 * fastcall: @name@12), so the rebuilt DLL must export exactly those. */
#include <windows.h>
#include <stdarg.h>

static int attached;
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) { if (reason == DLL_PROCESS_ATTACH) attached = 41; return TRUE; }

__declspec(dllexport) int __stdcall s_add(int a, int b) { return a + b + attached; }
__declspec(dllexport) int __fastcall f_mix(int a, int b, int c) { return a * 3 - b * 2 + c; }
__declspec(dllexport) long long __stdcall s_wide(long long a, int b) { return a * b - 5; }
__declspec(dllexport) float __stdcall s_flt(float x) { return x * 1.5f + 0.25f; }
__declspec(dllexport) double __cdecl c_avg(int n, ...) {
    va_list ap; double s = 0;
    va_start(ap, n);
    for (int i = 0; i < n; i++) s += va_arg(ap, double);
    va_end(ap);
    return n ? s / n : 0;
}
typedef struct { int x, y, z; double w; } vec_t;
__declspec(dllexport) vec_t c_vec(int x, double w) { vec_t v = {x, x * 2, x * 3, w + 0.125}; return v; }
/* a C++-style method: `this` in ECX, the callee removes the stack argument */
typedef struct { int base; } obj_t;
__declspec(dllexport) int __thiscall o_method(obj_t *self, int k) { return self->base * k + 1; }
