/* fake game engine DLL: exports, DllMain, callbacks across modules,
 * a data export, threads, and a plugin loaded at run time */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

__declspec(dllexport) int engine_version = 4207;
static int attaches, thread_attaches;
typedef int (*cmp_fn)(const void *, const void *);
typedef double (*plugin_fn)(double, int);

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) attaches++;
    if (reason == DLL_THREAD_ATTACH) thread_attaches++;
    return TRUE;
}

__declspec(dllexport) int engine_attaches(void) { return attaches; }
__declspec(dllexport) long long engine_add(long long a, long long b, long long c, long long d,
                                           long long e, long long f) { return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6; }
__declspec(dllexport) double engine_mix(double a, float b, int c, double d) { return a * b + c - d; }

/* the game hands us its own comparator: guest code of another module */
__declspec(dllexport) void engine_sort(int *v, int n, cmp_fn cmp) { qsort(v, n, sizeof *v, cmp); }
__declspec(dllexport) int engine_call(int (*fn)(int), int x) { return fn(x) + 1; }

typedef struct { int (*fn)(int); int in, out; } job;
static DWORD WINAPI worker(LPVOID p) { job *j = p; j->out = j->fn(j->in); return 0; }
__declspec(dllexport) int engine_thread(int (*fn)(int), int x) {
    job j = {fn, x, 0};
    HANDLE t = CreateThread(0, 0, worker, &j, 0, 0);
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    return j.out;
}

__declspec(dllexport) double engine_plugin(const char *dll, double x) {
    HMODULE h = LoadLibraryA(dll);
    if (!h) return -1;
    plugin_fn f = (plugin_fn)GetProcAddress(h, "plugin_scale");
    int *ver = (int *)GetProcAddress(h, "plugin_data");
    double r = f ? f(x, ver ? *ver : -100) : -2;
    return r;
}

__declspec(dllexport) int engine_resource(void) {
    /* reads its own embedded resource, like engines read icons/version info */
    HMODULE self;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)engine_resource, &self);
    HRSRC r = FindResourceA(self, "GAMEDATA", (LPCSTR)RT_RCDATA);
    if (!r) return -1;
    return (int)SizeofResource(self, r);
}
