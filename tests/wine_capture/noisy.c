/* a native library that prints the ways real ones do (TypeTreeGenerator is a
 * .NET NativeAOT DLL: Console.WriteLine -> WriteFile on the std handle it
 * looked up once) - used by test_native_capture.py */
#include <windows.h>
#include <stdio.h>
static HANDLE cached;
__declspec(dllexport) void noisy_crt(int i) { printf("Error generating tree nodes:\nSequence contains no matching element\n"); fflush(stdout); (void)i; }
__declspec(dllexport) void noisy_stderr(int i) { fprintf(stderr, "stderr line %d\n", i); fflush(stderr); }
__declspec(dllexport) void noisy_win32(int i) {
    char b[64]; DWORD n; int len = wsprintfA(b, "win32 line %d\r\n", i);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), b, len, &n, 0);
}
__declspec(dllexport) void noisy_cached(int i) {
    char b[64]; DWORD n; int len = wsprintfA(b, "cached line %d\r\n", i);
    if (!cached) cached = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(cached, b, len, &n, 0);
}
