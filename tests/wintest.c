/* Windows-specific stress test for the recompiler runtime */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

static CRITICAL_SECTION cs;
static volatile LONG counter;
static long long shared_sum;
static int locales;

static DWORD WINAPI worker(LPVOID arg) {             /* runs on an OS thread */
    int id = (int)(INT_PTR)arg; long long local = 0;
    for (int i = 0; i < 20000; i++) { local += (i * (id + 1)) % 7; InterlockedIncrement(&counter); }
    EnterCriticalSection(&cs); shared_sum += local; LeaveCriticalSection(&cs);
    return id * 10;
}
static int cmp_desc(const void *a, const void *b) {  /* called back by msvcrt qsort */
    return *(const int *)b - *(const int *)a;
}
static BOOL CALLBACK locale_cb(LPSTR s) { (void)s; locales++; return locales < 5; } /* called by kernel32 */
static void bye(void) { printf("atexit handler ran\n"); }

int main(void) {
    atexit(bye);
    InitializeCriticalSection(&cs);
    HANDLE th[4]; DWORD codes[4];
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, worker, (LPVOID)(INT_PTR)i, 0, NULL);
    WaitForMultipleObjects(4, th, TRUE, INFINITE);
    for (int i = 0; i < 4; i++) { GetExitCodeThread(th[i], &codes[i]); CloseHandle(th[i]); }
    printf("threads: counter=%ld sum=%lld exit codes %lu %lu %lu %lu\n", counter, shared_sum,
           codes[0], codes[1], codes[2], codes[3]);

    int v[12] = {5, 3, 9, 1, 12, 7, 8, 2, 11, 4, 6, 10};
    qsort(v, 12, sizeof(int), cmp_desc);
    printf("qsort callback:"); for (int i = 0; i < 12; i++) printf(" %d", v[i]); printf("\n");

    EnumSystemLocalesA(locale_cb, LCID_INSTALLED);
    printf("kernel32 callback: %d locales seen\n", locales);

    char path[MAX_PATH]; GetTempPathA(MAX_PATH, path); strcat(path, "recomp_wintest.bin");
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY, NULL);                    /* 7 arguments */
    DWORD n; char buf[64];
    WriteFile(f, "recompiled file io works", 24, &n, NULL);                  /* 5 arguments */
    SetFilePointer(f, 0, NULL, FILE_BEGIN);
    ReadFile(f, buf, sizeof buf - 1, &n, NULL); buf[n] = 0;
    CloseHandle(f); DeleteFileA(path);
    printf("file: '%s' (%lu bytes)\n", buf, n);

    printf("floats via msvcrt: pow=%.10f sqrt=%.10f atan2=%.10f\n", pow(2.5, 3.25), sqrt(7.0), atan2(-1.0, -2.0));
    typedef double (*fn_d_d)(double);
    fn_d_d c = (fn_d_d)GetProcAddress(GetModuleHandleA("msvcrt.dll"), "cos");
    printf("GetProcAddress cos(1)=%.12f\n", c(1.0));
    char wb[128]; wsprintfA(wb, "%s-%d-%x-%c-%s-%d", "varargs", 42, 0xbeef, 'Z', "many", -7);
    printf("wsprintf: %s\n", wb);
    int r = MulDiv(123456, 789, 1000);
    printf("MulDiv=%d tick-ok=%d\n", r, GetTickCount() > 0);
    return 17;
}
