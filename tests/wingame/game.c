/* fake game exe: statically imports engine.dll, reads a data file */
#include <windows.h>
#include <stdio.h>
#include <string.h>

__declspec(dllimport) int engine_version;
__declspec(dllimport) int engine_attaches(void);
__declspec(dllimport) long long engine_add(long long, long long, long long, long long, long long, long long);
__declspec(dllimport) double engine_mix(double, float, int, double);
__declspec(dllimport) void engine_sort(int *, int, int (*)(const void *, const void *));
__declspec(dllimport) int engine_call(int (*)(int), int);
__declspec(dllimport) int engine_thread(int (*)(int), int);
__declspec(dllimport) double engine_plugin(const char *, double);
__declspec(dllimport) int engine_resource(void);

static int desc(const void *a, const void *b) { return *(const int *)b - *(const int *)a; }
static int square(int x) { return x * x; }

int main(void) {
    printf("engine version %d, attaches %d\n", engine_version, engine_attaches());
    printf("add %lld\n", engine_add(1, 2, 3, 4, 5, 6));
    printf("mix %.3f\n", engine_mix(2.5, 4.0f, 7, 0.5));
    int v[6] = {5, 1, 9, 3, 7, 2};
    engine_sort(v, 6, desc);
    printf("sorted");
    for (int i = 0; i < 6; i++) printf(" %d", v[i]);
    printf("\ncall %d thread %d\n", engine_call(square, 12), engine_thread(square, 9));
    printf("plugin %.2f\n", engine_plugin("plugin.dll", 10.0));
    printf("resource %d\n", engine_resource());
    FILE *f = fopen("data\\level1.txt", "rb");
    char buf[64] = {0};
    if (f) { fread(buf, 1, sizeof buf - 1, f); fclose(f); }
    printf("level: %s\n", buf[0] ? strtok(buf, "\r\n") : "(missing)");
    return 0;
}
