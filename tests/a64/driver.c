/* loads a library (the original or the rebuilt one) and runs its tests */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*lib_cb)(int, void *);
struct ops { int (*twice)(int); double (*half)(double); const char *name; };

static int host_cb(int v, void *arg) { return v * 3 + *(int *)arg; }

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: driver LIB [test ...]\n"); return 2; }
    setvbuf(stdout, 0, _IOLBF, 0);
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    static const char *all[] = {"test_int", "test_float", "test_simd", "test_callbacks", "test_varargs",
                                "test_setjmp", "test_threads", "test_signals", "test_memory", "test_cxx",
                                "test_exceptions", 0};
    int hundred = 100, seven = 7;
    void (*set)(lib_cb, void *) = (void (*)(lib_cb, void *))dlsym(h, "lib_set_callback");
    if (set) set(host_cb, &hundred);
    for (int i = 0; all[i]; i++) {
        int want = argc == 2;
        for (int k = 2; k < argc; k++) want |= !strcmp(argv[k], all[i]);
        void (*t)(void) = (void (*)(void))dlsym(h, all[i]);
        if (want && t) t();
    }
    if (argc == 2) {
        /* function pointers of the library, called from here */
        lib_cb (*get)(void) = (lib_cb (*)(void))dlsym(h, "lib_get_function");
        const struct ops *(*ops)(void) = (const struct ops *(*)(void))dlsym(h, "lib_get_ops");
        int *g = dlsym(h, "lib_global");
        if (get) printf("driver: pointer call=%d\n", get()(5, &seven));
        if (ops) printf("driver: table=%d %.2f %s\n", ops()->twice(21), ops()->half(5.5), ops()->name);
        if (g) printf("driver: global=%d\n", *g);
    }
    dlclose(h);
    printf("driver: done\n");
    return 0;
}
