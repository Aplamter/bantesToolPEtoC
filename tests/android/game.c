/* native code for the test APKs (built for arm64-v8a and x86_64) */
#include <string.h>
int counter;
static int helper(int x) { return x * 3 + counter; }
__attribute__((visibility("default"))) int game_tick(int x) { counter++; return helper(x) + 1; }
__attribute__((visibility("default"))) int (*get_cb(void))(int) { return helper; }
__attribute__((visibility("default"))) int JNI_OnLoad(void *vm, void *reserved) { (void)vm; (void)reserved; return 0x00010006; }
__attribute__((visibility("default"))) void ANativeActivity_onCreate(void *a, void *s, unsigned long n) { (void)a; (void)s; (void)n; counter = 7; }
