/* two DLLs with the SAME preferred ImageBase: Windows/Wine must relocate one */
static int helper(int x) { return x * 3 + 1; }
__declspec(dllexport) int (*a_ptr(void))(int) { void *p; __asm__ volatile("movabs %1, %0" : "=r"(p) : "i"(helper)); return p; }
__declspec(dllexport) int a_call(int x) { return a_ptr()(x); }
