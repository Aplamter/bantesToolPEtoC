/* two DLLs with the SAME preferred ImageBase: Windows/Wine must relocate one */
static int helper(int x) { return x * 5 + 2; }
__declspec(dllexport) int (*b_ptr(void))(int) { void *p; __asm__ volatile("movabs %1, %0" : "=r"(p) : "i"(helper)); return p; }
__declspec(dllexport) int b_call(int x) { return b_ptr()(x); }
