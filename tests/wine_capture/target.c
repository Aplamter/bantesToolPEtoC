/* runtime-capture test target:
 *  - loads libA.dll and libB.dll (same ImageBase -> one is relocated)
 *  - patches 16 bytes of its own .text at run time ("self-modifying / unpacked code")
 *  - writes generated code into fresh executable private memory ("JIT")
 *  - then sleeps so it can be snapshotted */
#include <windows.h>
#include <stdio.h>
__declspec(dllimport) int a_call(int);
__declspec(dllimport) int b_call(int);
__attribute__((noinline, aligned(64))) int patch_me(int x) {
    volatile int y = x;
    y = y * 7 + 3; y ^= 0x55; y = y * 11 - 9; y ^= 0x1234;
    return y;
}
int main(int argc, char **argv) {
    printf("a=%d b=%d\n", a_call(2), b_call(2)); fflush(stdout);
    DWORD old;
    unsigned char *p = (unsigned char *)patch_me;
    static const unsigned char repl[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3,   /* mov eax,42; ret */
                                         0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
    if (VirtualProtect(p, sizeof repl, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(p, repl, sizeof repl);
        VirtualProtect(p, sizeof repl, old, &old);
        FlushInstructionCache(GetCurrentProcess(), p, sizeof repl);
    }
    printf("patch_me(1)=%d at %p\n", patch_me(1), (void *)p); fflush(stdout);
    unsigned char *jit = VirtualAlloc(0, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    static const unsigned char code[] = {0x48, 0x8D, 0x04, 0x09, 0xC3};   /* lea rax,[rcx+rcx]; ret */
    for (int i = 0; i < 64; i++) memcpy(jit + i * 16, code, sizeof code);
    VirtualProtect(jit, 8192, PAGE_EXECUTE_READ, &old);
    long long (*f)(long long) = (void *)jit;
    printf("jit(21)=%lld at %p\n", f(21), (void *)jit); fflush(stdout);
    int secs = argc > 1 ? atoi(argv[1]) : 60;
    /* keep generating code: every second rewrite the first region, and after
     * 3 seconds make a second one - so snapshots differ from each other */
    unsigned char *jit2 = 0;
    for (int t = 0; t < secs; t++) {
        Sleep(1000);
        VirtualProtect(jit, 8192, PAGE_READWRITE, &old);
        jit[1024 + (t & 63)] = (unsigned char)(0x90 + (t & 7));
        VirtualProtect(jit, 8192, PAGE_EXECUTE_READ, &old);
        if (t == 3 && !jit2) {
            jit2 = VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            memcpy(jit2, code, sizeof code);
        }
    }
    return 0;
}
