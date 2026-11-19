/* what Mono does: a vectored handler registered FIRST, machine code made at
 * run time ("JIT"), a null access in that code turned into a result by the
 * handler, and that code calling back into the program */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
static int seen;
static LONG CALLBACK handler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    seen++;
    ep->ContextRecord->Rax = 42;          /* "NullReferenceException": give a result instead */
    ep->ContextRecord->Rip += 3;          /* skip mov rax,[rcx] */
    return EXCEPTION_CONTINUE_EXECUTION;
}
static int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
static long long helper(void *self, long long x) { return x * 2 + 1; }
/* a helper with its own calling convention, like the stack probe Mono's
 * generated code calls: arguments in RAX and R10, result in R11, RAX kept */
__asm__(".text\n.globl probe_like\nprobe_like:\n  lea (%rax,%r10,1), %r11\n  ret\n");
extern void probe_like(void);
/* generated code that leaves a callback without returning from it, the way
 * Mono's handles a C# exception: outer() calls back into the program, the
 * callback calls unwind(), which jumps straight back into outer()'s frame */
static void *slot, *resume_at;
static void (*do_unwind)(void **, void *);
static int cb_ran;
__attribute__((noinline)) static long long churn(long long a) {
    long long x = a * 3, y = a + 7, z = a ^ 0x55, w = a - 1;
    cb_ran++;                      /* (the values above sit in registers main() also uses) */
    do_unwind(&slot, resume_at);
    return x + y + z + w;          /* never reached */
}
static void callback(void) { printf("callback: %lld\n", churn(cb_ran + 1)); }

int main(void) {
    void *h = AddVectoredExceptionHandler(1, handler);
    printf("handler registered: %s\n", h ? "yes" : "no"); fflush(stdout);
    int v[5] = {5, 3, 9, 1, 7};
    qsort(v, 5, sizeof v[0], cmp);         /* Windows calls back into the program */
    printf("sorted: %d %d %d %d %d\n", v[0], v[1], v[2], v[3], v[4]); fflush(stdout);
    unsigned char *jit = VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    unsigned char load[] = {0x48, 0x8B, 0x01, 0xC3};            /* mov rax,[rcx]; ret */
    unsigned char tail[] = {0xFF, 0xE1};                        /* jmp rcx */
    memcpy(jit, load, sizeof load); memcpy(jit + 16, tail, sizeof tail);
    long long (*f)(long long *) = (void *)jit;
    long long (*g)(void *, long long) = (void *)(jit + 16);
    long long one = 7;
    printf("generated code, good pointer: %lld\n", f(&one)); fflush(stdout);
    printf("generated code, null pointer: %lld (handler ran %d time)\n", f(0), seen); fflush(stdout);
    printf("generated code calls the program: %lld\n", g(helper, 20)); fflush(stdout);
    /* mov rax,rcx; mov r10,rdx; call r8; add rax,r11; ret */
    unsigned char odd[] = {0x48, 0x89, 0xC8, 0x49, 0x89, 0xD2, 0x41, 0xFF, 0xD0, 0x4C, 0x01, 0xD8, 0xC3};
    memcpy(jit + 32, odd, sizeof odd);
    long long (*k)(long long, long long, void *) = (void *)(jit + 32);
    printf("generated code calls a register-convention helper: %lld\n", k(5, 100, probe_like)); fflush(stdout);
    static const unsigned char unw[] = {0x53, 0x55, 0x57, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0x22, 0xFF, 0xD1, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x05, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5E, 0x5F, 0x5D, 0x5B, 0xC3, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x00, 0x48, 0x8B, 0x21, 0xFF, 0xE2, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    memcpy(jit + 256, unw, sizeof unw);
    int (*outer)(void (*)(void), void **) = (void *)(jit + 256);
    resume_at = jit + 256 + 0x1c;
    do_unwind = (void *)(jit + 256 + 0x40);
    long long keep1 = v[0] * 1000 + 7, keep2 = one * 31, keep3 = seen + 99;
    for (int round = 0; round < 3; round++) {
        int how = outer(callback, &slot);
        printf("round %d: came back %s; values kept: %lld %lld %lld\n", round,
               how == 2 ? "through the unwind" : "normally", keep1 + round, keep2 + round, keep3 + round);
        fflush(stdout);
    }
    printf("sorted again after unwinding: "); v[0] = 8; qsort(v, 5, sizeof v[0], cmp);
    printf("%d %d %d %d %d\n", v[0], v[1], v[2], v[3], v[4]); fflush(stdout);
    printf("removed: %lu\n", RemoveVectoredExceptionHandler(h));
    return 0;
}
