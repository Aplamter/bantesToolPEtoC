/* deliberately broken programs, to test the crash reports
 *   crashes null   -> NULL pointer write in a nested call
 *   crashes aes    -> uses an AES-NI instruction the runtime doesn't implement */
#include <stdio.h>
#include <string.h>
struct player { int hp; char name[16]; };
__attribute__((noinline)) void damage(struct player *p, int d) { p->hp -= d; }
__attribute__((noinline)) void level(struct player **ps, int n) { for (int i = 0; i <= n; i++) damage(ps[i], 10); }
int main(int argc, char **argv) {
    printf("starting %s\n", argc > 1 ? argv[1] : "");
    fflush(stdout);
    if (argc > 1 && !strcmp(argv[1], "null")) {
        struct player a = {100, "a"}, b = {100, "b"};
        struct player *ps[3] = {&a, &b, 0};
        level(ps, 2);
    }
    if (argc > 1 && !strcmp(argv[1], "aes")) {
        unsigned char k[16] = {1}, d[16] = {2};
        __asm__ volatile("movdqu %0,%%xmm0; movdqu %1,%%xmm1; aesenc %%xmm1,%%xmm0; movdqu %%xmm0,%0"
                         : "+m"(*(unsigned char(*)[16])d) : "m"(*(unsigned char(*)[16])k) : "xmm0", "xmm1");
        printf("aes byte %d\n", d[0]);
    }
    return 0;
}
