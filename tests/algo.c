/* integer-heavy test: sorting, hashing, recursion, malloc, strings, 128-bit math */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int cmp(const void *a, const void *b) { return (*(int*)a > *(int*)b) - (*(int*)a < *(int*)b); }
static uint32_t crc32(const uint8_t *p, size_t n) {
    uint32_t c = 0xffffffff;
    for (size_t i = 0; i < n; i++) { c ^= p[i]; for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320 & -(c & 1)); }
    return ~c;
}
static long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
struct node { int key; struct node *l, *r; };
static struct node *ins(struct node *t, int k) {
    if (!t) { t = calloc(1, sizeof *t); t->key = k; return t; }
    if (k < t->key) t->l = ins(t->l, k); else t->r = ins(t->r, k);
    return t;
}
static int depth(struct node *t) { if (!t) return 0; int a = depth(t->l), b = depth(t->r); return 1 + (a > b ? a : b); }
static void walk(struct node *t, long *sum, int *cnt) { if (!t) return; walk(t->l, sum, cnt); *sum += t->key * (long)(++*cnt); walk(t->r, sum, cnt); }

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 20000;
    int *a = malloc(n * sizeof(int));
    uint64_t x = 88172645463325252ULL;
    for (int i = 0; i < n; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; a[i] = (int)(x % 1000003) - 500000; }
    qsort(a, n, sizeof(int), cmp);
    printf("sorted: min=%d max=%d median=%d\n", a[0], a[n-1], a[n/2]);
    printf("crc32=%08x\n", crc32((uint8_t*)a, n * sizeof(int)));
    printf("fib(27)=%ld\n", fib(27));
    struct node *t = 0;
    for (int i = 0; i < n; i++) t = ins(t, a[(i * 7919) % n]);
    long s = 0; int c = 0; walk(t, &s, &c);
    printf("tree: depth=%d weighted=%ld\n", depth(t), s);
#ifdef __SIZEOF_INT128__
    unsigned __int128 big = (unsigned __int128)0xFFFFFFFFFFFFFFFFULL * 0x123456789ABCDEFULL;
    unsigned long long big_hi = (unsigned long long)(big >> 64), big_lo = (unsigned long long)big;
#else   /* 32-bit compilers have no __int128: the same product from 32-bit halves */
    volatile unsigned long long mx = 0xFFFFFFFFFFFFFFFFULL, my = 0x123456789ABCDEFULL;
    unsigned long long x0 = mx & 0xFFFFFFFFu, x1 = mx >> 32, y0 = my & 0xFFFFFFFFu, y1 = my >> 32;
    unsigned long long p00 = x0 * y0, p01 = x0 * y1, p10 = x1 * y0, p11 = x1 * y1;
    unsigned long long mid = (p00 >> 32) + (p01 & 0xFFFFFFFFu) + (p10 & 0xFFFFFFFFu);
    unsigned long long big_lo = (mid << 32) | (p00 & 0xFFFFFFFFu);
    unsigned long long big_hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
#endif
    printf("128-bit: %016llx%016llx  div=%lld mod=%lld\n", big_hi, big_lo,
           (long long)(-7000000000LL / 13), (long long)(-7000000000LL % 13));
    char buf[256]; snprintf(buf, sizeof buf, "%s|%5d|%-6s|%x|%c", "fmt", -42, "ab", 0xbeef, 'Z');
    printf("%s len=%zu rev=", buf, strlen(buf));
    for (int i = strlen(buf) - 1; i >= 0; i--) putchar(buf[i]);
    putchar('\n');
    char *dup = strdup("The quick brown fox"); char *tok = strtok(dup, " "); int words = 0;
    while (tok) { words++; tok = strtok(0, " "); }
    printf("words=%d strstr=%s\n", words, strstr("haystack needle hay", "needle"));
    return (int)(crc32((uint8_t*)a, (n < 16 ? n : 16) * sizeof(int)) & 0x7f);
}
