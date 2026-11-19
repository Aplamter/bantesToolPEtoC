/* stdin, files, environment, time-independent syscalls */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
int main(void) {
    char line[512]; int n = 0; long total = 0;
    while (fgets(line, sizeof line, stdin)) { n++; total += strlen(line); }
    printf("stdin: %d lines, %ld bytes\n", n, total);
    char path[] = "/tmp/recomp_test_XXXXXX"; int fd = mkstemp(path);
    FILE *f = fdopen(fd, "w+");
    for (int i = 0; i < 1000; i++) fprintf(f, "row %d %d\n", i, i * i);
    rewind(f); long sum = 0; int a, b;
    while (fscanf(f, "row %d %d\n", &a, &b) == 2) sum += b;
    fclose(f); unlink(path);
    printf("file roundtrip sum=%ld\n", sum);
    printf("env HOME set: %s\n", getenv("HOME") ? "yes" : "no");
    void *blocks[200]; for (int i = 0; i < 200; i++) { blocks[i] = malloc(1000 * (i + 1)); memset(blocks[i], i, 1000 * (i + 1)); }
    long chk = 0; for (int i = 0; i < 200; i++) chk += ((unsigned char*)blocks[i])[999 * (i + 1)];
    for (int i = 0; i < 200; i += 2) free(blocks[i]);
    printf("malloc check=%ld\n", chk);
    return 3;
}
