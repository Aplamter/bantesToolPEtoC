#include <stdio.h>
int main(int argc, char **argv) {
    printf("hello from the original binary! argc=%d\n", argc);
    for (int i = 0; i < argc; i++) printf("  argv[%d]=%s\n", i, argv[i]);
    return 42;
}
