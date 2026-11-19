#include <stdio.h>
int (*getptr(void))(int);
int main(void) { int (*f)(int) = getptr(); printf("leaf through a pointer: %d\n", f(8)); return 0; }
