/* test host for cil2c: embeds Mono like a game engine does, registers the
 * C translated from the assembly, then runs the (patched) program */
#include <mono/jit/jit.h>
#include <mono/metadata/assembly.h>
#include <mono/metadata/mono-config.h>
#include <stdio.h>
void cil_register_all(void);
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: host PROGRAM.exe [args]\n"); return 2; }
    mono_config_parse(NULL);
    MonoDomain *d = mono_jit_init(argv[1]);
    cil_register_all();
    MonoAssembly *a = mono_domain_assembly_open(d, argv[1]);
    if (!a) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    int r = mono_jit_exec(d, a, argc - 1, argv + 1);
    mono_jit_cleanup(d);
    return r;
}
