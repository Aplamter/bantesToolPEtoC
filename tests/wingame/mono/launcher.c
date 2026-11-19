/* stand-in for a Unity player: loads Mono from MonoBleedingEdge like
 * UnityPlayer.dll does, starts it, reports what was registered */
#include <windows.h>
#include <stdio.h>
int main(void) {
    HMODULE m = LoadLibraryA("MonoBleedingEdge\\EmbedRuntime\\mono-2.0-bdwgc.dll");
    if (!m) { printf("no mono\n"); return 1; }
    void *(*init)(const char *, const char *) = (void *)GetProcAddress(m, "mono_jit_init_version");
    int (*count)(void) = (void *)GetProcAddress(m, "fake_mono_icalls");
    init("Game", "v4.0.30319");
    printf("player: %d internal calls registered\n", count());
    return 0;
}
