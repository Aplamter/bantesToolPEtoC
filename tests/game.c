/* a tiny "game" that ships its assets encrypted and decrypts them at startup */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "game_data.h"
#include "game_icon.h"

static void decrypt(unsigned char *p, size_t n, uint64_t key) {
    uint64_t x = key;
    for (size_t i = 0; i < n; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; p[i] ^= (unsigned char)x; }
}

int main(void) {
    decrypt(packdata, sizeof packdata, 0xC0FFEE1234ULL);
    if (memcmp(packdata, "GPAK", 4)) { puts("bad key"); return 1; }
    uint32_t n, png, wav, lvl;
    memcpy(&n, packdata + 4, 4); memcpy(&png, packdata + 8, 4); memcpy(&wav, packdata + 12, 4); memcpy(&lvl, packdata + 16, 4);
    printf("asset pack: %u files (png %u bytes, wav %u bytes, level %u bytes)\n", n, png, wav, lvl);
    const char *level = (const char *)packdata + 20 + png + wav;
    int enemies = 0, hp = 0; const char *p = level;
    while ((p = strstr(p, "hp="))) { enemies++; { int v = 0; const char *q = p + 3; while (*q >= 48 && *q <= 57) v = v * 10 + (*q++ - 48); hp += v; } p += 3; }
    printf("%.*s", 31, level);
    printf("enemies=%d total_hp=%d\n", enemies, hp);
    unsigned s = 0; for (size_t i = 0; i < sizeof icon_png; i++) s = s * 31 + icon_png[i];
    printf("icon: %zu bytes, hash %08x\n", sizeof icon_png, s);
    return 0;
}
