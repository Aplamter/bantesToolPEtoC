#!/bin/sh
# builds the fake game into $1 (default ./game). Both DLLs get the same
# preferred base, like MSVC-built Unity DLLs (0x180000000).
set -e
OUT=${1:-game}
mkdir -p "$OUT/data"
CC=x86_64-w64-mingw32-gcc
x86_64-w64-mingw32-windres engine.rc -O coff -o "$OUT/engine_rc.o"
$CC -O2 -shared -o "$OUT/engine.dll" engine.c "$OUT/engine_rc.o" -Wl,--image-base=0x180000000 -Wl,--out-implib,"$OUT/libengine.a"
$CC -O2 -shared -o "$OUT/plugin.dll" plugin.c -Wl,--image-base=0x180000000
$CC -O2 -o "$OUT/game.exe" game.c -L"$OUT" -lengine
rm -f "$OUT/engine_rc.o" "$OUT/libengine.a"
printf 'forest of tests\r\n' > "$OUT/data/level1.txt"
