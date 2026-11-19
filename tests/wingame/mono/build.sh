#!/bin/sh
# fake Mono game: Game.exe + MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll + Game_Data/Managed/*.dll
set -e
OUT=${1:-out}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT/MonoBleedingEdge/EmbedRuntime" "$OUT/Game_Data/Managed"
CC=x86_64-w64-mingw32-gcc
$CC -O2 -shared -o "$OUT/MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll" "$HERE/fake_mono.c" -Wl,--image-base=0x180000000
$CC -O2 -o "$OUT/Game.exe" "$HERE/launcher.c"
mcs -nologo -target:library -out:"$OUT/Game_Data/Managed/Assembly-CSharp.dll" "$HERE/../../cil/scripts.cs"
