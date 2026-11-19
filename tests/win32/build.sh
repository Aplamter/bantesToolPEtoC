#!/bin/sh
# builds the 32-bit test "game" into $1: conv.exe + conv.dll (both get
# recompiled) + native.dll (kept native with `recomp.py game --keep
# native.dll`; it stands in for a system DLL). Run by ../run_game32_test.sh
set -e
OUT=${1:-out}
mkdir -p "$OUT"
CC=i686-w64-mingw32-gcc
$CC -O2 -shared -o "$OUT/native.dll" native.c -Wl,--out-implib,"$OUT/libnative.a"
$CC -O2 -shared -o "$OUT/conv.dll" conv_dll.c -Wl,--image-base=0x10000000 -Wl,--out-implib,"$OUT/libconv.a"
$CC -O2 -o "$OUT/conv.exe" conv.c -L"$OUT" -lconv -lnative -lm
rm -f "$OUT/libnative.a" "$OUT/libconv.a"
