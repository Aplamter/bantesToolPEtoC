#!/bin/sh
# C++ exception test: exc.exe + exc_dll.dll (MinGW g++: Windows SEH-based exceptions)
set -e
OUT=${1:-out}
mkdir -p "$OUT"
CXX=x86_64-w64-mingw32-g++
$CXX -O2 -shared -o "$OUT/exc_dll.dll" exc_dll.cpp -static -Wl,--image-base=0x180000000 -Wl,--out-implib,"$OUT/libexc_dll.a"
$CXX -O2 -o "$OUT/exc.exe" exc.cpp -L"$OUT" -lexc_dll -static
rm -f "$OUT/libexc_dll.a"
