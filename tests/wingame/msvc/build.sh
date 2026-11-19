#!/bin/sh
# MSVC-ABI C++ exception test (clang targeting x86_64-pc-windows-msvc,
# linked against msvcrt.dll for printf and vcruntime140.dll for C++ EH)
set -e
OUT=${1:-out}
mkdir -p "$OUT"
L=/usr/x86_64-w64-mingw32/lib
x86_64-w64-mingw32-dlltool -d vcruntime140.def -l "$OUT/libvcruntime140.a" -m i386:x86-64
clang --target=x86_64-pc-windows-msvc -O1 -fms-extensions -fexceptions -fcxx-exceptions \
      -c msvc_exc.cpp -o "$OUT/msvc_exc.obj"
lld-link /nologo /out:"$OUT/msvc_exc.exe" /entry:start /subsystem:console /nodefaultlib \
      /base:0x140000000 "/alternatename:??_7type_info@@6B@=dummy_type_info_vtbl" "$OUT/msvc_exc.obj" "$OUT/libvcruntime140.a" $L/libmsvcrt.a $L/libkernel32.a
rm -f "$OUT/msvc_exc.obj" "$OUT/libvcruntime140.a"
