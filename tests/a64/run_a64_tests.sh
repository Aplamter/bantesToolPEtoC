#!/bin/sh
# ARM64 shared libraries (Android lib/arm64-v8a/*.so): build a test library
# with gcc and with clang (pointer authentication + BTI), lift it, rebuild it
# and check that every test prints the same as the original.
# Needs: aarch64-linux-gnu-gcc/g++, clang + lld, qemu-aarch64.
set -u
cd "$(dirname "$0")"
HERE=$(pwd); ROOT=$(cd ../.. && pwd)
OUT=${OUT:-/tmp/recomp_a64}
SYS=/usr/aarch64-linux-gnu
rm -rf "$OUT"; mkdir -p "$OUT"
run() { qemu-aarch64 -L $SYS "$OUT/driver" "$@"; }
aarch64-linux-gnu-gcc -O1 driver.c -o "$OUT/driver" -ldl || exit 1
pass=0; fail=0
one() {  # name: OUT/name/libtest.so must exist
    d="$OUT/$1"
    python3 "$ROOT/recomp.py" lift "$d/libtest.so" -o "$d/out" > "$d/lift.log" 2>&1 &&
        (cd "$d/out" && python3 build_lift.py > "$d/build.log" 2>&1) || { echo "FAIL  $1: lift/build (see $d)"; fail=$((fail+1)); return; }
    run "$d/libtest.so" > "$d/want.txt" 2>&1
    timeout 300 qemu-aarch64 -L $SYS "$OUT/driver" "$d/out/libtest.so" > "$d/got.txt" 2>&1
    if cmp -s "$d/want.txt" "$d/got.txt"; then echo "PASS  $1"; pass=$((pass+1));
    else echo "FAIL  $1"; diff "$d/want.txt" "$d/got.txt" | head -10; fail=$((fail+1)); fi
}
mkdir -p "$OUT/gcc" "$OUT/clang"
aarch64-linux-gnu-gcc -O2 -fPIC -fvisibility=hidden -c lib.c -o "$OUT/gcc/lib.o" &&
aarch64-linux-gnu-g++ -O2 -fPIC -fvisibility=hidden -c libcxx.cpp -o "$OUT/gcc/libcxx.o" &&
aarch64-linux-gnu-g++ -shared -o "$OUT/gcc/libtest.so" "$OUT/gcc/lib.o" "$OUT/gcc/libcxx.o" -lm -lpthread && one gcc
F="--target=aarch64-linux-gnu --sysroot=$SYS -O2 -fPIC -fvisibility=hidden -mbranch-protection=standard"
GV=$(ls $SYS/include/c++ | head -1)
clang $F -c lib.c -o "$OUT/clang/lib.o" &&
clang++ $F -isystem $SYS/include/c++/$GV -isystem $SYS/include/c++/$GV/aarch64-linux-gnu -c libcxx.cpp -o "$OUT/clang/libcxx.o" &&
aarch64-linux-gnu-g++ -shared -o "$OUT/clang/libtest.so" "$OUT/clang/lib.o" "$OUT/clang/libcxx.o" -lm -lpthread && one clang
echo "$pass passed, $fail failed"
[ $fail = 0 ]
