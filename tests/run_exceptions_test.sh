#!/bin/sh
# Exceptions in recompiled Windows code, end to end (game -> build -> run -> compare):
#   cxx:  MinGW g++ exe + DLL - C++ throw/catch, destructors, rethrow, across
#         and through DLL frames (GCC SEH personality, RtlUnwindEx, collided unwinds)
#   msvc: clang (MSVC ABI) exe + Microsoft's vcruntime140.dll recompiled too -
#         __CxxFrameHandler3, catch blocks via STATUS_UNWIND_CONSOLIDATE, rethrow,
#         plus SEH: an access violation caught by __except, filters, __finally
# Needs: mingw g++, clang + lld-link, wine64, pip (downloads msvc-runtime once).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
W=${OUT:-/tmp/recomp_exc_test}
WINE=${WINE:-$(command -v wine64 || echo /usr/lib/wine/wine64)}
R="$HERE/../recomp.py"
rm -rf "$W" && mkdir -p "$W"
fail=0

check() {   # name folder exe
    (cd "$W/$2" && WINEDLLOVERRIDES="vcruntime140=n" WINEDEBUG=-all "$WINE" "$3" > "$W/$1.orig" 2>/dev/null) || true
    python3 "$R" game "$W/$2" -o "$W/$1_proj" $4 > "$W/$1.game.log" 2>&1
    python3 "$W/$1_proj/build_game.py" > "$W/$1.build.log" 2>&1
    (cd "$W/$1_proj/build" && WINEDLLOVERRIDES="vcruntime140=n" WINEDEBUG=-all timeout 120 "$WINE" "$3" > "$W/$1.rebuilt" 2>"$W/$1.err") || true
    if [ -s "$W/$1.orig" ] && cmp -s "$W/$1.orig" "$W/$1.rebuilt"; then
        echo "PASS  exceptions/$1 ($(wc -l < "$W/$1.orig") lines identical)"
    else
        echo "FAIL  exceptions/$1 (diff $W/$1.orig $W/$1.rebuilt; $W/$1.err)"; fail=1
    fi
}

(cd "$HERE/wingame/cxx" && sh build.sh "$W/cxx") >/dev/null
check cxx cxx exc.exe

VCRT="$W/vcrt"
mkdir -p "$VCRT"
pip download msvc-runtime --platform win_amd64 --only-binary=:all: --no-deps -d "$VCRT" -q
python3 - "$VCRT" <<'EOF'
import os, sys, zipfile
d = sys.argv[1]
w = [f for f in os.listdir(d) if f.endswith(".whl")][0]
z = zipfile.ZipFile(os.path.join(d, w))
for n in z.namelist():
    if n.lower().endswith("/vcruntime140.dll"):
        open(os.path.join(d, "vcruntime140.dll"), "wb").write(z.read(n))
EOF
(cd "$HERE/wingame/msvc" && sh build.sh "$W/msvc") >/dev/null
cp "$VCRT/vcruntime140.dll" "$W/msvc/"     # for the original's run
check msvc msvc msvc_exc.exe
exit $fail
