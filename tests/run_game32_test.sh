#!/bin/sh
# 32-bit whole-game round trip: a 32-bit exe + a DLL that both get recompiled
# and a DLL that stays native (it stands in for a system DLL). Covers every
# 32-bit calling convention in both directions, floats on the x87 stack,
# frame-based exception handling, threads and x87 precision control.
# Needs: i686-w64-mingw32-gcc, wine.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
W=${OUT:-/tmp/recomp_game32_test}
WINE=${WINE:-$(command -v wine || echo /usr/lib/wine/wine)}
export WINEDEBUG=-all
rm -rf "$W" && mkdir -p "$W"
cd "$HERE/win32" && sh build.sh "$W/game" >/dev/null
python3 "$HERE/../recomp.py" game "$W/game" -o "$W/project" --keep native.dll
python3 "$W/project/build_game.py"
run() {     # folder output-file: stdout + exit code (conv.exe exits with 33)
    rc=0
    (cd "$1" && "$WINE" conv.exe > "$2") || rc=$?
    echo "exit $rc" >> "$2"
}
run "$W/game" "$W/original.txt"
run "$W/project/build" "$W/rebuilt.txt"
if diff "$W/original.txt" "$W/rebuilt.txt" >/dev/null &&
   [ "$(cd "$W/game" && find . -type f | sort)" = "$(cd "$W/project/build" && find . -type f ! -name recomp_rt.dll | sort)" ]; then
    echo "PASS  32-bit game: same output, same files (+ the shared runtime recomp_rt.dll)"
else
    echo "FAIL  32-bit game (see $W/original.txt vs $W/rebuilt.txt)"; exit 1
fi
