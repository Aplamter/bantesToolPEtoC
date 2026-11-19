#!/bin/sh
# Whole-game round trip: build a fake Windows game (exe + engine DLL + plugin
# DLL loaded at run time + Unity asset files), decompile the folder with
# `recomp.py game`, build the project back, run both under Wine, compare.
# Needs: x86_64-w64-mingw32-gcc, wine64, python3 with UnityPy + lz4.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
W=${OUT:-/tmp/recomp_game_test}
WINE=${WINE:-$(command -v wine64 || echo /usr/lib/wine/wine64)}
rm -rf "$W" && mkdir -p "$W"
cd "$HERE/wingame" && sh build.sh "$W/game" >/dev/null
python3 "$HERE/wingame/make_unity.py" "$W/game/game_Data"
python3 "$HERE/../recomp.py" game "$W/game" -o "$W/project"
python3 "$W/project/build_game.py"
(cd "$W/game" && WINEDEBUG=-all "$WINE" game.exe > "$W/original.txt")
(cd "$W/project/build" && WINEDEBUG=-all "$WINE" game.exe > "$W/rebuilt.txt")
if diff "$W/original.txt" "$W/rebuilt.txt" >/dev/null &&
   [ "$(cd "$W/game" && find . -type f | sort)" = "$(cd "$W/project/build" && find . -type f ! -name recomp_rt.dll | sort)" ]; then
    echo "PASS  whole game: same output, same files (+ the shared runtime recomp_rt.dll)"
else
    echo "FAIL  whole game (see $W/original.txt vs $W/rebuilt.txt)"; exit 1
fi
