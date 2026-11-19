#!/bin/sh
# Live runtime-capture test on Windows binaries under Wine:
#   WINPY=/path/to/windows/python.exe sh tests/wine_capture/run_wine_capture_test.sh
# (Windows Python e.g. from https://www.nuget.org/packages/python, unpacked: tools/python.exe)
set -u
cd "$(dirname "$0")"
: "${WINPY:?set WINPY to a Windows python.exe}"
export WINEDEBUG=-all
CC=x86_64-w64-mingw32-gcc
$CC -O1 -shared -o libA.dll libA.c -Wl,--image-base,0x6f000000 || exit 1
$CC -O1 -shared -o libB.dll libB.c -Wl,--image-base,0x6f000000 || exit 1
$CC -O1 -o target.exe target.c libA.dll libB.dll || exit 1
OUT=${OUT:-/tmp/recomp_wine_capture}
rm -rf "$OUT"; mkdir -p "$OUT"
W() { printf 'Z:%s' "$(printf '%s' "$1" | tr '/' '\\')"; }
rc=0
echo "== launch mode"
echo | timeout 300 wine "$WINPY" "$(W "$PWD/drive_launch.py")" "$(W "$OUT/launch")" 2>&1 | cat > "$OUT/launch.log"
python3 check_reports.py "$OUT/launch" launch || rc=1
wineserver -k 2>/dev/null
echo "== attach mode (capture --name)"
( echo | wine ./target.exe 14 2>&1 | cat > "$OUT/target.log" & )
sleep 3
echo | timeout 300 wine "$WINPY" "$(W "$PWD/../../recomp.py")" capture --name target.exe -o "$(W "$OUT/attach")" \
    --runtime-duration 6 --runtime-interval 2 2>&1 | cat > "$OUT/attach.log"
python3 check_reports.py "$OUT/attach/runtime" attach || rc=1
wineserver -k 2>/dev/null
echo "== native library output capture (Unity previews)"
x86_64-w64-mingw32-gcc -O1 -shared -o noisy.dll noisy.c || exit 1
echo | timeout 120 wine "$WINPY" "$(W "$PWD/drive_native_capture.py")" 2>&1 | tr -d '\r' > "$OUT/native.log"
if [ "$(head -1 "$OUT/native.log")" = "CONSOLE-AFTER: this line must reach the console" ] &&
   [ "$(grep -c '^block[012]: ' "$OUT/native.log")" -eq 21 ]; then
    echo "PASS  native output: CRT printf, other-CRT stderr, WriteFile, cached handle - all captured in 3 blocks, none leaked"
else
    echo "FAIL  native output capture (see $OUT/native.log)"; rc=1
fi
exit $rc
