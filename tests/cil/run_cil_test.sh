#!/bin/sh
# C# -> C (cil2c): compile each test with mcs, run it on Mono, translate it to
# C, run the C version inside the same Mono (embedded), compare the output.
# Then check the patched assembly really needs the C (no IL left in them).
# Needs: mono, mcs, libmono-2.0 (Linux), gcc.

HERE=$(cd "$(dirname "$0")" && pwd)
W=${OUT:-/tmp/recomp_cil_test}
LIB=${MONO_LIB:-/usr/lib/mono/4.5}
rm -rf "$W" && mkdir -p "$W"
fail=0
for t in game_logic scripts; do
    mcs -nologo -out:"$W/$t.exe" "$HERE/$t.cs"
    (cd "$W" && { mono "$t.exe" > "$t.orig"; echo "exit $?" >> "$t.orig"; })
    python3 "$HERE/../../recomp.py" cil "$W/$t.exe" -o "$W/$t" --lib "$LIB" | tail -1
    gcc -O2 -w -c -o "$W/$t/host.o" "$HERE/host.c" $(pkg-config --cflags mono-2)
    gcc -O2 -w -o "$W/$t/host" "$W/$t/host.o" "$W/$t"/*.c -I"$W/$t" -lmono-2.0 -lm -lpthread
    (cd "$W" && { timeout 120 "./$t/host" "$t/$t.exe" > "$t.c_out" 2> "$t.err"; echo "exit $?" >> "$t.c_out"; })
    if cmp -s "$W/$t.orig" "$W/$t.c_out" && ! (cd "$W" && mono "$t/$t.exe" >/dev/null 2>&1); then
        echo "PASS  cil/$t ($(wc -l < "$W/$t.orig") lines identical; patched IL alone does not run)"
    else
        echo "FAIL  cil/$t (diff $W/$t.orig $W/$t.c_out; $W/$t.err)"; fail=1
    fi
done
exit $fail
