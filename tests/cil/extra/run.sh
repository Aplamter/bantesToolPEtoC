#!/bin/sh
# more C# -> C checks, each against real Mono: struct enumerators through
# interfaces, constrained calls, static constructors, numeric conversions,
# unsafe code, events, iterators, exceptions. Needs mono, mcs, libmono-2.0.
HERE=$(cd "$(dirname "$0")" && pwd)
W=${OUT:-/tmp/recomp_cil_extra}
LIB=${MONO_LIB:-/usr/lib/mono/4.5}
rm -rf "$W" && mkdir -p "$W"
fail=0
for t in e f g h m; do
    mcs -nologo -unsafe -nowarn:0652,0220,0221 -out:"$W/$t.exe" "$HERE/$t.cs" || { fail=1; continue; }
    (cd "$W" && mono "$t.exe" > "$t.orig" 2>&1)
    python3 "$HERE/../../../recomp.py" cil "$W/$t.exe" -o "$W/$t" --lib "$LIB" > /dev/null
    gcc -O1 -w -c -o "$W/$t/host.o" "$HERE/../host.c" $(pkg-config --cflags mono-2)
    gcc -O1 -w -o "$W/$t/host" "$W/$t/host.o" "$W/$t"/*.c -I"$W/$t" -lmono-2.0 -lm -lpthread -ldl
    (cd "$W" && timeout 120 "./$t/host" "$t/$t.exe" > "$t.c_out" 2>&1)
    if cmp -s "$W/$t.orig" "$W/$t.c_out"; then echo "PASS  cil/extra/$t"; else echo "FAIL  cil/extra/$t (diff -a $W/$t.orig $W/$t.c_out)"; fail=1; fi
done
mcs -nologo -out:"$W/s.exe" "$HERE/s.cs"
python3 "$HERE/../../../recomp.py" cil "$W/s.exe" -o "$W/s" --lib "$LIB" > /dev/null
gcc -O1 -w -c -o "$W/s/host.o" "$HERE/../host.c" $(pkg-config --cflags mono-2)
gcc -O1 -w -o "$W/s/host" "$W/s/host.o" "$W/s"/*.c -I"$W/s" -lmono-2.0 -lm -lpthread -ldl
for m in 1 2 3 4 5 6; do
    a=$(cd "$W" && mono s.exe $m 2>&1); b=$(cd "$W" && timeout 30 ./s/host s/s.exe $m 2>&1 | head -1)
    [ "$a" = "$b" ] || { echo "FAIL  cil/extra/s $m: mono '$a', C '$b'"; fail=1; }
done
[ $fail = 0 ] && echo "PASS  cil/extra/s (static constructors)"
exit $fail
