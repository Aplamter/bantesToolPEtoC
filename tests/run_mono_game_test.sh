#!/bin/sh
# Mono game plumbing on Windows (under Wine): a fake Unity-style game
# (Game.exe loads MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll, which here
# is a stand-in that logs registrations) + a real C# assembly in
# Game_Data/Managed. After `game` + build, the recompiled Mono must receive the
# translated C# methods as internal calls from recomp_cil.dll, which the
# shared runtime loads when mono_jit_init_version returns.
# (The C# semantics themselves are tested against real Mono: tests/cil/run_cil_test.sh)
HERE=$(cd "$(dirname "$0")" && pwd)
W=${OUT:-/tmp/recomp_mono_game_test}
WINE=${WINE:-$(command -v wine64 || echo /usr/lib/wine/wine64)}
rm -rf "$W" && mkdir -p "$W"
sh "$HERE/wingame/mono/build.sh" "$W/game" >/dev/null
python3 "$HERE/../recomp.py" game "$W/game" -o "$W/project" > "$W/game.log" 2>&1
python3 "$W/project/build_game.py" > "$W/build.log" 2>&1
(cd "$W/project/build" && WINEDEBUG=-all timeout 120 "$WINE" Game.exe > "$W/run.txt" 2>&1)
want=$(python3 -c "import json; r=json.load(open('$W/project/cil/cil_report.json')); print(sum(len(x['icall_names']) for x in r.values() if x))")
got=$(tr -d '\r' < "$W/run.txt" | sed -n 's/player: \([0-9]*\) internal calls registered/\1/p')
if [ -n "$got" ] && [ "$got" = "$want" ] && [ "$want" -gt 0 ]; then
    echo "PASS  mono game: recompiled Mono got all $got internal calls of the translated C#"
else
    echo "FAIL  mono game: expected $want internal calls, got '$got' (see $W/run.txt, $W/build.log)"; exit 1
fi
