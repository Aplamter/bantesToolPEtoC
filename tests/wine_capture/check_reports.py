"""check the reports a Wine capture run wrote (runs on the Linux side)"""
import glob, json, os, sys
out = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "launch"
fails = []
def ok(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond: fails.append(msg)
summ = json.load(open(os.path.join(out, "capture_summary.json")))
snaps = sorted(glob.glob(os.path.join(out, "snapshot_*")))
ok(len(snaps) >= 3, f"{mode}: at least 3 snapshots ({len(snaps)})")
r = json.load(open(os.path.join(snaps[0], "runtime_report.json")))
mods = {m["path"].replace("\\", "/").split("/")[-1].lower(): m for m in r["modules"]}
t = mods.get("target.exe")
ok(t is not None, f"{mode}: target.exe overlaid")
if t:
    sec = [s for s in t["sections"] if s["section"] == ".text"][0]
    ok(sec["bytes_changed"] == 16, f"{mode}: target.exe .text: exactly the 16 patched bytes changed ({sec['bytes_changed']})")
    rng = sec["changed_ranges"]
    ok(len(rng) == 1 and int(rng[0][1], 16) - int(rng[0][0], 16) == 16, f"{mode}: one 16-byte changed range {rng}")
for lib in ("liba.dll", "libb.dll"):
    m = mods.get(lib)
    ok(m is not None, f"{mode}: {lib} overlaid")
    if m:
        relocated = m["base"] != m["preferred_base"]
        sec = [s for s in m["sections"] if s["section"] == ".text"][0]
        ok(sec["bytes_changed"] == 0, f"{mode}: {lib} relocated={relocated}: 0 false changes ({sec['bytes_changed']})")
        if relocated:
            ok(sec["relocations_normalized"] > 0, f"{mode}: {lib} relocations undone ({sec['relocations_normalized']})")
ok(any(m["base"] != m["preferred_base"] for k, m in mods.items() if k.startswith("lib")),
   f"{mode}: at least one DLL was really relocated")
regs = r["executable_regions"]
jit = [e for e in regs if e.get("candidate_kind") == "private_dynamic_or_jit" and e.get("captured_size") == 8192]
ok(len(jit) >= 1, f"{mode}: the 8 KB generated-code region was saved")
tails = [e for e in regs if e.get("candidate_kind") == "game_module_exec_page_not_in_overlay"]
ok(not tails, f"{mode}: no zero-filled page tails saved as code ({len(tails)})")
diffs = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(out, "snapshot_*", "diff_from_previous.json")))]
ok(len(diffs) >= 2, f"{mode}: snapshot diffs written ({len(diffs)})")
ok(any(d["regions_changed"] for d in diffs), f"{mode}: diff saw the generated code change")
ok(any(d["regions_new"] for d in diffs) or mode == "attach", f"{mode}: diff saw a new region appear")
if jit and os.path.isfile(jit[0]["file"].replace("Z:\\", "/").replace("\\", "/")):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    from recomp.runtime_capture import disassemble_region
    f = jit[0]["file"].replace("Z:\\", "/").replace("\\", "/")
    n = disassemble_region(f, int(jit[0]["base"], 16), 64)
    lst = open(f[:-4] + ".asm.txt").read()
    ok(n and "LEA RAX" in lst.upper(), f"{mode}: region listing decodes the generated code (lea rax,[rcx+rcx])")
print(f"{len(fails)} failed")
sys.exit(1 if fails else 0)
