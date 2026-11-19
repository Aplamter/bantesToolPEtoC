#!/usr/bin/env python3
"""
recomp - static recompiler: machine code -> C that does the same thing.

  recomp.py vm-decode BYTECODE --isa ISA -o IR.json decode a documented bytecode format
  recomp.py vmc     IR.json -o OUT               compile documented neutral VM IR to C
  recomp.py scan    FILE [--extract DIR] [-v]    what is this file? entropy map, encrypted
                                                 regions, packers, embedded assets
  recomp.py lift    FILE -o OUT [--runtime-capture] generate C and optionally capture live code
  recomp.py build   OUT [--trace]                compile it (--trace: per-instruction tracing)
  recomp.py verify  FILE OUT [--stdin F] [-- args]
                                                 run both, compare; on failure collect logs
                                                 and explain the crash
  recomp.py explain OUT [CRASHFILE]              annotate a crash report with assembly,
                                                 generated C lines and a diagnosis
  recomp.py unpack  FILE OUT [--extract DIR] [-- args]
                                                 run recompiled, dump memory at exit, report
                                                 what the program decrypted itself
  recomp.py dotnet  FILE -o OUT                  .NET assemblies: IL -> C# (via ilspycmd)
  recomp.py all     FILE -o OUT [-- args]        scan + lift + build + verify

Windows .exe files are built with MinGW and run under Wine when not on Windows.
64-bit programs need x86_64-w64-mingw32-gcc, 32-bit programs i686-w64-mingw32-gcc.
Runtime environment variables: RECOMP_LOG=0..4, RECOMP_LOGFILE, RECOMP_CRASHFILE.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def is_pe(path):
    with open(path, "rb") as f:
        return f.read(2) == b"MZ"


def exe_in(out):
    mk = os.path.join(os.path.abspath(out), "Makefile")
    if os.path.exists(mk):
        m = re.search(r"^OUT = (.+)$", open(mk).read(), re.M)
        if m:
            # make-safe name (see cmd_build): make splits names at spaces
            return os.path.join(os.path.abspath(out), re.sub(r"[^A-Za-z0-9_.+-]", "_", m.group(1).strip()))
    for n in ("recompiled.exe", "recompiled"):
        p = os.path.join(os.path.abspath(out), n)
        if os.path.exists(p):
            return p
    return os.path.join(os.path.abspath(out), "recompiled")


def runner(path):
    """command prefix to run an executable here"""
    if path.lower().endswith(".exe") or is_pe(path):
        if os.name == "nt":
            return [path]
        wine = shutil.which("wine") or shutil.which("wine64") or "/usr/lib/wine/wine64"
        return [wine, path]
    return [path]


def wine_env(env):
    env.setdefault("WINEDEBUG", "-all")
    env.setdefault("WINEPREFIX", os.path.join(os.path.expanduser("~"), ".recomp-wine"))
    return env


# --------------------------------------------------------------------------
def cmd_cil(a):
    from recomp.cil import compile as cilc
    import json
    os.makedirs(a.out, exist_ok=True)
    print(f"== cil: C# (IL) -> C, {len(a.files)} assemblies")
    regs, reps = [], []
    for f in a.files:
        r = cilc.translate(f, a.out, a.lib or [])
        regs.append(r["register"])
        reps.append(r)
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recomp", "cil")
    for fn in ("cil_rt.h", "cil_rt.c", "mono_api.h"):
        shutil.copyfile(os.path.join(here, fn), os.path.join(a.out, fn))
    with open(os.path.join(a.out, "cil_register.c"), "w") as fh:
        fh.write("/* registers every translated assembly with Mono (call after mono_jit_init) */\n")
        for r in regs:
            fh.write(f"void {r}(void);\n")
        fh.write("#ifdef _WIN32\n__declspec(dllexport)\n#endif\nvoid cil_register_all(void) {\n")
        for r in regs:
            fh.write(f"    {r}();\n")
        fh.write("}\n")
    with open(os.path.join(a.out, "cil_report.json"), "w") as fh:
        json.dump(reps, fh, indent=1)
    t = sum(r["translated"] for r in reps)
    n = sum(r["methods_with_il"] for r in reps)
    print(f"   {t}/{n} methods with IL are now C ({100 * t // max(n, 1)}%); "
          f"the rest stays IL (reasons: cil_report.json)")


def _runtime_options(parser, flag=True):
    if flag:
        parser.add_argument("--runtime-capture", action="store_true",
                            help="launch the original game normally and snapshot executable memory (Windows only)")
    parser.add_argument("--runtime-delay", type=float, default=10,
                        help="seconds after launch before the first snapshot (default: 10)")
    parser.add_argument("--runtime-duration", type=float, default=20,
                        help="capture window in seconds (default: 20; use 0 for one snapshot)")
    parser.add_argument("--runtime-interval", type=float, default=10,
                        help="seconds between snapshots (default: 10)")
    parser.add_argument("--runtime-max-exec-mb", type=int, default=128,
                        help="maximum executable-memory bytes per snapshot (default: 128 MB)")


def _lift_snapshots(summary, out_dir):
    from recomp.runtime_capture import lift_runtime_overlays
    lifted = {}
    for snap in summary["snapshots"]:
        snapshot_dir = snap["directory"]
        dest = os.path.join(out_dir, "runtime_lifts", os.path.basename(snapshot_dir))
        results = lift_runtime_overlays(snapshot_dir, dest, lifted_hashes=lifted)
        n_lift = sum(1 for x in results if x.get("lift_output"))
        n_asm = sum(1 for x in results if x.get("listing"))
        for x in results:
            if x.get("status") == "not_lifted":
                print(f"   not lifted: {os.path.basename(str(x.get('module')))}: {x.get('reason')}")
        if n_lift or n_asm:
            print(f"   {os.path.basename(snapshot_dir)}: {n_lift} changed module(s) lifted, "
                  f"{n_asm} code region listing(s) written")
    print(f"   memory report: {os.path.join(out_dir, 'runtime')}")


def _capture_runtime(executable, out_dir, cwd, args):
    from recomp.runtime_capture import launch_and_capture
    print("== runtime capture: launching original game normally; process will remain running")
    try:
        summary = launch_and_capture(executable, os.path.join(out_dir, "runtime"), cwd=cwd,
            delay=args.runtime_delay, duration=args.runtime_duration,
            interval=args.runtime_interval, max_exec_mb=args.runtime_max_exec_mb, log=print)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(f"runtime capture failed: {exc}")
    print(f"   PID {summary['pid']}; {len(summary['snapshots'])} snapshot(s)")
    if summary.get("note"):
        print(f"   note: {summary['note']}")
    _lift_snapshots(summary, out_dir)


def cmd_capture(a):
    from recomp.runtime_capture import attach_and_capture
    print("== capture: snapshotting a running process (read-only; it keeps running)")
    try:
        summary = attach_and_capture(os.path.join(a.out, "runtime"), pid=a.pid, name=a.name, wait=a.wait,
            root_dir=a.root, delay=a.runtime_delay, duration=a.runtime_duration,
            interval=a.runtime_interval, max_exec_mb=a.runtime_max_exec_mb, log=print)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(f"capture failed: {exc}")
    print(f"   PID {summary['pid']}; {len(summary['snapshots'])} snapshot(s)")
    _lift_snapshots(summary, a.out)


def cmd_apk(path, out, a, split_unity):
    from recomp import game as gamemod
    if getattr(a, "runtime_capture", False):
        raise SystemExit("--runtime-capture is for Windows games, not APKs")
    gamemod.analyze_apk(path, out, split_unity=split_unity, lift_native=not getattr(a, "no_native", False),
                        abi=getattr(a, "abi", None), keep=getattr(a, "keep", None) or (),
                        redo=getattr(a, "redo", None) or ())
    print(f"   build it:  cd {out} && python build_game.py   (writes the signed APK)")


def cmd_game(a):
    from recomp import game as gamemod
    if os.path.isfile(a.folder) and a.folder.lower().endswith((".apk", ".xapk", ".apks", ".apkm")):
        return cmd_apk(a.folder, a.out, a, split_unity=True)
    manifest = gamemod.analyze(a.folder, a.out, only_copy=a.copy_only, runtime_dirs=a.runtime_dlls or (),
                    add_runtime=not a.no_runtime_dlls, cil=not a.no_cil, cil_all=a.cil_all,
                    keep=a.keep or (), redo=a.redo or ())
    if a.runtime_capture:
        candidates = [e.get("path") for e in manifest.get("files", [])
                      if e.get("kind") == "native" and str(e.get("path", "")).lower().endswith(".exe")]
        if a.runtime_exe:
            rel = a.runtime_exe
            executable = rel if os.path.isabs(rel) else os.path.join(a.folder, rel)
        else:
            candidates.sort(key=lambda x: (x.count("/"), len(x)))
            if not candidates:
                raise SystemExit("game --runtime-capture: no native .exe found; specify --runtime-exe")
            executable = os.path.join(a.folder, candidates[0])
        _capture_runtime(executable, a.out, a.folder, a)


def cmd_vm_decode(a):
    from recomp import vmdecode as dec
    try:
        report = dec.decode(a.bytecode, a.isa, a.out)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        sys.exit(f"vm-decode: {e}")
    print(f"== vm-decode: decoded {report['instructions']} instructions from {report['bytes']} bytes -> {a.out}")


def cmd_vmc(a):
    from recomp import vmc as vmcmod
    try:
        report = vmcmod.compile_ir(a.input, a.out)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        sys.exit(f"vmc: {e}")
    print(f"== vmc: translated {report['instructions']} neutral VM instructions to C in {a.out}")
    print("   note: requires a documented/authorized instruction listing; not a VMProtect decoder")


def cmd_scan(a):
    from recomp import scan as scanmod
    text, _ = scanmod.report(a.file, a.extract, verbose=a.verbose)
    print(text)


def cmd_lift(a):
    from recomp import lift as liftmod
    if a.file.lower().endswith((".apk", ".xapk", ".apks", ".apkm")):
        # an APK is a set of files: a project like `game` makes, without
        # splitting Unity assets; build_game.py writes the signed APK
        if getattr(a, "build", False):
            raise SystemExit("--build: for an APK, run python build_game.py in the project")
        return cmd_apk(a.file, a.out, a, split_unity=False)
    try:
        liftmod.lift(a.file, a.out, base=getattr(a, "base", None))
        if getattr(a, "build", False):
            cmd_build(argparse.Namespace(out=a.out, jobs=getattr(a, "jobs", 0), trace=False, keep_runtime=False))
        if getattr(a, "runtime_capture", False):
            _capture_runtime(a.file, a.out, os.path.dirname(os.path.abspath(a.file)), a)
    except liftmod.NotNativeCode as e:
        print(f"== lift: {a.file}\n   not machine code: {e}")
        sys.exit(2)
    except liftmod.LiftError as e:
        print(f"== lift: {a.file}\n   cannot lift: {e}")
        sys.exit(1)


# --------------------------------------------------------------------------
# build: never start more compilers than the RAM can hold
# --------------------------------------------------------------------------
GB = 1 << 30
GCC_RAM_PER_JOB = float(os.environ.get("RECOMP_GB_PER_JOB", "1.5")) * GB  # one gcc on one code_*.c


def available_ram():
    """free RAM in bytes (Linux, Windows, macOS), or None if unknown"""
    try:
        if os.name == "nt":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("len", ctypes.c_ulong), ("load", ctypes.c_ulong),
                            ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                            ("tpage", ctypes.c_ulonglong), ("apage", ctypes.c_ulonglong),
                            ("tvirt", ctypes.c_ulonglong), ("avirt", ctypes.c_ulonglong),
                            ("ext", ctypes.c_ulonglong)]
            m = MS()
            m.len = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return m.avail
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
    except (OSError, ValueError, AttributeError):
        return None


def build_jobs(requested):
    if requested:
        return requested, "set with -j"
    cpus = os.cpu_count() or 1
    ram = available_ram()
    if ram is None:
        return max(1, min(cpus, 2)), "RAM unknown"
    jobs = max(1, min(cpus, int(ram // GCC_RAM_PER_JOB)))
    return jobs, f"{ram / GB:.1f} GB free RAM"


def find_gcc(arch):
    """a MinGW gcc for `arch` ("i686" or "x86_64") on a Windows machine whose
    PATH has no <arch>-w64-mingw32-gcc: plain gcc if it targets that CPU, else
    the usual MSYS2 / WinLibs folders"""
    cands = [shutil.which("gcc")]
    sub = ["mingw32"] if arch == "i686" else ["mingw64", "ucrt64", "clang64"]
    for root in ("C:/msys64", "C:/msys2", "C:/tools/msys64", "C:/", "C:/winlibs"):
        cands += [f"{root}/{s}/bin/gcc.exe" for s in sub]
    for g in cands:
        if not g or not os.path.isfile(g):
            continue
        try:
            m = subprocess.run([g, "-dumpmachine"], capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if m.strip().startswith(arch):
            return g.replace("\\", "/")
    return None


def make_command(module_dir=None):
    """(make command, environment) for building one lift output. The Makefile
    names its compiler (x86_64-w64-mingw32-gcc, or i686-w64-mingw32-gcc for a
    32-bit program). MSYS2/WinLibs on Windows may only have plain
    gcc/windres/dlltool, and make may be called mingw32-make."""
    mk = next((m for m in ("make", "mingw32-make") if shutil.which(m)), None)
    if not mk:
        raise SystemExit("make not found: install it (MSYS2: pacman -S make) and put it on PATH")
    cc = ""
    try:
        with open(os.path.join(module_dir or ".", "Makefile")) as f:
            for line in f:
                if line.startswith("CC = "):
                    cc = line[5:].strip()
                    break
    except OSError:
        pass
    env = dict(os.environ)
    over = []
    if cc.endswith("-w64-mingw32-gcc") and not shutil.which(cc):
        arch = cc.split("-")[0]
        gcc = find_gcc(arch) if os.name == "nt" else None
        if not gcc:
            pkg = "mingw-w64-i686-gcc" if arch == "i686" else "mingw-w64-x86_64-gcc"
            what = "a 32-bit program needs the 32-bit MinGW compiler" if arch == "i686" else \
                   "a 64-bit program needs the 64-bit MinGW compiler"
            raise SystemExit(f"{cc} not found: {what}.\n"
                             f"  Windows (MSYS2): pacman -S {pkg}   then put "
                             f"C:\\msys64\\{'mingw32' if arch == 'i686' else 'mingw64'}\\bin on PATH\n"
                             f"  Linux: apt install gcc-mingw-w64-{'i686' if arch == 'i686' else 'x86-64'}")
        bindir = os.path.dirname(gcc)
        env["PATH"] = bindir.replace("/", os.sep) + os.pathsep + env.get("PATH", "")
        over = [f"CC={gcc}"]
    if cc.endswith("-w64-mingw32-gcc"):
        # windres/dlltool: many MinGW installs (MSYS2, WinLibs) have the
        # compiler under its long name but these two only as plain
        # windres.exe / dlltool.exe. Look for each one on its own.
        prefix = cc[:-3]
        bindir = os.path.dirname((over[0][3:] if over else shutil.which(cc)) or "").replace("\\", "/")
        try:
            with open(os.path.join(module_dir or ".", "Makefile")) as f:
                text = f.read()
        except OSError:
            text = ""
        for var, tool in (("WINDRES", "windres"), ("DLLTOOL", "dlltool")):
            if shutil.which(prefix + tool) and not over:
                continue
            exe = ".exe" if os.name == "nt" else ""
            found = next((p for p in (f"{bindir}/{prefix}{tool}{exe}", f"{bindir}/{tool}{exe}")
                          if bindir and os.path.isfile(p)), None) or shutil.which(prefix + tool) or \
                (shutil.which(tool) if os.name == "nt" else None)
            if found:
                over.append(f"{var}={found.replace(chr(92), '/')}")
            elif f"$({var})" in text:
                arch = cc.split("-")[0]
                raise SystemExit(f"{prefix}{tool} not found (and no plain {tool} next to {cc}): it is part of "
                                 f"MinGW's binutils.\n"
                                 f"  Windows (MSYS2): pacman -S mingw-w64-{arch}-binutils\n"
                                 f"  Linux: apt install binutils-mingw-w64-{'i686' if arch == 'i686' else 'x86-64'}")
    return [mk] + over, env


def cmd_build(a):
    t = time.time()
    jobs, why = build_jobs(a.jobs)
    print(f"== build: {jobs} parallel compiler(s) ({why}; change with -j N)")
    if not getattr(a, "keep_runtime", False):
        from recomp.lift import refresh_runtime
        refresh_runtime(a.out)
    if os.path.isfile(os.path.join(a.out, "ANALYSIS_ONLY.txt")):
        sys.exit(f"nothing to build: {open(os.path.join(a.out, 'ANALYSIS_ONLY.txt')).read().strip()}")
    if os.path.isfile(os.path.join(a.out, "lift.json")):
        # the output's own builder (build_lift.py): no make needed
        from recomp import build_lift
        build_lift.build(a.out, jobs, getattr(a, "trace", False))
        return
    mk, env = make_command(a.out)
    cmd = mk + ["-s", f"-j{jobs}", "-C", a.out]
    if os.path.exists(os.path.join(a.out, "Makefile")):
        cmd.append(f"OUT={os.path.basename(exe_in(a.out))}")
    if getattr(a, "trace", False):
        subprocess.run(mk + ["-s", "-C", a.out, "clean"], capture_output=True, env=env)
        cmd.append("TRACE=1")
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    os.makedirs(os.path.join(a.out, "logs"), exist_ok=True)
    with open(os.path.join(a.out, "logs", "build.log"), "w") as f:
        f.write(r.stdout + r.stderr)
    if r.returncode:
        print(r.stdout[-3000:], r.stderr[-3000:])
        sys.exit(f"build failed (full log: {os.path.join(a.out, 'logs', 'build.log')})")
    print(f"   built {exe_in(a.out)} ({time.time() - t:.1f}s)")


def run(cmd, stdin_data, extra_env=None, cwd=None):
    env = dict(os.environ)
    if "wine" in os.path.basename(cmd[0]):
        env = wine_env(env)
    env.update(extra_env or {})
    t = time.time()
    try:
        r = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=600, env=env, cwd=cwd)
        return r.returncode, r.stdout, r.stderr, time.time() - t
    except subprocess.TimeoutExpired as e:
        return "timeout", e.stdout or b"", e.stderr or b"", time.time() - t


def cmd_verify(a):
    stdin_data = open(a.stdin, "rb").read() if a.stdin else b""
    logs = os.path.join(os.path.abspath(a.out), "logs")
    os.makedirs(logs, exist_ok=True)
    crash = os.path.join(logs, "crash.txt")
    for p in (crash, crash + ".2"):
        if os.path.exists(p):
            os.remove(p)
    # run both from the SAME path (one after the other), so argv[0] / the
    # module path are identical, with the original's folder as working dir
    stage = os.path.join(os.path.abspath(a.out), "stage")
    os.makedirs(stage, exist_ok=True)
    staged = os.path.join(stage, os.path.basename(a.file))
    cwd = os.path.dirname(os.path.abspath(a.file))

    rt = os.path.join(os.path.abspath(a.out), "recomp_rt.dll")
    if os.path.exists(rt):                  # Windows: the shared runtime goes next to it
        shutil.copy2(rt, os.path.join(stage, "recomp_rt.dll"))

    def staged_run(src, env):
        shutil.copy2(src, staged)
        return run(runner(staged) + a.args, stdin_data, env, cwd=cwd)

    orig = staged_run(os.path.abspath(a.file), {})
    rec = staged_run(exe_in(a.out), {"RECOMP_CRASHFILE": crash})
    same = orig[0] == rec[0] and orig[1] == rec[1]
    print(f"== verify: {a.file} {' '.join(a.args)}")
    print(f"   original:   exit={orig[0]} stdout={len(orig[1])} bytes  ({orig[3]:.2f}s)")
    print(f"   recompiled: exit={rec[0]} stdout={len(rec[1])} bytes  ({rec[3]:.2f}s)")
    if same:
        print("   MATCH - recompiled program behaves the same")
        return True
    print("   MISMATCH")
    ol, rl = orig[1].splitlines(), rec[1].splitlines()
    for i in range(max(len(ol), len(rl))):
        x = ol[i] if i < len(ol) else b"<missing>"
        y = rl[i] if i < len(rl) else b"<missing>"
        if x != y:
            print(f"   first difference at line {i + 1}:\n     original:   {x[:160]!r}\n"
                  f"     recompiled: {y[:160]!r}")
            break
    # collect a detailed log of the failing run
    runlog = os.path.join(logs, "run.log")
    staged_run(exe_in(a.out), {"RECOMP_LOG": "2", "RECOMP_LOGFILE": runlog,
                                "RECOMP_CRASHFILE": crash + ".2"})
    for nm, data in (("stdout.original", orig[1]), ("stdout.recompiled", rec[1]),
                     ("stderr.recompiled", rec[2])):
        with open(os.path.join(logs, nm), "wb") as f:
            f.write(data)
    print(f"   logs: {logs}/  (run.log = every syscall/API call, stdout.* = both outputs)")
    if os.path.exists(crash) and os.path.getsize(crash):
        print()
        explain(a.out, crash)
    elif rec[0] == "timeout":
        print("   the recompiled program hung (timeout). Run it with RECOMP_LOG=3 to see "
              "which functions it loops in")
    elif rec[2]:
        print("   recompiled stderr:", rec[2].decode(errors="replace")[-600:])
    return False


# --------------------------------------------------------------------------
def load_listing(out, wanted=None):
    """rows of listing.tsv. With `wanted` (a set of addresses), only the rows
    of the instructions that contain one of them are kept: the file is read
    line by line, so a listing of millions of instructions isn't loaded."""
    lst = {}
    p = os.path.join(out, "listing.tsv")
    if not os.path.exists(p):
        return lst
    want = sorted(wanted) if wanted is not None else None
    k = 0
    with open(p) as f:
        next(f, None)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 6:
                continue
            ad, ln = int(parts[0], 16), int(parts[1])
            if want is not None:
                # the listing is sorted by address: skip wanted addresses below
                # this row, keep the row if the next one falls inside it
                while k < len(want) and want[k] < ad:
                    k += 1
                if not (k < len(want) and want[k] < ad + ln):
                    continue
            lst[ad] = (ln, parts[2], parts[3], parts[5])
    return lst


def explain(out, crashfile=None):
    import bisect
    crashfile = crashfile or os.path.join(out, "logs", "crash.txt")
    if not os.path.exists(crashfile):
        print(f"no crash report at {crashfile}")
        return
    text = open(crashfile).read()
    lst = load_listing(out, {int(h, 16) for h in re.findall(r"0x[0-9a-f]+", text)})
    addrs = sorted(lst)

    def containing(a):
        i = bisect.bisect_right(addrs, a) - 1
        if i >= 0 and addrs[i] <= a < addrs[i] + lst[addrs[i]][0]:
            return addrs[i]
        return None

    def ann(a):
        if a in lst:
            return f"{lst[a][2]}   [{lst[a][3]}]"
        c = containing(a)
        if c is not None:
            return f"MIDDLE of instruction {c:#x} ({lst[c][2]}) +{a - c}"
        return ""

    def get(k):
        m = re.search(rf"^{k}: (.*)$", text, re.M)
        return m.group(1) if m else ""

    reason, detail, insn, addr = get("reason"), get("detail"), get("instruction"), get("address")
    print("== explain: " + crashfile)
    print(f"   WHAT:  {reason}")
    if detail:
        print(f"   WHY:   {detail}")
    m = re.match(r"(0x[0-9a-f]+)", insn)
    if m:
        ia = int(m.group(1), 16)
        print(f"   WHERE: {insn.strip()}")
        if ann(ia):
            print(f"          asm: {ann(ia)}")
        if ia in lst:
            print(f"          bytes: {lst[ia][1]}")
    if addr:
        print(f"   ADDR:  {addr}")
        m2 = re.match(r"(0x[0-9a-f]+)", addr)
        if m2 and ann(int(m2.group(1), 16)):
            print(f"          {ann(int(m2.group(1), 16))}")
    hints = []
    if "could not translate" in reason:
        hints.append("open lift_report.txt -> TRANSLATION for the reason; teach lift.py (Emitter) that op")
    if "unimplemented special CPU" in reason:
        hints.append("add the op to rt_callother() in runtime/rt_common.c, rebuild")
    if "STACK OVERFLOW" in text:
        hints.append("deep recursion: compare with the original, or raise the guest stack size")
    if "NULL pointer" in text:
        hints.append("a pointer was 0: often a syscall/API the runtime emulates returned 0; "
                     "check logs/run.log for the last calls before the crash")
    if "no recompiled code" in reason:
        hints.append("check whether the target is in listing.tsv; if it's data, the program "
                     "computes code addresses at runtime (jump table, JIT, packed code)")
    for h in hints:
        print(f"   HINT:  {h}")
    print("\n   ---- full report, every address annotated with its instruction ----")
    for line in text.splitlines():
        extra = ""
        st = line.strip()
        if st.startswith(("0x", "[rsp", "[esp")) or "->" in line:
            hs = re.findall(r"0x[0-9a-f]{5,}", line)
            notes = [ann(int(h, 16)).split("   [")[0] for h in hs[:2]]
            notes = [n for n in notes if n]
            if notes:
                extra = "    ; " + " | ".join(notes)
        print("   " + line + extra)


def cmd_explain(a):
    from recomp import lift as liftmod
    explain(a.out, a.crashfile)


# --------------------------------------------------------------------------
def dump_records(path):
    """(vaddr, bytes) records of a RECOMP_DUMP file, read one at a time"""
    import struct
    with open(path, "rb") as f:
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            v, n = struct.unpack("<QQ", hdr)
            yield v, f.read(n)


def cmd_unpack(a):
    from recomp import lift as liftmod
    from recomp import scan as scanmod
    dump = os.path.join(os.path.abspath(a.out), "memdump.bin")
    stdin_data = open(a.stdin, "rb").read() if a.stdin else b""
    run(runner(exe_in(a.out)) + a.args, stdin_data,
        {"RECOMP_DUMP": dump, "RECOMP_ARGV0": os.path.abspath(a.file)})
    if not os.path.exists(dump):
        sys.exit("program did not exit normally, no memory dump (run `verify` to see why)")
    img = liftmod.Image(a.file)
    segs = {s["vaddr"]: s for s in img.segments}
    print(f"== unpack: {a.file}")
    found = 0
    outdir = a.extract or os.path.join(a.out, "unpacked")
    os.makedirs(outdir, exist_ok=True)
    # one dumped region in memory at a time, compared with the same segment
    # of the original file
    for v, after in dump_records(dump):
        s = segs.get(v)
        if s is None:
            if len(after) >= 256:
                p = os.path.join(outdir, f"heap_{v:x}.bin")
                open(p, "wb").write(after)
                assets = scanmod.find_assets(after)
                print(f"   heap {v:#x} ({len(after)} bytes) saved; {len(assets)} assets inside")
                if assets:
                    scanmod.carve(after, assets, os.path.join(outdir, f"heap_{v:x}_assets"))
            continue
        before = img.seg_bytes(s).ljust(s["memsz"], b"\0")
        k, n = 0, min(len(after), len(before))
        while k < n:
            if before[k] == after[k]:
                k += 1
                continue
            start, gap = k, 0
            while k < n and gap < 64:
                gap = gap + 1 if before[k] == after[k] else 0
                k += 1
            end = k - gap
            if end - start < 256:
                continue
            eb, ea = scanmod.shannon(before[start:end]), scanmod.shannon(after[start:end])
            kind = "DECRYPTED/UNPACKED at runtime" if eb >= 7.0 and ea < eb - 0.4 else "modified at runtime"
            print(f"   {v + start:#x}-{v + end:#x} ({end - start} bytes): entropy {eb:.2f} -> {ea:.2f}  => {kind}")
            if kind.startswith("DECRYPTED"):
                found += 1
                blob = after[start:end]
                p = os.path.join(outdir, f"decrypted_{v + start:x}.bin")
                open(p, "wb").write(blob)
                assets = scanmod.find_assets(blob) + scanmod.text_runs(blob)
                print(f"     saved {p}")
                for x in assets:
                    print(f"     asset +{x['offset']:#x}: {x['ext']} ({x['length']} bytes)")
                if assets:
                    scanmod.carve(blob, assets, os.path.join(outdir, f"decrypted_{v + start:x}_assets"))
        del before, after
    img.close()
    if not found:
        print("   nothing high-entropy was decrypted during this run "
              "(try running it with inputs that load the assets)")
    os.remove(dump)


# --------------------------------------------------------------------------
def cmd_dotnet(a):
    f, data = liftmod.map_file(a.file)
    kind = scanmod.identify(data)
    if f:
        data.close()
        f.close()
    print(f"== dotnet: {a.file}\n   {kind['summary']}")
    if not kind.get("dotnet"):
        print("   this is not a .NET IL assembly; use `lift` instead")
        sys.exit(1)
    tool = shutil.which("ilspycmd") or os.path.expanduser("~/.dotnet/tools/ilspycmd")
    if not os.path.exists(tool):
        print("   ilspycmd is not installed. Install the .NET SDK, then:\n"
              "     dotnet tool install -g ilspycmd\n"
              "   (or open the file in ILSpy / dnSpyEx; both turn IL back into C#)")
        sys.exit(1)
    os.makedirs(a.out, exist_ok=True)
    env = dict(os.environ, DOTNET_ROLL_FORWARD="Major", DOTNET_CLI_TELEMETRY_OPTOUT="1")
    r = subprocess.run([tool, "-p", "-o", a.out, a.file], capture_output=True, text=True, env=env)
    if r.returncode:
        print(r.stdout[-2000:], r.stderr[-2000:])
        sys.exit("ilspycmd failed")
    n = sum(len([f for f in fs if f.endswith(".cs")]) for _, _, fs in os.walk(a.out))
    print(f"   wrote a C# project with {n} source files to {a.out}")


# --------------------------------------------------------------------------
def main():
    argv = sys.argv[1:]
    extra = []
    if "--" in argv:
        k = argv.index("--")
        argv, extra = argv[:k], argv[k + 1:]
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("vm-decode", help="decode bytecode using a user-supplied documented ISA map")
    s.add_argument("bytecode"); s.add_argument("--isa", required=True, help="documented ISA JSON map"); s.add_argument("-o", "--out", required=True, help="decoded neutral IR JSON")
    s = sub.add_parser("vmc", help="compile self-contained documented neutral VM IR to C")
    s.add_argument("input", help="JSON neutral VM IR"); s.add_argument("-o", "--out", required=True)
    s = sub.add_parser("scan"); s.add_argument("file"); s.add_argument("--extract"); s.add_argument("-v", "--verbose", action="store_true")
    s = sub.add_parser("lift"); s.add_argument("file"); s.add_argument("-o", "--out", required=True)
    s.add_argument("--base", type=lambda x: int(x, 0), help="move a Windows DLL/exe to this ImageBase first")
    s.add_argument("--build", action="store_true", help="compile the lift output right away (same as `build OUT`)")
    s.add_argument("--abi", help="Android APK: ABI whose native libraries are lifted (default: the first)")
    s.add_argument("--no-native", action="store_true", help="Android APK: don't lift native libraries")
    s.add_argument("-j", "--jobs", type=int, default=0, help="with --build: parallel compilers")
    _runtime_options(s)
    s = sub.add_parser("build"); s.add_argument("out"); s.add_argument("-j", "--jobs", type=int, default=0, help="parallel compilers (default: as many as free RAM allows)"); s.add_argument("--trace", action="store_true")
    s.add_argument("--keep-runtime", action="store_true", help="don't update the project's runtime sources from this recomp")
    s = sub.add_parser("refresh-runtime", help="update a lift output's or game project's runtime sources from this recomp")
    s.add_argument("project")
    s = sub.add_parser("verify"); s.add_argument("file"); s.add_argument("out"); s.add_argument("--stdin")
    s = sub.add_parser("explain"); s.add_argument("out"); s.add_argument("crashfile", nargs="?")
    s = sub.add_parser("unpack"); s.add_argument("file"); s.add_argument("out"); s.add_argument("--extract"); s.add_argument("--stdin")
    s = sub.add_parser("cil", help="C# assemblies (IL) -> C for the Mono runtime")
    s.add_argument("files", nargs="+"); s.add_argument("-o", "--out", required=True)
    s.add_argument("--lib", action="append", help="where referenced assemblies are (mscorlib, ...)")
    s = sub.add_parser("game", help="a whole game folder -> a project that builds back into it")
    s.add_argument("folder"); s.add_argument("-o", "--out", required=True)
    s.add_argument("--runtime-dlls", action="append", metavar="DIR",
                   help="where to find vcruntime140.dll/msvcp140.dll if the game doesn't ship them (default on Windows: System32)")
    s.add_argument("--no-runtime-dlls", action="store_true", help="don't add Microsoft's C++ runtime DLLs")
    s.add_argument("--no-cil", action="store_true", help="Mono games: keep the C# as IL (don't translate it to C)")
    s.add_argument("--cil-all", action="store_true", help="Mono games: translate mscorlib.dll too")
    s.add_argument("--redo", action="append", metavar="FILE",
                   help="analyze only this file again (repeatable; 'cil' = the C# -> C translation) and keep "
                        "the rest of the existing project: for trying a fix without the whole run")
    s.add_argument("--copy-only", action="store_true", help="skip recompiling (exe/dll copied unchanged); assets are still split")
    s.add_argument("--keep", action="append", metavar="FILE",
                   help="don't recompile this exe/dll (file name or path inside the game folder): it is "
                        "copied unchanged and runs as native code (repeatable)")
    s.add_argument("--runtime-exe", help="game executable to launch for runtime capture (path relative to game folder by default)")
    s.add_argument("--abi", help="Android: ABI whose native libraries are lifted for analysis (default: the first, e.g. arm64-v8a)")
    s.add_argument("--no-native", action="store_true", help="Android: don't lift native libraries (faster)")
    _runtime_options(s)
    s = sub.add_parser("capture", help="snapshot the code of a process that is already running (Windows)")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--pid", type=int, help="process ID")
    g.add_argument("--name", help="exe file name, e.g. Game.exe (the newest such process)")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--wait", type=float, default=0, help="with --name: wait up to N seconds for it to start (launchers)")
    s.add_argument("--root", help="folder whose modules are overlaid (default: the exe's folder)")
    _runtime_options(s, flag=False)
    s.set_defaults(runtime_delay=0)
    s = sub.add_parser("dotnet"); s.add_argument("file"); s.add_argument("-o", "--out", required=True)
    s = sub.add_parser("all"); s.add_argument("file"); s.add_argument("-o", "--out", required=True)
    s.add_argument("-j", "--jobs", type=int, default=0); s.add_argument("--stdin"); s.add_argument("--trace", action="store_true")
    _runtime_options(s)
    a = p.parse_args(argv)
    a.args = extra
    if a.cmd == "vm-decode":
        cmd_vm_decode(a)
    elif a.cmd == "vmc":
        cmd_vmc(a)
    elif a.cmd == "scan":
        cmd_scan(a)
    elif a.cmd == "lift":
        cmd_lift(a)
    elif a.cmd == "capture":
        cmd_capture(a)
    elif a.cmd == "refresh-runtime":
        from recomp.lift import refresh_runtime
        if not refresh_runtime(a.project):
            print("   runtime already up to date")
    elif a.cmd == "build":
        cmd_build(a)
    elif a.cmd == "verify":
        sys.exit(0 if cmd_verify(a) else 1)
    elif a.cmd == "explain":
        cmd_explain(a)
    elif a.cmd == "unpack":
        cmd_unpack(a)
    elif a.cmd == "dotnet":
        cmd_dotnet(a)
    elif a.cmd == "game":
        cmd_game(a)
    elif a.cmd == "cil":
        cmd_cil(a)
    elif a.cmd == "all":
        a.extract, a.verbose = None, False
        cmd_scan(a)
        print()
        cmd_lift(a)
        cmd_build(a)
        sys.exit(0 if cmd_verify(a) else 1)


if __name__ == "__main__":
    main()
