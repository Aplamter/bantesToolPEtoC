#!/usr/bin/env python3
"""Compile a recomp lift output into the rebuilt program - no make needed.

    python build_lift.py [-j N] [--trace] [--clean]

Reads lift.json (written by `recomp.py lift`): compiles every C file to an
object file, several at a time; assembles the .S files; on Windows outputs
builds the shared runtime recomp_rt.dll; links. Only what is out of date is
rebuilt (an object older than its source or than any header). The commands
are exactly the ones in the Makefile next to it.

Needs only the compiler named in lift.json on PATH: gcc for Linux outputs,
x86_64-w64-mingw32-gcc / i686-w64-mingw32-gcc for Windows outputs (on
Windows a plain MinGW gcc for the same CPU is found too).

ARM64 libraries (Android lib/arm64-v8a/*.so): the compiler is found by
android_cc.py - the Android NDK, any clang with lld, or zig - and installed
if there is none (see android_cc.py; --no-install turns that off).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

GB = 1 << 30
GB_PER_JOB = float(os.environ.get("RECOMP_GB_PER_JOB", "1.5"))   # one gcc on one code_*.c


def free_ram():
    try:
        if os.name == "nt":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("len", ctypes.c_ulong), ("load", ctypes.c_ulong),
                            ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                            ("x", ctypes.c_ulonglong * 5)]
            m = MS()
            m.len = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return m.avail
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return None


def find_cc(cc):
    """the compiler to run: `cc` itself if it is on PATH; for a MinGW cross
    compiler name on a machine without it, a gcc that targets the same CPU"""
    if shutil.which(cc):
        return cc
    arch = "i686" if cc.startswith("i686") else "x86_64" if cc.startswith("x86_64") else None
    if arch is None:
        return None
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
        if m.startswith(arch) and "mingw" in m:
            return g
    return None


def mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return -1.0


def android_tools():
    """android_cc.py: next to this script (in a lift output and in recomp itself)"""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import android_cc
    return android_cc


def build(outdir, jobs=0, trace=False, log=print, install=True):
    """returns the path of the built program; raises SystemExit on failure"""
    with open(os.path.join(outdir, "lift.json"), encoding="utf-8") as f:
        m = json.load(f)
    acc = tc = None
    if str(m["cc"]).startswith("a64:"):
        # an ARM64 library: built by a cross compiler that android_cc finds or installs
        acc = android_tools()
        tc = acc.get(m["cc"][4:], install=install, log=log)
        log(f"   compiler: {tc}")
        cc_argv, cc = tc.cc, tc.cc[0]
    else:
        cc = find_cc(m["cc"])
        if not cc:
            raise SystemExit(f"compiler not found: {m['cc']} (install it and put it on PATH)")
        cc_argv = [cc]
    if os.path.dirname(cc):          # its helper programs (as, ld) sit next to it
        os.environ["PATH"] = os.path.dirname(cc) + os.pathsep + os.environ.get("PATH", "")
    if not jobs:
        ram = free_ram()
        jobs = max(1, min(os.cpu_count() or 1, int(ram // (GB_PER_JOB * GB)) if ram else 2))
    P = lambda n: os.path.join(outdir, n)
    os.makedirs(P("logs"), exist_ok=True)
    logf = open(P(os.path.join("logs", "build.log")), "w", encoding="utf-8")
    # a trace build and a normal build must not share objects
    stamp = P(".trace_build")
    was_trace = os.path.exists(stamp)
    if was_trace != bool(trace):
        for c in m["compiles"]:
            if c["flags"] and os.path.exists(P(c["obj"])):
                os.remove(P(c["obj"]))
        if trace:
            open(stamp, "w").close()
        elif was_trace:
            os.remove(stamp)
    headers = max([mtime(P(n)) for n in os.listdir(outdir) if n.endswith(".h")] + [-1.0])

    def run(argv, what):
        r = subprocess.run(cc_argv + argv, cwd=outdir, capture_output=True, text=True)
        logf.write(f"$ {' '.join(cc_argv) if tc else m['cc']} {' '.join(argv)}\n{r.stdout}{r.stderr}")
        if r.returncode:
            logf.flush()
            tail = (r.stdout + r.stderr)[-3000:]
            raise SystemExit(f"build failed: {what}\n{tail}\n(full log: {P(os.path.join('logs', 'build.log'))})")

    todo = []
    for c in m["compiles"]:
        dep = max(mtime(P(c["src"])), headers if c["flags"] else -1.0)
        if c["src"] == "tables.c":
            dep = max([dep, mtime(P("image.bin"))] +
                      [mtime(P(n)) for n in os.listdir(outdir) if n.startswith("map_") and n.endswith(".bin")])
        if c["src"] == "rsrc.S":
            dep = max(dep, mtime(P("rsrc.bin")))
        if mtime(P(c["obj"])) < dep or mtime(P(c["obj"])) < 0:
            todo.append(c)
    t0 = time.time()
    done = [0]

    def compile_one(c):
        flags = c["flags"] + (m.get("trace_flags", []) if trace and c["flags"] else [])
        run(flags + ["-c", c["src"], "-o", c["obj"]], f"compiling {c['src']}")
        done[0] += 1
        log(f"   compiled {done[0]}/{len(todo)}  {c['src']}")

    if todo:
        log(f"   {len(todo)} of {len(m['compiles'])} files to compile, {jobs} at a time")
        # the big code files first, so the long ones start early
        todo.sort(key=lambda c: -os.path.getsize(P(c["src"])))
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            for _ in ex.map(compile_one, todo):
                pass
    rt = m.get("runtime")
    if rt and mtime(P(rt["out"])) < max(mtime(P(d)) for d in rt["deps"]):
        run(rt["argv"], f"building {rt['out']}")
        log(f"   built the shared runtime {rt['out']}")
    link = m["link"]
    out = P(m["out"])
    newest = max([mtime(P(o)) for o in link["objs"]] + [mtime(P(d)) for d in link.get("deps", [])])
    if mtime(out) < newest:
        prefix = link["prefix"]
        if tc:
            acc.stub_libs(tc, outdir, m.get("stubs", []), run)
            prefix = acc.adapt_link(tc, prefix)
        run(prefix + link["objs"] + link["suffix"], f"linking {m['out']}")
        if tc:
            acc.finish(outdir, m["out"], m.get("post"), m.get("undefined_ok", []), log)
    logf.close()
    log(f"   built {out} ({time.time() - t0:.1f}s)")
    return out


def clean(outdir, log=print):
    with open(os.path.join(outdir, "lift.json"), encoding="utf-8") as f:
        m = json.load(f)
    names = [c["obj"] for c in m["compiles"]] + m.get("clean", []) + [".trace_build"] + \
        [os.path.join("stubs", s) for s in m.get("stubs", [])]
    n = 0
    for name in names:
        p = os.path.join(outdir, name)
        if os.path.exists(p):
            os.remove(p)
            n += 1
    log(f"   removed {n} built files")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dir", nargs="?", default=here, help="lift output folder (default: where this script is)")
    ap.add_argument("-j", "--jobs", type=int, default=0, help="compilers at a time (default: as many as free RAM allows)")
    ap.add_argument("--trace", action="store_true", help="build with the per-instruction trace hook")
    ap.add_argument("--clean", action="store_true", help="delete the built files")
    ap.add_argument("--no-install", action="store_true",
                    help="ARM64 libraries: stop if no compiler is found instead of installing one")
    a = ap.parse_args()
    if not os.path.isfile(os.path.join(a.dir, "lift.json")):
        sys.exit(f"no lift.json in {a.dir}: this is not a lift output (or it was lifted by an older recomp; lift it again)")
    print(f"== build_lift: {a.dir}")
    if a.clean:
        clean(a.dir)
    else:
        build(a.dir, a.jobs, a.trace, install=not a.no_install)


if __name__ == "__main__":
    main()
