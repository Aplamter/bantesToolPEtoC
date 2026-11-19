#!/usr/bin/env python3
"""Build a recomp game project back into the game.

    python3 build_game.py [-o OUT] [-j N] [--only PATH]

Reads game.json, compiles every recompiled module (make in modules/*),
rebuilds the Unity asset files from assets/*, copies files/*, and writes the
original folder layout to OUT (default: build/). Then checks every data file
against the SHA-256 of the original.

Needs: make, and the compiler named in each module's Makefile
(x86_64-w64-mingw32-gcc for 64-bit Windows games, i686-w64-mingw32-gcc for
32-bit ones). Asset bundles need `pip install lz4`.
Progress bars: `pip install tqdm` (optional; without it you get plain lines).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unity_join  # noqa: E402

try:
    from tqdm import tqdm
except ImportError:          # progress bars are optional
    tqdm = None

GB = 1 << 30


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


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


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


def object_files(module_dir):
    """the .o files the module's Makefile builds (OBJS = ...)"""
    with open(os.path.join(module_dir, "Makefile")) as f:
        for line in f:
            if line.startswith("OBJS = "):
                return line[7:].split()
    return []


def objects_done(module_dir, objs):
    """how many objects are built and newer than their source"""
    n = 0
    for o in objs:
        op = os.path.join(module_dir, o)
        base = os.path.splitext(op)[0]
        src = next((base + ext for ext in (".c", ".S") if os.path.exists(base + ext)), None)
        try:
            if os.path.getmtime(op) >= (os.path.getmtime(src) if src else 0):
                n += 1
        except OSError:
            pass
    return n


class Progress:
    """tqdm bars when tqdm is installed, plain lines otherwise"""

    def __init__(self, total):
        self.total = total
        self.done = 0
        self.bar = tqdm(total=total, unit="file", desc="game", position=0,
                        bar_format="{desc:<12}{percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} files "
                                   "[{elapsed}<{remaining}]") if tqdm else None

    def say(self, msg):
        (tqdm.write if self.bar else print)(msg)

    def step(self):
        self.done += 1
        if self.bar:
            self.bar.update(1)

    def module(self, name, total):
        return ModuleProgress(self, name, total)

    def close(self):
        if self.bar:
            self.bar.close()


class ModuleProgress:
    def __init__(self, parent, name, total):
        self.parent, self.name, self.total = parent, name, max(total, 1)
        self.last, self.printed = -1, -10
        self.bar = tqdm(total=self.total, unit="obj", desc=name[:28], position=1, leave=False,
                        bar_format="  {desc:<28}{percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} C files "
                                   "{postfix} [{elapsed}<{remaining}]") if tqdm else None
        self.tty = sys.stdout.isatty()

    def update(self, n, linking=False):
        n = min(n, self.total)
        if self.bar:
            if n > self.bar.n:
                self.bar.update(n - self.bar.n)
            if linking:
                self.bar.set_postfix_str("linking")
            return
        pct = 100 * n // self.total
        if pct == self.last and not linking:
            return
        self.last = pct
        msg = f"   compiling {self.name}: {pct:3d}% ({n}/{self.total} C files)" + (", linking" if linking else "")
        if self.tty:
            print("\r" + msg, end="", flush=True)
        elif pct >= self.printed + 10 or linking:
            print(msg, flush=True)
            self.printed = pct

    def close(self):
        if self.bar:
            self.bar.close()
        elif self.tty and self.last >= 0:
            print()


def compile_lift(md, rel, jobs, prog):
    """an ARM64 library (lift.json): built by its own build_lift.py, which
    finds or installs the Android compiler. Returns (ok, output tail)."""
    with open(os.path.join(md, "lift.json"), encoding="utf-8") as f:
        objs = [c["obj"] for c in json.load(f)["compiles"]]
    mp = prog.module(os.path.basename(rel), len(objs))
    with open(os.path.join(md, "build.log"), "w") as log:
        p = subprocess.Popen([sys.executable, "build_lift.py", "-j", str(jobs)], cwd=md,
                             stdout=log, stderr=subprocess.STDOUT)
        while p.poll() is None:
            n = objects_done(md, objs)
            mp.update(n, linking=n >= len(objs))
            time.sleep(0.5)
    mp.update(objects_done(md, objs))
    mp.close()
    with open(os.path.join(md, "build.log"), errors="replace") as f:
        tail = f.read()[-4000:]
    return p.returncode == 0, tail


def compile_module(md, rel, jobs, prog):
    """runs make in md, showing how many of its C files are compiled.
    Returns (ok, output tail)."""
    if os.path.exists(os.path.join(md, "lift.json")) and not os.path.exists(os.path.join(md, "Makefile")):
        return compile_lift(md, rel, jobs, prog)
    objs = object_files(md)
    mp = prog.module(os.path.basename(rel), len(objs))
    with open(os.path.join(md, "build.log"), "w") as log:
        mk, env = make_command(md)
        p = subprocess.Popen(mk + ["-s", f"-j{jobs}", "-C", md, f"OUT={target_of(md)}"],
                             stdout=log, stderr=subprocess.STDOUT, env=env)
        while p.poll() is None:
            n = objects_done(md, objs)
            mp.update(n, linking=n >= len(objs))
            time.sleep(0.5)
    mp.update(objects_done(md, objs))
    mp.close()
    with open(os.path.join(md, "build.log"), errors="replace") as f:
        tail = f.read()[-4000:]
    return p.returncode == 0, tail


def make_safe(name):
    """a file name make can use as a target: make splits names at spaces
    ("Gorilla Tag.exe" would be the two targets "Gorilla" and "Tag.exe")"""
    return re.sub(r"[^A-Za-z0-9_.+-]", "_", name)


def target_of(module_dir):
    """the file the module's Makefile builds. Always a make-safe name: when
    the Makefile's OUT is not, compile_module overrides it with this one."""
    if not os.path.exists(os.path.join(module_dir, "Makefile")):
        with open(os.path.join(module_dir, "lift.json"), encoding="utf-8") as f:
            return json.load(f)["out"]
    with open(os.path.join(module_dir, "Makefile")) as f:
        for line in f:
            if line.startswith("OUT = "):
                return make_safe(line[6:].strip())
    raise SystemExit(f"{module_dir}/Makefile has no OUT")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("-o", "--out", default=os.path.join(here, "build"))
    ap.add_argument("-j", "--jobs", type=int, default=0, help="parallel compilers per module")
    ap.add_argument("--only", action="append", help="build only these paths (repeatable)")
    # Android projects: the rebuilt APK and its signature
    ap.add_argument("--apk-out", help="Android: where to write the rebuilt APK (default: PROJECT/<name>-rebuilt.apk)")
    ap.add_argument("--key", help="Android: sign with this RSA private key (PEM, unencrypted)")
    ap.add_argument("--cert", help="Android: ... and this certificate (PEM)")
    ap.add_argument("--ks", help="Android: sign with this keystore instead (needs apksigner)")
    ap.add_argument("--ks-pass", default="android", help="Android: keystore password (default: android)")
    ap.add_argument("--ks-alias", help="Android: key alias in the keystore")
    ap.add_argument("--no-sign", action="store_true", help="Android: write the APK unsigned")
    a = ap.parse_args()
    with open(os.path.join(here, "game.json")) as f:
        man = json.load(f)
    jobs = a.jobs
    if not jobs:
        ram = free_ram()
        jobs = max(1, min(os.cpu_count() or 1, int(ram // (1.5 * GB)) if ram else 2))
    t0 = time.time()
    todo = [e for e in man["files"] if not a.only or e["path"] in a.only]
    print(f"== build_game: {len(todo)} files -> {a.out}  ({jobs} compiler jobs)")
    prog = Progress(len(todo))
    bad = 0
    stats = {"recompiled": 0, "identical": 0, "modified": 0, "copied": 0}
    rt_done = set()
    first = True
    for e in todo:
        if not first:
            prog.step()          # the previous file is finished
        first = False
        rel = e["path"]
        dst = os.path.join(a.out, rel)
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        if "module" in e:
            md = os.path.join(here, e["module"])
            t = time.time()
            ok, tail = compile_module(md, rel, jobs, prog)
            if not ok:
                prog.say(f"   FAILED to compile {rel} (full log: {os.path.join(md, 'build.log')}):\n{tail}")
                bad += 1
                continue
            built = os.path.join(md, target_of(md))
            if not os.path.isfile(built):
                prog.say(f"   FAILED to compile {rel}: make reported success but {built} was not "
                         f"created (full log: {os.path.join(md, 'build.log')}):\n{tail}")
                bad += 1
                continue
            shutil.copy2(built, dst)
            rt = os.path.join(md, "recomp_rt.dll")
            if os.path.exists(rt):
                # the shared runtime: next to every rebuilt file (Windows
                # reuses the copy that is already loaded)
                rtdst = os.path.join(os.path.dirname(dst) or ".", "recomp_rt.dll")
                if rtdst not in rt_done:
                    shutil.copy2(rt, rtdst)
                    rt_done.add(rtdst)
            prog.say(f"   recompiled  {rel}  ({time.time() - t:.0f}s)")
            stats["recompiled"] += 1
            continue
        if "cil" in e:
            # C# translated to C: the assembly is patched to call recomp_cil.dll
            shutil.copy2(os.path.join(here, e["cil"]), dst)
            prog.say(f"   C# -> C     {rel}  ({e.get('cil_methods', '?')} methods)")
            stats["recompiled"] += 1
            continue
        if "assets" in e:
            how = unity_join.join(os.path.join(here, e["assets"]), dst)
        else:
            shutil.copy2(os.path.join(here, "files", rel), dst)
            how = "copied"
        same = sha256(dst) == e["sha256"]
        if how == "modified" or not same:
            prog.say(f"   {'modified' if how == 'modified' else 'DIFFERENT'}  {rel}"
                  f"{'' if how == 'modified' else '  (unexpected: it should be identical)'}")
            stats["modified"] += 1
            if how != "modified":
                bad += 1
        else:
            stats["identical" if "assets" in e else "copied"] += 1
    if todo:
        prog.step()
    prog.close()
    print(f"   {stats['recompiled']} recompiled, {stats['identical']} rebuilt from assets "
          f"(identical), {stats['copied']} copied (identical), {stats['modified']} modified")
    if man.get("container", {}).get("type") == "apk" and not a.only:
        if bad:
            print("   the APK is not written: fix the problems above first")
        else:
            bad += build_apk(here, man, a)
    print(f"   done in {time.time() - t0:.0f}s" + (f", {bad} PROBLEM(S)" if bad else ""))
    sys.exit(1 if bad else 0)


def build_apk(here, man, a):
    """pack the rebuilt files into an APK (original order, compression,
    alignment) and sign it; returns the number of problems"""
    import apk_sign
    c = man["container"]
    out = os.path.abspath(a.apk_out or os.path.join(here, os.path.splitext(c["name"])[0] + "-rebuilt.apk"))
    unsigned = out + ".unsigned"
    n = apk_sign.pack(os.path.abspath(a.out), c["entries"], unsigned)
    print(f"== APK: {n} entries packed")
    if a.no_sign:
        os.replace(unsigned, out)
        print(f"   written UNSIGNED: {out} (Android installs only signed APKs: sign it before installing)")
        return 0
    min_sdk = (c.get("apk", {}).get("manifest") or {}).get("minSdk")
    try:
        if a.ks:
            apk_sign.sign_with_apksigner(unsigned, out, a.ks, a.ks_pass, a.ks_alias)
            who = f"keystore {a.ks}"
        elif a.key or a.cert:
            if not (a.key and a.cert):
                raise SystemExit("--key and --cert go together")
            apk_sign.sign(unsigned, out, a.key, a.cert, min_sdk)
            who = f"key {a.key}"
        else:
            try:
                k, crt = apk_sign.ensure_key(os.path.join(here, "signing"))
                apk_sign.sign(unsigned, out, k, crt, min_sdk)
                who = "the project's key (signing/)"
            except RuntimeError:
                if not (shutil.which("apksigner") and shutil.which("keytool")):
                    raise SystemExit("signing needs `pip install cryptography` (or apksigner + keytool on PATH); "
                                     "or use --no-sign")
                ks = apk_sign.keytool_keystore(os.path.join(here, "signing"))
                apk_sign.sign_with_apksigner(unsigned, out, ks, "recomp", "rebuild")
                who = "the project's keystore (signing/rebuild.jks)"
    finally:
        if os.path.exists(unsigned):
            os.remove(unsigned)
    ok, how = apk_sign.check(out)
    print(f"   signed with {who}: {out}")
    print(f"   check: {how}")
    print("   install: remove the original app first (different signature), then: adb install " +
          os.path.basename(out))
    return 0 if ok else 1


if __name__ == "__main__":
    main()
