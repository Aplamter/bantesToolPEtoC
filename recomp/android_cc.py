#!/usr/bin/env python3
"""The compiler for rebuilt ARM64 libraries (Android lib/arm64-v8a/*.so):
find one on this machine, or install one.

    python android_cc.py            show which compiler would be used
    python android_cc.py --install  install one now if none is found

A rebuilt library needs no Android headers and no Android libraries to
build: it is compiled freestanding and linked against stand-ins for the
libraries it imports from (made here, see stub_libs). So any compiler that
makes ARM64 Linux/Android code and comes with the LLVM linker will do. In
this order:

  1. $RECOMP_ANDROID_CC          a clang you name (path or command)
  2. the Android NDK             $ANDROID_NDK_HOME, $ANDROID_NDK_ROOT,
                                 $ANDROID_HOME/ndk/<version>, Android
                                 Studio's default SDK folder, ~/.recomp/ndk
  3. clang with ld.lld on PATH   (LLVM for Windows, apt install clang lld,
                                 brew install llvm lld)
  4. zig                         `zig` on PATH or the `ziglang` Python package
                                 (zig cc is clang + lld)
  5. for Linux libraries only: aarch64-linux-gnu-gcc

If none is there, one is installed (unless RECOMP_NO_INSTALL=1): the
official Android NDK is downloaded from dl.google.com and unpacked into
~/.recomp/ndk (about 0.7 GB to download, 2-3 GB unpacked); if that is not
possible (no connection to Google, macOS), `pip install ziglang` (80 MB).
Downloading the NDK means accepting its license:
https://developer.android.com/ndk/downloads

This file is copied into every lift output (build_lift.py uses it), so it
only needs Python's standard library.
"""
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

API = 21                      # oldest Android the rebuilt library is marked for (5.0)
HOME = os.path.join(os.path.expanduser("~"), ".recomp")
# the current long-term-support NDK: (file, size, SHA-1) per system
# (from https://developer.android.com/ndk/downloads)
NDK_VERSION = "r30"
NDK_FILES = {
    "linux": ("android-ndk-r30-linux.zip", 738633529, "5107f898313790e449e87eee2183d9a20602dee9"),
    "windows": ("android-ndk-r30-windows.zip", 727980788, "9bf167a1985fa7d4a036186b78f702eab9179408"),
}
NDK_URL = "https://dl.google.com/android/repository/"
NDK_LICENSE = "https://developer.android.com/ndk/downloads"
EXE = ".exe" if os.name == "nt" else ""

TEST_C = "int recomp_probe(int a) { return a + 1; }\n"


class Toolchain:
    """cc: the command (a list) that compiles and links for the target;
    kind: ndk / clang / zig / gcc; lld: links with the LLVM linker"""

    def __init__(self, cc, kind, where, lld=True):
        self.cc, self.kind, self.where, self.lld = cc, kind, where, lld

    def __str__(self):
        return f"{self.kind}: {' '.join(self.cc)}"


def _run(argv, cwd=None, timeout=120):
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(argv, 127, "", str(e))


def _works(cc, link_extra=()):
    """can this command compile ARM64 code and link a shared library from it
    without any system library? (what a rebuilt library needs)"""
    with tempfile.TemporaryDirectory(prefix="recomp_cc_") as d:
        with open(os.path.join(d, "t.c"), "w") as f:
            f.write(TEST_C)
        r = _run(cc + ["-ffreestanding", "-fPIC", "-c", "t.c", "-o", "t.o"], cwd=d)
        if r.returncode:
            return False, (r.stderr or r.stdout).strip()[-400:]
        r = _run(cc + list(link_extra) + ["-shared", "-nostdlib", "-o", "t.so", "t.o"], cwd=d)
        if r.returncode:
            return False, (r.stderr or r.stdout).strip()[-400:]
        try:
            with open(os.path.join(d, "t.so"), "rb") as f:
                h = f.read(20)
        except OSError:
            return False, "no output file"
        if h[:4] != b"\x7fELF" or struct.unpack_from("<H", h, 18)[0] != 183:
            return False, "the output is not an ARM64 ELF file"
    return True, ""


def _target(platform):
    return f"aarch64-linux-android{API}" if platform == "android" else "aarch64-linux-gnu"


# ---- the Android NDK ---------------------------------------------------------
def ndk_roots():
    """folders that may be an NDK, newest version first"""
    out = []
    for v in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "ANDROID_NDK", "ANDROID_NDK_LATEST_HOME", "NDK_HOME", "NDK_ROOT"):
        if os.environ.get(v):
            out.append(os.environ[v])
    sdks = [os.environ.get(v) for v in ("ANDROID_HOME", "ANDROID_SDK_ROOT")]
    home = os.path.expanduser("~")
    sdks += [os.path.join(home, "Android", "Sdk"), os.path.join(home, "Library", "Android", "sdk"),
             os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk") if os.environ.get("LOCALAPPDATA") else None,
             "/opt/android-sdk", "/usr/lib/android-sdk"]
    parents = [os.path.join(s, "ndk") for s in sdks if s] + [os.path.join(HOME, "ndk")]
    for s in sdks:
        if s:
            out.append(os.path.join(s, "ndk-bundle"))

    def ver(n):
        return [int(x) if x.isdigit() else 0 for x in n.replace("-", ".").replace("r", "").split(".")]
    for p in parents:
        try:
            names = sorted(os.listdir(p), key=ver, reverse=True)
        except OSError:
            continue
        out += [os.path.join(p, n) for n in names]
    return out


def ndk_clang(root):
    pre = os.path.join(root, "toolchains", "llvm", "prebuilt")
    try:
        hosts = sorted(os.listdir(pre))
    except OSError:
        return None
    for h in hosts:
        c = os.path.join(pre, h, "bin", "clang" + EXE)
        if os.path.isfile(c):
            return c
    return None


# ---- finding -----------------------------------------------------------------
def _clang_candidates():
    names = ["clang"] + [f"clang-{v}" for v in range(30, 10, -1)]
    seen, out = set(), []
    for n in names:
        p = shutil.which(n)
        if p and os.path.realpath(p) not in seen:
            seen.add(os.path.realpath(p))
            out.append(p)
    for d in ("C:/Program Files/LLVM/bin", "C:/msys64/clang64/bin", "C:/msys64/ucrt64/bin",
              "/opt/homebrew/opt/llvm/bin", "/usr/local/opt/llvm/bin"):
        p = os.path.join(d, "clang" + EXE)
        if os.path.isfile(p) and os.path.realpath(p) not in seen:
            seen.add(os.path.realpath(p))
            out.append(p)
    return out


def _zig_commands():
    out = []
    if shutil.which("zig"):
        out.append([shutil.which("zig")])
    try:
        import ziglang  # noqa: F401
        out.append([sys.executable, "-m", "ziglang"])
    except ImportError:
        pass
    return out


def find(platform="android", log=None):
    """a working Toolchain, or None. platform: "android" or "linux" """
    why = []

    def note(what, msg):
        why.append(f"{what}: {msg}")
    tgt = _target(platform)
    env = os.environ.get("RECOMP_ANDROID_CC")
    if env:
        cc = env.split() if not os.path.isfile(env) else [env]
        for cand, kind, lld in ((cc + [f"--target={tgt}", "-fuse-ld=lld"], "clang", True), (cc, "gcc", False)):
            ok, msg = _works(cand)
            if ok:
                return Toolchain(cand, kind, env, lld)
        note(f"$RECOMP_ANDROID_CC ({env})", msg)
    for root in ndk_roots():
        c = ndk_clang(root)
        if not c:
            continue
        cc = [c, f"--target={tgt}"]
        ok, msg = _works(cc, ["-fuse-ld=lld"])
        if ok:
            return Toolchain(cc + ["-fuse-ld=lld"], "ndk", root)
        note(f"NDK in {root}", msg)
    for c in _clang_candidates():
        cc = [c, f"--target={tgt}", "-fuse-ld=lld"]
        ok, msg = _works(cc)
        if ok:
            return Toolchain(cc, "clang", c)
        note(c, msg.splitlines()[-1] if msg else "does not work")
    for z in _zig_commands():
        cc = z + ["cc", "-target", "aarch64-linux-android" if platform == "android" else "aarch64-linux-gnu"]
        ok, msg = _works(cc)
        if ok:
            return Toolchain(cc, "zig", " ".join(z))
        note(" ".join(z), msg.splitlines()[-1] if msg else "does not work")
    if platform == "linux":
        g = shutil.which("aarch64-linux-gnu-gcc")
        if g:
            ok, msg = _works([g])
            if ok:
                return Toolchain([g], "gcc", g, lld=False)
            note(g, msg)
    if log:
        for w in why:
            log(f"   (not usable: {w})")
    return None


# ---- installing --------------------------------------------------------------
def _download(url, dst, size, sha1, log):
    part = dst + ".part"
    have = os.path.getsize(part) if os.path.exists(part) else 0
    req = urllib.request.Request(url, headers={"User-Agent": "recomp", **({"Range": f"bytes={have}-"} if have else {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        if have and r.status != 206:
            have = 0
        total = size or (have + int(r.headers.get("Content-Length") or 0))
        shown = -1
        with open(part, "ab" if have else "wb") as f:
            done = have
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                f.write(b)
                done += len(b)
                pct = 100 * done // total if total else 0
                if pct >= shown + 5:
                    shown = pct
                    log(f"   downloading: {pct:3d}%  ({done >> 20} of {total >> 20} MB)")
    if size and os.path.getsize(part) != size:
        raise OSError(f"download incomplete ({os.path.getsize(part)} of {size} bytes); run it again to continue")
    if sha1:
        h = hashlib.sha1()
        with open(part, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        if h.hexdigest() != sha1:
            os.remove(part)
            raise OSError("the downloaded file is damaged (checksum mismatch)")
    os.replace(part, dst)


def install_ndk(log=print):
    """download and unpack the Android NDK into ~/.recomp/ndk; returns its folder"""
    sysname = "windows" if os.name == "nt" else "linux" if sys.platform.startswith("linux") else None
    if sysname is None or sysname not in NDK_FILES:
        raise OSError("the NDK is offered as a .zip for Windows and Linux only")
    if struct.calcsize("P") != 8:
        raise OSError("the NDK needs a 64-bit system")
    name, size, sha1 = NDK_FILES[sysname]
    dest = os.path.join(HOME, "ndk")
    os.makedirs(dest, exist_ok=True)
    free = shutil.disk_usage(dest).free
    if free < 4 << 30:
        raise OSError(f"not enough free disk space in {dest} ({free >> 30} GB; 4 GB needed)")
    log(f"   installing the Android NDK {NDK_VERSION} into {dest}")
    log(f"   (from {NDK_URL}{name}, {size >> 20} MB; by downloading it you accept its license: {NDK_LICENSE})")
    z = os.path.join(dest, name)
    if not os.path.exists(z):
        _download(NDK_URL + name, z, size, sha1, log)
    log("   unpacking ...")
    with zipfile.ZipFile(z) as zf:
        for zi in zf.infolist():
            out = zf.extract(zi, dest)
            mode = (zi.external_attr >> 16) & 0o7777
            if mode and os.name != "nt" and not os.path.islink(out):
                if (zi.external_attr >> 16) & 0o170000 == 0o120000:     # a symbolic link stored as a file
                    with open(out) as f:
                        target = f.read()
                    os.remove(out)
                    os.symlink(target, out)
                else:
                    os.chmod(out, mode)
    os.remove(z)
    root = os.path.join(dest, f"android-ndk-{NDK_VERSION}")
    if not ndk_clang(root):
        raise OSError(f"the NDK was unpacked, but there is no clang in {root}")
    return root


def install_zig(log=print):
    log("   installing the zig compiler (Python package `ziglang`, about 80 MB) ...")
    r = _run([sys.executable, "-m", "pip", "install", "--user", "ziglang"], timeout=1800)
    if r.returncode:
        r = _run([sys.executable, "-m", "pip", "install", "ziglang"], timeout=1800)
    if r.returncode:
        raise OSError("pip install ziglang failed: " + (r.stderr or r.stdout).strip()[-300:])
    import importlib
    import site
    importlib.invalidate_caches()
    up = site.getusersitepackages()
    if up not in sys.path:
        sys.path.append(up)


HELP = """no compiler for ARM64 Android libraries was found, and none could be installed.
Install one of these, then run the build again:
  * the Android NDK: https://developer.android.com/ndk/downloads - unpack it and set
    ANDROID_NDK_HOME to its folder (Android Studio: SDK Manager > SDK Tools > NDK)
  * LLVM (clang + lld): Windows https://github.com/llvm/llvm-project/releases (LLVM-...-win64.exe,
    tick "add to PATH"); Linux `apt install clang lld`; macOS `brew install llvm lld`
  * zig: `pip install ziglang`
or set RECOMP_ANDROID_CC to a clang that can make ARM64 code."""


def get(platform="android", install=True, log=print):
    """a working Toolchain; installs one if needed. Raises SystemExit with
    instructions if there is none."""
    tc = find(platform)
    if tc:
        return tc
    if install and os.environ.get("RECOMP_NO_INSTALL", "") not in ("1", "true", "yes"):
        log("   no compiler for ARM64 libraries on this machine: installing one (RECOMP_NO_INSTALL=1 turns this off)")
        errors = []
        for what, fn in (("the Android NDK", install_ndk), ("zig", install_zig)):
            try:
                fn(log)
            except (OSError, zipfile.BadZipFile, subprocess.SubprocessError, ImportError) as e:
                errors.append(f"{what}: {e}")
                log(f"   could not install {what}: {e}")
                continue
            tc = find(platform, log)
            if tc:
                log(f"   installed: {tc}")
                return tc
            errors.append(f"{what}: installed, but it does not work here")
    find(platform, log)          # says why what is there was not usable
    raise SystemExit(HELP)


# ---- what build_lift.py needs besides the compiler ------------------------------
def adapt_link(tc, argv):
    """the link command for this toolchain: the GNU linker knows no packed
    relocations; zig takes no linker script through -Wl"""
    out = []
    for a in argv:
        if a.startswith("-Wl,--pack-dyn-relocs=") or a == "-Wl,--use-android-relr-tags":
            if not tc.lld or a.endswith("=none") or tc.kind == "zig":
                continue
        if a.startswith("-Wl,-T,") and tc.kind == "zig":
            out += ["-T", a[7:]]
            continue
        out.append(a)
    return out


def stub_libs(tc, outdir, names, run):
    """stand-ins for the libraries the rebuilt library imports from: empty
    shared libraries with the right names, so the linker records them as
    needed (the real ones are on the device). run(argv, what) runs the
    compiler."""
    d = os.path.join(outdir, "stubs")
    os.makedirs(d, exist_ok=True)
    src = os.path.join(d, "stub.c")
    if not os.path.exists(src):
        with open(src, "w") as f:
            f.write("/* recomp: stand-in for a system library (only its name matters) */\n"
                    "int recomp_stub_;\n")
    for n in names:
        p = os.path.join(d, n)
        if os.path.exists(p):
            continue
        run(["-shared", "-nostdlib", "-fPIC", f"-Wl,-soname,{n}", "-o", os.path.join("stubs", n),
             os.path.join("stubs", "stub.c")], f"making the stand-in for {n}")


def undefined_symbols(path):
    """names of the undefined dynamic symbols of a built library"""
    import a64elf
    with open(path, "rb") as f:
        e = a64elf.DynElf(f.read())
    return sorted({s.name for s in e.syms if s.name and not s.defined}), e


def finish(outdir, out, post, undefined_ok, log=print):
    """after linking: check the imports, and point the library's unwind
    information at the original's (exceptions unwind through frames of the
    program, whose return addresses are those of the original code)"""
    import a64elf
    path = os.path.join(outdir, out)
    undef, e = undefined_symbols(path)
    bad = [n for n in undef if n not in set(undefined_ok) and n != "recomp_stub_"]
    if bad:
        raise SystemExit(f"build failed: {out} needs symbols that neither the original nor the runtime imports: "
                         f"{', '.join(bad[:12])}{' ...' if len(bad) > 12 else ''}\n"
                         "(the compiler called a support function; please report this with the names above)")
    eh = (post or {}).get("eh_frame_hdr")
    if eh:
        sec, dist = post["image"]
        g = a64elf.section_addr(path, sec)
        if g is None or not a64elf.patch_eh_frame_hdr(path, g - dist, eh[0], eh[1]):
            log("   WARNING: the unwind information could not be attached: C++ exceptions thrown in this "
                "library will end the program")
    return path


def main():
    install = "--install" in sys.argv[1:]
    for plat in ("android",):
        tc = find(plat, print)
        if not tc and install:
            tc = get(plat)
        print(f"== compiler for ARM64 {plat} libraries: {tc if tc else 'none found'}")
        if not tc:
            print(HELP.split("\n", 1)[1])
            sys.exit(1)


if __name__ == "__main__":
    main()
