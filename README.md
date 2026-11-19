# recomp: binary analysis and runtime-assisted reconstruction

`recomp` statically analyzes Windows PE and Linux ELF programs, translates supported machine instructions to C, and provides build/verification tools. Generated code is intentionally low-level. Complete behavioral equivalence is not guaranteed for every executable.

## Install

```sh
pip install pypcode lief
# Optional Unity asset support:
pip install UnityPy lz4
```

Windows builds require the matching MinGW compiler (64-bit: `x86_64-w64-mingw32-gcc`; 32-bit: `i686-w64-mingw32-gcc`). Mono/CIL translation uses the bundled translator.

## Commands

| Command | Purpose |
|---|---|
| `scan FILE [--extract DIR]` | Identify format, inspect sections/entropy, and triage embedded data. |
| `lift FILE -o OUT` | Lift supported native instructions to C and emit listings/reports. |
| `lift FILE -o OUT --build [-j N]` | Lift, then compile the output right away. |
| `lift FILE -o OUT --runtime-capture` | Also launch the original executable normally and snapshot accessible executable memory on Windows. |
| `game FOLDER -o PROJECT` | Analyze a whole game folder, native modules, managed assemblies, and assets. |
| `game FOLDER -o PROJECT --runtime-capture --runtime-exe Game.exe` | Also capture runtime code from the selected game executable and loaded modules in the game folder. |
| `capture (--pid N \| --name Game.exe [--wait S]) -o OUT` | Snapshot a process that is already running (started by you, a launcher or Steam). |
| `build OUT` | Compile a lift output. Updates the project's runtime sources from this recomp first (`--keep-runtime` to skip). |
| `refresh-runtime PROJECT` | Update the runtime sources in a lift output or a whole game project (run before `build_game.py` after updating recomp). |
| `verify FILE OUT` | Compare original and rebuilt program behavior for the supplied run. |
| `unpack FILE OUT` | Inspect memory of the recompiled program at exit; this is separate from original-process runtime capture. |
| `vm-decode BYTECODE --isa ISA -o IR.json` | Decode a user-supplied documented bytecode format. |
| `vmc IR.json -o OUT` | Compile self-contained documented VM IR to C. |
| `dotnet FILE -o OUT` | Decompile .NET assemblies to C# using ILSpy if installed. |

## Runtime capture on Windows

Runtime capture is opt-in because the game must actually run and may need user input to reach the code paths of interest. It starts the original executable normally, waits for the configured delay, and takes read-only snapshots while leaving the game process running. It does not inject code, alter memory protections, bypass anti-tamper checks, or change the target process.

Example for a whole game:

```powershell
python recomp.py game "C:\Games\MyGame" -o out\MyGame `
  --runtime-capture --runtime-exe MyGame.exe `
  --runtime-delay 15 --runtime-duration 60 --runtime-interval 10
```

For one executable:

```powershell
python recomp.py lift "C:\Games\MyGame\MyGame.exe" -o out\lift `
  --runtime-capture --runtime-delay 15 --runtime-duration 30
```

The process is intentionally left running after capture so you can continue testing it; close it yourself when finished. Reports and snapshots are written under `runtime/`. Loaded PE modules inside the selected game folder are copied with their live executable sections overlaid onto their on-disk image. Changed overlays are sent through the normal lifter and results go under `runtime_lifts/`. Executable private pages (often used by JIT engines), and executable pages of game modules that no overlay covers, are saved as bounded raw `.bin` regions with base addresses and hashes.

How overlays are compared:

- **Relocations are undone first.** Windows usually loads a module at a different address than its file asks for (ASLR) and patches every absolute address in it. Live bytes are normalised back to the file's preferred ImageBase before they are compared or written. Without this step every relocated module looks modified, and the overlay would hold pointers for the wrong base, because the lifter maps the image at the ImageBase in its header.
- **Import-address-table slots inside executable sections are ignored**, because the loader always fills them in.
- **Unreadable pages don't discard a section.** Reads fall back to page-by-page; unreadable pages keep their disk bytes and the section is reported as `partial`.
- Each section reports `changed_ranges` (RVAs), `relocations_normalized` and `iat_bytes_masked`.
- Raw regions identical to an earlier snapshot are referenced instead of saved again, and an overlay identical to one already lifted is not lifted again.
- If the executable you launched exits (for example a launcher that starts the real game), the snapshots taken so far are kept, and `capture_summary.json` says so.
- Hitting `--runtime-max-exec-mb` is recorded as `executable_capture_truncated`.

Generated code (JIT) in the *rebuilt* program does not need to be converted to C: when recompiled code jumps to executable memory outside every lifted image, the Windows runtime (`rt_platform_unknown_target` in `runtime/rt_win.c`) calls it as native code, and calls from that code back into the program are dispatched to the recompiled chunks again (see `tests/wingame/veh_jit.c`). The raw `private_exec` dumps are evidence for analysis, not inputs the rebuild depends on.

### What runtime capture can and cannot do

- Executable sections with no bytes in the file (for example a section that is only filled at run time) can't be overlaid onto the file; their live pages are saved as raw `MEM_IMAGE` regions with `module` and `module_rva` instead.
- It can record executable pages that Windows allows the current user to read, compare executable PE sections against their disk bytes, and lift changed sections when the resulting PE remains parseable.
- A difference is only a candidate runtime modification; relocations, hotpatches, instrumentation, and self-modifying code can also cause differences.
- Private/JIT executable regions are preserved as raw dumps and reported. They are **not automatically converted to C** because the tool may not know their architecture, function boundaries, calling convention, or lifetime.
- A runtime snapshot is not a complete process image. Imports, relocations, TLS, runtime-created state, managed runtime services, and external dependencies still matter.
- Virtualized instructions that remain interpreted by a VM are not necessarily present as ordinary native code. This tool does not recover private VM instruction sets or defeat DRM/anti-cheat protections.
- Runtime capture requires 64-bit Python for 64-bit games (a 32-bit Python stops with a clear error) and matching process access rights. It has been tested on a real Windows game (Granny, IL2CPP) and, with `tests/wine_capture`, against the Windows APIs under Wine.

### Attaching to a running game

If the game is started by a launcher (the exe you launch exits and starts another), or you want to reach a menu or level first, capture it while it runs:

```powershell
python recomp.py capture --name Granny.exe -o out\GrannyRun --runtime-duration 60 --runtime-interval 10
python recomp.py capture --name Game.exe --wait 120 -o out\run   # waits up to 2 minutes for it to start
python recomp.py capture --pid 12345 -o out\run --root "C:\Games\MyGame"
```

Every snapshot after the first has `diff_from_previous.json`: executable regions that appeared, disappeared or changed, and module sections whose live bytes changed. The console shows the same summary as it goes. With pypcode installed, every saved code region also gets a disassembly listing (`region_<address>.asm.txt`) next to its `.bin`.

## Compiling a lift output

Every lift output contains `build_lift.py` and `lift.json`. The script compiles the output with only the compiler, with no `make` needed:

```sh
python build_lift.py            # in the output folder; or: python recomp.py build OUT
python build_lift.py -j 4       # 4 compilers at a time (default: as many as free RAM allows)
python build_lift.py --clean    # delete the built files
```

It compiles several C files at a time, only rebuilds what is out of date, and writes `logs/build.log`. The commands are the same as in the `Makefile` that is still written next to it: the object files are byte-identical, and a Windows `.exe`/`.dll` differs only in the link timestamp and header checksum.

## Size of the generated C

| setting (when lifting) | effect |
|---|---|
| `RECOMP_DEAD_FLAGS=0` | keep every status-flag update (default: flag writes that are overwritten before anything reads them are left out) |
| `RECOMP_FLAGS_ABI=0` | treat a call like any other exit when deciding which flags are still needed (default: the six status flags are dead at a call, as in every x86 calling convention) |
| `RECOMP_COMPACT=0` | long spelling of the C (default: short macros that expand to exactly the same code) |
| `RECOMP_FILE_LINES=50000` | lines per `code_*.c` file (default 120000: fewer, bigger files; about 850 MB of RAM per compiler) |
| `RECOMP_FAULT_ADDR=0` | don't record each instruction's address (64-bit; a little smaller and faster, but a crash can't reach the program's `__except`) |

## Diagnostics: exact locations of every problem

Every lift writes `diagnostics.jsonl`, with one JSON object per problem, and a `PROBLEMS` section at the end of `lift_report.txt`. Each record has `va`, `rva`, `file_offset`, `section`, the containing `function`, the raw `bytes`, and the decoder's own error text. There are four kinds:

- `undecodable_on_code_path` (error): a known function start, or a jump/call target, can't be decoded. This crashes if it runs. `reached_by` says which jump or call leads there.
- `undecodable_at_data_pointer` (warning): only a data pointer leads there. It's usually a table or marker inside the code section (MinGW's constructor list, for example).
- `untranslatable` (error): decoded, but one of its P-code operations can't be expressed in C. The record has the instruction text and bytes.
- `undecodable_range` (info/warning): bytes only the linear sweep visited, with a `guess` (int3/zero/nop padding, string data, table data).

## CPU features the recompiled program sees

The runtime answers the program's CPUID and XGETBV. `RECOMP_CPUID` decides what it reports:

| value | the program is told |
|---|---|
| `baseline` (default) | SSE2 only. Programs that pick code paths at run time take the oldest, most-tested ones. |
| `verified` | Additionally SSE3, SSSE3, SSE4.1, SSE4.2, POPCNT, LZCNT, BMI1, BMI2, ADX, MOVBE, AES-NI, PCLMULQDQ, SHA, AVX, AVX2, FMA and F16C, if this CPU has them. These are the families `tests/isa.c` checks. AVX-512 is never reported: Ghidra's model of it drops the mask registers. |
| `host` | Everything this CPU reports. Use it only for testing. |

Code that uses these instructions without checking CPUID first is translated in any mode.

## Whole-game output

`game` preserves the original folder layout, lifts supported native EXE/DLL modules, translates supported managed IL where possible, and processes Unity assets when optional dependencies are installed. The project contains `game.json`, module outputs, copied files, assets, and `build_game.py`.

## Android games (.apk)

`game` and `lift` accept an `.apk` directly:

```sh
python recomp.py scan  mygame.apk                 # package, ABIs, engine, signing schemes
python recomp.py game  mygame.apk -o mygame_src   # Unity games (IL2CPP or Mono)
python recomp.py lift  mygame.apk -o mygame_src   # any other app (native code)
cd mygame_src && python build_game.py             # writes mygame-rebuilt.apk, signed
```

What the project contains:

- Unity (`assets/bin/Data`): the asset files are split into objects exactly like a PC Unity game, so the same edits work. IL2CPP data (`libil2cpp.so`, `global-metadata.dat`) is found in the APK layout.
- Native libraries (`lib/<abi>/*.so`): `arm64-v8a` libraries are **recompiled**: lifted from Ghidra P-code to C, compiled back to ARM64, and the rebuilt `.so` replaces the original in the APK (each is a module in `modules/`). Other ABIs are kept unchanged; choose the ABI with `--abi`, skip native code with `--no-native`, leave one library as it is with `--keep libfoo.so`. A library recomp can't rebuild (text relocations, imported TLS variables, exported ifuncs) is lifted for analysis only and kept unchanged; its `lift_report.txt` says why.

### The ARM64 compiler (installed for you)

`build_game.py` / `build_lift.py` need a compiler that makes ARM64 code. It is found or installed by `recomp/android_cc.py`, in this order: `$RECOMP_ANDROID_CC`, the Android NDK (`$ANDROID_NDK_HOME`, Android Studio's SDK folder, `~/.recomp/ndk`), any `clang` + `ld.lld` on PATH, `zig` (or the `ziglang` pip package). If none is there it **downloads the official Android NDK r30** from dl.google.com into `~/.recomp/ndk` (about 0.7 GB, checksum-verified; downloading it means accepting the NDK license), and if that isn't possible (macOS, no connection to Google) it runs `pip install ziglang`. `RECOMP_NO_INSTALL=1` or `--no-install` turns installing off. `python recomp/android_cc.py` shows which compiler would be used.

How the rebuilt library works: the original image is kept inside it as data, relocated by the system loader like the original. Integer, memory and branch instructions become C; floating-point/NEON, atomics and pointer authentication are re-emitted as the same instruction (exact by construction). Function entries and call return sites in the image jump into the runtime, so native code (JNI, callbacks, C++ exceptions, `longjmp`, signal handlers, threads) can enter and leave recompiled code freely, and the original unwind tables still work. Set `RECOMP_LOG=1` (or `2`) to see what the runtime does in `logcat`/stderr; a crash prints the address in the *original* library and the last calls.
- Everything else (dex, resources, manifest) is copied unchanged.

`build_game.py` writes the APK with the original entry order and compression, aligned the way `zipalign -p` does (4 bytes; 16 KiB for uncompressed `.so`), and signs it with v1 (JAR) and v2 signatures. The original signature cannot be kept (nobody but the developer has that key), so:

| Option | Signs with |
|---|---|
| (default) | A key made for the project on the first build, in `signing/`. It is reused, so rebuilds install as updates of each other. |
| `--key k.pem --cert c.pem` | Your own key and certificate. |
| `--ks my.jks --ks-pass PASS [--ks-alias A]` | Your keystore, through `apksigner`. |
| `--no-sign` | Nothing. |

`--apk-out PATH` changes where the APK goes. For apps that support Android 4.2 and older (minSdk < 18) the v1 signature uses SHA-1, as Android requires. Because the key differs from the store version, uninstall the original before installing the rebuilt APK.

Split packages (`.xapk`, `.apks`, `.apkm`) are not unpacked: extract the base APK from them and use that.

## Verification

Run the portable tests with:

```sh
python -m unittest discover -s tests -p 'test_*.py'
```

End-to-end native round-trip tests are in `tests/run_tests.sh`. `TARGETS="musl win win32"` adds Windows 64- and 32-bit round trips under Wine, and `tests/isa.c` checks every instruction family listed above. Whole-game, exception and C# suites are `tests/run_game_test.sh`, `tests/run_game32_test.sh`, `tests/run_exceptions_test.sh`, `tests/run_mono_game_test.sh` and `tests/cil/`.

`tests/a64/run_a64_tests.sh` builds an ARM64 test library twice (gcc, and clang with pointer authentication + BTI), recompiles it, and checks under qemu that integer, float, NEON, callbacks, varargs, setjmp, threads/TLS/atomics, signals, C++ and C++ exceptions all print exactly what the original prints.

The Android suite, `tests/android/run_android_tests.sh`, builds real APKs with `aapt2`, `zipalign` and `apksigner` (a native app, an IL2CPP and a Mono Unity game, an old minSdk-14 app), turns them into projects, rebuilds them and checks the result with `apksigner verify`, `zipalign -c`, `aapt dump badging` and an entry-by-entry comparison, plus a modded Unity asset and every signing option.

The live runtime-capture test runs a Windows Python under Wine against a test program that relocates DLLs, patches its own code and generates code:

```sh
WINPY=/path/to/windows/python.exe sh tests/wine_capture/run_wine_capture_test.sh
```

(A Windows Python can be taken from the `python` package on nuget.org: unzip it and use `tools/python.exe`. Run Wine Python with its output going to a pipe.)

## Scope and limitations

This project is intended for software you own or are authorized to analyze. It does not include the previous experimental bridge/hybrid subsystem or the experimental ML learner. OS/runtime imports and ordinary DLL dependencies are still required for a reconstructed executable to run; removing an optional bridge generator does not remove those underlying dependencies.
