"""Builds the APKs the Android tests use, the way real apps are built:
aapt2 compiles + links resources and the binary AndroidManifest.xml, real
ARM64 / x86-64 shared libraries go into lib/<abi>/ (stored, page aligned:
extractNativeLibs=false), zipalign aligns, apksigner signs (v1 + v2 + v3).

    python3 make_test_apks.py OUTDIR
    -> OUTDIR/native.apk   NativeActivity app, no Java code
    -> OUTDIR/unity.apk    Unity-style game: libunity/libil2cpp/libmain + assets/bin/Data
Needs: aapt2, zipalign, apksigner, keytool (JRE), android.jar (android-sdk-platform-*),
aarch64-linux-gnu-gcc, gcc, python3 with lz4."""
import glob
import os
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ANDROID_JAR = (sorted(glob.glob("/usr/lib/android-sdk/platforms/*/android.jar")) or [""])[-1]


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kw)


def manifest(pkg, activity, label, extra_app="", min_sdk=23):
    return f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg}">
  <uses-sdk android:minSdkVersion="{min_sdk}" android:targetSdkVersion="33"/>
  <application android:label="@string/app_name" android:hasCode="false" android:extractNativeLibs="false"{extra_app}>
    <activity android:name="{activity}" android:exported="true">
      <meta-data android:name="android.app.lib_name" android:value="main"/>
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
'''


def build(out, name, pkg, activity, label, libs, assets, keystore, min_sdk=23):
    w = os.path.join(out, f"_{name}")
    shutil.rmtree(w, ignore_errors=True)
    os.makedirs(os.path.join(w, "res", "values"))
    with open(os.path.join(w, "res", "values", "strings.xml"), "w") as f:
        f.write(f'<resources><string name="app_name">{label}</string></resources>\n')
    with open(os.path.join(w, "AndroidManifest.xml"), "w") as f:
        f.write(manifest(pkg, activity, label, min_sdk=min_sdk))
    run("aapt2", "compile", "--dir", os.path.join(w, "res"), "-o", os.path.join(w, "res.zip"))
    base = os.path.join(w, "base.apk")
    run("aapt2", "link", "-o", base, "-I", ANDROID_JAR, "--manifest", os.path.join(w, "AndroidManifest.xml"),
        "--version-code", "3", "--version-name", "1.2", os.path.join(w, "res.zip"))
    with zipfile.ZipFile(base, "a") as z:
        for arc, data, stored in libs + assets:
            zi = zipfile.ZipInfo(arc, date_time=(2024, 5, 1, 12, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
    aligned = os.path.join(w, "aligned.apk")
    run("zipalign", "-f", "-p", "4", base, aligned)
    final = os.path.join(out, f"{name}.apk")
    run("apksigner", "sign", "--ks", keystore, "--ks-pass", "pass:testpass", "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true", "--v3-signing-enabled", "true", "--out", final, aligned)
    shutil.rmtree(w, ignore_errors=True)
    return final


def main():
    out = os.path.abspath(sys.argv[1])
    os.makedirs(out, exist_ok=True)
    ks = os.path.join(out, "test.jks")
    if not os.path.exists(ks):
        run("keytool", "-genkeypair", "-keystore", ks, "-storepass", "testpass", "-keypass", "testpass",
            "-alias", "test", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-dname", "CN=recomp test, O=recomp, C=PL")
    so = {}
    for abi, cc in (("arm64-v8a", "aarch64-linux-gnu-gcc"), ("x86_64", "gcc")):
        p = os.path.join(out, f"libmain_{abi}.so")
        run(cc, "-O2", "-shared", "-fPIC", "-o", p, os.path.join(HERE, "game.c"))
        so[abi] = open(p, "rb").read()
        os.remove(p)
    # native app: one library per ABI, an asset, stored libraries (extractNativeLibs=false)
    native_libs = [(f"lib/{abi}/libmain.so", so[abi], True) for abi in so]
    import random
    rnd = random.Random(7)
    native_assets = [("assets/config.txt", b"difficulty=hard\nmusic=on\n" * 20, False),
                     ("assets/levels/level1.dat", bytes(range(256)) * 40, False),
                     # a JAR manifest line is at most 72 bytes: this name must be wrapped
                     ("assets/" + "a_very_long_folder_name_for_testing/" * 3 + "and_a_long_file_name_too.json",
                      b'{"ok": true}', False),
                     ("assets/m\u00fasica/canci\u00f3n_\u00fc\u00f1.txt".encode().decode("unicode_escape"),
                      "na\u00efve caf\u00e9".encode(), False),
                     # bigger than the 1 MiB chunks of the v2 digest, stored and compressed
                     ("assets/big_stored.bin", bytes(rnd.getrandbits(8) for _ in range(3 << 20)), True),
                     ("assets/big_text.txt", b"lorem ipsum dolor sit amet " * 120000, False)]
    build(out, "native", "com.recomp.nativetest", "android.app.NativeActivity", "Native Test",
          native_libs, native_assets, ks)
    # an old app (Android 4.0+): its v1 signature must use SHA-1
    build(out, "legacy", "com.recomp.legacytest", "android.app.NativeActivity", "Legacy Test",
          native_libs, native_assets[:2], ks, min_sdk=14)
    # Unity-style game: Unity's library names, game data in assets/bin/Data
    ud = os.path.join(out, "_unitydata")
    subprocess.run([sys.executable, os.path.join(HERE, "..", "wingame", "make_unity.py"), ud], check=True)
    unity_assets = []
    for fn in sorted(os.listdir(ud)):
        unity_assets.append((f"assets/bin/Data/{fn}", open(os.path.join(ud, fn), "rb").read(), False))
    shutil.rmtree(ud)
    unity_assets.append(("assets/bin/Data/Managed/Metadata/global-metadata.dat",
                         b"\xaf\x1b\xb1\xfa" + bytes(4000), False))
    unity_assets.append(("assets/bin/Data/unity default resources", b"UnityFS-ish placeholder" * 10, False))
    unity_libs = [("lib/arm64-v8a/libmain.so", so["arm64-v8a"], True),
                  ("lib/arm64-v8a/libunity.so", so["arm64-v8a"], True),
                  ("lib/arm64-v8a/libil2cpp.so", so["arm64-v8a"], True)]
    build(out, "unity", "com.recomp.unitytest", "com.unity3d.player.UnityPlayerActivity", "Unity Test",
          unity_libs, unity_assets, ks)
    # Mono-backend Unity game: the C# assemblies are files in assets/bin/Data/Managed
    mono_assets = [a for a in unity_assets if "Metadata" not in a[0]]
    cs = os.path.join(out, "_Game.cs")
    with open(cs, "w") as f:
        f.write("public class Player { public int hp = 100; public string Hello() { return \"hi\"; } }\n")
    dll = os.path.join(out, "_Assembly-CSharp.dll")
    run("mcs", "-target:library", "-out:" + dll, cs)
    mono_assets.append(("assets/bin/Data/Managed/Assembly-CSharp.dll", open(dll, "rb").read(), False))
    os.remove(cs); os.remove(dll)
    mono_libs = [("lib/arm64-v8a/libmain.so", so["arm64-v8a"], True),
                 ("lib/arm64-v8a/libunity.so", so["arm64-v8a"], True),
                 ("lib/arm64-v8a/libmonobdwgc-2.0.so", so["arm64-v8a"], True)]
    build(out, "unity_mono", "com.recomp.monotest", "com.unity3d.player.UnityPlayerActivity", "Mono Test",
          mono_libs, mono_assets, ks)
    print(f"test APKs in {out}")


if __name__ == "__main__":
    main()
