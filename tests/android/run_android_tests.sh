#!/bin/sh
# Android APK support, end to end: build real APKs (aapt2/zipalign/apksigner),
# turn them into projects (game for Unity, lift for the native app), rebuild
# the APKs and check them with Google's tools:
#   apksigner verify (v1 + v2), zipalign -c -p 4, aapt dump badging identical,
#   every entry identical to the original, in the same order and compression,
# plus: a modded Unity asset, the project key reused, own key / keystore,
# SHA-1 v1 signing (minSdk < 18), native libraries lifted for analysis.
# Needs: aapt aapt2 apksigner zipalign keytool android.jar aarch64-linux-gnu-gcc
#        mcs, python3 with cryptography, lz4, UnityPy.
set -u
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
OUT=${OUT:-/tmp/recomp_android}
rm -rf "$OUT"; mkdir -p "$OUT"
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass + 1)); }
bad()  { echo "FAIL  $1"; fail=$((fail + 1)); }
t()    { if "$@" > "$OUT/last.log" 2>&1; then ok "$NAME"; else bad "$NAME  (see $OUT/last.log)"; cat "$OUT/last.log" | tail -5; fi; }

python3 make_test_apks.py "$OUT/apks" > "$OUT/make.log" 2>&1 || { echo "FAIL  making test APKs (see $OUT/make.log)"; exit 1; }

roundtrip() {  # name command(game|lift)
    n=$1; cmd=$2; P="$OUT/proj_$n"
    NAME="$n: recomp.py $cmd"; t python3 "$ROOT/recomp.py" $cmd "$OUT/apks/$n.apk" -o "$P"
    NAME="$n: build_game.py (files identical, APK signed + verified)"
    t sh -c "cd '$P' && python3 build_game.py"
    NAME="$n: same entries, order, compression, contents, alignment"
    t python3 compare_apks.py "$OUT/apks/$n.apk" "$P/$n-rebuilt.apk" --may-change=lib/arm64-v8a/
    NAME="$n: apksigner verify (v1 + v2)"
    t sh -c "apksigner verify -v '$P/$n-rebuilt.apk' | grep -q 'v1 scheme (JAR signing): true' &&
             apksigner verify -v '$P/$n-rebuilt.apk' | grep -q 'v2 scheme (APK Signature Scheme v2): true'"
    NAME="$n: zipalign -c -p 4"; t zipalign -c -p 4 "$P/$n-rebuilt.apk"
    NAME="$n: aapt dump badging identical"
    t sh -c "aapt dump badging '$OUT/apks/$n.apk' > '$OUT/a.txt' 2>&1; aapt dump badging '$P/$n-rebuilt.apk' > '$OUT/b.txt' 2>&1; diff '$OUT/a.txt' '$OUT/b.txt'"
}
roundtrip unity game
roundtrip unity_mono game
roundtrip native lift
roundtrip legacy lift
NAME="legacy (minSdk 14): v1 uses SHA-1 and verifies down to API 14"
t sh -c "unzip -p '$OUT/proj_legacy/legacy-rebuilt.apk' META-INF/MANIFEST.MF | grep -q SHA1-Digest &&
         apksigner verify --min-sdk-version 14 '$OUT/proj_legacy/legacy-rebuilt.apk'"

NAME="unity: Unity files split into objects"; t test -f "$OUT/proj_unity/assets/assets__bin__Data__resources.assets/recipe.json"
NAME="native: lift keeps Unity-style assets as plain files (no splitting)"; t test ! -d "$OUT/proj_native/assets"
NAME="native libraries recompiled (exports found)"
t sh -c "grep -q JNI_OnLoad '$OUT/proj_native/modules/lib__arm64-v8a__libmain.so/symbols.tsv' &&
         grep -q game_tick '$OUT/proj_native/modules/lib__arm64-v8a__libmain.so/symbols.tsv' &&
         test -f '$OUT/proj_native/modules/lib__arm64-v8a__libmain.so/lift.json'"
NAME="only the chosen ABI is lifted (x86_64 copy noted, not lifted)"; t test ! -d "$OUT/proj_native/modules/lib__x86_64__libmain.so"

# a mod: same-size edit of a Unity TextAsset, rebuilt APK carries it and verifies
P="$OUT/proj_unity"
python3 - "$P" <<'PY'
import sys, glob
p = glob.glob(sys.argv[1] + "/assets/assets__bin__Data__resources.assets/objects/*credits*.bin")[0]
b = open(p, "rb").read(); open(p, "wb").write(b.replace(b"made by tests", b"MODDED-TESTS!"))
PY
cert1=$(apksigner verify --print-certs "$P/unity-rebuilt.apk" 2>/dev/null | grep SHA-256)
NAME="mod: rebuild with an edited Unity asset"; t sh -c "cd '$P' && python3 build_game.py"
NAME="mod: only that file changed, APK valid"; t python3 compare_apks.py "$OUT/apks/unity.apk" "$P/unity-rebuilt.apk" assets/bin/Data/resources.assets --may-change=lib/arm64-v8a/
NAME="mod: UnityPy reads the new text from the rebuilt APK"
t python3 -c "
import zipfile, UnityPy
env = UnityPy.load(zipfile.ZipFile('$P/unity-rebuilt.apk').read('assets/bin/Data/resources.assets'))
txt = [o.read().m_Script for o in env.objects if o.read().m_Name == 'credits'][0]
assert (txt if isinstance(txt, str) else txt.decode()) == 'MODDED-TESTS!', txt"
cert2=$(apksigner verify --print-certs "$P/unity-rebuilt.apk" 2>/dev/null | grep SHA-256)
NAME="the project key is kept: both builds have the same certificate"; t test -n "$cert1" -a "$cert1" = "$cert2"

# own key (PEM) and own keystore
python3 - "$OUT" <<'PY'
import sys, datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
n = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "my own key")])
t = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
c = x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(5) \
    .not_valid_before(t).not_valid_after(t + datetime.timedelta(days=9000)).sign(k, hashes.SHA256())
open(sys.argv[1] + "/my.key", "wb").write(k.private_bytes(serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open(sys.argv[1] + "/my.crt", "wb").write(c.public_bytes(serialization.Encoding.PEM))
PY
NAME="own key: --key/--cert"
t sh -c "cd '$OUT/proj_native' && python3 build_game.py --key '$OUT/my.key' --cert '$OUT/my.crt' --apk-out '$OUT/own.apk' &&
         apksigner verify --print-certs '$OUT/own.apk' | grep -q 'CN=my own key'"
NAME="own keystore: --ks (apksigner)"
t sh -c "cd '$OUT/proj_native' && python3 build_game.py --ks '$OUT/apks/test.jks' --ks-pass testpass --apk-out '$OUT/ks.apk' &&
         apksigner verify --print-certs '$OUT/ks.apk' | grep -q 'CN=recomp test'"
NAME="--no-sign writes an unsigned APK"
t sh -c "cd '$OUT/proj_native' && python3 build_game.py --no-sign --apk-out '$OUT/unsigned.apk' && ! apksigner verify '$OUT/unsigned.apk'"

# v1 with SHA-1, for apps that still support Android 4.2 and older
NAME="v1 signature with SHA-1 (minSdk < 18) verifies for API 14"
t python3 -c "
import sys; sys.path.insert(0, '$ROOT/recomp')
import apk_sign, subprocess
apk_sign.sign('$OUT/unsigned.apk', '$OUT/sha1.apk', '$OUT/my.key', '$OUT/my.crt', min_sdk=14)
r = subprocess.run(['apksigner', 'verify', '-v', '--min-sdk-version', '14', '$OUT/sha1.apk'], capture_output=True, text=True)
assert r.returncode == 0 and 'v1 scheme (JAR signing): true' in r.stdout, r.stdout + r.stderr"

NAME="split APK container is refused with a clear message"
python3 -c "
import zipfile; z = zipfile.ZipFile('$OUT/test.xapk', 'w'); z.write('$OUT/apks/native.apk', 'com.recomp.nativetest.apk'); z.close()"
t sh -c "python3 '$ROOT/recomp.py' game '$OUT/test.xapk' -o '$OUT/proj_x' 2>&1 | grep -q 'base APK'"

echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
