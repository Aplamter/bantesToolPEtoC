"""compare a rebuilt APK with the original: same entries (minus the old
signature files), same order, same compression, identical contents; stored
entries aligned (4 bytes, native libraries 16 KiB). Prints problems, exit 1 if any."""
import struct
import sys
import zipfile

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", ".."))
from recomp.apk import is_v1_signature_file

orig, new = sys.argv[1], sys.argv[2]
# entries a test modified on purpose; --may-change=PREFIX: entries that may
# differ (recompiled native libraries)
allow_changed = {a for a in sys.argv[3:] if not a.startswith("--may-change=")}
may_change = tuple(a.split("=", 1)[1] for a in sys.argv[3:] if a.startswith("--may-change="))
bad = []
with zipfile.ZipFile(orig) as a, zipfile.ZipFile(new) as b:
    ea = [e for e in a.infolist() if not is_v1_signature_file(e.filename) and not e.is_dir()]
    eb = [e for e in b.infolist() if not is_v1_signature_file(e.filename)]
    if [e.filename for e in ea] != [e.filename for e in eb]:
        bad.append(f"entry list differs:\n  {[e.filename for e in ea]}\n  {[e.filename for e in eb]}")
    for x, y in zip(ea, eb):
        if x.compress_type != y.compress_type:
            bad.append(f"{x.filename}: compression {x.compress_type} -> {y.compress_type}")
        same = a.read(x) == b.read(y)
        if x.filename in allow_changed:
            if same:
                bad.append(f"{x.filename}: expected a change, but it is identical")
        elif not same and not x.filename.startswith(may_change or ("\0",)):
            bad.append(f"{x.filename}: contents differ")
    raw = open(new, "rb").read()
    for y in eb:
        if y.compress_type == zipfile.ZIP_STORED:
            n, m = struct.unpack_from("<HH", raw, y.header_offset + 26)
            at = y.header_offset + 30 + n + m
            need = 16384 if y.filename.endswith(".so") else 4
            if at % need:
                bad.append(f"{y.filename}: data at {at:#x}, not aligned to {need}")
for p in bad:
    print("PROBLEM:", p)
print(f"{len(eb)} entries compared, {len(bad)} problem(s)")
sys.exit(1 if bad else 0)
