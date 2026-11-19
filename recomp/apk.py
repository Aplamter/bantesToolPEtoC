"""Android APK files: what is inside, and the binary AndroidManifest.xml.

An APK is a ZIP file:
    AndroidManifest.xml      binary XML (package name, version, activities)
    classes*.dex             Java/Kotlin code (Dalvik bytecode)
    resources.arsc           compiled resources
    res/, assets/            resources and raw assets
    lib/<abi>/*.so           native code, one folder per CPU (arm64-v8a, ...)
    META-INF/                v1 (JAR) signature files, among others
and, in front of its central directory, an APK Signing Block holding the
v2/v3 signatures.

Unity games: lib/<abi>/libunity.so, and the game data under assets/bin/Data/
(globalgamemanagers, level*, sharedassets*.assets, data.unity3d). IL2CPP
builds have lib/<abi>/libil2cpp.so + assets/bin/Data/Managed/Metadata/
global-metadata.dat; Mono builds have the C# assemblies in
assets/bin/Data/Managed/.
"""
import struct
import zipfile

ABIS = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86", "armeabi", "mips", "mips64", "riscv64"]
UNITY_DATA = "assets/bin/Data/"
SIG_FILE_EXT = (".SF", ".RSA", ".DSA", ".EC")


def is_apk(path):
    try:
        with zipfile.ZipFile(path) as z:
            return "AndroidManifest.xml" in z.NameToInfo
    except (OSError, zipfile.BadZipFile):
        return False


def is_split_container(path):
    """.xapk / .apks / .apkm: a ZIP holding several APKs (base + splits)"""
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (OSError, zipfile.BadZipFile):
        return False
    return "AndroidManifest.xml" not in names and any(n.lower().endswith(".apk") for n in names)


# ---- binary XML (AXML) ------------------------------------------------------
RES_STRING_POOL, RES_XML, RES_XML_START_NS, RES_XML_END_NS = 0x0001, 0x0003, 0x0100, 0x0101
RES_XML_START_EL, RES_XML_END_EL, RES_XML_CDATA, RES_XML_RESMAP = 0x0102, 0x0103, 0x0104, 0x0180
ANDROID_NS = "http://schemas.android.com/apk/res/android"
# attribute resource IDs, for files that strip attribute names
ATTR_IDS = {0x01010003: "name", 0x0101021b: "versionCode", 0x0101021c: "versionName",
            0x0101020c: "minSdkVersion", 0x01010270: "targetSdkVersion", 0x01010001: "label",
            0x01010002: "icon", 0x0101000f: "debuggable", 0x010104ea: "extractNativeLibs",
            0x0101000c: "hasCode", 0x01010024: "value"}


class AxmlError(Exception):
    pass


def _string_pool(d, o):
    hsz, size = struct.unpack_from("<HI", d, o + 2)
    count, styles, flags, s_start, _ = struct.unpack_from("<IIIII", d, o + 8)
    utf8 = flags & 0x100
    offs = struct.unpack_from(f"<{count}I", d, o + hsz)
    base = o + s_start
    out = []
    for so in offs:
        p = base + so
        if utf8:
            n = d[p]; p += 1
            if n & 0x80:
                p += 1                  # (UTF-16 length, two bytes)
            n = d[p]; p += 1
            if n & 0x80:
                n = ((n & 0x7f) << 8) | d[p]; p += 1
            out.append(d[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", d, p)[0]; p += 2
            if n & 0x8000:
                n = ((n & 0x7fff) << 16) | struct.unpack_from("<H", d, p)[0]; p += 2
            out.append(d[p:p + 2 * n].decode("utf-16-le", "replace"))
    return out


def parse_axml(d):
    """binary XML -> nested dicts {"tag", "attrs": {name: value}, "children": [...]}"""
    if len(d) < 8 or struct.unpack_from("<H", d, 0)[0] != RES_XML:
        raise AxmlError("not a binary XML file")
    strings, resmap = [], []
    root = {"tag": None, "attrs": {}, "children": []}
    stack = [root]
    o = struct.unpack_from("<H", d, 2)[0]
    end = min(len(d), struct.unpack_from("<I", d, 4)[0])
    while o + 8 <= end:
        typ, hsz, size = struct.unpack_from("<HHI", d, o)
        if size < 8:
            break
        if typ == RES_STRING_POOL:
            strings = _string_pool(d, o)
        elif typ == RES_XML_RESMAP:
            resmap = list(struct.unpack_from(f"<{(size - hsz) // 4}I", d, o + hsz))
        elif typ == RES_XML_START_EL:
            ns, name, a_start, a_size, a_count = struct.unpack_from("<iiHHH", d, o + 16)
            el = {"tag": strings[name] if 0 <= name < len(strings) else "?", "attrs": {}, "children": []}
            p = o + 16 + a_start
            for _ in range(a_count):
                a_ns, a_name, a_raw, _, _, dtype, data = struct.unpack_from("<iiiHBBI", d, p)
                key = strings[a_name] if 0 <= a_name < len(strings) else ""
                if (not key) and a_name < len(resmap):
                    key = ATTR_IDS.get(resmap[a_name], f"attr_{resmap[a_name]:#x}")
                if dtype == 0x03:
                    val = strings[data] if data < len(strings) else ""
                elif dtype in (0x10,):
                    val = struct.unpack("<i", struct.pack("<I", data))[0]
                elif dtype == 0x11:
                    val = data
                elif dtype == 0x12:
                    val = data != 0
                elif dtype == 0x01:
                    val = f"@0x{data:08x}"
                elif a_raw >= 0 and a_raw < len(strings):
                    val = strings[a_raw]
                else:
                    val = data
                el["attrs"][key] = val
                p += a_size
            stack[-1]["children"].append(el)
            stack.append(el)
        elif typ == RES_XML_END_EL:
            if len(stack) > 1:
                stack.pop()
        o += size
    if not root["children"]:
        raise AxmlError("no elements")
    return root["children"][0]


def manifest_info(xml):
    """the parts of a parsed manifest that matter here"""
    a = xml["attrs"]
    info = {"package": a.get("package"), "versionCode": a.get("versionCode"),
            "versionName": a.get("versionName"), "minSdk": None, "targetSdk": None,
            "label": None, "debuggable": False, "extractNativeLibs": None, "hasCode": True,
            "launcher": None, "activities": []}
    for c in xml["children"]:
        if c["tag"] == "uses-sdk":
            info["minSdk"] = c["attrs"].get("minSdkVersion")
            info["targetSdk"] = c["attrs"].get("targetSdkVersion")
        elif c["tag"] == "application":
            ca = c["attrs"]
            info["label"] = ca.get("label")
            info["debuggable"] = bool(ca.get("debuggable", False))
            info["extractNativeLibs"] = ca.get("extractNativeLibs")
            info["hasCode"] = ca.get("hasCode", True)
            for act in c["children"]:
                if act["tag"] not in ("activity", "activity-alias"):
                    continue
                name = act["attrs"].get("name")
                info["activities"].append(name)
                for f in act["children"]:
                    if f["tag"] != "intent-filter":
                        continue
                    acts = {x["attrs"].get("name") for x in f["children"] if x["tag"] == "action"}
                    cats = {x["attrs"].get("name") for x in f["children"] if x["tag"] == "category"}
                    if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
                        info["launcher"] = info["launcher"] or name
    return info


# ---- APK signing block --------------------------------------------------------
def signing_block_ids(path):
    """IDs of the pairs in the APK Signing Block (0x7109871a = v2, 0xf05368c0 =
    v3, 0x1b93ad61 = v3.1, 0x42726577 = padding), or [] if there is none"""
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65557))
        tail = f.read()
    k = tail.rfind(b"PK\x05\x06")
    if k < 0:
        return []
    cd_off = struct.unpack_from("<I", tail, k + 16)[0]
    if cd_off < 32:
        return []
    with open(path, "rb") as f:
        f.seek(cd_off - 24)
        foot = f.read(24)
        if foot[8:] != b"APK Sig Block 42":
            return []
        bsize = struct.unpack_from("<Q", foot, 0)[0]
        f.seek(cd_off - bsize - 8)
        blk = f.read(bsize + 8)
    ids, o = [], 8
    while o + 12 <= len(blk) - 24:
        n, pid = struct.unpack_from("<QI", blk, o)
        ids.append(pid)
        o += 8 + n
    return ids


def info(path):
    """everything about an APK that recomp uses"""
    with zipfile.ZipFile(path) as z:
        entries = z.infolist()
        names = [e.filename for e in entries]
        man_raw = z.read("AndroidManifest.xml") if "AndroidManifest.xml" in z.NameToInfo else b""
    r = {"path": path, "entries": len(entries), "manifest": None}
    if man_raw:
        try:
            r["manifest"] = manifest_info(parse_axml(man_raw))
        except (AxmlError, struct.error, IndexError) as e:
            r["manifest_error"] = str(e)
    libs = {}
    for n in names:
        p = n.split("/")
        if len(p) == 3 and p[0] == "lib" and p[2].endswith(".so"):
            libs.setdefault(p[1], []).append(p[2])
    r["abis"] = sorted(libs, key=lambda a: ABIS.index(a) if a in ABIS else 99)
    r["native_libs"] = {a: sorted(v) for a, v in libs.items()}
    r["dex"] = sorted(n for n in names if n.startswith("classes") and n.endswith(".dex"))
    all_libs = {x for v in libs.values() for x in v}
    unity = "libunity.so" in all_libs or any(n.startswith(UNITY_DATA) for n in names)
    r["unity"] = None
    if unity:
        il2cpp = "libil2cpp.so" in all_libs or any(n.endswith("global-metadata.dat") for n in names)
        mono = any(n.startswith(UNITY_DATA + "Managed/") and n.endswith(".dll") for n in names)
        r["unity"] = {"backend": "il2cpp" if il2cpp else "mono" if mono else "unknown",
                      "data_files": sum(1 for n in names if n.startswith(UNITY_DATA)),
                      "metadata": next((n for n in names if n.endswith("global-metadata.dat")), None)}
    v1 = [n for n in names if n.startswith("META-INF/") and n.upper().endswith(SIG_FILE_EXT)]
    ids = signing_block_ids(path)
    r["signatures"] = {"v1": bool(v1), "v2": 0x7109871a in ids, "v3": 0xf05368c0 in ids or 0x1b93ad61 in ids}
    r["stored_so"] = sum(1 for e in entries if e.filename.endswith(".so") and e.compress_type == 0)
    return r


def is_v1_signature_file(name):
    """META-INF files a (re)signing replaces: MANIFEST.MF and *.SF/*.RSA/*.DSA/*.EC
    (other META-INF files, like services or *.version, are app content)"""
    if not name.startswith("META-INF/") or name.count("/") != 1:
        return False
    u = name.upper()
    return u == "META-INF/MANIFEST.MF" or u.endswith(SIG_FILE_EXT)


def summary_text(r):
    m = r.get("manifest") or {}
    L = [f"Android APK: {r['entries']} entries"]
    if m:
        L.append(f"  package {m.get('package')}  version {m.get('versionName')} ({m.get('versionCode')})  "
                 f"minSdk {m.get('minSdk')}  targetSdk {m.get('targetSdk')}")
        if m.get("launcher"):
            L.append(f"  launcher activity {m['launcher']}")
    elif r.get("manifest_error"):
        L.append(f"  AndroidManifest.xml could not be decoded: {r['manifest_error']}")
    if r["abis"]:
        for a in r["abis"]:
            L.append(f"  native code {a}: {', '.join(r['native_libs'][a])}")
    else:
        L.append("  no native code")
    L.append(f"  Java/Kotlin code: {len(r['dex'])} dex file(s)")
    u = r.get("unity")
    if u:
        L.append(f"  Unity game ({u['backend']}): {u['data_files']} files under {UNITY_DATA}")
    s = r["signatures"]
    L.append("  signed: " + (", ".join(k for k in ("v1", "v2", "v3") if s[k]) or "no"))
    return "\n".join(L)
