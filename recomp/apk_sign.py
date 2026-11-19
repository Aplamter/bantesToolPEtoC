"""Write an APK back from a recomp project, and sign it.

Used by build_game.py (standalone: no recomp needed). Packing follows the
original APK: the same entries in the same order, each with its original
compression and timestamp. Stored (uncompressed) entries are aligned like
zipalign does: 4 bytes, and 16 KiB for native libraries (extractNativeLibs=
false; 16 KiB also suits devices with 4 KiB pages).

Signing:
  v1  JAR signature: META-INF/MANIFEST.MF, CERT.SF, CERT.RSA (SHA-256, or
      SHA-1 for apps that still support Android below 4.3)
  v2  APK Signature Scheme v2: the APK Signing Block in front of the central
      directory, over 1 MiB chunks of the file (Android 7+ checks this one)
with an RSA key: by default the project's own key (signing/ in the project,
created on the first build, kept for later builds so they install as updates
of each other), or one you pass. The original developer's key is not
available, so Android sees the rebuilt APK as signed by someone else: remove
the original app before installing it.

Needs: pip install cryptography (or, without it: apksigner + keytool on PATH).
"""
import base64
import hashlib
import os
import shutil
import struct
import subprocess
import zipfile

ALIGN = 4
ALIGN_SO = 16384
V2_BLOCK_ID = 0x7109871A
SIG_RSA_PKCS1_SHA256 = 0x0103
CHUNK = 1 << 20


# ---- packing ------------------------------------------------------------------
def pack(build_dir, entries, out_path, log=print):
    """entries: game.json's container entries (signature files are skipped)"""
    n = 0
    with zipfile.ZipFile(out_path, "w") as z:
        for e in entries:
            if e.get("signature_file"):
                continue
            name = e["name"]
            src = os.path.join(build_dir, *name.split("/"))
            if not os.path.isfile(src):
                raise SystemExit(f"APK entry missing from the build: {name}")
            zi = zipfile.ZipInfo(name, date_time=tuple(e["date_time"]))
            zi.compress_type = zipfile.ZIP_DEFLATED if e["compress"] == zipfile.ZIP_DEFLATED else zipfile.ZIP_STORED
            zi.external_attr = e.get("external_attr", 0)
            zi.create_system = e.get("create_system", 0)
            if zi.compress_type == zipfile.ZIP_STORED:
                align = ALIGN_SO if name.endswith(".so") else ALIGN
                name_len = len(name.encode("utf-8"))
                data_at = z.fp.tell() + 30 + name_len + 6        # 6: the alignment extra field's header
                pad = (-data_at) % align
                # extra field 0xD935: what zipalign writes (alignment, then padding)
                zi.extra = struct.pack("<HHH", 0xD935, 2 + pad, align) + b"\0" * pad
            with open(src, "rb") as f, z.open(zi, "w") as dst:
                shutil.copyfileobj(f, dst, 1 << 20)
            n += 1
    return n


# ---- keys -----------------------------------------------------------------------
def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.serialization import pkcs7
        return x509, hashes, serialization, padding, rsa, pkcs7
    except ImportError:
        return None


def ensure_key(sign_dir, log=print):
    """(key.pem, cert.pem) of the project's own signing key; created once"""
    os.makedirs(sign_dir, exist_ok=True)
    kp, cp = os.path.join(sign_dir, "rebuild_key.pem"), os.path.join(sign_dir, "rebuild_cert.pem")
    if os.path.isfile(kp) and os.path.isfile(cp):
        return kp, cp
    c = _crypto()
    if c is None:
        raise RuntimeError("cryptography not installed")
    x509, hashes, serialization, _, rsa, _ = c
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "recomp rebuild"),
                      x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "recomp")])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365 * 40)).sign(key, hashes.SHA256()))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    log(f"   created the project's signing key: {sign_dir} (keep it: later rebuilds signed with it "
        f"install as updates)")
    return kp, cp


# ---- v1 (JAR) -----------------------------------------------------------------------
def _wrap72(line):
    """JAR manifest lines are at most 72 bytes; longer ones continue after a space"""
    b = line.encode("utf-8")
    out = [b[:72]]
    b = b[72:]
    while b:
        out.append(b" " + b[:71])
        b = b[71:]
    return b"\r\n".join(out) + b"\r\n"


def v1_files(apk_path, key, cert, sha1=False):
    """MANIFEST.MF, CERT.SF, CERT.RSA bytes for the entries of apk_path"""
    _, hashes, serialization, _, _, pkcs7 = _crypto()
    H, label = (hashlib.sha1, "SHA1") if sha1 else (hashlib.sha256, "SHA-256")
    b64 = lambda d: base64.b64encode(d).decode()
    sections = []
    with zipfile.ZipFile(apk_path) as z:
        for zi in z.infolist():
            if zi.is_dir():
                continue
            h = H()
            with z.open(zi) as f:
                for blk in iter(lambda: f.read(1 << 20), b""):
                    h.update(blk)
            sections.append(_wrap72(f"Name: {zi.filename}") + f"{label}-Digest: {b64(h.digest())}\r\n\r\n".encode())
    main = b"Manifest-Version: 1.0\r\nCreated-By: recomp\r\n\r\n"
    mf = main + b"".join(sections)
    sf = (b"Signature-Version: 1.0\r\nCreated-By: recomp\r\n" +
          f"{label}-Digest-Manifest: {b64(H(mf).digest())}\r\n".encode() +
          f"{label}-Digest-Manifest-Main-Attributes: {b64(H(main).digest())}\r\n".encode() +
          b"X-Android-APK-Signed: 2\r\n\r\n")
    for sec in sections:
        # the entry's Name lines (wrapped names: all of them), then the digest
        # of its whole MANIFEST.MF section
        head = sec[:sec.rindex(f"{label}-Digest:".encode())]
        sf += head + f"{label}-Digest: {b64(H(sec).digest())}\r\n\r\n".encode()
    if sha1:
        # the cryptography PKCS#7 builder refuses SHA-1, so build it here
        rsa_sig = _pkcs7_detached(sf, key, cert, sha1=True)
    else:
        opts = [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.NoAttributes]
        rsa_sig = (pkcs7.PKCS7SignatureBuilder().set_data(sf)
                   .add_signer(cert, key, hashes.SHA256())
                   .sign(serialization.Encoding.DER, opts))
    return mf, sf, rsa_sig


def _der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + body


def _der_int(v):
    return _der(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big"))


def _pkcs7_detached(data, key, cert, sha1=True):
    """DER PKCS#7 SignedData, detached content, no signed attributes (what
    jarsigner/apksigner write for v1): RSA PKCS#1 v1.5 over data."""
    _, hashes, serialization, padding, _, _ = _crypto()
    oid = lambda dotted: _der(0x06, _oid_body(dotted))
    null = b"\x05\x00"
    h_oid = "1.3.14.3.2.26" if sha1 else "2.16.840.1.101.3.4.2.1"
    sig = key.sign(data, padding.PKCS1v15(), hashes.SHA1() if sha1 else hashes.SHA256())
    digest_alg = _der(0x30, oid(h_oid) + null)
    signer = _der(0x30,
                  _der_int(1) +
                  _der(0x30, cert.issuer.public_bytes() + _der_int(cert.serial_number)) +
                  digest_alg +
                  _der(0x30, oid("1.2.840.113549.1.1.1") + null) +
                  _der(0x04, sig))
    signed_data = _der(0x30,
                       _der_int(1) +
                       _der(0x31, digest_alg) +
                       _der(0x30, oid("1.2.840.113549.1.7.1")) +
                       _der(0xA0, cert.public_bytes(serialization.Encoding.DER)) +
                       _der(0x31, signer))
    return _der(0x30, oid("1.2.840.113549.1.7.2") + _der(0xA0, signed_data))


def _oid_body(dotted):
    p = [int(x) for x in dotted.split(".")]
    out = bytes([40 * p[0] + p[1]])
    for v in p[2:]:
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(enc))
    return out


def add_v1(apk_in, apk_out, key, cert, sha1=False):
    mf, sf, rsa_sig = v1_files(apk_in, key, cert, sha1)
    shutil.copyfile(apk_in, apk_out)
    with zipfile.ZipFile(apk_out, "a") as z:
        for name, data in (("META-INF/MANIFEST.MF", mf), ("META-INF/CERT.SF", sf), ("META-INF/CERT.RSA", rsa_sig)):
            zi = zipfile.ZipInfo(name, date_time=(1981, 1, 1, 1, 1, 2))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)


# ---- v2 -------------------------------------------------------------------------------
def _lp(b):
    return struct.pack("<I", len(b)) + b


def _zip_sections(data):
    k = data.rfind(b"PK\x05\x06")
    if k < 0:
        raise SystemExit("not a ZIP file (no end of central directory)")
    cd_off = struct.unpack_from("<I", data, k + 16)[0]
    return cd_off, k


def _chunked_digest(parts):
    digests = []
    for p in parts:
        for i in range(0, len(p), CHUNK):
            c = p[i:i + CHUNK]
            digests.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(c)) + c).digest())
    return hashlib.sha256(b"\x5a" + struct.pack("<I", len(digests)) + b"".join(digests)).digest()


def add_v2(apk_in, apk_out, key, cert):
    _, hashes, serialization, padding, _, _ = _crypto()
    data = open(apk_in, "rb").read()
    cd_off, eocd = _zip_sections(data)
    entries, cd, eocd_b = data[:cd_off], data[cd_off:eocd], data[eocd:]
    digest = _chunked_digest([entries, cd, eocd_b])
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    signed = (_lp(_lp(struct.pack("<I", SIG_RSA_PKCS1_SHA256) + _lp(digest))) +
              _lp(_lp(cert_der)) + _lp(b""))
    sig = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = _lp(signed) + _lp(_lp(struct.pack("<I", SIG_RSA_PKCS1_SHA256) + _lp(sig))) + _lp(pub)
    value = _lp(_lp(signer))
    pair = struct.pack("<QI", 4 + len(value), V2_BLOCK_ID) + value
    size = len(pair) + 8 + 16
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    new_eocd = bytearray(eocd_b)
    struct.pack_into("<I", new_eocd, 16, cd_off + len(block))
    with open(apk_out, "wb") as f:
        f.write(entries + block + cd + bytes(new_eocd))


def sign(apk_in, apk_out, key_pem, cert_pem, min_sdk=None):
    x509, hashes, serialization, _, _, _ = _crypto()
    key = serialization.load_pem_private_key(open(key_pem, "rb").read(), password=None)
    cert = x509.load_pem_x509_certificate(open(cert_pem, "rb").read())
    tmp = apk_out + ".v1.tmp"
    add_v1(apk_in, tmp, key, cert, sha1=bool(min_sdk is not None and int(min_sdk) < 18))
    add_v2(tmp, apk_out, key, cert)
    os.remove(tmp)


def sign_with_apksigner(apk_in, apk_out, ks, ks_pass, alias=None):
    cmd = ["apksigner", "sign", "--ks", ks, "--ks-pass", f"pass:{ks_pass}", "--out", apk_out]
    if alias:
        cmd += ["--ks-key-alias", alias]
    subprocess.run(cmd + [apk_in], check=True)


def keytool_keystore(sign_dir):
    """a project keystore made with keytool (when cryptography is missing)"""
    ks = os.path.join(sign_dir, "rebuild.jks")
    if not os.path.isfile(ks):
        os.makedirs(sign_dir, exist_ok=True)
        subprocess.run(["keytool", "-genkeypair", "-keystore", ks, "-storepass", "recomp", "-keypass", "recomp",
                        "-alias", "rebuild", "-keyalg", "RSA", "-keysize", "2048", "-validity", "14000",
                        "-dname", "CN=recomp rebuild, O=recomp"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ks


def check(apk_path):
    """(ok, text): apksigner verify when it is installed, else our own v2 digest check"""
    if shutil.which("apksigner"):
        r = subprocess.run(["apksigner", "verify", "-v", apk_path], capture_output=True, text=True)
        lines = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.startswith(("Verifies", "Verified using v",
                                                                                  "DOES NOT", "ERROR"))]
        return r.returncode == 0, "apksigner: " + "; ".join(lines[:4])
    data = open(apk_path, "rb").read()
    cd_off, eocd = _zip_sections(data)
    foot = data[cd_off - 24:cd_off]
    if foot[8:] != b"APK Sig Block 42":
        return False, "no APK Signing Block"
    size = struct.unpack_from("<Q", foot, 0)[0]
    start = cd_off - size - 8
    e = bytearray(data[eocd:])
    struct.pack_into("<I", e, 16, start)
    digest = _chunked_digest([data[:start], data[cd_off:eocd], bytes(e)])
    return digest in data[start:cd_off], "v2 content digest " + ("matches" if digest in data[start:cd_off] else "DOES NOT match")
