# -*- coding: utf-8 -*-
"""Generate test vectors for WinHash JS hash implementations."""
import hashlib, zlib, json, os

INPUTS = [
    ("empty", b""),
    ("a", b"a"),
    ("abc", b"abc"),
    ("md", b"message digest"),
    ("alpha", b"abcdefghijklmnopqrstuvwxyz"),
    ("alnum", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
    ("digits", b"1234567890" * 10),
    ("block63", b"x" * 63),
    ("block64", b"x" * 64),
    ("block65", b"x" * 65),
    ("block119", b"x" * 119),
    ("block120", b"x" * 120),
    ("block127", b"x" * 127),
    ("block128", b"x" * 128),
    ("binary256", bytes(range(256))),
    ("long10k", (b"WinHash test vector payload - " * 400)),
    ("arabic", "مرحبا بك في وين هاش 123!".encode("utf-8")),
    ("unicode", "Ω≈ç√∫˜µ≤≥÷aA1!@#$".encode("utf-8")),
]

HASHES = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512", "ripemd160",
]

out = {"inputs": [], "hashes": {}}
for name, data in INPUTS:
    out["inputs"].append({"name": name, "hex": data.hex(), "len": len(data)})
    entry = {}
    for h in HASHES:
        try:
            entry[h] = hashlib.new(h, data).hexdigest()
        except Exception as e:
            entry[h] = "ERR:" + str(e)
    entry["crc32"] = format(zlib.crc32(data) & 0xFFFFFFFF, "08x")
    # FNV-1a 32-bit
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    entry["fnv1a32"] = format(h, "08x")
    out["hashes"][name] = entry

# HMAC-SHA256 vectors (key, message)
hmac_cases = [
    ("", "msg"),
    ("key", "The quick brown fox jumps over the lazy dog"),
    ("صمةمفتاح", "رسالة تجريبية"),
    ("0123456789abcdef" * 2, "x" * 300),
]
import hmac
out["hmac"] = []
for k, m in hmac_cases:
    kb = k.encode("utf-8")
    mb = m.encode("utf-8")
    out["hmac"].append({
        "key": k, "msg": m,
        "sha256": hmac.new(kb, mb, hashlib.sha256).hexdigest(),
        "sha1": hmac.new(kb, mb, hashlib.sha1).hexdigest(),
        "sha512": hmac.new(kb, mb, hashlib.sha512).hexdigest(),
    })

base = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(base, "vectors.js"), "w", encoding="utf-8") as f:
    f.write("window.VECTORS = ")
    json.dump(out, f, ensure_ascii=False)
    f.write(";\n")
print("wrote vectors.js", len(out["inputs"]), "inputs")
