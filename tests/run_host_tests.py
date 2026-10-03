#!/usr/bin/env python3
"""Builds the C crypto/FAT code natively and checks it against Python references."""

import hashlib
import hmac
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "tests" / "build"
sys.path.insert(0, str(ROOT / "tools"))
import cardvault  # noqa: E402

SRC = [
    "tests/host_test.c",
    "tests/aes_openssl.c",
    "card_vault/crypto/sha512.c",
    "card_vault/crypto/kdf.c",
    "card_vault/crypto/xts.c",
    "card_vault/vault/fat32.c",
]

failures = 0


def check(name, ok):
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    failures += not ok


def hkdf(salt, ikm, info, n):
    prk = hmac.new(salt or bytes(64), ikm, hashlib.sha512).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        out += t
        i += 1
    return out[:n]


def main():
    BUILD.mkdir(exist_ok=True)
    exe = BUILD / "host_test"
    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-o", str(exe)]
        + [str(ROOT / s) for s in SRC]
        + ["-lcrypto"],
        check=True,
    )

    out = dict(
        l.split("=", 1) for l in subprocess.run([exe, "kdf"], check=True, capture_output=True, text=True).stdout.split()
    )
    a = b"a" * 1000
    check("sha512 abc", out["sha512_abc"] == hashlib.sha512(b"abc").hexdigest())
    check("sha512 empty", out["sha512_empty"] == hashlib.sha512(b"").hexdigest())
    check("sha512 chunked 1000", out["sha512_1000a"] == hashlib.sha512(a).hexdigest())
    for n in range(110, 114):
        check(f"sha512 padding len {n}", out[f"sha512_a{n}"] == hashlib.sha512(a[:n]).hexdigest())
    check("hmac", out["hmac_short"] == hmac.new(b"key", b"The quick brown fox", hashlib.sha512).hexdigest())
    check("hmac long key", out["hmac_longkey"] == hmac.new(a[:200], b"msg", hashlib.sha512).hexdigest())
    check("pbkdf2", out["pbkdf2"] == hashlib.pbkdf2_hmac("sha512", b"password", b"saltsalt", 1000, 100).hex())
    check("hkdf", out["hkdf"] == hkdf(b"salt", b"ikm-material", b"info", 200).hex())
    check("hkdf no salt", out["hkdf_nosalt"] == hkdf(b"", b"ikm", b"", 32).hex())

    key = bytes((i * 3 + 1) & 0xFF for i in range(32)) + bytes(0xA0 ^ ((i * 5) & 0xFF) for i in range(32))
    xts_file = BUILD / "xts.bin"
    subprocess.run([exe, "xts", str(xts_file)], check=True)
    ct = xts_file.read_bytes()
    pt = bytes((i * 31 + 7) & 0xFF for i in range(len(ct)))
    check("xts-aes-256 vs cryptography", cardvault.xts_process(key, 1000, pt, encrypt=True) == ct)

    for sectors in (131072, 2 * 1024 * 1024):  # 64 MiB (512 B clusters) and 1 GiB (4 KiB clusters)
        img = BUILD / "vault.img"
        plain = BUILD / "plain.img"
        subprocess.run([exe, "fat", str(img), str(sectors)], check=True)
        keyfile = BUILD / "test.key"
        check_bytes = hmac.new(key, cardvault.MK_CHECK_LABEL, hashlib.sha512).digest()[:16]
        keyfile.write_text(
            f"Version: 1\nVault ID: {'00' * 16}\nVolume sectors: {sectors}\n"
            f"Master key: {key.hex()}\nCheck: {check_bytes.hex()}\n"
        )
        rc = subprocess.run(
            [sys.executable, ROOT / "tools/cardvault.py", "decrypt", "--key", keyfile, "--image", img, "--out", plain],
            capture_output=True,
        ).returncode
        check(f"[{sectors} sectors] tool decrypts to FAT32", rc == 0)
        fsck = subprocess.run(["fsck.fat", "-n", "-v", str(plain)], capture_output=True, text=True)
        check(f"[{sectors} sectors] fsck.fat clean", fsck.returncode == 0)
        if fsck.returncode:
            print(fsck.stdout, fsck.stderr)

        env = dict(os.environ, MTOOLS_SKIP_CHECK="1")
        payload = BUILD / "payload.bin"
        payload.write_bytes(os.urandom(3 * 1024 * 1024 + 123))
        subprocess.run(["mcopy", "-i", str(plain), str(payload), "::/secret.bin"], check=True, env=env)
        back = BUILD / "payload.back"
        back.unlink(missing_ok=True)
        subprocess.run(["mcopy", "-i", str(plain), "::/secret.bin", str(back)], check=True, env=env)
        check(f"[{sectors} sectors] file round trip in volume", back.read_bytes() == payload.read_bytes())

        enc2 = BUILD / "vault2.img"
        subprocess.run(
            [sys.executable, ROOT / "tools/cardvault.py", "encrypt", "--key", keyfile, "--plain", plain, "--out", enc2],
            check=True,
            capture_output=True,
        )
        rc = subprocess.run(
            [sys.executable, ROOT / "tools/cardvault.py", "verify", "--key", keyfile, "--image", enc2],
            capture_output=True,
        ).returncode
        check(f"[{sectors} sectors] re-encrypt + verify", rc == 0)
        for f in (img, plain, enc2, back, payload):
            f.unlink(missing_ok=True)

    print("ALL PASS" if not failures else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
