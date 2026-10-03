#!/usr/bin/env python3
"""Card Vault PC companion.

Offline access to a Card Vault volume using the recovery key, plus transfer
of the recovery key to/from the Flipper over its USB CLI.

With the Flipper connected (no card, no password needed):
  unlock     open the vault as a USB drive using the recovery key
  rekey      set a new password + new blank card (old card stops working)
  fetch-key  download recovery.key right after creating a vault

Without the Flipper (SD card in a card reader):
  decrypt    vault.img + recovery.key -> plain FAT32 image (mount / open it)
  encrypt    plain FAT32 image + recovery.key -> vault.img (copy back to SD)
  verify     check that a recovery key opens a vault image

By default the key is recovery.key next to this script.

Requires: pip install cryptography pyserial
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SECTOR = 512
CHUNK_SECTORS = 2048  # 1 MiB per I/O
MK_CHECK_LABEL = b"CardVault mk-check v1"
FLIPPER_DIR = "/ext/apps_data/card_vault"
FLIPPER_KEY_PATH = f"{FLIPPER_DIR}/recovery.key"
FLIPPER_APP = "/ext/apps/Tools/card_vault.fap"
DEFAULT_KEY = Path(__file__).resolve().parent / "recovery.key"


@dataclass
class RecoveryKey:
    vault_id: bytes
    volume_sectors: int
    master_key: bytes  # data key || tweak key (IEEE 1619 key1 || key2)
    check: bytes

    @classmethod
    def load(cls, path: Path) -> "RecoveryKey":
        fields = {}
        for line in path.read_text(encoding="ascii").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            k, v = line.split(":", 1)
            fields[k.strip().lower()] = v.strip()
        try:
            if fields["version"] != "1":
                raise ValueError(f"unsupported version {fields['version']}")
            rk = cls(
                vault_id=bytes.fromhex(fields["vault id"]),
                volume_sectors=int(fields["volume sectors"]),
                master_key=bytes.fromhex(fields["master key"]),
                check=bytes.fromhex(fields["check"]),
            )
        except KeyError as e:
            raise ValueError(f"recovery key is missing field {e}") from None
        if len(rk.master_key) != 64 or len(rk.vault_id) != 16 or len(rk.check) != 16:
            raise ValueError("recovery key has malformed fields")
        expected = hmac.new(rk.master_key, MK_CHECK_LABEL, hashlib.sha512).digest()[:16]
        if not hmac.compare_digest(expected, rk.check):
            raise ValueError("recovery key checksum mismatch (file damaged or mistyped)")
        return rk


def xts_process(key: bytes, first_sector: int, data: bytes, encrypt: bool) -> bytes:
    out = bytearray(len(data))
    for i in range(len(data) // SECTOR):
        tweak = (first_sector + i).to_bytes(16, "little")
        c = Cipher(algorithms.AES(key), modes.XTS(tweak))
        op = c.encryptor() if encrypt else c.decryptor()
        out[i * SECTOR : (i + 1) * SECTOR] = op.update(data[i * SECTOR : (i + 1) * SECTOR]) + op.finalize()
    return bytes(out)


def transform(src: Path, dst: Path, rk: RecoveryKey, encrypt: bool) -> None:
    size = src.stat().st_size
    if size % SECTOR:
        raise ValueError(f"{src} size is not a multiple of {SECTOR}")
    sectors = size // SECTOR
    if sectors != rk.volume_sectors:
        raise ValueError(f"{src} has {sectors} sectors, recovery key expects {rk.volume_sectors}")
    tmp = dst.with_name(dst.name + ".part")
    with open(src, "rb") as fi, open(tmp, "wb") as fo:
        done = 0
        while done < sectors:
            n = min(CHUNK_SECTORS, sectors - done)
            fo.write(xts_process(rk.master_key, done, fi.read(n * SECTOR), encrypt))
            done += n
            print(f"\r  {done * 100 // sectors:3d}%", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)
    os.replace(tmp, dst)


def check_fat32(boot: bytes) -> bool:
    return boot[510:512] == b"\x55\xaa" and boot[82:90] == b"FAT32   "


def cmd_decrypt(a) -> int:
    rk = RecoveryKey.load(a.key)
    transform(a.image, a.out, rk, encrypt=False)
    with open(a.out, "rb") as f:
        boot = f.read(SECTOR)
    if not check_fat32(boot):
        print("WARNING: decrypted volume has no FAT32 boot sector - wrong key?", file=sys.stderr)
        return 2
    print(f"Decrypted to {a.out}")
    print("  Linux:   sudo mount -o loop,uid=$(id -u) " + str(a.out) + " /mnt")
    print("  Windows: open with 7-Zip, or mount with OSFMount")
    print("  macOS:   hdiutil attach -imagekey diskimage-class=CRawDiskImage " + str(a.out))
    print("Delete the plain image securely when done - it is NOT encrypted.")
    return 0


def cmd_encrypt(a) -> int:
    rk = RecoveryKey.load(a.key)
    with open(a.plain, "rb") as f:
        if not check_fat32(f.read(SECTOR)):
            print("refusing: input is not a FAT32 volume", file=sys.stderr)
            return 2
    transform(a.plain, a.out, rk, encrypt=True)
    print(f"Encrypted to {a.out}; copy it to SD:{FLIPPER_DIR}/vault.img")
    return 0


def cmd_verify(a) -> int:
    rk = RecoveryKey.load(a.key)
    with open(a.image, "rb") as f:
        boot = xts_process(rk.master_key, 0, f.read(SECTOR), encrypt=False)
    if not check_fat32(boot):
        print("FAIL: key does not open this image", file=sys.stderr)
        return 2
    print(f"OK: vault {rk.vault_id.hex()} opens with this key")
    return 0


class FlipperCli:
    PROMPT = b">: "

    def __init__(self, port: str | None):
        import serial
        from serial.tools import list_ports

        if not port:
            found = [p.device for p in list_ports.comports() if p.vid == 0x0483 and p.pid == 0x5740]
            if not found:
                raise RuntimeError("Flipper not found (is it connected and NOT in vault USB-drive mode?)")
            port = found[0]
        self.s = serial.Serial(port, 230400, timeout=0.2)
        self.s.reset_input_buffer()
        self.s.write(b"\r")
        self._until(self.PROMPT)
        # the CLI may print the banner and several prompts; drain until quiet
        while self.s.read(4096):
            pass

    def _until(self, marker: bytes, timeout: float = 10) -> bytes:
        buf = b""
        end = time.monotonic() + timeout
        while not buf.endswith(marker):
            if time.monotonic() > end:
                raise TimeoutError(f"Flipper CLI timeout, got: {buf[-200:]!r}")
            buf += self.s.read(1)
        return buf

    def cmd(self, line: str) -> str:
        self.s.write(line.encode() + b"\r")
        out = self._until(self.PROMPT).decode(errors="replace")
        body = out.split("\n", 1)[1] if "\n" in out else ""
        return body[: -len(self.PROMPT)].strip("\r\n")

    def read_file(self, path: str) -> bytes:
        self.s.write(f"storage read {path}\r".encode())
        out = self._until(self.PROMPT)
        marker = out.find(b"Size: ")
        if marker < 0:
            raise RuntimeError(out.decode(errors="replace").split("\n", 1)[-1].strip(" \r\n>:"))
        header_end = out.index(b"\r\n", marker)
        size = int(out[marker + 6 : header_end])
        data = out[header_end + 2 : header_end + 2 + size]
        if len(data) != size:
            raise RuntimeError("short read from Flipper")
        return data

    def write_file(self, path: str, data: bytes) -> None:
        self.cmd(f"storage remove {path}")
        self.s.write(f"storage write_chunk {path} {len(data)}\r".encode())
        self._until(b"Ready\r\n")
        self.s.write(data)
        self._until(self.PROMPT)

    def close(self):
        self.s.close()


def cmd_fetch_key(a) -> int:
    cli = FlipperCli(a.port)
    try:
        data = cli.read_file(FLIPPER_KEY_PATH)
    finally:
        cli.close()
    a.out.write_bytes(data)
    try:
        rk = RecoveryKey.load(a.out)
    except ValueError as e:
        a.out.unlink()
        print(f"downloaded file is invalid: {e}", file=sys.stderr)
        return 2
    os.chmod(a.out, 0o600)
    print(f"Saved recovery key for vault {rk.vault_id.hex()} to {a.out}")
    print("Now press OK on the Flipper to erase its copy, and store this file offline.")
    return 0


def push_key_and_launch(key: Path, port: str | None, mode: str) -> RecoveryKey:
    rk = RecoveryKey.load(key)
    cli = FlipperCli(port)
    try:
        cli.cmd("loader close")
        cli.cmd(f"storage mkdir {FLIPPER_DIR}")
        cli.write_file(FLIPPER_KEY_PATH, key.read_bytes())
        out = cli.cmd(f"loader open {FLIPPER_APP} {mode}")
        if "rror" in out or "an't" in out:
            cli.cmd(f"storage remove {FLIPPER_KEY_PATH}")
            raise RuntimeError(f"could not start Card Vault: {out}")
    finally:
        cli.close()
    return rk


def find_vault_mount(timeout: float) -> str | None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if sys.platform.startswith("linux"):
            with open("/proc/mounts") as f:
                for line in f:
                    dev, mnt = line.split()[:2]
                    if mnt.rstrip("/").endswith("/CARDVAULT"):
                        return mnt.replace("\\040", " ")
        elif sys.platform == "darwin" and os.path.isdir("/Volumes/CARDVAULT"):
            return "/Volumes/CARDVAULT"
        elif os.name == "nt":
            import ctypes
            import string

            for d in string.ascii_uppercase:
                buf = ctypes.create_unicode_buffer(64)
                if ctypes.windll.kernel32.GetVolumeInformationW(f"{d}:\\", buf, 64, None, None, None, None, 0):
                    if buf.value == "CARDVAULT":
                        return f"{d}:\\"
        time.sleep(1)
    return None


def cmd_unlock(a) -> int:
    rk = push_key_and_launch(a.key, a.port, "recovery-unlock")
    print(f"Vault {rk.vault_id.hex()[:8]}...: unlocking with recovery key (the Flipper erases its copy).")
    mnt = find_vault_mount(30)
    if mnt:
        print(f"Vault is open: {mnt}")
    else:
        print("Vault drive is attached (CARDVAULT) - open it in your file manager.")
    print("When done: eject the drive (or press Back -> Lock on the Flipper).")
    return 0


def cmd_rekey(a) -> int:
    rk = push_key_and_launch(a.key, a.port, "restore")
    print(f"Vault {rk.vault_id.hex()[:8]}...: re-key started on the Flipper.")
    print("On the Flipper: enter the NEW password twice, then hold a BLANK card to its back.")
    print("The old card and old password stop working afterwards. The key file stays valid.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("unlock", help="open the vault on the Flipper with the recovery key")
    s.add_argument("--key", type=Path, default=DEFAULT_KEY)
    s.add_argument("--port")
    s.set_defaults(fn=cmd_unlock)

    s = sub.add_parser("rekey", help="new password + new blank card, using the recovery key")
    s.add_argument("--key", type=Path, default=DEFAULT_KEY)
    s.add_argument("--port")
    s.set_defaults(fn=cmd_rekey)

    s = sub.add_parser("decrypt", help="decrypt vault.img to a plain FAT32 image")
    s.add_argument("--key", type=Path, default=DEFAULT_KEY)
    s.add_argument("--image", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.set_defaults(fn=cmd_decrypt)

    s = sub.add_parser("encrypt", help="encrypt a plain FAT32 image back to vault.img")
    s.add_argument("--key", type=Path, default=DEFAULT_KEY)
    s.add_argument("--plain", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.set_defaults(fn=cmd_encrypt)

    s = sub.add_parser("verify", help="check that a recovery key opens vault.img")
    s.add_argument("--key", type=Path, default=DEFAULT_KEY)
    s.add_argument("--image", type=Path, required=True)
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("fetch-key", help="download recovery.key from the Flipper")
    s.add_argument("--out", type=Path, default=DEFAULT_KEY)
    s.add_argument("--port")
    s.set_defaults(fn=cmd_fetch_key)


    a = p.parse_args()
    try:
        return a.fn(a)
    except (ValueError, RuntimeError, TimeoutError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
