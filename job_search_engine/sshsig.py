"""
sshsig — verify an OpenSSH signature (`ssh-keygen -Y sign`) made by a FIDO2 security key.

⭐ WHY, 2026-10-01. The Ed25519 approval key lived in a file on the laptop that every agent
there could read, so "only he can approve a send" was true by convention, not by mechanism.
An `sk-ssh-ed25519` key's private half never leaves the YubiKey, and every signature carries a
user-presence flag the device sets only on a physical touch. The relay checks both.

ONLY `sk-ssh-ed25519@openssh.com` IS ACCEPTED. A plain ssh-ed25519 key is a file, which is the
problem this module exists to remove, so accepting one here would quietly restore it.

Formats, from OpenSSH PROTOCOL.sshsig and PROTOCOL.u2f:

  armored blob = "SSHSIG" uint32 version(1) string publickey string namespace
                 string reserved string hash_algorithm string signature
  signed data  = "SSHSIG" string namespace string reserved string hash_algorithm string H(msg)
  sk publickey = string "sk-ssh-ed25519@openssh.com" string pk(32) string application
  sk signature = string "sk-ssh-ed25519@openssh.com" string sig(64) byte flags uint32 counter
  the device signs SHA256(application) || flags || counter || SHA256(signed data)

Pure apart from `cryptography`, which the engine already depends on.
"""
from __future__ import annotations

import base64
import hashlib
import struct

SK_ED25519 = b"sk-ssh-ed25519@openssh.com"
MAGIC = b"SSHSIG"
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04


class Invalid(Exception):
    """The signature does not prove what it must. The message says which check failed."""


class _R:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise Invalid("truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u8(self) -> int:
        return self.take(1)[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def done(self) -> bool:
        return self.i == len(self.b)


def _s(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def parse_pubkey_line(line: str) -> bytes:
    """`sk-ssh-ed25519@openssh.com AAAA... comment` -> the raw public key blob."""
    parts = line.strip().split()
    if len(parts) < 2 or parts[0].encode() != SK_ED25519:
        raise Invalid("not an sk-ssh-ed25519 public key line")
    blob = base64.b64decode(parts[1])
    if _R(blob).string() != SK_ED25519:
        raise Invalid("key type inside the blob does not match the line")
    return blob


def unarmor(text: str) -> bytes:
    lines = [l.strip() for l in text.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN SSH SIGNATURE-----" or \
            lines[-1] != "-----END SSH SIGNATURE-----":
        raise Invalid("not an armored SSH signature")
    return base64.b64decode("".join(lines[1:-1]))


def verify(blob: bytes, message: bytes, namespace: str, allowed: list[bytes],
           require_uv: bool = False) -> dict:
    """Verify a raw SSHSIG blob. Returns {'counter', 'flags', 'key_index'} or raises Invalid.

    🚨 Every check is required. A missing namespace check lets a signature made for another
    purpose (a git commit, a funlab approval) approve a send. A missing presence check accepts a
    signature the device made without a touch. A missing allowlist check accepts any YubiKey.
    """
    r = _R(blob)
    if r.take(6) != MAGIC:
        raise Invalid("bad magic")
    if r.u32() != 1:
        raise Invalid("unsupported version")
    pub = r.string()
    ns = r.string()
    reserved = r.string()
    hash_alg = r.string()
    sig = r.string()
    if not r.done():
        raise Invalid("trailing bytes")
    if ns != namespace.encode():
        raise Invalid("wrong namespace")
    if pub not in allowed:
        raise Invalid("key not allowed")
    if hash_alg == b"sha512":
        mh = hashlib.sha512(message).digest()
    elif hash_alg == b"sha256":
        mh = hashlib.sha256(message).digest()
    else:
        raise Invalid("unsupported hash")

    pr = _R(pub)
    if pr.string() != SK_ED25519:
        raise Invalid("not an sk-ssh-ed25519 key")
    pk = pr.string()
    application = pr.string()
    if not pr.done() or len(pk) != 32:
        raise Invalid("malformed public key")

    sr = _R(sig)
    if sr.string() != SK_ED25519:
        raise Invalid("signature type does not match the key")
    raw = sr.string()
    flags = sr.u8()
    counter = sr.u32()
    if not sr.done() or len(raw) != 64:
        raise Invalid("malformed signature")

    signed = MAGIC + _s(ns) + _s(reserved) + _s(hash_alg) + _s(mh)
    device_msg = (hashlib.sha256(application).digest() + bytes([flags]) +
                  struct.pack(">I", counter) + hashlib.sha256(signed).digest())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(raw, device_msg)
    except Exception:
        raise Invalid("bad signature")
    # ⚠️ Checked AFTER the signature, because the flags are only trustworthy once signed.
    if not flags & FLAG_USER_PRESENT:
        raise Invalid("no user presence: the device signed without a touch")
    if require_uv and not flags & FLAG_USER_VERIFIED:
        raise Invalid("no user verification")
    return {"counter": counter, "flags": flags, "key_index": allowed.index(pub)}
