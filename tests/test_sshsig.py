#!/usr/bin/env python3
"""Security-key approvals: what the relay must accept and everything it must refuse.

⭐ WHY, 2026-10-01. The Ed25519 approval key was a file on the laptop that any agent there could
read. The replacement is an sk-ssh-ed25519 key on a YubiKey, verified here from OpenSSH's own
signature format. Each refusal below is a check a forgery could otherwise slip past.

📌 TWO KINDS OF VECTOR. A REAL signature made by the YubiKey and cross-checked with
`ssh-keygen -Y verify` (tests/fixtures/sshsig_yubikey.json) proves the parser matches OpenSSH. A
software key that builds the same format proves the refusals, including the one no real device
will produce on request: a validly signed blob with the touch flag clear.

Run:  python3 tests/test_sshsig.py
"""
import base64
import hashlib
import json
import os
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
import sshsig as S                                            # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser                  # noqa: E402

fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


def s(b):
    return struct.pack(">I", len(b)) + b


def soft_key(app=b"ssh:job-search-send"):
    k = Ed25519PrivateKey.generate()
    pk = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return k, s(S.SK_ED25519) + s(pk) + s(app), app


def sign(k, pub, app, msg, ns="job-search-send", flags=0x01, counter=7, hash_alg=b"sha512",
         sig_type=S.SK_ED25519):
    mh = (hashlib.sha512 if hash_alg == b"sha512" else hashlib.sha256)(msg).digest()
    signed = S.MAGIC + s(ns.encode()) + s(b"") + s(hash_alg) + s(mh)
    dev = hashlib.sha256(app).digest() + bytes([flags]) + struct.pack(">I", counter) + \
        hashlib.sha256(signed).digest()
    sig = s(sig_type) + s(k.sign(dev)) + bytes([flags]) + struct.pack(">I", counter)
    return S.MAGIC + struct.pack(">I", 1) + s(pub) + s(ns.encode()) + s(b"") + s(hash_alg) + s(sig)


def refused(label, blob, msg, allowed, ns="job-search-send", why=None):
    try:
        S.verify(blob, msg, ns, allowed)
        check(label, False)
    except S.Invalid as e:
        check(label + (f"  [{e}]" if why is None else ""), why is None or why in str(e))


MSG = b"nonce.1790000000.abcdef"
k, pub, app = soft_key()

print("a good signature:")
got = S.verify(sign(k, pub, app, MSG), MSG, "job-search-send", [pub])
check("is accepted", got["counter"] == 7 and got["key_index"] == 0)
check("…and sha256 is accepted too", S.verify(sign(k, pub, app, MSG, hash_alg=b"sha256"), MSG,
                                               "job-search-send", [pub]))
k2, pub2, app2 = soft_key()
check("a second allowed key is found by index",
      S.verify(sign(k2, pub2, app2, MSG), MSG, "job-search-send", [pub, pub2])["key_index"] == 1)

print("\nwhat must be refused:")
refused("🚨 no touch: validly signed, user-presence flag clear", sign(k, pub, app, MSG, flags=0x00),
        MSG, [pub], why="no user presence")
refused("🚨 a signature for another purpose (wrong namespace)", sign(k, pub, app, MSG, ns="git"),
        MSG, [pub], why="wrong namespace")
refused("🚨 a key that is not on the allowlist", sign(k2, pub2, app2, MSG), MSG, [pub],
        why="key not allowed")
refused("🚨 one character of the message changed", sign(k, pub, app, MSG), MSG + b"x", [pub],
        why="bad signature")
refused("🚨 the flags byte edited after signing", sign(k, pub, app, MSG)[:-5] + b"\x05" +
        sign(k, pub, app, MSG)[-4:], MSG, [pub], why="bad signature")
refused("a plain ssh-ed25519 signature type", sign(k, pub, app, MSG, sig_type=b"ssh-ed25519"),
        MSG, [pub], why="signature type")
refused("an unsupported hash", sign(k, pub, app, MSG, hash_alg=b"md5"), MSG, [pub],
        why="unsupported hash")
refused("trailing bytes", sign(k, pub, app, MSG) + b"\x00", MSG, [pub], why="trailing")
refused("truncated", sign(k, pub, app, MSG)[:40], MSG, [pub], why=None)
refused("bad magic", b"XXXXXX" + sign(k, pub, app, MSG)[6:], MSG, [pub], why="bad magic")
uv = sign(k, pub, app, MSG, flags=0x01)
try:
    S.verify(uv, MSG, "job-search-send", [pub], require_uv=True)
    check("require_uv refuses a touch-only signature", False)
except S.Invalid as e:
    check("require_uv refuses a touch-only signature", "verification" in str(e))

print("\nkey lines:")
line = f"sk-ssh-ed25519@openssh.com {base64.b64encode(pub).decode()} test"
check("a public key line parses to the blob", S.parse_pubkey_line(line) == pub)
try:
    S.parse_pubkey_line("ssh-ed25519 AAAA test")
    check("a plain ssh-ed25519 key line is refused", False)
except S.Invalid:
    check("a plain ssh-ed25519 key line is refused", True)

print("\nthe relay's token path (verify_approval):")
import tempfile                                                # noqa: E402
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/sk.db"
sys.path.insert(0, str(HERE))
import test_parse                                              # noqa: E402  (strips BUNNY_*)
app = test_parse.load_app()
if getattr(app, "BUNNY_DB_URL", ""):
    sys.exit("refusing to run: the app is bound to a remote database")
app.init_db()
fp = app.fingerprint("acme@jobs.example.com", "dana@acme.com", "Re: hi", "Thanks, Dana.")
nonce, exp = "n0nce", 4102444800


def tok(blob):
    return f"sk1.{nonce}.{exp}.{base64.urlsafe_b64encode(blob).decode().rstrip('=')}"


good = tok(sign(k, pub, b"ssh:job-search-send", f"{nonce}.{exp}.{fp}".encode()))
app.APPROVAL_SK_KEYS = line
check("a touch-signed token for THIS message is accepted", app.verify_approval(good, fp, "t") == nonce)
fp2 = app.fingerprint("acme@jobs.example.com", "dana@acme.com", "Re: hi", "Thanks, Dana!")
try:
    app.verify_approval(good, fp2, "t")
    check("🚨 the same token for an edited body is refused", False)
except app.HTTPException as e:
    check("🚨 the same token for an edited body is refused", e.code == 403)
app.APPROVAL_SK_KEYS = ""
try:
    app.verify_approval(good, fp, "t")
    check("with no APPROVAL_SK_KEYS a security-key token is refused", False)
except app.HTTPException as e:
    check("with no APPROVAL_SK_KEYS a security-key token is refused", e.code in (403, 500))
app.APPROVAL_SK_KEYS, app.APPROVAL_SK_ONLY = line, True
try:
    app.verify_approval("abc.4102444800.sig", fp, "t")
    check("🚨 APPROVAL_SK_ONLY refuses the old file-key approval", False)
except app.HTTPException as e:
    check("🚨 APPROVAL_SK_ONLY refuses the old file-key approval", e.code == 403)
app.APPROVAL_SK_ONLY = False

print("\n/send to an address that has never written (the real route, transport stubbed):")
# ⭐ WHY, 2026-10-01. The known-recipient rule refused Turnkey's own application address. A
# security-key approval now may reach a new address; a file-key approval may not, because that
# key can be read off the laptop. Jonathan applied the change himself; these pin it down.
import asyncio                                                  # noqa: E402
import secrets as _sec                                          # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EdK  # noqa: E402

FROM = f"turnkey@{app.MAIL_DOMAIN}"
COLD = "jobs@turnkey.example"
app.ADMIN_TOKEN, app.SMTP_USER, app.SMTP_PASS = "adm", "u", "p"
app.TRANSPORT_ORDER, app.REQUIRE_KNOWN_RECIPIENT = ["resend"], True
app.APPROVAL_SK_KEYS = line
_fk = _EdK.generate()                                           # the file key, for the legacy path
app.APPROVAL_PUBKEY = _fk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
delivered = []
app._send_via_resend = lambda f, t, s, b, parent, bcc=None: delivered.append(t) or "<stub@x>"


class _H(dict):
    def get(self, k, d=None): return dict.get(self, k, d)


class _Req:
    client = None
    def __init__(self, payload): self._p, self.headers = payload, _H()
    async def json(self): return self._p


def _payload(body):
    return {"from_alias": FROM, "to": COLD, "subject": "Application", "body": body, "approved": True}


def _sk_token(body):
    fp_ = app.fingerprint(FROM, COLD, "Application", body)
    n = _sec.token_urlsafe(8)
    return f"sk1.{n}.{exp}.{base64.urlsafe_b64encode(sign(k, pub, b'ssh:job-search-send', f'{n}.{exp}.{fp_}'.encode())).decode().rstrip('=')}"


def _file_token(body):
    fp_ = app.fingerprint(FROM, COLD, "Application", body)
    n = _sec.token_urlsafe(8)
    return f"{n}.{exp}.{base64.urlsafe_b64encode(_fk.sign(f'{n}.{exp}.{fp_}'.encode())).decode().rstrip('=')}"


def _send(body, token):
    try:
        r = asyncio.run(app.send(_Req(_payload(body)), authorization="Bearer adm", x_approval=token))
        return r.get("ok") and "sent"
    except app.HTTPException as e:
        return e.code


check("⭐ a YubiKey-approved send reaches a new address", _send("one", _sk_token("one")) == "sent"
      and delivered == [COLD])
with app.db() as _c:
    check("…and the event log says why it was allowed",
          _c.execute("SELECT count(*) n FROM event WHERE kind='send_cold_sk'").fetchone()["n"] == 1)
check("🚨 a file-key approval to a new address is still refused", _send("two", _file_token("two")) == 403)
check("…and nothing was delivered for it", delivered == [COLD])
app.SK_ALLOWS_COLD = False
check("🚨 SK_ALLOWS_COLD=0 refuses even a YubiKey approval", _send("three", _sk_token("three")) == 403)
app.SK_ALLOWS_COLD = True
with app.db() as _c:
    _c.execute("INSERT INTO message(received_at,to_alias,raw_payload,from_addr,application_ref) "
               "VALUES (?,?,?,?,?)", (app.now(), FROM, "{}", COLD, "turnkey"))
check("once they have written, a file-key approval reaches them as before",
      _send("four", _file_token("four")) == "sent")
_tok = _sk_token("five")
_send("five", _tok)
check("🚨 a used YubiKey approval cannot be replayed", _send("five", _tok) != "sent")

print("\nthe real YubiKey:")
fx = HERE / "fixtures" / "sshsig_yubikey.json"
if fx.exists():
    d = json.loads(fx.read_text())
    blob = S.unarmor(d["signature"])
    allowed = [S.parse_pubkey_line(d["public_key"])]
    r = S.verify(blob, d["message"].encode(), d["namespace"], allowed)
    check("a signature made by the device verifies (also checked by ssh-keygen -Y verify)",
          r["flags"] & S.FLAG_USER_PRESENT)
    refused("…and refuses the same signature for a different message", blob,
            d["message"].encode() + b"!", allowed, d["namespace"], why="bad signature")
else:
    check("the device fixture exists", False)

print(f"\n{'ALL PASS' if not fails else f'{len(fails)} FAILED'}")
sys.exit(1 if fails else 0)
