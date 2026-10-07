#!/usr/bin/env python3
"""Mail approval by passkey: the ceremony end to end, and everything the relay must refuse.

⭐ WHY, 2026-10-07. The harness moved to a VM that holds the admin token, and sending mail
still needed the laptop's YubiKey-SSH key. The passkey path lets the operator approve from a
phone. Its whole value is the refusals below, so each one is a case a forgery could otherwise
slip through.

📌 A SOFTWARE AUTHENTICATOR. A P-256 key here builds real registration and assertion
structures (CBOR, authenticator data, client data, an ECDSA signature), and the relay verifies
them with py_webauthn exactly as it would a YubiKey's. That also proves the point the design
rests on: software CAN make a credential, which is why activation needs a hardware key.

Two parts. The pure checks run anywhere. The ceremony needs `webauthn`; without it, it SKIPS,
and with --strict a skip is a failure (the drift job installs it and passes --strict).

Run:  python3 tests/test_passkey.py [--strict]
"""
import asyncio
import base64
import hashlib
import json
import os
import pathlib
import struct
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
sys.path.insert(0, str(HERE))
import passkey as P                                           # noqa: E402

fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


print("pure helpers:")
fp = hashlib.sha256(b"x").hexdigest()
ch = P.challenge_for(fp)
check("a challenge is 16 random bytes plus the 32-byte fingerprint", len(ch) == 48 and P.fp_in_challenge(ch) == fp)
check("two challenges for one email differ", P.challenge_for(fp) != ch)
check("enroll_message names the credential and its key",
      P.enroll_message("abc", b"KEY") == b"enroll.abc." + hashlib.sha256(b"KEY").hexdigest().encode())
check("enroll_message changes when the key changes",
      P.enroll_message("abc", b"KEY") != P.enroll_message("abc", b"KEY2"))
c = P.short_code(b"KEY")
check("short_code is three groups of four", len(c) == 14 and c.count("-") == 2)
check("sign count 0 -> 0 is allowed (many passkeys never count)", P.sign_count_ok(0, 0))
check("sign count must grow once it is used", P.sign_count_ok(5, 6) and not P.sign_count_ok(5, 5)
      and not P.sign_count_ok(5, 4))
check("the page script is served from the origin, not inline",
      "<script src=\"/passkey.js\">" in P.enroll_page("t") and "'unsafe-inline'" not in
      P.PAGE_HEADERS["Content-Security-Policy"].split("script-src")[1].split(";")[0])
check("the approval page escapes the email body",
      "<b>" not in P.approve_page("t", {"status": "queued", "from_alias": "a", "to_addr": "b",
                                         "subject": "s", "body": "<b>x</b>"}))

try:
    import webauthn                                           # noqa: F401
    import cbor2
except ImportError:
    print("\nSKIP the ceremony: pip install webauthn==2.8.0")
    if "--strict" in sys.argv:
        sys.exit("FAIL: --strict and webauthn is not installed")
    sys.exit(1 if fails else 0)

from cryptography.hazmat.primitives.asymmetric import ec                     # noqa: E402
from cryptography.hazmat.primitives import hashes                            # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser              # noqa: E402
import sshsig as S                                                           # noqa: E402

RP, ORIGIN = "relay.test", "https://relay.test"


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class SoftAuthenticator:
    """A P-256 credential that answers navigator.credentials.create/get."""

    def __init__(self):
        self.k = ec.generate_private_key(ec.SECP256R1())
        self.cid = os.urandom(32)
        self.count = 0

    def _cose(self):
        n = self.k.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def create(self, opts, origin=ORIGIN, flags=0x45):
        cd = json.dumps({"type": "webauthn.create", "challenge": opts["challenge"],
                         "origin": origin, "crossOrigin": False}).encode()
        ad = (hashlib.sha256(opts["rp"]["id"].encode()).digest() + bytes([flags]) + struct.pack(">I", 0)
              + bytes(16) + struct.pack(">H", len(self.cid)) + self.cid + self._cose())
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"id": b64u(self.cid), "rawId": b64u(self.cid), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "attestationObject": b64u(att), "transports": []},
                "clientExtensionResults": {}}

    def get(self, opts, origin=ORIGIN, flags=0x05, count=None, challenge=None):
        self.count = self.count + 1 if count is None else count
        cd = json.dumps({"type": "webauthn.get", "challenge": challenge or opts["challenge"],
                         "origin": origin, "crossOrigin": False}).encode()
        ad = hashlib.sha256(opts["rpId"].encode()).digest() + bytes([flags]) + struct.pack(">I", self.count)
        sig = self.k.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cid), "rawId": b64u(self.cid), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad),
                             "signature": b64u(sig), "userHandle": None},
                "clientExtensionResults": {}}


# ---- the relay, on a scratch database, transport stubbed ------------------------------
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/pk.db"
import test_parse                                             # noqa: E402  (strips BUNNY_*)
app = test_parse.load_app()
if getattr(app, "BUNNY_DB_URL", ""):
    sys.exit("refusing to run: the app is bound to a remote database")
app.init_db()
app.PUBLIC_URL, app.NTFY_URL = ORIGIN, ""
app.ADMIN_TOKEN, app.SMTP_USER, app.SMTP_PASS = "adm", "u", "p"
app.TRANSPORT_ORDER, app.REQUIRE_KNOWN_RECIPIENT, app.SK_ALLOWS_COLD = ["resend"], True, True
delivered = []
app._send_via_resend = lambda f, t, s, b, parent, bcc=None: delivered.append((t, b)) or "<stub@x>"

# The operator's hardware key, as test_sshsig builds one.
_sk = Ed25519PrivateKey.generate()
_skpk = _sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
_sb = lambda b: struct.pack(">I", len(b)) + b                 # noqa: E731
SKPUB = _sb(S.SK_ED25519) + _sb(_skpk) + _sb(b"ssh:job-search-send")
app.APPROVAL_SK_KEYS = f"sk-ssh-ed25519@openssh.com {base64.b64encode(SKPUB).decode()} op"


def sk_sign(msg, ns=P.ENROLL_NAMESPACE, flags=0x01):
    mh = hashlib.sha512(msg).digest()
    signed = S.MAGIC + _sb(ns.encode()) + _sb(b"") + _sb(b"sha512") + _sb(mh)
    dev = hashlib.sha256(b"ssh:job-search-send").digest() + bytes([flags]) + struct.pack(">I", 3) + \
        hashlib.sha256(signed).digest()
    sig = _sb(S.SK_ED25519) + _sb(_sk.sign(dev)) + bytes([flags]) + struct.pack(">I", 3)
    blob = S.MAGIC + struct.pack(">I", 1) + _sb(SKPUB) + _sb(ns.encode()) + _sb(b"") + _sb(b"sha512") + _sb(sig)
    return b64u(blob)


class _H(dict):
    def get(self, k, d=None): return dict.get(self, k, d)


class Req:
    client = None
    def __init__(self, payload=None): self._p, self.headers = payload or {}, _H()
    async def json(self): return self._p


def call(fn, *a, **k):
    """(result, None) or (None, http code)."""
    try:
        r = fn(*a, **k)
        if asyncio.iscoroutine(r):
            r = asyncio.run(r)
        return (json.loads(json.dumps(getattr(r, "content", r))), None)
    except app.HTTPException as e:
        return None, e.code


ADM = "Bearer adm"
FROM, TO = f"acme@{app.MAIL_DOMAIN}", "jobs@acme.example"
EMAIL = {"from_alias": FROM, "to": TO, "subject": "Re: next steps", "body": "Thursday works. Thanks."}

print("\nenrollment:")
yk = SoftAuthenticator()
r, e = call(app.passkey_enroll_start, Req(), authorization=None)
check("minting an enrollment link needs the admin token", e == 401)
r, _ = call(app.passkey_enroll_start, Req(), authorization=ADM)
etok = r["url"].rsplit("/", 1)[1]
opts, _ = call(app.passkey_enroll_options, etok)
reg, _ = call(app.passkey_enroll_verify, etok, Req({"label": "YubiKey 5C", "credential": yk.create(opts)}))
check("a registration is stored PENDING with a code", reg and reg["status"] == "pending" and len(reg["code"]) == 14)
check("the code is the one the laptop will compute", reg["code"] == P.short_code(yk._cose()))
_, e = call(app.passkey_enroll_verify, etok, Req({"credential": yk.create(opts)}))
check("🚨 an enrollment link works once", e in (404, 409))

print("\na pending credential approves nothing:")
_, e = call(app.send_queue_add, Req(EMAIL), authorization=ADM)
check("🚨 queueing is refused while no credential is ACTIVE", e == 409)

print("\nactivation:")
cid = reg["credential_id"]
with app.db() as con:
    pub = P.unb64u(con.execute("SELECT public_key FROM passkey_credential WHERE credential_id=?",
                               (cid,)).fetchone()["public_key"])
msg = P.enroll_message(cid, pub)
_, e = call(app.passkey_activate, Req({"credential_id": cid, "signature": sk_sign(msg, ns="job-search-send")}),
            authorization=ADM)
check("🚨 a send-namespace signature cannot activate (namespaces are separate)", e == 403)
_, e = call(app.passkey_activate, Req({"credential_id": cid, "signature": sk_sign(msg, flags=0x00)}),
            authorization=ADM)
check("🚨 a signature without the touch flag cannot activate", e == 403)
_, e = call(app.passkey_activate, Req({"credential_id": cid, "signature": sk_sign(P.enroll_message(cid, b"other"))}),
            authorization=ADM)
check("🚨 a signature over a different key cannot activate", e == 403)
r, _ = call(app.passkey_activate, Req({"credential_id": cid, "signature": sk_sign(msg)}), authorization=ADM)
check("⭐ a touch-signed activation makes it ACTIVE", r and r["status"] == "active")

print("\nqueue, approve, send:")
_, e = call(app.send_queue_add, Req(EMAIL), authorization=None)
check("queueing needs the admin token", e == 401)
q, _ = call(app.send_queue_add, Req(EMAIL), authorization=ADM)
qtok = q["url"].rsplit("/", 1)[1]
check("queueing sends nothing", q and q["ok"] and delivered == [])

o, _ = call(app.approve_options, qtok, Req())
check("the challenge carries this email's fingerprint",
      P.fp_in_challenge(P.unb64u(o["challenge"])) == q["fingerprint"])
check("the options demand user verification", o.get("userVerification") == "required")
_, e = call(app.approve_verify, qtok, Req(yk.get(o, flags=0x01)))
check("🚨 an assertion without user verification (PIN/biometric) is refused", e == 403 and delivered == [])

o, _ = call(app.approve_options, qtok, Req())
stranger = SoftAuthenticator()
_, e = call(app.approve_verify, qtok, Req(stranger.get(o)))
check("🚨 a credential that was never activated is refused", e == 403 and delivered == [])

o, _ = call(app.approve_options, qtok, Req())
_, e = call(app.approve_verify, qtok, Req(yk.get(o, origin="https://evil.test")))
check("🚨 an assertion from another origin is refused", e == 403 and delivered == [])

o, _ = call(app.approve_options, qtok, Req())
with app.db() as con:                                        # an agent edits the queued email
    con.execute("UPDATE send_queue SET body=? WHERE token=?", ("Changed by someone else.", qtok))
_, e = call(app.approve_verify, qtok, Req(yk.get(o)))
check("🚨 an email changed after queueing is refused", e == 403 and delivered == [])
with app.db() as con:
    con.execute("UPDATE send_queue SET body=? WHERE token=?", (EMAIL["body"], qtok))

o, _ = call(app.approve_options, qtok, Req())
o2, _ = call(app.approve_options, qtok, Req())
_, e = call(app.approve_verify, qtok, Req(yk.get(o)))
check("🚨 an assertion over a superseded challenge is refused", e == 403 and delivered == [])

o, _ = call(app.approve_options, qtok, Req())
r, e = call(app.approve_verify, qtok, Req(yk.get(o)))
check("⭐ a verified assertion sends THIS exact email", r and r.get("ok") and delivered == [(TO, EMAIL["body"])])
with app.db() as con:
    row = con.execute("SELECT status, draft_id, approved_by FROM send_queue WHERE token=?", (qtok,)).fetchone()
    cold = con.execute("SELECT count(*) n FROM event WHERE kind='send_cold_sk'").fetchone()["n"]
check("…the queue row says sent, with the draft and who approved", row["status"] == "sent"
      and row["draft_id"] and row["approved_by"] == "passkey:YubiKey 5C")
check("…and a new address was allowed the way a YubiKey touch allows it", cold == 1)

_, e = call(app.approve_verify, qtok, Req(yk.get(o)))
check("🚨 the same assertion cannot send it twice", e == 409 and len(delivered) == 1)
_, e = call(app.approve_options, qtok, Req())
check("🚨 a sent email offers no new challenge", e == 409)

print("\nclone detection:")
q2, _ = call(app.send_queue_add, Req({**EMAIL, "body": "Second one."}), authorization=ADM)
t2 = q2["url"].rsplit("/", 1)[1]
o, _ = call(app.approve_options, t2, Req())
_, e = call(app.approve_verify, t2, Req(yk.get(o, count=1)))
check("🚨 a sign count that went backwards is refused", e == 403 and len(delivered) == 1)

print("\nthe laptop command, approve.py passkey-activate (window replaced, relay in-process):")
# ⭐ This runs the REAL command function. Only the two things a test cannot do are replaced:
# the GTK window (by the software security key, which signs in whatever namespace it is asked
# for) and the network (urlopen is routed to the endpoint functions above).
import io                                                     # noqa: E402
import urllib.request as _ur                                  # noqa: E402
import approve as AP                                          # noqa: E402

phone = SoftAuthenticator()
r, _ = call(app.passkey_enroll_start, Req(), authorization=ADM)
t3 = r["url"].rsplit("/", 1)[1]
o, _ = call(app.passkey_enroll_options, t3)
reg2, _ = call(app.passkey_enroll_verify, t3, Req({"label": "Pixel", "credential": phone.create(o)}))
seen_ns = []


def _fake_touch(key, message, header, body, namespace=AP.SK_NAMESPACE):
    seen_ns.append(namespace)
    check("the window shows the code the phone showed", any(reg2["code"] in h for h in header))
    # touch_sign() splits each header line on its first colon; v0.90.0 shipped one without.
    check("every window header line is 'Label: value'", all(":" in h for h in header))
    raw = P.unb64u(sk_sign(message, ns=namespace))
    return "-----BEGIN SSH SIGNATURE-----\n" + base64.b64encode(raw).decode() + "\n-----END SSH SIGNATURE-----", ""


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _fake_urlopen(req, timeout=None):
    path = req.full_url.split(ORIGIN, 1)[1]
    payload = json.loads(req.data) if req.data else None
    fn = {"/passkey/credentials": app.passkey_credentials, "/passkey/activate": app.passkey_activate}[path]
    out, code = call(fn, Req(payload), authorization=req.get_header("Authorization"))
    if code:
        raise AP.urllib.error.HTTPError(req.full_url, code, "refused", {}, io.BytesIO(b"{}"))
    return _Resp(json.dumps(out).encode())


keyfile = pathlib.Path(tempfile.mkdtemp()) / "id_sk"
keyfile.with_suffix(".pub").write_text(app.APPROVAL_SK_KEYS + "\n")
os.environ.update(RELAY_URL=ORIGIN, RELAY_API_TOKEN="adm")
AP.touch_sign, _real_urlopen, _ur.urlopen = _fake_touch, _ur.urlopen, _fake_urlopen
try:
    rc = AP.passkey_activate_main(["--sk-key", str(keyfile)])
finally:
    _ur.urlopen = _real_urlopen
check("it signs in the ENROLLMENT namespace, never the send one", seen_ns == [P.ENROLL_NAMESPACE])
with app.db() as con:
    st = con.execute("SELECT status FROM passkey_credential WHERE credential_id=?",
                     (reg2["credential_id"],)).fetchone()["status"]
check("⭐ the command activates the one pending credential", rc == 0 and st == "active")

print("\nrevocation:")
for _c in (cid, reg2["credential_id"]):
    call(app.passkey_revoke, Req({"credential_id": _c}), authorization=ADM)
o, e = call(app.approve_options, t2, Req())
check("a revoked credential leaves nothing able to approve", e == 409)

print(f"\n{'ALL PASS' if not fails else f'{len(fails)} FAILED'}")
sys.exit(1 if fails else 0)
