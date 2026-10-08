#!/usr/bin/env python3
"""Root operations approved by passkey: the relay's half (rootops.py and the /root/* routes).

⭐ WHY, 2026-10-08. The operator is often away from the host's admin login, and some maintenance
needs root. A root broker on the host runs a FIXED list of operations, each one only after it has
verified the operator's passkey assertion itself. The relay carries the request and the assertion.

🚨 WHAT MUST NEVER HAPPEN:
  - the relay running anything, or the admin or submit token reaching the broker's routes;
  - an assertion stored for a request whose hash does not match its operation;
  - the same request approved twice, or approved after it expired;
  - the canonical form drifting from the broker's copy (CANONICAL_VECTOR, checked by both suites).

The ceremony needs `webauthn` and `cbor2`; without them it SKIPS, and --strict fails the skip.

Run:  python3 tests/test_root_request.py [--strict]
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
import rootops as RO                                          # noqa: E402

fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


print("the operation list and the canonical form (rootops.py):")
vec, want = RO.CANONICAL_VECTOR
check("the shared test vector hashes as the broker expects", RO.op_hash(**vec) == want)
check("the canonical form carries the domain, the host and the expiry",
      all(s in RO.canonical(**vec) for s in (b'"d":"job-search-root-op.v1"', b'"host":"host01"',
                                              b'"exp":1791000000')))
check("another host changes the hash", RO.op_hash(**dict(vec, host="other")) != want)
check("another expiry changes the hash", RO.op_hash(**dict(vec, expires=1791000001)) != want)
for label, op, args in [("an op not on the list", "shell", {"cmd": "id"}),
                        ("a tag that is not a release tag", "submitter-install", {"tag": "main"}),
                        ("a tag with a shell suffix", "submitter-install", {"tag": "v1.2.3;id"}),
                        ("an extra argument", "submitter-install", {"tag": "v1.2.3", "x": "y"}),
                        ("a missing argument", "sudoers-level", {"level": "LIVE"}),
                        ("a level not on the list (OPERATE)", "sudoers-level", {"level": "OPERATE", "state": "off"}),
                        ("a non-string argument", "submitter-timer", {"state": True}),
                        # 🚨 THE ESCALATING DIRECTIONS (2026-10-08): a tap may stop, never start or grant.
                        ("🚨 timer ON (lifts a brake)", "submitter-timer", {"state": "on"}),
                        ("🚨 kill switch OFF (lifts a brake)", "submitter-kill", {"state": "off"}),
                        ("🚨 sudo level INSTALL ON (grants a right)", "sudoers-level", {"level": "INSTALL", "state": "on"}),
                        ("🚨 sudo level RELEASE ON (grants a right)", "sudoers-level", {"level": "RELEASE", "state": "on"}),
                        ("🚨 sudo level LIVE ON (grants a right)", "sudoers-level", {"level": "LIVE", "state": "on"})]:
    try:
        RO.validate(op, args, "host01")
        check(f"refused: {label}", False)
    except ValueError:
        check(f"refused: {label}", True)
for op, args in [("submitter-install", {"tag": "v1.2.3"}), ("submitter-timer", {"state": "off"}),
                 ("submitter-kill", {"state": "on"}), ("sudoers-level", {"level": "LIVE", "state": "off"})]:
    try:
        RO.validate(op, args, "host01")
        check(f"allowed: {op} {args}", True)
    except ValueError:
        check(f"allowed: {op} {args}", False)
try:
    RO.validate("submitter-timer", {"state": "off"}, "Bad Host")
    check("refused: a malformed host", False)
except ValueError:
    check("refused: a malformed host", True)

try:
    import webauthn                                           # noqa: F401
    import cbor2
except ImportError:
    print("\nSKIP the ceremony: pip install webauthn==2.8.0")
    if "--strict" in sys.argv:
        sys.exit("FAIL: --strict and webauthn is not installed")
    sys.exit(1 if fails else 0)

from cryptography.hazmat.primitives import hashes            # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec     # noqa: E402

RP, ORIGIN = "relay.test", "https://relay.test"


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class SoftAuthenticator:
    """A P-256 credential that answers navigator.credentials.get (see test_passkey.py)."""

    def __init__(self):
        self.k = ec.generate_private_key(ec.SECP256R1())
        self.cid = os.urandom(32)
        self.count = 0

    def cose(self):
        n = self.k.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def get(self, opts, origin=ORIGIN, flags=0x05, count=None):
        self.count = self.count + 1 if count is None else count
        cd = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"],
                         "origin": origin, "crossOrigin": False}).encode()
        ad = hashlib.sha256(opts["rpId"].encode()).digest() + bytes([flags]) + struct.pack(">I", self.count)
        sig = self.k.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cid), "rawId": b64u(self.cid), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad),
                             "signature": b64u(sig), "userHandle": None},
                "clientExtensionResults": {}}


os.environ["DB_PATH"] = tempfile.mkdtemp() + "/ro.db"
import test_parse                                             # noqa: E402  (strips BUNNY_*)
app = test_parse.load_app()
if getattr(app, "BUNNY_DB_URL", ""):
    sys.exit("refusing to run: the app is bound to a remote database")
app.init_db()
app.PUBLIC_URL, app.NTFY_URL = ORIGIN, ""
app.ADMIN_TOKEN, app.READ_TOKEN, app.SUBMIT_TOKEN, app.ROOT_BROKER_TOKEN = "adm", "rd", "sub", "brk"
ADM, BRK = "Bearer adm", "Bearer brk"


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


yk = SoftAuthenticator()
with app.db() as con:
    con.execute("INSERT INTO passkey_credential(credential_id, public_key, sign_count, label, status, code, "
                "created_at, activated_at) VALUES (?,?,0,'phone','active','TEST-CODE-0000','2026-10-08',"
                "'2026-10-08')", (b64u(yk.cid), b64u(yk.cose())))

print("\nqueue a request (admin only):")
REQ = {"op": "submitter-install", "args": {"tag": "v0.93.2"}, "host": "host01"}
for tok, label in (("Bearer rd", "the read token"), ("Bearer sub", "the submit token"),
                   (BRK, "the broker token")):
    _, e = call(app.root_request_create, Req(REQ), authorization=tok)
    check(f"{label} cannot queue a root request", e in (401, 403))
_, e = call(app.root_request_create, Req(dict(REQ, op="shell", args={"cmd": "id"})), authorization=ADM)
check("an op not on the list is refused (400)", e == 400)
_, e = call(app.root_request_create, Req(dict(REQ, op="sudoers-level", args={"level": "LIVE", "state": "on"})),
            authorization=ADM)
check("🚨 a request to GRANT a sudo level is refused at the relay too (400)", e == 400)
r, e = call(app.root_request_create, Req(REQ), authorization=ADM)
check("the admin token queues one and gets an approval link", e is None and "/root/approve/" in r["approval_url"])
rid, token = r["id"], r["approval_url"].rsplit("/", 1)[1]
check("…whose hash is the canonical hash of exactly that request",
      r["op_hash"] == RO.op_hash("submitter-install", {"tag": "v0.93.2"}, "host01", r["expires_at"]))

print("\nthe broker's routes take the broker token only:")
for tok, label in ((ADM, "the admin token"), ("Bearer rd", "the read token"), ("Bearer sub", "the submit token"),
                   ("Bearer nope", "a wrong token"), (None, "no token")):
    _, e1 = call(app.root_pending, Req(), authorization=tok)
    _, e2 = call(app.root_result, rid, Req({"outcome": "done"}), authorization=tok)
    _, e3 = call(app.root_credentials, Req(), authorization=tok)
    check(f"{label}: refused on /root/pending, /root/result and /root/credentials",
          all(x in (401, 403) for x in (e1, e2, e3)))
check("nothing is pending before a person approves",
      call(app.root_pending, Req(), authorization=BRK)[0]["pending"] == [])
_, e = call(app.root_result, rid, Req({"outcome": "done"}), authorization=BRK)
check("a result for a request nobody approved is refused (409)", e == 409)
creds = call(app.root_credentials, Req(), authorization=BRK)[0]["credentials"]
check("the installer can read the active passkey's public key", creds and creds[0]["public_key"] == b64u(yk.cose()))

with app.db() as con:
    item = app._root_item(con, token)
page = P.root_approve_page(token, item)
check("the page says what runs, in plain words", "Install engine v0.93.2 into the submitter" in page)
check("…names the host, and points its button at the root endpoints",
      "host01" in page and "data-base='/root/approve/'" in page)


def opts():
    return call(app.root_approve_options, token, Req())


print("\nthe passkey must approve THIS request:")
o, _ = opts()
check("options carry a challenge that embeds the operation hash",
      P.fp_in_challenge(base64.urlsafe_b64decode(o["challenge"] + "==")) == r["op_hash"])
_, e = call(app.root_approve_verify, token, Req(yk.get(o, flags=0x01)))
check("no user verification: refused", e == 403)
o, _ = opts()
_, e = call(app.root_approve_verify, token, Req(yk.get(o, origin="https://evil.test")))
check("another origin: refused", e == 403)
o, _ = opts()
with app.db() as con:
    con.execute("UPDATE root_request SET args_json=? WHERE id=?", (json.dumps({"tag": "v6.6.6"}), rid))
_, e = call(app.root_approve_verify, token, Req(yk.get(o)))
check("🚨 the operation edited after it was queued: refused", e == 403)
with app.db() as con:
    con.execute("UPDATE root_request SET args_json=? WHERE id=?", (json.dumps({"tag": "v0.93.2"}), rid))
o, _ = opts()
good = yk.get(o, count=7)
r2, e = call(app.root_approve_verify, token, Req(good))
check("the right passkey over the right request approves it", e is None and r2["approved"])
_, e = call(app.root_approve_verify, token, Req(good))
check("the same assertion again: refused", e == 409)
with app.db() as con:
    st = con.execute("SELECT status FROM root_request WHERE id=?", (rid,)).fetchone()["status"]
check("approving runs nothing: the request waits for the broker", st == "approved")

print("\nthe broker's view:")
pend = call(app.root_pending, Req(), authorization=BRK)[0]["pending"]
check("the approved request is pending, with the raw assertion", len(pend) == 1 and pend[0]["assertion_json"])
a = json.loads(pend[0]["assertion_json"])
ch = json.loads(base64.urlsafe_b64decode(a["response"]["clientDataJSON"] + "=="))["challenge"]
chb = base64.urlsafe_b64decode(ch + "==")
h = RO.op_hash(pend[0]["op"], json.loads(pend[0]["args_json"]), pend[0]["host"], pend[0]["expires_at"])
check("…and the signed challenge carries the hash of the operation, recomputable from the row",
      chb[16:].hex() == h)
v = webauthn.verify_authentication_response(
    credential=a, expected_challenge=chb, expected_rp_id=RP, expected_origin=ORIGIN,
    credential_public_key=yk.cose(), credential_current_sign_count=0, require_user_verification=True)
check("…and the stored assertion verifies on its own, as the broker will verify it", v.new_sign_count == 7)
_, e = call(app.root_request_get, rid, Req(), authorization=ADM)
check("the harness can read the status", e is None)
check("…but never the assertion", "assertion_json" not in call(app.root_request_get, rid, Req(), authorization=ADM)[0])
_, e = call(app.root_result, rid, Req({"outcome": "maybe"}), authorization=BRK)
check("a result other than done, failed or refused: 400", e == 400)
r3, e = call(app.root_result, rid, Req({"outcome": "done", "code": 0, "output": "installed: 0.93.2"}),
             authorization=BRK)
check("the broker records the result", e is None)
check("…and the request leaves the pending list", call(app.root_pending, Req(), authorization=BRK)[0]["pending"] == [])
_, e = call(app.root_result, rid, Req({"outcome": "done"}), authorization=BRK)
check("a second result: refused (409)", e == 409)

print("\nexpiry:")
r4 = call(app.root_request_create, Req(dict(REQ, op="submitter-timer", args={"state": "off"})),
          authorization=ADM)[0]
tok4 = r4["approval_url"].rsplit("/", 1)[1]
with app.db() as con:
    con.execute("UPDATE root_request SET expires_at=? WHERE id=?", (int(__import__("time").time()) + 60, r4["id"]))
_, e = call(app.root_approve_options, tok4, Req())
check("a request inside the broker's pickup margin can no longer be approved", e == 409)

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
