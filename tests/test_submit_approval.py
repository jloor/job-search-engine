#!/usr/bin/env python3
"""A person's passkey approval of one exact submit record, and the live run that consumes it.

⭐ WHY, 2026-10-08. The submitter could fill and verify a form, and only a person could click
Submit. The last mile is one click, gated by the operator's passkey over the EXACT record the
shadow run read back. These cases are what makes that gate worth having.

🚨 WHAT MUST NEVER HAPPEN:
  - an approval that does not bind the record (a record edited after approval still passing);
  - an approval used twice, or a live run that arms twice (a duplicate application);
  - application.status changing for any run that did not consume an approval;
  - the submit token approving, or arming without an approved record that matches.

The ceremony needs `webauthn` and `cbor2`; without them it SKIPS, and --strict fails the skip.

Run:  python3 tests/test_submit_approval.py [--strict]
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
import record as R                                            # noqa: E402

fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


print("the record fingerprint (record.py):")
F = [{"id": "first_name", "label": "First Name", "value": "Alex"},
     {"id": "email", "label": "Email", "value": "acme@jobs.example.com"}]
FILES = {"resume.pdf": "a" * 64}
fp = R.fingerprint(7, "https://job-boards.greenhouse.io/acme/jobs/1", F, FILES)
check("it is 64 hex characters", len(fp) == 64 and int(fp, 16) >= 0)
check("field order and spacing do not change it",
      fp == R.fingerprint(7, "https://job-boards.greenhouse.io/acme/jobs/1",
                          [dict(F[1], value="  acme@jobs.example.com "), F[0]], FILES))
check("a changed value changes it",
      fp != R.fingerprint(7, "https://job-boards.greenhouse.io/acme/jobs/1",
                          [F[0], dict(F[1], value="other@jobs.example.com")], FILES))
check("a changed file changes it", fp != R.fingerprint(7, "https://job-boards.greenhouse.io/acme/jobs/1",
                                                       F, {"resume.pdf": "b" * 64}))
check("another application changes it", fp != R.fingerprint(8, "https://job-boards.greenhouse.io/acme/jobs/1", F, FILES))
try:
    R.fingerprint(7, "u", F, {"resume.pdf": "not-a-hash"})
    check("a malformed file hash is refused", False)
except ValueError:
    check("a malformed file hash is refused", True)

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


os.environ["DB_PATH"] = tempfile.mkdtemp() + "/sa.db"
import test_parse                                             # noqa: E402  (strips BUNNY_*)
app = test_parse.load_app()
if getattr(app, "BUNNY_DB_URL", ""):
    sys.exit("refusing to run: the app is bound to a remote database")
app.init_db()
app.PUBLIC_URL, app.NTFY_URL = ORIGIN, ""
app.ADMIN_TOKEN, app.READ_TOKEN, app.SUBMIT_TOKEN = "adm", "rd", "sub"
S, ADM = "Bearer sub", "Bearer adm"


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


URL = "https://job-boards.greenhouse.io/acme/jobs/1"
yk = SoftAuthenticator()
with app.db() as con:
    con.execute("INSERT INTO company(id, name) VALUES (1, 'Acme')")
    for i in (1, 2):
        con.execute("INSERT INTO posting(id, company_id, title, canonical_url, captured_at) "
                    "VALUES (?,1,'Role',?, '2026-10-01')", (i, URL if i == 1 else URL + "0"))
        con.execute("INSERT INTO application(id, posting_id, status, package_path, alias_used, company_raw, "
                    "role_raw) VALUES (?,?, 'draft', 'applications/acme/a', 'acme@jobs.example.com', "
                    "'Acme', 'Role')", (i, i))
    con.execute("INSERT INTO passkey_credential(credential_id, public_key, sign_count, label, status, code, "
                "created_at) VALUES (?,?,0,'phone','active','TEST-CODE-0000','2026-10-08')", (b64u(yk.cid), b64u(yk.cose())))


def shadow(app_id, fields=F, files=FILES, fp_override=None):
    run = call(app.submit_run_open, Req({"application_id": app_id, "mode": "shadow"}), authorization=S)[0]["run_id"]
    url = URL if app_id == 1 else URL + "0"
    rfp = fp_override or R.fingerprint(app_id, url, fields, files)
    return run, call(app.submit_run_close, run, Req({"outcome": "shadow_complete", "record_fp": rfp,
                                                      "record": {"fields": fields, "files": files}}),
                     authorization=S)


print("\na shadow run produces an approval:")
run_bad, (_, e) = shadow(2, fp_override="0" * 64)
check("a record whose fingerprint the relay cannot reproduce is refused (400)", e == 400)
_, e = call(app.submit_run_close, run_bad, Req({"outcome": "error", "stop_reason": "record refused"}),
            authorization=S)
check("…and the run is still open, so the runner can close it as an error", e is None)
run1, (r, e) = shadow(1)
token = r["approval_url"].rsplit("/", 1)[1]
check("a complete shadow run returns an approval link", e is None and "/submit/approve/" in r["approval_url"])
with app.db() as con:
    st = con.execute("SELECT status FROM application WHERE id=1").fetchone()["status"]
check("…and the application is still a draft", st == "draft")
with app.db() as con:
    item = app._approval_item(con, token)
page = P.submit_approve_page(token, item)
check("the approval page shows the field values", "acme@jobs.example.com" in page)
check("…and its button points the script at the submit approval endpoints",
      "data-base='/submit/approve/'" in page)
check("the page escapes field values", "<b>" not in P.submit_approve_page(
    token, dict(item, record_json=json.dumps({"fields": [{"id": "x", "label": "L", "value": "<b>v</b>"}]}))))
check("the live queue is empty until a person approves",
      call(app.submit_next, Req(), authorization=S, app_id=1, mode="live")[0]["next"] is None)


def opts():
    o, e = call(app.submit_approve_options, token, Req())
    return o, e


print("\nthe passkey must approve THIS record:")
o, _ = opts()
check("options carry a challenge that embeds the record fingerprint",
      P.fp_in_challenge(base64.urlsafe_b64decode(o["challenge"] + "==")) ==
      R.fingerprint(1, URL, F, FILES))
_, e = call(app.submit_approve_verify, token, Req(yk.get(o, flags=0x01)))
check("no user verification: refused", e == 403)
o, _ = opts()
_, e = call(app.submit_approve_verify, token, Req(yk.get(o, origin="https://evil.test")))
check("another origin: refused", e == 403)
o_old, _ = opts()
o, _ = opts()
_, e = call(app.submit_approve_verify, token, Req(yk.get(o_old)))
check("a superseded challenge: refused", e in (403, 409))
o, _ = opts()
with app.db() as con:
    con.execute("UPDATE submit_approval SET record_json=replace(record_json, 'Alex', 'Mallory')")
_, e = call(app.submit_approve_verify, token, Req(yk.get(o)))
check("🚨 the record edited after the shadow run: refused", e == 403)
with app.db() as con:
    con.execute("UPDATE submit_approval SET record_json=replace(record_json, 'Mallory', 'Alex')")
with app.db() as con:          # a credential that HAS counted: 0 is allowed only for one that never does
    con.execute("UPDATE passkey_credential SET sign_count=10")
o, _ = opts()
_, e = call(app.submit_approve_verify, token, Req(yk.get(o, count=5)))
check("a sign count that went backwards: refused", e == 403)
o, _ = opts()
good = yk.get(o, count=50)
r, e = call(app.submit_approve_verify, token, Req(good))
check("the right passkey over the right record approves it", e is None and r["approved"])
_, e = call(app.submit_approve_verify, token, Req(good))
check("the same assertion again: refused", e == 409)
with app.db() as con:
    st = con.execute("SELECT status FROM application WHERE id=1").fetchone()["status"]
check("🚨 approving submits nothing: still a draft", st == "draft")

print("\nthe live run:")
nxt = call(app.submit_next, Req(), authorization=S, app_id=1, mode="live")[0]["next"]
check("the approved draft is offered to a LIVE run, with its record fingerprint",
      nxt and nxt["record_fp"] == R.fingerprint(1, URL, F, FILES))
check("…but not to a shadow run", call(app.submit_next, Req(), authorization=S, app_id=1)[0]["next"] is None)
_, e = call(app.submit_run_open, Req({"application_id": 1, "mode": "live", "record_fp": "0" * 64}),
            authorization=S)
check("a live run that does not carry the approved record cannot open", e == 409)
live = call(app.submit_run_open, Req({"application_id": 1, "mode": "live", "record_fp": nxt["record_fp"]}),
            authorization=S)[0]["run_id"]
_, e = call(app.submit_run_submitted, live, Req({"url": "x"}), authorization=S)
check("🚨 reporting a submission before arming: refused", e == 409)
_, e = call(app.submit_run_arm, live, Req({"record_fp": "0" * 64}), authorization=S)
check("arming with a different record: refused", e == 409)
_, e = call(app.submit_run_arm, live, Req({"record_fp": nxt["record_fp"]}), authorization="Bearer adm")
check("the admin token cannot arm (submit scope only)", e == 403)
r, e = call(app.submit_run_arm, live, Req({"record_fp": nxt["record_fp"]}), authorization=S)
check("arming consumes the approval and returns a nonce", e is None and len(r["nonce"]) == 32)
_, e = call(app.submit_run_arm, live, Req({"record_fp": nxt["record_fp"]}), authorization=S)
check("🚨 a second arm: refused (one approval, one click)", e == 409)
_, e = call(app.submit_run_submitted, run1, Req({"url": "x"}), authorization=S)
check("a shadow run can never report a submission", e == 409)
r, e = call(app.submit_run_submitted, live, Req({"url": URL + "/confirmation", "excerpt": "Thank you"}),
            authorization=S)
with app.db() as con:
    row = dict(con.execute("SELECT status, status_source FROM application WHERE id=1").fetchone())
    run = dict(con.execute("SELECT outcome, stop_reason FROM submit_run WHERE id=?", (live,)).fetchone())
check("the armed live run marks the application submitted, source 'submitter'",
      e is None and row == {"status": "submitted", "status_source": "submitter"})
check("…and the run keeps the proof", run["outcome"] == "submitted" and "/confirmation" in run["stop_reason"])
_, e = call(app.submit_run_submitted, live, Req({"url": "x"}), authorization=S)
check("a second report: refused", e == 409)

print("\nclosing rules:")
s2 = call(app.submit_run_open, Req({"application_id": 2, "mode": "shadow"}), authorization=S)[0]["run_id"]
_, e = call(app.submit_run_close, s2, Req({"outcome": "unknown"}), authorization=S)
check("only a live run closes 'unknown'", e == 400)
_, e = call(app.submit_run_close, s2, Req({"outcome": "submitted"}), authorization=S)
check("no runner can close a run 'submitted' (only the armed route sets it)", e == 400)
with app.db() as con:
    con.execute("UPDATE submit_approval SET status='pending', expires_at=0 WHERE application_id=1")
_, e = opts()
check("an expired approval cannot be approved", e == 409)

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
