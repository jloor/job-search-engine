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
_inj = P.submit_approve_page(token, dict(item, record_json=json.dumps(
    {"fields": [{"id": "x", "label": "L", "value": "<b>v</b>"}]})))
check("the page escapes field values (the value's own markup never renders)",
      "<b>v</b>" not in _inj and "&lt;b&gt;v&lt;/b&gt;" in _inj)
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

print("\nreleasing a record:")
with app.db() as con:
    con.execute("UPDATE submit_approval SET status='pending', expires_at=? WHERE application_id=1",
                (2_000_000_000,))
call(app.submit_clear, 1, Req({"note": "retake"}), authorization=ADM)
with app.db() as con:
    st = con.execute("SELECT status FROM submit_approval WHERE application_id=1").fetchone()["status"]
check("a clear expires the application's unused approval, so a stale record is never approved", st == "expired")

print("\nthe emailed security code (one code, for the run that armed):")
URL3 = URL + "3"
with app.db() as con:
    con.execute("INSERT INTO posting(id, company_id, title, canonical_url, captured_at) "
                "VALUES (3, 1, 'Role', ?, '2026-10-01')", (URL3,))
    con.execute("INSERT INTO application(id, posting_id, status, package_path, alias_used, company_raw, "
                "role_raw) VALUES (3, 3, 'draft', 'applications/acme/c', 'acme3@jobs.example.com', 'Acme', 'Role')")
s3 = call(app.submit_run_open, Req({"application_id": 3, "mode": "shadow"}), authorization=S)[0]["run_id"]
fp3 = R.fingerprint(3, URL3, F, FILES)
tok3 = call(app.submit_run_close, s3, Req({"outcome": "shadow_complete", "record_fp": fp3,
                                           "record": {"fields": F, "files": FILES}}),
            authorization=S)[0]["approval_url"].rsplit("/", 1)[1]
o3, _ = call(app.submit_approve_options, tok3, Req())
call(app.submit_approve_verify, tok3, Req(yk.get(o3, count=60)))
live3 = call(app.submit_run_open, Req({"application_id": 3, "mode": "live", "record_fp": fp3}),
             authorization=S)[0]["run_id"]


def mail(mid, at, to="acme3@jobs.example.com", frm="no-reply@us.greenhouse-mail.io",
         subj="Security code for your application to Acme", code="AbCd1234", dkim="pass", dmarc="pass",
         cls="otp"):
    with app.db() as con:
        con.execute("INSERT INTO message(id, received_at, to_alias, from_addr, subject, raw_payload, "
                    "classification, otp_code, auth_dkim, auth_dmarc) VALUES (?,?,?,?,?,'{}',?,?,?,?)",
                    (mid, at, to, frm, subj, cls, code, dkim, dmarc))


_, e = call(app.submit_run_code, live3, Req(), authorization=S)
check("no code before the run has armed (409)", e == 409)
_, e = call(app.submit_run_code, s3, Req(), authorization=S)
check("a shadow run never gets a code", e == 409)
mail(901, "2020-01-01T00:00:00+00:00")                         # before the arm: never
call(app.submit_run_arm, live3, Req({"record_fp": fp3}), authorization=S)
_, e = call(app.submit_run_code, live3, Req(), authorization="Bearer adm")
check("the admin token cannot fetch a code (submit scope only)", e == 403)
_, e = call(app.submit_run_code, live3, Req(), authorization=S)
check("mail received BEFORE the run armed is never used (404, not yet)", e == 404)
LATER = "2099-01-01T00:00:0{}+00:00"
mail(902, LATER.format(1), to="someone@jobs.example.com")
mail(903, LATER.format(2), frm="no-reply@greenhouse-mail.io.evil.example")
mail(904, LATER.format(3), dkim="fail", dmarc="fail")
mail(905, LATER.format(4), subj="Your interview next week")
mail(906, LATER.format(5), code="AbCd123")
mail(907, LATER.format(6), cls="confirmation")
_, e = call(app.submit_run_code, live3, Req(), authorization=S)
check("🚨 another alias, a look-alike sender domain, failed DKIM/DMARC, the wrong subject, a malformed "
      "code, and a non-otp message are all refused", e == 404)
mail(908, LATER.format(7))
r, e = call(app.submit_run_code, live3, Req(), authorization=S)
check("the one qualifying message releases its code", e is None and r == {"code": "AbCd1234", "message_id": 908})
mail(909, LATER.format(8), code="ZzZz9999")
_, e = call(app.submit_run_code, live3, Req(), authorization=S)
check("🚨 a second code for the same run: refused (409), even for a newer message", e == 409)
with app.db() as con:
    ev = [r["detail"] for r in con.execute("SELECT detail FROM event WHERE kind='submit_code_released'")]
check("the audit names the message, never the code", ev and all("AbCd1234" not in d for d in ev))

print("\nproof by confirmation email:")
_, e = call(app.submit_run_confirmation, live3, Req(), authorization=S)
check("no confirmation yet (404); a security-code email labelled 'confirmation' (message 907) is NOT proof",
      e == 404)
_, e = call(app.submit_run_confirmation, s3, Req(), authorization=S)
check("a shadow run never asks for one (409)", e == 409)
_, e = call(app.submit_run_confirmation, live3, Req(), authorization="Bearer adm")
check("the admin token cannot read it (submit scope only)", e == 403)
mail(920, "2020-01-01T00:00:00+00:00", cls="confirmation", subj="Thank you for applying")   # before the arm
mail(921, LATER.format(9), cls="confirmation", subj="Thank you for applying", to="someone@jobs.example.com")
mail(922, "2099-01-01T00:01:00+00:00", cls="confirmation", subj="Thank you for applying",
     frm="careers@greenhouse-mail.io.evil.example")
mail(923, "2099-01-01T00:01:01+00:00", cls="confirmation", subj="Thank you for applying", dkim="fail", dmarc="fail")
mail(924, "2099-01-01T00:01:02+00:00", cls="rejection", subj="Thank you for applying")
_, e = call(app.submit_run_confirmation, live3, Req(), authorization=S)
check("🚨 before the arm, another alias, a look-alike sender, failed DKIM/DMARC, or not a confirmation: "
      "none is proof", e == 404)
mail(925, "2099-01-01T00:02:00+00:00", cls="confirmation", subj="Thank you for applying to Acme")
r, e = call(app.submit_run_confirmation, live3, Req(), authorization=S)
check("the qualifying confirmation is proof", e is None and r["message_id"] == 925)

print("\nAshby: eligibility, the batch, and the 'not_clicked' release (2026-10-08):")
AURL = "https://jobs.ashbyhq.com/acme/11111111-2222-4333-8444-555555555555"
with app.db() as con:
    for i in (5, 6):
        con.execute("INSERT INTO posting(id, company_id, title, canonical_url, captured_at) "
                    "VALUES (?, 1, 'Role', ?, '2026-10-01')", (i, AURL + ("" if i == 5 else "6")))
        con.execute("INSERT INTO application(id, posting_id, status, package_path, alias_used, company_raw, "
                    "role_raw) VALUES (?, ?, 'draft', 'applications/acme/x', 'acme5@jobs.example.com', 'Acme', 'Role')",
                    (i, i))
nxt = call(app.submit_next, Req(), authorization=S, app_id=5)[0]["next"]
check("an Ashby draft is eligible for a shadow run, marked ats=ashby", nxt and nxt["ats"] == "ashby")
fp5, fp6 = R.fingerprint(5, AURL, F, FILES), R.fingerprint(6, AURL + "6", F, FILES)
toks = {}
for aid, fpx in ((5, fp5), (6, fp6)):
    s = call(app.submit_run_open, Req({"application_id": aid, "mode": "shadow"}), authorization=S)[0]["run_id"]
    toks[aid] = call(app.submit_run_close, s, Req({"outcome": "shadow_complete", "record_fp": fpx,
                                                   "record": {"fields": F, "files": FILES}}),
                     authorization=S)[0]["approval_url"].rsplit("/", 1)[1]
    o, _ = call(app.submit_approve_options, toks[aid], Req())
    call(app.submit_approve_verify, toks[aid], Req(yk.get(o, count=200 + aid)))
b, e = call(app.submit_next, Req(), authorization=S, mode="live", ats="ashby", all=1)
check("a batch lists every approved Ashby application, oldest approval first, with its company",
      e is None and [i["application_id"] for i in b["items"]] == [5, 6] and b["items"][0]["company"] == "Acme")
_, e = call(app.submit_next, Req(), authorization=S, mode="live", ats="greenhouse", all=1)
check("a batch is refused for a board that needs no person's click (400)", e == 400)
_, e = call(app.submit_next, Req(), authorization=S, mode="shadow", ats="ashby", all=1)
check("a batch is live only (400)", e == 400)
ZERO = {k: 0 for k in app.SUBMIT_CLICK_COUNTERS}


def live_armed(aid, fpx):
    rid = call(app.submit_run_open, Req({"application_id": aid, "mode": "live", "record_fp": fpx}),
               authorization=S)[0]["run_id"]
    call(app.submit_run_arm, rid, Req({"record_fp": fpx}), authorization=S)
    return rid


r5 = live_armed(5, fp5)
for bad, why in ((dict(ZERO, human_clicks=1), "a person's click"), (dict(ZERO, sanctioned=1), "a request let through"),
                 (dict(ZERO, submit_events=1), "a blocked attempt"), (None, "no counters at all")):
    _, e = call(app.submit_run_close, r5, Req({"outcome": "not_clicked", **({"counters": bad} if bad is not None else {})}),
                authorization=S)
    check(f"🚨 'not_clicked' is refused when the page recorded {why} (400)", e == 400)
r, e = call(app.submit_run_close, r5, Req({"outcome": "not_clicked", "counters": ZERO}), authorization=S)
with app.db() as con:
    st = con.execute("SELECT status, consumed_run_id FROM submit_approval WHERE application_id=5 "
                     "ORDER BY id DESC LIMIT 1").fetchone()
check("no click, zero counters: closed not_clicked and the approval is back to approved",
      e is None and r.get("released") is True and dict(st) == {"status": "approved", "consumed_run_id": None})
nxt = call(app.submit_next, Req(), authorization=S, app_id=5, mode="live")[0]["next"]
check("…so the next live run is offered it again", nxt and nxt["record_fp"] == fp5)
r6 = live_armed(6, fp6)
with app.db() as con:
    con.execute("INSERT INTO message(id, received_at, to_alias, from_addr, subject, raw_payload, classification, "
                "otp_code, auth_dkim, auth_dmarc) VALUES (990, '2099-02-01T00:00:00+00:00', 'acme5@jobs.example.com', "
                "'no-reply@ashbyhq.com', 'Your security code', '{}', 'otp', 'Zz12Yy34', 'pass', 'pass')")
r, e = call(app.submit_run_code, r6, Req(), authorization=S)
check("an Ashby sender's code is released to the run that armed (the operator's rule)", e is None and r["message_id"] == 990)
_, e = call(app.submit_run_close, r6, Req({"outcome": "not_clicked", "counters": ZERO}), authorization=S)
check("🚨 a run that was released a security code can never close not_clicked (400)", e == 400)
with app.db() as con:
    con.execute("INSERT INTO message(id, received_at, to_alias, from_addr, subject, raw_payload, classification, "
                "otp_code, auth_dkim, auth_dmarc) VALUES (991, '2099-02-01T00:01:00+00:00', 'acme5@jobs.example.com', "
                "'no-reply@ashbyhq.com.evil.example', 'Thank you for applying', '{}', 'confirmation', NULL, 'pass', 'pass')")
_, e = call(app.submit_run_confirmation, r6, Req(), authorization=S)
check("a look-alike Ashby sender is not proof", e == 404)

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
