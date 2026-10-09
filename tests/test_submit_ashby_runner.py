#!/usr/bin/env python3
"""The runner's Ashby path (the hand-off) and the batch, with a fake relay, browser and API.

🚨 WHAT MUST NEVER HAPPEN:
  - an Ashby live run that clicks Submit itself (final_submit) instead of handing off;
  - a hand-off before the relay consumed the approval (arm);
  - 'not_clicked' when the page counted ANY click or submit attempt (then it is 'unknown');
  - a batch that keeps going after a form nobody clicked (he has left; the rest stay untouched).

Nothing here touches a network, a browser or poppler.
Run:  python3 tests/test_submit_ashby_runner.py
"""
import copy
import io
import json
import pathlib
import sys
import tempfile
import urllib.error

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
import record as R                                              # noqa: E402
import submit as S                                              # noqa: E402

fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


ALIAS = "acme@jobs.example.com"
PID = "11111111-2222-4333-8444-555555555555"
URL = f"https://jobs.ashbyhq.com/acme/{PID}"
JOB = {"id": PID, "title": "Integration Engineer", "location": "Remote", "isRemote": True,
       "descriptionPlain": "Fully remote. The pay range is $100,000 - $120,000 per year."}


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(job=JOB, board_ok=True):
    def op(req, timeout=0):
        u = req.full_url
        if "/posting-api/job-board/acme" in u and board_ok:
            return Resp(json.dumps({"jobs": [job] if job else []}).encode())
        raise urllib.error.HTTPError(u, 404, "not found", {}, None)
    return op


class Relay:
    def __init__(self, items=None, release=True, spam=None):
        self.steps, self.closed, self.armed, self.reported = [], [], [], []
        self.items, self.release, self.n = items or [], release, 0
        self.spam = spam or {"refusals": 1, "released": True, "retry_at": 4102444800, "manual": False}

    def open(self, **kw):
        self.opened = kw
        self.n += 1
        return 70 + self.n

    def step(self, run_id, **kw):
        self.steps.append(kw)

    def close(self, run_id, **kw):
        self.closed.append(kw)
        if kw.get("outcome") == "spam_refused":
            return {"ok": True, **self.spam}
        return {"ok": True, "released": self.release} if kw.get("outcome") == "not_clicked" else {"ok": True}

    def arm(self, run_id, record_fp):
        self.armed.append(record_fp)
        return "ab" * 16

    def submitted(self, run_id, **kw):
        self.reported.append(kw)

    def confirmation(self, run_id):
        return None

    def code(self, run_id):
        return {"code": "AbCd1234", "message_id": 557}

    def next_all(self, ats):
        return list(self.items)


FIELDS = [{"id": "_systemfield_name", "name": "_systemfield_name", "kind": "text", "label": "Name", "required": True, "visible": True},
          {"id": "_systemfield_email", "name": "_systemfield_email", "kind": "email", "label": "Email", "required": True, "visible": True},
          {"id": "_systemfield_resume", "name": "_systemfield_resume", "kind": "file", "label": "Resume", "required": True, "visible": True},
          {"id": "q-yes", "name": "q-yes", "kind": "yesno", "label": "Are you legally authorized to work in the United States?",
           "required": True, "visible": True}]
ZERO = {"submit_events": 0, "submit_calls": 0, "post_navigations": 0, "sanctioned": 0,
        "submit_requests": 0, "human_clicks": 0}


class FakeBrowser:
    """proofs: what each await_proof returns, in order. counters: the readback after the hand-off."""
    def __init__(self, proofs=("proof",), counters=None, spam_page=False):
        self.proofs, self.counters, self.spam_page = list(proofs), counters, spam_page
        self.sent, self.filled, self.handoff_kw = [], {}, None

    def __call__(self, cmd, **kw):
        self.sent.append(cmd)
        if cmd == "open":
            self.opened_url = kw["url"]
            return {"ok": True, "url": kw["url"], "title": "Apply"}
        if cmd == "harvest":
            return {"ok": True, "fields": copy.deepcopy(FIELDS), "captcha": False, "password_inputs": 0}
        if cmd == "shot":
            pathlib.Path(kw["path"]).write_bytes(b"\x89PNG\r\n\x1a\n")
            return {"ok": True, "path": kw["path"]}
        if cmd == "fill":
            res = []
            for f in kw["files"]:
                self.filled[f["id"]] = {"files": [{"name": pathlib.Path(f["path"]).name, "size": 9}]}
                res.append({"id": f["id"], "kind": "file", "status": "set"})
            for y in kw["yesnos"]:
                self.filled[y["id"]] = {"value": y["value"]}
                res.append({"id": y["id"], "kind": "yesno", "status": "set", "chosen": y["value"]})
            for t in kw["texts"]:
                self.filled[t["id"]] = {"value": t["value"]}
                res.append({"id": t["id"], "kind": "text", "status": "set"})
            return {"ok": True, "results": res}
        if cmd == "readback":
            out = [{"id": f["id"], "label": f["label"], "kind": f["kind"], **self.filled.get(f["id"], {"value": ""})}
                   for f in FIELDS]
            c = self.counters if (self.counters is not None and "handoff" in self.sent) else ZERO
            return {"ok": True, "fields": out, "blocked_submits": dict(c)}
        if cmd == "arm":
            return {"ok": True}
        if cmd == "handoff":
            self.handoff_kw = kw
            return {"ok": True, "handed_off": True}
        if cmd == "await_proof":
            st = self.proofs.pop(0) if self.proofs else "no_proof"
            return {"ok": True, "status": st, "url": URL + "/application",
                    "excerpt": {"proof": "Your application was successfully submitted",
                                "spam_refused": "flagged as possible spam"}.get(st, ""),
                    **({"spam_page": self.spam_page} if st == "no_proof" else {})}
        if cmd == "enter_code":
            return {"ok": True, "status": "proof", "url": URL, "excerpt": "Your application was successfully submitted"}
        if cmd == "status":
            return {"ok": True}
        raise RuntimeError(f"unexpected command {cmd}")

    def quit(self):
        pass


repo = pathlib.Path(tempfile.mkdtemp())
pkg = repo / "applications" / "acme" / "role"
pkg.mkdir(parents=True)
(pkg / "job-description.md").write_text("# Role\n\n## Full posting text (verbatim)\n\ntext\n")
(pkg / "resume.pdf").write_bytes(b"%PDF resume")
CFG = {"identity": {"full_name": "Alex Rivera"},
       "form_rule": [{"match": "^name$", "from": "identity.full_name", "kind": "text"},
                     {"match": "legally authorized", "answer": "Yes", "kind": "select"}]}
S.pdf_text = lambda p: f"Alex Rivera {ALIAS}"
FP = R.fingerprint(42, URL, [{"id": "_systemfield_email", "label": "Email", "value": ALIAS},
                             {"id": "_systemfield_name", "label": "Name", "value": "Alex Rivera"},
                             {"id": "_systemfield_resume", "label": "Resume", "value": "resume.pdf"},
                             {"id": "q-yes", "label": "Are you legally authorized to work in the United States?", "value": "yes"}],
                   {"resume.pdf": R.file_sha(pkg / "resume.pdf")})
LIVE = {"application_id": 42, "package_path": "applications/acme/role", "alias_used": ALIAS, "url": URL,
        "mode": "live", "record_fp": FP, "files": {"resume.pdf": R.file_sha(pkg / "resume.pdf")},
        "company": "Acme"}


def run(browser, relay=None, item=None, batch=False):
    relay, alerts = relay or Relay(), []
    ev = pathlib.Path(tempfile.mkdtemp())
    r = S.Run(relay, lambda: browser, CFG, repo, ev, headed=False, opener=opener_for(),
              version="test", notify=alerts.append, sleep=lambda s: None, batch=batch).go(dict(item or LIVE))
    return r, relay, alerts


print("an Ashby shadow run:")
br = FakeBrowser()
r, relay, _ = run(br, item=dict(LIVE, mode="shadow"))
check("it records the board as ashby", relay.opened["ats"] == "ashby")
check("it opens the FORM at <posting>/application", br.opened_url == URL + "/application")
check("it closes shadow_complete with the record", r["outcome"] == "shadow_complete")
check("the record fingerprint is computed over the CANONICAL posting URL",
      relay.closed[-1]["record_fp"] == FP)

print("\nthe hand-off, and the person's click:")
br = FakeBrowser(proofs=["proof"])
r, relay, alerts = run(br)
check("🚨 the runner never clicks Submit itself on Ashby", "final_submit" not in br.sent)
check("arm comes before the hand-off, and the hand-off carries the nonce",
      br.sent.index("arm") < br.sent.index("handoff") and br.handoff_kw["nonce"] == "ab" * 16)
check("one 'ready for your click' alert", any("Ready for your click" in a["title"] for a in alerts))
check("proof on the page: submitted, reported to the relay", r["outcome"] == "submitted" and relay.reported)

print("\na spam refusal, then the person's second click:")
br = FakeBrowser(proofs=["spam_refused", "proof"])
r, relay, alerts = run(br)
check("the refusal is recorded as a step, and the person is told nothing was sent",
      any("possible spam" in s["detail"] for s in relay.steps)
      and any("refused that click" in a["title"] for a in alerts))
check("…then the second click's proof submits it", r["outcome"] == "submitted")

print("\na spam refusal and no proof (the operator's rule, 2026-10-08):")
CLICKED = dict(ZERO, human_clicks=1, submit_events=1)
br = FakeBrowser(proofs=["spam_refused", "no_proof"], counters=CLICKED, spam_page=True)
r, relay, _ = run(br)
check("the refusal still on the page: closed spam_refused, never 'unknown'",
      r["outcome"] == "spam_refused" and relay.closed[-1]["outcome"] == "spam_refused"
      and all(c["outcome"] != "unknown" for c in relay.closed))
check("…the confirmation email was awaited first", any(s["name"] == "confirm" for s in relay.steps))
check("…and it says the approval is kept, with the retry time", "retry after" in r["why"])
r, relay, _ = run(FakeBrowser(proofs=["spam_refused", "no_proof"], counters=CLICKED, spam_page=True),
                  relay=Relay(spam={"refusals": 2, "released": False, "retry_at": None, "manual": True}))
check("the second refusal: set aside for manual entry", r["outcome"] == "spam_refused" and "manual entry" in r["why"])
br = FakeBrowser(proofs=["spam_refused", "no_proof"], counters=CLICKED, spam_page=False)
r, relay, _ = run(br)
check("🚨 the refusal GONE from the page at the end (a later click may have gone through): 'unknown'",
      r["outcome"] == "unknown")
br = FakeBrowser(proofs=["no_proof"], counters=CLICKED, spam_page=True)
r, relay, _ = run(br)
check("🚨 a spam page with no refusal seen during the hand-off: 'unknown'", r["outcome"] == "unknown")

print("\nno click:")
br = FakeBrowser(proofs=["no_proof"], counters=ZERO)
r, relay, _ = run(br)
check("no click and zero counters: closed not_clicked, with the counters", r["outcome"] == "not_clicked"
      and relay.closed[-1]["outcome"] == "not_clicked" and relay.closed[-1]["counters"] == ZERO)
check("…and the run says the approval is kept", "kept for the next batch" in r["why"])
check("…and nothing is reported as submitted", not relay.reported)
br = FakeBrowser(proofs=["no_proof"], counters=dict(ZERO, human_clicks=1))
r, relay, _ = run(br)
check("🚨 a click without proof is never 'not_clicked': the mail fallback, then 'unknown'",
      r["outcome"] == "unknown" and all(c["outcome"] != "not_clicked" for c in relay.closed))

print("\nthe emailed code after the person's click:")
br = FakeBrowser(proofs=["code_step"])
r, relay, _ = run(br)
check("the runner enters the code (the operator's rule) and the form is submitted",
      "enter_code" in br.sent and r["outcome"] == "submitted")

print("\nthe batch:")
items = [dict(LIVE, application_id=42), dict(LIVE, application_id=43), dict(LIVE, application_id=44)]
brs = iter([FakeBrowser(proofs=["proof"]), FakeBrowser(proofs=["no_proof"], counters=ZERO), FakeBrowser()])
relay, alerts = Relay(items=items), []
S.killed = lambda: None
seen = []


def factory():
    b = next(brs)
    seen.append(b)
    return b


# Each item's approved fingerprint must be over its OWN application id, as the relay's would be.
for it in items:
    it["record_fp"] = R.fingerprint(it["application_id"], URL,
                                    [{"id": "_systemfield_email", "label": "Email", "value": ALIAS},
                                     {"id": "_systemfield_name", "label": "Name", "value": "Alex Rivera"},
                                     {"id": "_systemfield_resume", "label": "Resume", "value": "resume.pdf"},
                                     {"id": "q-yes", "label": "Are you legally authorized to work in the United States?", "value": "yes"}],
                                    {"resume.pdf": R.file_sha(pkg / "resume.pdf")})
orig_opener = S.Run.__init__


def init(self, *a, **kw):
    kw["opener"] = opener_for()
    orig_opener(self, *a, **kw)


S.Run.__init__ = init
rc = S.run_batch(relay, "ashby", factory, CFG, repo, pathlib.Path(tempfile.mkdtemp()), False, "test",
                 alerts.append, sleep=lambda s: None)
S.Run.__init__ = orig_opener
ready = [a for a in alerts if "Ready for your click" in a["title"]]
check("ONE 'ready' alert for the whole batch, naming its size", len(ready) == 1 and "3 applications" in ready[0]["title"])
check("the first form is submitted, the second is not clicked", relay.reported and len(seen) == 2)
check("🚨 the batch stops at the first form nobody clicked: the third is never opened", len(seen) == 2)
check("a batch with an unclicked form does not exit 0", rc == 3)
try:
    S.run_batch(relay, "greenhouse", factory, CFG, repo, pathlib.Path(tempfile.mkdtemp()), False, "t", None)
    check("a batch is refused for a board that needs no person's click", False)
except SystemExit:
    check("a batch is refused for a board that needs no person's click", True)

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
