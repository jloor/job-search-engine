#!/usr/bin/env python3
"""The submitter's runner, step by step, with a fake relay, a fake browser and a fake API.

🚨 WHAT MUST NEVER HAPPEN:
  - a run that reaches the review screenshot with a field the page does not hold as decided;
  - a stop that is not recorded (every stop writes its step, closes the run, alerts once);
  - a closed run whose outcome claims more than happened (there is no "submitted" outcome);
  - a submit attempt on the page passing as a clean run;
  - a run starting while the kill switch is set.

Nothing here touches a network, a browser or poppler.

Run:  python3 tests/test_submit_runner.py
"""
import copy
import io
import json
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
import submit as S                                              # noqa: E402

fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


ALIAS = "acme@jobs.example.com"
JOB = {"title": "Integration Engineer", "location": {"name": "Remote - US"},
       "content": "&lt;p&gt;Fully remote. The pay range is $100,000 - $120,000 per year.&lt;/p&gt;",
       "questions": [
           {"label": "First Name", "required": True, "fields": [{"name": "first_name", "type": "input_text"}]},
           {"label": "Email", "required": True, "fields": [{"name": "email", "type": "input_text"}]},
           {"label": "Resume/CV", "required": True, "fields": [{"name": "resume", "type": "input_file"}]},
           {"label": "Will you require sponsorship?", "required": True,
            "fields": [{"name": "question_1", "type": "multi_value_single_select",
                        "values": [{"label": "Yes", "value": 1}, {"label": "No", "value": 0}]}]}]}


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(job, board_ok=True):
    import urllib.error

    def op(req, timeout=0):
        u = req.full_url
        if u.endswith("/v1/boards/acme"):
            if board_ok:
                return Resp(b'{"name": "Acme"}')
        elif "/jobs/1001" in u and job is not None:
            return Resp(json.dumps(job).encode())
        raise urllib.error.HTTPError(u, 404, "not found", {}, None)
    return op


class Relay:
    def __init__(self):
        self.steps, self.closed, self.opened = [], None, None
        self.armed, self.reported = [], []

    def open(self, **kw):
        self.opened = kw
        return 7

    def step(self, run_id, **kw):
        self.steps.append(kw)

    def close(self, run_id, **kw):
        self.closed = kw
        return {"ok": True, "approval_url": "https://relay.example/submit/approve/T"} \
            if kw.get("outcome") == "shadow_complete" else {"ok": True}

    def arm(self, run_id, record_fp):
        self.armed.append(record_fp)
        return "ab" * 16

    def submitted(self, run_id, **kw):
        self.reported.append(kw)

    code_after = 2                     # the qualifying mail "arrives" on the third poll
    code_polls = 0

    def code(self, run_id):
        self.code_polls += 1
        if self.code_after is None or self.code_polls <= self.code_after:
            return None
        return {"code": "AbCd1234", "message_id": 557}


FIELDS = [{"id": "first_name", "name": "", "kind": "text", "label": "First Name", "required": True, "visible": True},
          {"id": "email", "name": "", "kind": "text", "label": "Email", "required": True, "visible": True},
          {"id": "resume", "name": "", "kind": "file", "label": "Attach", "required": False, "visible": True},
          {"id": "question_1", "name": "", "kind": "select", "label": "Will you require sponsorship?",
           "required": True, "visible": True}]


class FakeBrowser:
    def __init__(self, page_edit=None, blocked=None, captcha=False, fields=None, proof="proof",
                 crash_on=None):
        self.page_edit, self.blocked, self.captcha = page_edit or {}, blocked, captcha
        self.proof, self.crash_on = proof, crash_on
        self.fields = fields or FIELDS
        self.sent, self.quit_called, self.filled = [], False, {}

    def __call__(self, cmd, **kw):
        self.sent.append(cmd)
        if cmd == "open":
            return {"ok": True, "url": kw["url"], "title": "Apply"}
        if cmd == "harvest":
            return {"ok": True, "fields": copy.deepcopy(self.fields), "captcha": self.captcha,
                    "password_inputs": 0}
        if cmd == "shot":
            pathlib.Path(kw["path"]).write_bytes(b"\x89PNG\r\n\x1a\n" + cmd.encode())
            return {"ok": True, "path": kw["path"]}
        if cmd == "fill":
            res = []
            for f in kw["files"]:
                self.filled[f["id"]] = {"files": [{"name": pathlib.Path(f["path"]).name, "size": 9}]}
                res.append({"id": f["id"], "kind": "file", "status": "set"})
            for s in kw["selects"]:
                self.filled[s["id"]] = {"value": s["values"][0]}
                res.append({"id": s["id"], "kind": "select", "status": "set", "chosen": s["values"][0]})
            for t in kw["texts"]:
                self.filled[t["id"]] = {"value": t["value"]}
                res.append({"id": t["id"], "kind": "text", "status": "set"})
            return {"ok": True, "results": res}
        if cmd == "readback":
            out = []
            for f in self.fields:
                v = dict(self.filled.get(f["id"], {"value": ""}))
                v.update(self.page_edit.get(f["id"], {}))
                out.append({"id": f["id"], "label": f["label"], "kind": f["kind"], **v})
            return {"ok": True, "fields": out,
                    "blocked_submits": self.blocked or {"submit_events": 0, "submit_calls": 0,
                                                        "post_navigations": 0}}
        if cmd == self.crash_on:
            raise RuntimeError(f"form.js {cmd}: the browser died")
        if cmd == "arm":
            return {"ok": True, "armed": True}
        if cmd == "enter_code":
            self.code_given = kw.get("code")
            return {"ok": True, "entered": True, "status": "proof",
                    "url": "https://job-boards.greenhouse.io/acme/jobs/1001/confirmation",
                    "excerpt": "Thank you for applying"}
        if cmd in ("final_submit", "await_proof"):
            return {"ok": True, "status": self.proof, "url": "https://job-boards.greenhouse.io/acme/jobs/1001/confirmation",
                    "excerpt": "Thank you for applying"}
        raise RuntimeError(f"unexpected command {cmd}")

    def quit(self):
        self.quit_called = True


repo = pathlib.Path(tempfile.mkdtemp())
pkg = repo / "applications" / "acme" / "role"
pkg.mkdir(parents=True)
(pkg / "job-description.md").write_text("# Role\n\n## Full posting text (verbatim)\n\ntext\n")
(pkg / "resume.pdf").write_bytes(b"%PDF resume")
CFG = {"identity": {"first_name": "Alex"},
       "form_rule": [{"match": "sponsorship", "answer": "No", "kind": "select"}]}
PDF_TEXT = {"resume.pdf": f"Alex Rivera {ALIAS}"}
S.pdf_text = lambda p: PDF_TEXT.get(p.name, "")
ITEM = {"application_id": 42, "package_path": "applications/acme/role", "alias_used": ALIAS,
        "url": "https://job-boards.greenhouse.io/acme/jobs/1001"}


def run(browser=None, job=JOB, board_ok=True, cfg=CFG, item=None, relay=None):
    relay, alerts = relay or Relay(), []
    br = browser or FakeBrowser()
    ev = pathlib.Path(tempfile.mkdtemp())
    r = S.Run(relay, lambda: br, cfg, repo, ev, headed=False, opener=opener_for(job, board_ok),
              version="test", notify=alerts.append, sleep=lambda s: None).go(dict(item or ITEM))
    return r, relay, br, alerts, ev


print("a clean shadow run:")
r, relay, br, alerts, ev = run()
names = [s["name"] for s in relay.steps]
check("it ends shadow_complete", r["outcome"] == "shadow_complete" and relay.closed["outcome"] == "shadow_complete")
check("every step is recorded in order",
      names == ["claim", "liveness", "gates", "package", "open", "answers", "fill", "readback",
                "review", "record"])
check("every step is ok", all(s["outcome"] == "ok" for s in relay.steps))
check("the run opened in shadow mode", relay.opened["mode"] == "shadow")
check("the loaded, filled and review steps each carry a screenshot with its sha256",
      all(s["screenshot_path"] and len(s["sha256"]) == 64
          for s in relay.steps if s["name"] in ("open", "fill", "review")))
rec = json.loads((ev / "42" / "7" / "fields.json").read_text())
check("fields.json holds what the PAGE read back, with the file by name",
      {x["label"]: x["value"] for x in rec} == {"First Name": "Alex", "Email": ALIAS,
                                                "Resume/CV": "resume.pdf",
                                                "Will you require sponsorship?": "No"})
check("🚨 no command named submit was ever sent to the browser", "submit" not in br.sent)
check("the browser is closed at the end", br.quit_called)
check("one phone alert, carrying the approval link",
      len(alerts) == 1 and "shadow_complete" in alerts[0]["title"] and "/submit/approve/" in alerts[0]["message"])
import record as RR                                              # noqa: E402
posted = relay.closed
check("the shadow close posts the record and its fingerprint, computed as the relay will",
      posted.get("record_fp") == RR.fingerprint(42, ITEM["url"], posted["record"]["fields"],
                                                posted["record"]["files"])
      and posted["record"]["files"] == {"resume.pdf": RR.file_sha(pkg / "resume.pdf")})
check("🚨 a shadow run never arms and never reports a submission", not relay.armed and not relay.reported)
APPROVED_FP = posted["record_fp"]
LIVE = dict(ITEM, mode="live", record_fp=APPROVED_FP, files=dict(posted["record"]["files"]))

print("\nstops, each recorded where it happened:")


def stopped_at(label, step, **kw):
    r, relay, br, alerts, _ = run(**kw)
    last = relay.steps[-1] if relay.steps else {}
    check(f"{label}: stops at {step}",
          r["outcome"] == "stopped" and relay.closed["stop_step"] == step
          and last.get("name") == step and last.get("outcome") == "stop")
    check(f"{label}: one alert, and the reason travels", len(alerts) == 1 and relay.closed["stop_reason"])
    return r, relay, br


stopped_at("the job is gone from a board that answers", "liveness", job=None)
r, relay, _ = run(job=None, board_ok=False)[:3]
check("a board that does not answer is an ERROR, never a 'gone' verdict",
      r["outcome"] == "error" and relay.closed["stop_step"] == "liveness")
stopped_at("an office obligation in the text", "gates",
           job=dict(JOB, content="This role is hybrid. Pay $100,000 - $120,000."))
stopped_at("no pay range", "gates", job=dict(JOB, content="Fully remote."))
stopped_at("an onsite location", "gates",
           job=dict(JOB, location={"name": "Paris, France"}))
PAY = " The pay range is $100,000 - $120,000 per year."
r, relay, _ = stopped_at("a US city with no remote evidence", "gates",
                         job=dict(JOB, location={"name": "Austin, Texas"}, content="Our team." + PAY))
check("…for the geography, not the pay", "geography" in relay.closed["stop_reason"])
r, relay, _ = run(job=dict(JOB, location={"name": "United States"},
                           content="Our implementation model." + PAY))[:3]
check("a country-wide location passes the gate (the runner is not stricter than the queue)",
      r["outcome"] == "shadow_complete")
r, relay, _ = stopped_at("a country-wide location that states an office obligation", "gates",
                         job=dict(JOB, location={"name": "United States"},
                                  content="This role is hybrid." + PAY))
check("…for the office obligation, not the pay", "office obligation" in relay.closed["stop_reason"])
import greenhouse as GH                                          # noqa: E402
q = GH.questions({"questions": [{"label": "Resume/CV", "required": True, "fields": [
    {"name": "resume", "type": "input_file"}, {"name": "resume_text", "type": "textarea"}]}]})
check("only the first field of a Greenhouse question carries 'required'",
      q["resume"]["required"] and not q["resume_text"]["required"])
PDF_TEXT["resume.pdf"] = "Alex Rivera other@jobs.example.com"
stopped_at("the résumé carries a different alias", "package")
PDF_TEXT["resume.pdf"] = f"Alex Rivera {ALIAS}"
r, relay, br = stopped_at("a required question with no rule", "answers", cfg={"identity": {"first_name": "Alex"}})
check("…and the browser is still closed", br.quit_called)
r, relay, br = stopped_at("a CAPTCHA on the page", "open", browser=FakeBrowser(captcha=True))
check("…recorded once, not twice", [x["name"] for x in relay.steps].count("open") == 1)
r, relay, br = stopped_at("the page changed a value after the fill", "readback",
                          browser=FakeBrowser(page_edit={"first_name": {"value": "Alexander"}}))
check("…and the reason names the field and both values",
      "First Name" in relay.closed["stop_reason"] and "Alexander" in relay.closed["stop_reason"])
stopped_at("a file the page does not hold", "readback",
           browser=FakeBrowser(page_edit={"resume": {"files": []}}))
stopped_at("a required field left empty on the page", "readback",
           browser=FakeBrowser(fields=FIELDS + [{"id": "q9", "name": "", "kind": "text", "label": "Optional?",
                                                 "required": True, "visible": False}]))

print("\na LIVE run:")
r, relay, br, alerts, ev = run(item=LIVE)
check("the approved record, read back exactly, is submitted", r["outcome"] == "submitted")
check("…it armed once with the approved fingerprint, then clicked once",
      relay.armed == [APPROVED_FP] and br.sent.count("final_submit") == 1 and br.sent.count("arm") == 1)
check("…and reported the proof", relay.reported and "/confirmation" in relay.reported[0]["url"])
r, relay, br, _, _ = run(item=LIVE, browser=FakeBrowser(page_edit={"first_name": {"value": "Alexander"}}))
check("🚨 a page that reads back differently stops BEFORE arming",
      r["outcome"] == "stopped" and not relay.armed and "final_submit" not in br.sent)
r, relay, br, _, _ = run(item=LIVE, cfg=dict(CFG, identity={"first_name": "Alexa"}))
check("🚨 an answer that changed since approval (the page reads back what was decided, but it is "
      "not what was approved) stops at 'match', BEFORE arming",
      r["outcome"] == "stopped" and relay.closed["stop_step"] == "match" and not relay.armed
      and "final_submit" not in br.sent)
r, relay, br, _, _ = run(item=dict(LIVE, files={"resume.pdf": "0" * 64}))
check("🚨 a package file changed after approval stops before the browser opens",
      r["outcome"] == "stopped" and relay.closed["stop_step"] == "package" and not relay.armed)
r, relay, br, alerts, _ = run(item=LIVE, browser=FakeBrowser(proof="no_proof"))
check("🚨 a click with no proof closes UNKNOWN, never error, and is not reported submitted",
      r["outcome"] == "unknown" and relay.closed["outcome"] == "unknown" and not relay.reported)
check("…with an urgent alert", alerts and alerts[-1]["priority"] == 5)
r, relay, br, _, _ = run(item=LIVE, browser=FakeBrowser(crash_on="final_submit"))
check("🚨 a crash after arming also closes UNKNOWN (the click may have happened)",
      r["outcome"] == "unknown" and relay.closed["outcome"] == "unknown")
r, relay, br, _, _ = run(item=LIVE, browser=FakeBrowser(proof="human_step"))
check("a CAPTCHA after the click waits for a person, then takes the proof, without clicking again",
      br.sent.count("final_submit") == 1 and "await_proof" in br.sent and br.sent.count("arm") == 1)

print("\nthe emailed security code:")
r, relay, br, alerts, _ = run(item=LIVE, browser=FakeBrowser(proof="code_step"))
check("a code step waits for the relay's code, enters it, and ends submitted",
      r["outcome"] == "submitted" and relay.code_polls == 3 and br.code_given == "AbCd1234"
      and br.sent.count("final_submit") == 1 and br.sent.count("enter_code") == 1)
check("🚨 the code appears in NO step detail and NO alert",
      all("AbCd1234" not in (s.get("detail") or "") for s in relay.steps)
      and all("AbCd1234" not in json.dumps(a) for a in alerts))
check("…while the step names the message the code came from",
      any("message 557" in (s.get("detail") or "") for s in relay.steps))
WAIT = S.CODE_WAIT_S // S.CODE_POLL_S


class ResendBrowser(FakeBrowser):
    """A page with (or without) a resend control; a resend makes the relay's code 'arrive'."""
    def __init__(self, relay, has_control=True, delivers=True, **kw):
        super().__init__(proof="code_step", **kw)
        self.relay, self.has_control, self.delivers = relay, has_control, delivers

    def __call__(self, cmd, **kw):
        if cmd == "resend_code":
            self.sent.append(cmd)
            if not self.has_control:
                raise RuntimeError("form.js resend_code: no resend control on the page")
            if self.delivers:
                self.relay.code_after = self.relay.code_polls       # the next poll finds it
            return {"ok": True, "resent": True}
        return super().__call__(cmd, **kw)


rl = Relay()
rl.code_after = None
r, relay, br, alerts, _ = run(item=LIVE, browser=ResendBrowser(rl), relay=rl)
check("⭐ no code after one wait: the run asks the board to RESEND, then enters the new code",
      r["outcome"] == "submitted" and br.sent.count("resend_code") == 1 and br.sent.count("enter_code") == 1
      and relay.code_polls == WAIT + 1)
check("…and the step says it asked for a resend",
      any("asked the board to resend" in (s.get("detail") or "") for s in relay.steps))
rl = Relay()
rl.code_after = None
r, relay, br, alerts, _ = run(item=LIVE, browser=ResendBrowser(rl, delivers=False), relay=rl)
check("🚨 two resends and still no code: UNKNOWN after three waits, nothing typed, never retried",
      r["outcome"] == "unknown" and br.sent.count("resend_code") == S.CODE_RESENDS
      and "enter_code" not in br.sent and relay.code_polls == WAIT * (S.CODE_RESENDS + 1))
rl = Relay()
rl.code_after = None
r, relay, br, alerts, _ = run(item=LIVE, browser=ResendBrowser(rl, has_control=False), relay=rl)
check("a page with no resend control: UNKNOWN after one wait, and the step says why",
      r["outcome"] == "unknown" and relay.code_polls == WAIT
      and any("no resend" in (s.get("detail") or "") for s in relay.steps))

print("\na submit attempt on the page:")
r, relay, _, _, _ = run(browser=FakeBrowser(blocked={"submit_events": 1, "submit_calls": 0,
                                                      "post_navigations": 0}))
check("🚨 a blocked submit attempt is an ERROR, never a clean run",
      r["outcome"] == "error" and relay.closed["stop_step"] == "readback")

print("\nthe kill switch:")
os.environ["SUBMIT_DISABLED"] = "1"
check("SUBMIT_DISABLED=1 stops runs", S.killed())
os.environ["SUBMIT_DISABLED"] = "0"
kf = pathlib.Path(tempfile.mkdtemp()) / "disabled"
os.environ["SUBMIT_KILL_FILE"] = str(kf)
check("no kill file, no switch", not S.killed())
kf.write_text("")
check("the kill file stops runs", S.killed())
os.environ.pop("SUBMIT_DISABLED")

print("\nholding the form on screen:")
for v, want in (("", 0), ("120", 120), ("900", 600), ("-5", 0), ("abc", 0)):
    os.environ["SUBMIT_HOLD_SECONDS"] = v
    check(f"SUBMIT_HOLD_SECONDS={v!r} holds {want}s (capped at 600, junk is 0)", S._hold_seconds() == want)
os.environ.pop("SUBMIT_HOLD_SECONDS")

print("\nthe relay client:")
seen = []


def rop(req, timeout=0):
    seen.append((req.get_method(), req.full_url, req.headers.get("Authorization")))
    return Resp(b'{"next": null}')


S.Relay("https://relay.example.com/", "tok", rop).next(5)
check("the client sends the submit token as a bearer, to /submit/next with the app id",
      seen[-1] == ("GET", "https://relay.example.com/submit/next?mode=shadow&app_id=5", "Bearer tok"))
S.Relay("https://relay.example.com/", "tok", rop).next(5, "live")
check("…and asks for a LIVE item only when told to",
      seen[-1][1] == "https://relay.example.com/submit/next?mode=live&app_id=5")
try:
    S.Relay("", "tok")
    check("a relay client without a URL refuses to start", False)
except SystemExit:
    check("a relay client without a URL refuses to start", True)

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
