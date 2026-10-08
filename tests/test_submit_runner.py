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

    def open(self, **kw):
        self.opened = kw
        return 7

    def step(self, run_id, **kw):
        self.steps.append(kw)

    def close(self, run_id, **kw):
        self.closed = kw


FIELDS = [{"id": "first_name", "name": "", "kind": "text", "label": "First Name", "required": True, "visible": True},
          {"id": "email", "name": "", "kind": "text", "label": "Email", "required": True, "visible": True},
          {"id": "resume", "name": "", "kind": "file", "label": "Attach", "required": False, "visible": True},
          {"id": "question_1", "name": "", "kind": "select", "label": "Will you require sponsorship?",
           "required": True, "visible": True}]


class FakeBrowser:
    def __init__(self, page_edit=None, blocked=None, captcha=False, fields=None):
        self.page_edit, self.blocked, self.captcha = page_edit or {}, blocked, captcha
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


def run(browser=None, job=JOB, board_ok=True, cfg=CFG):
    relay, alerts = Relay(), []
    br = browser or FakeBrowser()
    ev = pathlib.Path(tempfile.mkdtemp())
    r = S.Run(relay, lambda: br, cfg, repo, ev, headed=False, opener=opener_for(job, board_ok),
              version="test", notify=alerts.append).go(dict(ITEM))
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
check("one phone alert", len(alerts) == 1 and "shadow_complete" in alerts[0]["title"])

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

print("\nthe relay client:")
seen = []


def rop(req, timeout=0):
    seen.append((req.get_method(), req.full_url, req.headers.get("Authorization")))
    return Resp(b'{"next": null}')


S.Relay("https://relay.example.com/", "tok", rop).next(5)
check("the client sends the submit token as a bearer, to /submit/next with the app id",
      seen[-1] == ("GET", "https://relay.example.com/submit/next?app_id=5", "Bearer tok"))
try:
    S.Relay("", "tok")
    check("a relay client without a URL refuses to start", False)
except SystemExit:
    check("a relay client without a URL refuses to start", True)

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
