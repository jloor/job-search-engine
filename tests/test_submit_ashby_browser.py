#!/usr/bin/env python3
"""The Ashby hand-off in browser/form.js, against a synthetic Ashby-shaped form, in a real browser.

⭐ WHY (2026-10-08). Ashby refuses a scripted Submit as possible spam, and imitating a person to pass
that check is evasion. So an Ashby live run fills and verifies the form, then HANDS the Submit
button to the operator for his own click. Ashby's buttons sit outside any <form>: its Submit fires no
submit event, and the Greenhouse guards do not see it. These cases are the Ashby guards.

🚨 WHAT MUST NEVER HAPPEN:
  - a submit request reaching the server before the hand-off: a page script that clicks Submit (an
    untrusted click) and one that sends the submit request itself must both be blocked AND counted;
  - an untrusted click passing the hand-off: only a trusted click on the handed-off button counts;
  - a hand-off without the relay's nonce (an armed, consumed approval);
  - a form nobody clicked reading as anything but "nothing happened" (all counters zero).

Needs node and the browser/ dependencies; without them it prints SKIP and exits 0 (--strict fails).
Run:  python3 tests/test_submit_ashby_browser.py [--strict]
"""
import http.server
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading

HERE = pathlib.Path(__file__).resolve().parent
PKG_DIR = HERE.parent / "job_search_engine"
sys.path.insert(0, str(PKG_DIR))
STRICT = "--strict" in sys.argv
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


def skip(why):
    print(f"SKIP: {why}")
    sys.exit(1 if STRICT else 0)


if not shutil.which("node"):
    skip("node is not installed")
probe = subprocess.run(["node", "-e", "require('playwright')"], cwd=str(PKG_DIR / "browser"),
                       capture_output=True, text=True)
if probe.returncode != 0:
    skip("playwright is not installed in job_search_engine/browser (npm ci there)")

import answers as A                                             # noqa: E402
import submit as S                                              # noqa: E402

FORM = (HERE / "fixtures" / "submit-form-ashby.html").read_bytes()
posts = []


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(FORM)

    def do_POST(self):                                          # a submit request got through
        n = int(self.headers.get("Content-Length") or 0)
        posts.append((self.path, self.rfile.read(n).decode(errors="replace")))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}/example/0000/application"
LINKEDIN, GROUP, YESNO, WHY, RADIO = (f"1a2b3c4d-0000-4000-8000-00000000000{i}" for i in (2, 3, 4, 5, 6))

pkg = pathlib.Path(tempfile.mkdtemp())
(pkg / "resume.pdf").write_bytes(b"%PDF-1.4 resume " * 64)
(pkg / "form-answers.json").write_text(json.dumps({GROUP: "Other (please specify)",
                                                   WHY: "Because the integrations are the product."}))
CFG = {"identity": {"full_name": "Alex Rivera", "phone": "555-010-0199",
                    "linkedin": "https://www.example.com/in/alex"},
       "form_rule": [{"match": "^name$", "from": "identity.full_name", "kind": "text"},
                     {"match": "linkedin", "from": "identity.linkedin", "kind": "text"},
                     {"match": "legally authorized", "answer": "Yes", "kind": "select"},
                     {"match": "nyc-metro", "answer": "Yes", "kind": "select"}]}
ALIAS = "acme@jobs.example.com"
ENV = dict(os.environ, FORMJS_TEST_HUMAN_CLICK="1")


def filled(url):
    """A browser on the form, filled and read back. Returns (br, decisions, fill results, readback)."""
    br = S.Browser("node", env=ENV)
    br("open", url=url, headed=False, settle=300)
    h = br("harvest")
    decisions, stops = A.plan(h["fields"], {}, CFG, pkg, ALIAS)
    assert not stops, stops
    fr = br(**A.fill_command(decisions))
    files = [{"id": x["id"], "name": pathlib.Path(x["path"]).name} for x in A.fill_command(decisions)["files"]]
    rb = br("readback", files=files)
    return br, h, decisions, fr, rb


print("harvest, answers, fill and read-back on an Ashby form:")
br, h, decisions, fr, rb = filled(BASE)
try:
    kinds = {f["id"]: f["kind"] for f in h["fields"]}
    req = {f["id"] for f in h["fields"] if f["required"]}
    check("the yes/no widget is ONE field, keyed by the question id", kinds.get(YESNO) == "yesno")
    check("the checkbox group is ONE field, keyed by the question id, with its options",
          kinds.get(GROUP) == "checkgroup"
          and next(f for f in h["fields"] if f["id"] == GROUP)["options"][-1] == "Other (please specify)")
    check("the group's option checkboxes are not separate fields",
          not any(k.startswith("g1_") for k in kinds))
    # ⚠️ 2026-10-09: each radio used to be its own field labelled "Yes" or "No", never required.
    rf = next((f for f in h["fields"] if f["id"] == RADIO), {})
    check("the radio group is ONE field, keyed by the question id, labelled by the question",
          rf.get("kind") == "radiogroup" and rf.get("label", "").startswith("Are you based in the NYC")
          and rf.get("options") == ["Yes", "No"])
    check("the group's radios are not separate fields", not any(k.startswith("f0_") for k in kinds))
    check("the radio group's required is read from the question title's class", RADIO in req)
    check("required is read from the question title's class (yes/no, group) and the attribute (text)",
          {YESNO, GROUP, "_systemfield_name", WHY} <= req and LINKEDIN not in req)
    by = {d.id: d for d in decisions}
    check("the yes/no answer comes from a Yes/No select rule, as exactly 'yes'", by[YESNO].value == "yes")
    check("the group answer comes ONLY from form-answers.json", by[GROUP].source == "package form-answers.json")
    check("the radio answer comes from a select rule, matched to an offered option",
          by[RADIO].value == "Yes" and by[RADIO].source.startswith("form_rule") and not by[RADIO].problem)
    check("the fill checks the radio and reports it set",
          any(r["id"] == RADIO and r["status"] == "set" and r["chosen"] == "Yes" for r in fr["results"]))
    check("the read-back shows the checked option's label",
          any(f["id"] == RADIO and f.get("value") == "Yes" for f in rb["fields"]))
    check("the phone is found by its label (Ashby ids are UUIDs)", by["1a2b3c4d-0000-4000-8000-000000000001"].value == "555-010-0199")
    check("the email is the application's alias", by["_systemfield_email"].value == ALIAS)
    check("the résumé goes to the system résumé field, never to 'Autofill from resume'",
          by["_systemfield_resume"].answered and not by.get("autofill-upload", A.Decision("x", "file", "", False)).answered)
    check("every planned field reports set", all(r["status"] == "set" for r in fr["results"]))
    bad = S.compare(decisions, fr["results"], rb["fields"], rb["uploads"])
    check("the read-back matches every decision (yes/no from aria-pressed, the group's ticks)", not bad)
    if bad:
        print("     ", bad)
    check("nothing is required and empty", not S.required_empty(rb["fields"], h["fields"]))
    check("no submit request reached the server", not posts)

    print("\n🚨 the page cannot submit on its own:")
    br("fill", texts=[{"id": LINKEDIN, "value": "click-me"}])
    c = br("readback")["blocked_submits"]
    check("a page script's click on Submit (untrusted) is blocked and counted", c["submit_events"] >= 1)
    br("fill", texts=[{"id": LINKEDIN, "value": "fetch-me"}])
    c = br("readback")["blocked_submits"]
    check("a page script's own submit request is aborted at the network and counted", c["submit_requests"] >= 1)
    check("…and still nothing reached the server", not posts)
    try:
        br("handoff", nonce=secrets.token_hex(16), hold_s=30)
        check("a hand-off without arming is refused", False)
    except RuntimeError as e:
        check("a hand-off without arming is refused", "not armed" in str(e))
finally:
    br.quit()

print("\nthe hand-off: a person's click, and only that:")
posts.clear()
br, h, decisions, fr, rb = filled(BASE)
try:
    nonce = secrets.token_hex(16)
    br("arm", nonce=nonce)
    r = br("handoff", nonce=nonce, hold_s=30, clicks=3)
    check("the hand-off tags the button and holds the form", r.get("handed_off"))
    br("fill", texts=[{"id": LINKEDIN, "value": "click-me"}])
    check("🚨 during the hand-off, a page script's click still does not submit", not posts)
    br("test_human_click")
    r = br("await_proof", wait_s=10)
    check("the person's click submits, and Ashby's success text is the proof",
          r["status"] == "proof" and "successfully submitted" in r["excerpt"])
    check("exactly one submit request reached the server", len(posts) == 1)
    c = br("readback")["blocked_submits"]
    check("the click is counted as the person's", c["human_clicks"] == 1)
finally:
    br.quit()

print("\na spam refusal, then the person's second click:")
posts.clear()
br, *_ = filled(BASE + "?spam=1")
try:
    nonce = secrets.token_hex(16)
    br("arm", nonce=nonce)
    br("handoff", nonce=nonce, hold_s=30, clicks=3)
    br("test_human_click")
    r = br("await_proof", wait_s=10)
    check("the refusal is reported as spam_refused, with the page's words",
          r["status"] == "spam_refused" and "possible spam" in r["excerpt"])
    r = br("await_proof", wait_s=2)
    check("no further click: no proof, and the refusal still on the page (spam_page)",
          r["status"] == "no_proof" and r.get("spam_page") is True)
    br("test_human_click")
    r = br("await_proof", wait_s=10)
    check("the person's second click goes through", r["status"] == "proof")
    check("two clicks, both the person's", br("readback")["blocked_submits"]["human_clicks"] == 2)
finally:
    br.quit()

print("\nno click:")
posts.clear()
br, *_ = filled(BASE)
try:
    nonce = secrets.token_hex(16)
    br("arm", nonce=nonce)
    br("handoff", nonce=nonce, hold_s=30)
    r = br("await_proof", wait_s=2)
    c = br("readback")["blocked_submits"]
    check("no proof, and every counter reads zero: nothing was attempted",
          r["status"] == "no_proof" and not any(c.values()))
    check("…and no spam refusal on the page", r.get("spam_page") is False)
    check("nothing reached the server", not posts)
finally:
    br.quit()

print("\nthe emailed code after the person's click:")
posts.clear()
br, *_ = filled(BASE + "?code=1")
try:
    nonce = secrets.token_hex(16)
    br("arm", nonce=nonce)
    br("handoff", nonce=nonce, hold_s=30)
    br("test_human_click")
    r = br("await_proof", wait_s=10)
    check("the code step is recognised after the person's click", r["status"] == "code_step")
    r = br("enter_code", code="AbCd1234", wait_s=10)
    check("the runner enters the code and the form is accepted", r["status"] == "proof")
    c = br("readback")["blocked_submits"]
    check("the code click is counted as the runner's, not as a second click by the person",
          c["human_clicks"] == 1 and c["sanctioned"] >= 1)
finally:
    br.quit()

print("\nthe test-only click does not exist without its variable:")
br = S.Browser("node")
try:
    br("open", url=BASE, headed=False, settle=200)
    try:
        br("test_human_click")
        check("test_human_click is refused on a normal process", False)
    except RuntimeError as e:
        check("test_human_click is refused on a normal process", "unknown command" in str(e))
finally:
    br.quit()

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
