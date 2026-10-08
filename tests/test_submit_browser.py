#!/usr/bin/env python3
"""The submitter's browser driver (browser/form.js) against a synthetic form, in a real browser.

🚨 WHAT MUST NEVER HAPPEN:
  - a submission reaching the server. The fixture page tries twice on its own (a submit event,
    and a direct form.submit() that skips the event); both must be blocked AND counted;
  - a value the page changed after it was typed passing the read-back;
  - a file that did not attach passing the read-back.

Needs node and the browser/ dependencies (`npm ci` in job_search_engine/browser, then
`npx playwright install chromium-headless-shell`). Without them it prints SKIP and exits 0;
--strict turns the skip into a failure.

Run:  python3 tests/test_submit_browser.py [--strict]
"""
import http.server
import pathlib
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

FORM = (HERE / "fixtures" / "submit-form.html").read_bytes()
posts = []


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(FORM)

    def do_POST(self):                                          # a submission got through
        posts.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h1>Thank you for applying</h1>")

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{srv.server_address[1]}/apply"

pkg = pathlib.Path(tempfile.mkdtemp())
(pkg / "resume.pdf").write_bytes(b"%PDF-1.4 resume " * 64)
(pkg / "cover-letter.pdf").write_bytes(b"%PDF-1.4 letter " * 64)
(pkg / "form-answers.json").write_text(
    '{"question_103": "Because the work is interesting.", "question_104": "https://example.com"}')
CFG = {"identity": {"first_name": "Alex", "last_name": "Rivera", "phone": "555-010-0199",
                    "country": "United States"},
       "eeo": {"gender": "Female"},
       "form_rule": [{"match": "sponsorship", "answer": "No", "kind": "select"},
                     {"match": "linkedin", "answer": "https://www.example.com/in/alex", "kind": "text"}],
       "form_spellings": {"Female": ["Woman"]}}
shots = pathlib.Path(tempfile.mkdtemp())

print("one full fill:")
br = S.Browser("node")
try:
    o = br("open", url=URL, headed=False, settle=300)
    check("the form opens", "Example Role" in o["title"])
    h = br("harvest")
    kinds = {f["id"]: f["kind"] for f in h["fields"]}
    req = {f["id"] for f in h["fields"] if f["required"]}
    check("harvest sees the react-select controls as selects",
          kinds.get("country") == "select" and kinds.get("question_102") == "select")
    check("harvest sees the phone, the textarea and both file inputs",
          kinds.get("phone") == "tel" and kinds.get("question_103") == "textarea"
          and kinds.get("resume") == "file" and kinds.get("cover_letter") == "file")
    check("harvest reads required from aria-required", {"first_name", "country", "question_102"} <= req)
    check("the label loses its trailing asterisk",
          any(f["label"] == "First Name" for f in h["fields"]))
    check("no CAPTCHA on the fixture", not h["captcha"])

    decisions, stops = A.plan(h["fields"], {}, CFG, pkg, "acme@jobs.example.com")
    check("every required field has an answer", not stops)
    fr = br(**A.fill_command(decisions))
    status = {r["id"]: r for r in fr["results"]}
    check("every planned field reports set",
          all(r["status"] == "set" for r in fr["results"]), )
    check("the gender select chose the page's own wording (Woman), via [form_spellings]",
          status.get("gender", {}).get("chosen") == "Woman")
    check("🚨 an option rendered twice, with different spacing, is still chosen",
          (status.get("country", {}).get("chosen") or "").replace(" ", "") == "UnitedStates+1")
    p1 = shots / "filled.png"
    br("shot", path=str(p1))
    check("a screenshot is written, and it is a PNG", p1.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n")
    files = [{"id": x["id"], "name": pathlib.Path(x["path"]).name} for x in A.fill_command(decisions)["files"]]
    rb = br("readback", files=files)
    bad = S.compare(decisions, fr["results"], rb["fields"], rb["uploads"])
    check("🚨 the page's own edit to Website is caught by the read-back",
          len(bad) == 1 and "Website" in bad[0])
    check("a flag-and-code country value reads back as the country name, not just '+1'",
          next(f for f in rb["fields"] if f["id"] == "country")["value"] == "United States +1")
    check("the textarea is read back WHOLE, not truncated",
          next(f for f in rb["fields"] if f["id"] == "question_103")["value"]
          == "Because the work is interesting.")
    check("the upload that keeps its input is proved by the input (name and size)",
          next(f for f in rb["fields"] if f["id"] == "cover_letter")["files"][0]["size"] > 0)
    check("🚨 the upload whose input the page REPLACED reported set, not a timeout",
          status["resume"]["status"] == "set" and status["resume"]["via"] in ("input", "shown"))
    check("…its input is gone and the page shows the filename instead",
          all(f["id"] != "resume" for f in rb["fields"]) and rb["uploads"]["resume"]["shown"])
    nofile = [d for d in decisions if d.id == "resume"]
    check("a replaced input whose filename the page does NOT show is still caught",
          S.compare(nofile, [{"id": "resume", "status": "set"}], rb["fields"],
                    {"resume": {"held": None, "shown": False}}))
    check("nothing required is left empty", not S.required_empty(rb["fields"], h["fields"]))
    check("no submit was attempted", not any(rb["blocked_submits"].values()))
finally:
    br.quit()

print("\nthe page tries to submit by itself:")
for trigger, key in (("submit-me", "submit_events"), ("post-me", "submit_calls")):
    br = S.Browser("node")
    try:
        br("open", url=URL, headed=False, settle=300)
        br("fill", texts=[{"id": "question_101", "value": trigger}])
        rb = br("readback")
        check(f"{trigger}: the attempt is blocked and COUNTED ({key})", rb["blocked_submits"][key] >= 1)
        check(f"{trigger}: the page is still the form", any(f["id"] == "first_name" for f in rb["fields"]))
    finally:
        br.quit()
br = S.Browser("node")
try:
    br("open", url=URL, headed=False, settle=300)
    br("fill", texts=[{"id": "question_101", "value": "bypass-me"}])
    rb = br("readback")
    # The init script runs in every frame, the borrowed one included, so the page guard catches
    # this before the network sees it. 📌 The network guard (a non-GET top navigation is aborted)
    # is therefore defence in depth with no direct trigger here: no page script found so far gets
    # past the first two guards.
    check("bypass-me: a submit() borrowed from a fresh frame is still blocked and counted",
          rb["blocked_submits"]["submit_calls"] >= 1)
    check("bypass-me: the page is still the form", any(f["id"] == "first_name" for f in rb["fields"]))
finally:
    br.quit()
check("🚨 no POST ever reached the server", not posts)

print("\nthe protocol:")
br = S.Browser("node")
try:
    try:
        br("submit")
        check("an unknown command (submit) is refused", False)
    except RuntimeError as e:
        check("an unknown command (submit) is refused", "unknown command" in str(e))
    try:
        br("harvest")
        check("a command before open is refused", False)
    except RuntimeError as e:
        check("a command before open is refused", "no page open" in str(e))
finally:
    br.quit()

srv.shutdown()
print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
