#!/usr/bin/env python3
"""A quarter of the queue could not be read at all, and a blocked row looks live.

🚨 THE MEASUREMENT. job_verify_queue's first two runs checked 36 rows and returned 9 as
blocked, about 25%. Workday tenants, careers-page wrappers and anything rendered by
JavaScript sit in that quarter permanently: no amount of retrying a fetch renders a page.
A row nobody can read is offered to a human exactly like one that is live.

⭐ THE SPLIT THIS GUARDS. liveness.js in the harvester DESCRIBES a page: status, final URL,
field count, file inputs, and which phrases it found. render_liveness DECIDES. The reader
knows nothing about what a healthy Lever page looks like versus a healthy Workday one, and
it must not, because a reader that decides is a reader that invents verdicts.

⚠️ THE ASYMMETRY IS THE POINT. Calling a live requisition dead costs a real application.
Calling a dead one unknown costs one wasted look. So `dead` needs real evidence and anything
positive wins.

The three fixtures below are REAL reads taken on 2026-09-18, not invented shapes.

Run:  python3 tests/test_render_liveness.py
"""
import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("app", HERE.parent / "job_search_engine" / "app.py")
app = importlib.util.module_from_spec(spec)
sys.modules["app"] = app
spec.loader.exec_module(app)
fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:58} {got!r}")
    if not ok:
        fails.append(f"{label}: got {got!r} want {want!r}")


# GE HealthCare, R4044244. The requisition is gone and Workday answers HTTP 200 with a soft
# 404, which is why every plain fetch returned blocked rather than dead.
GEHC = {"http_status": 200, "title": "GE HealthCare Careers", "field_count": 0,
        "file_inputs": 0, "redirected": False, "text_length": 427,
        "gone_markers": ["the page you are looking for"], "alive_markers": []}

# Celigo, Senior Solutions Architect. A live Greenhouse application page.
CELIGO = {"http_status": 200, "title": "Job Application for Senior Solutions Architect at Celigo",
          "field_count": 25, "file_inputs": 2, "redirected": False, "text_length": 9000,
          "gone_markers": [], "alive_markers": ["apply for this job", "submit application",
                                                "resume/cv", "first name"]}

# 📌 Redox, Senior Integration Coordinator. A live LEVER POSTING page has ZERO fields,
# because the form lives at /apply. A field count alone would call this dead.
REDOX = {"http_status": 200, "title": "Redox - Senior Integration Coordinator",
         "field_count": 0, "file_inputs": 0, "redirected": False, "text_length": 6000,
         "gone_markers": [], "alive_markers": ["apply for this job"]}

print("\nreal reads taken 2026-09-18:")
check("a Workday soft 404 is dead", app.render_liveness("u", GEHC)[0], "dead")
check("a live Greenhouse form is live", app.render_liveness("u", CELIGO)[0], "live")
check("a live Lever posting with no fields is live", app.render_liveness("u", REDOX)[0], "live")

print("\nthe asymmetry holds:")
check("a real 404 is dead without any marker",
      app.render_liveness("u", {"http_status": 404, "gone_markers": [], "alive_markers": []})[0], "dead")
check("a render failure is never a verdict",
      app.render_liveness("u", {"error": "navigation failed: timeout"})[0], "unknown")
check("a silent page is not evidence",
      app.render_liveness("u", {"http_status": 200, "field_count": 0, "file_inputs": 0,
                                "gone_markers": [], "alive_markers": []})[0], "unknown")
check("a gone marker loses to a working form",
      app.render_liveness("u", {"http_status": 200, "field_count": 20, "file_inputs": 1,
                                "gone_markers": ["no longer available"],
                                "alive_markers": []})[0], "live")
check("a file input alone is enough to be live",
      app.render_liveness("u", {"http_status": 200, "field_count": 1, "file_inputs": 1,
                                "gone_markers": [], "alive_markers": []})[0], "live")

print("\nevidence travels with every verdict:")
for name, obs in (("dead", GEHC), ("live", CELIGO)):
    ev = app.render_liveness("u", obs)[1]
    check(f"the {name} verdict says what was seen", "rendered: http 200" in ev, True)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
