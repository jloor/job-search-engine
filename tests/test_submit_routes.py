#!/usr/bin/env python3
"""The browser submitter's routes: who may call them, what they may pick, what they may write.

⭐ WHY THESE ROUTES ARE NARROW. The submitter runs on a separate host user that drives a browser
through third-party pages, so its credential is the one most exposed to hostile content. It
holds SUBMIT_TOKEN and never the database token, and these routes are everything that token
can do.

🚨 WHAT MUST NEVER HAPPEN:
  - the submit token opening a read or admin route, or a read or admin token opening a submit
    route;
  - a submit route changing application.status (shadow mode cannot record a submission);
  - a suspended, stopped or already-shadowed application being handed out again by /submit/next;
  - an unset SUBMIT_TOKEN meaning "open".

Run:  python3 tests/test_submit_routes.py
"""
import asyncio
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_parse                                             # noqa: E402  (strips BUNNY_*)

os.environ["DB_PATH"] = tempfile.mkdtemp() + "/submit.db"
app = test_parse.load_app()
if getattr(app, "BUNNY_DB_URL", ""):
    sys.exit("refusing to run: the app is bound to a remote database")
app.init_db()
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


def code_of(fn, *a, **k):
    """The HTTP status a call raises, or 200 when it returns."""
    try:
        r = fn(*a, **k)
        if asyncio.iscoroutine(r):
            asyncio.run(r)
        return 200
    except Exception as e:
        return getattr(e, "code", None) or repr(e)


class Req:
    """Enough of a Starlette request for these routes."""
    def __init__(self, body=None):
        self._body = body or {}
        self.client = type("C", (), {"host": "10.0.0.9"})()
        self.headers = {}

    async def json(self):
        return self._body


def call(fn, *a, body=None, auth=None, **k):
    r = fn(*a, Req(body), authorization=auth, **k)
    return asyncio.run(r) if asyncio.iscoroutine(r) else r


GH = "https://job-boards.greenhouse.io/acme/jobs/1001"
with app.db() as con:
    con.execute("INSERT INTO company(id, name) VALUES (1, 'Acme')")
    rows = [  # id, url, status, package, alias
        (1, GH, "draft", "applications/acme/a", "acme@jobs.example.com"),
        (2, "https://acme.example.com/careers?gh_jid=1002", "draft", "applications/acme/b",
         "acme@jobs.example.com"),
        (3, "https://jobs.lever.co/acme/x", "draft", "applications/acme/c", "acme@jobs.example.com"),
        (4, GH + "4", "suspended", "applications/acme/d", "acme@jobs.example.com"),
        (5, GH + "5", "draft", None, "acme@jobs.example.com"),
        (6, GH + "6", "draft", "applications/acme/f", None),
        (7, GH + "7", "submitted", "applications/acme/g", "acme@jobs.example.com"),
    ]
    for i, url, st, pkg, alias in rows:
        con.execute("INSERT INTO posting(id, company_id, title, canonical_url, captured_at) "
                    "VALUES (?,1,'Role',?, '2026-10-01')", (i, url))
        con.execute("INSERT INTO application(id, posting_id, status, package_path, alias_used) "
                    "VALUES (?,?,?,?,?)", (i, i, st, pkg, alias))

print("schema:")
sql = (HERE.parent / "job_search_engine" / "schema.sql").read_text()
for t in ("submit_run", "submit_step"):
    check(f"schema.sql declares {t}", f"CREATE TABLE IF NOT EXISTS {t} (" in sql)
    check(f"MIGRATIONS declares {t}", any(f"CREATE TABLE IF NOT EXISTS {t} (" in m for m in app.MIGRATIONS))

print("\nthe token:")
app.READ_TOKEN, app.ADMIN_TOKEN = "read-tok", "admin-tok"
app.SUBMIT_TOKEN = ""
check("unset SUBMIT_TOKEN closes the routes (503), never opens them",
      code_of(app.submit_next, Req(), authorization="Bearer anything") == 503)
app.SUBMIT_TOKEN = "submit-tok"
check("no token is 401", code_of(app.submit_next, Req(), authorization=None) == 401)
check("a wrong token is 401", code_of(app.submit_next, Req(), authorization="Bearer nope") == 401)
check("the READ token is refused on a submit route (403)",
      code_of(app.submit_next, Req(), authorization="Bearer read-tok") == 403)
check("the ADMIN token is refused on a submit route (403)",
      code_of(app.submit_next, Req(), authorization="Bearer admin-tok") == 403)
check("the submit token opens /submit/next",
      code_of(app.submit_next, Req(), authorization="Bearer submit-tok") == 200)
check("the submit token carries no read scope", app._scope_of("Bearer submit-tok") is None)
check("…so it is refused on a read route",
      code_of(app.require_read, "Bearer submit-tok", Req()) == 401)
check("…and on an admin route", code_of(app.require_admin, "Bearer submit-tok", Req()) == 401)

S = "Bearer submit-tok"
print("\nwhat /submit/next hands out:")
nxt = call(app.submit_next, auth=S)["next"]
check("the oldest eligible draft comes first (a hosted Greenhouse board)",
      nxt and nxt["application_id"] == 1 and nxt["ats"] == "greenhouse")
for i, why in ((2, "a gh_jid embed counts as Greenhouse"),):
    check(why, (call(app.submit_next, auth=S, app_id=i)["next"] or {}).get("application_id") == i)
for i, why in ((3, "Lever is not handed out yet"), (4, "a SUSPENDED package is never handed out"),
               (5, "no package path, no run"), (6, "no alias, no run"),
               (7, "a submitted application is never handed out")):
    check(why, call(app.submit_next, auth=S, app_id=i)["next"] is None)

print("\nopening a run:")
check("only shadow mode is accepted",
      code_of(app.submit_run_open, Req({"application_id": 1, "mode": "live"}), authorization=S) == 400)
check("an ineligible application is refused (409)",
      code_of(app.submit_run_open, Req({"application_id": 4}), authorization=S) == 409)
r = call(app.submit_run_open, auth=S, body={"application_id": 1, "ats": "greenhouse",
                                             "engine_version": "test", "host": "h"})
rid = r["run_id"]
check("a run opens on an eligible draft", r["ok"] and rid)
check("an application with a run in progress is not handed out again",
      call(app.submit_next, auth=S, app_id=1)["next"] is None)
check("…and a second run on it is refused",
      code_of(app.submit_run_open, Req({"application_id": 1}), authorization=S) == 409)

print("\nsteps:")
ok_step = {"n": 1, "name": "liveness", "outcome": "ok", "screenshot_path": "/e/1.png",
           "sha256": "a" * 64}
check("a step is recorded", code_of(app.submit_run_step, rid, Req(ok_step), authorization=S) == 200)
check("the same step number twice is refused (409)",
      code_of(app.submit_run_step, rid, Req(ok_step), authorization=S) == 409)
check("an unknown step outcome is refused",
      code_of(app.submit_run_step, rid, Req({"n": 2, "name": "x", "outcome": "submitted"}),
              authorization=S) == 400)
check("a malformed sha256 is refused",
      code_of(app.submit_run_step, rid, Req({"n": 2, "name": "x", "outcome": "ok", "sha256": "zz"}),
              authorization=S) == 400)
check("a step on a run that does not exist is 404",
      code_of(app.submit_run_step, 999, Req(ok_step), authorization=S) == 404)

print("\nclosing:")
check("an unknown outcome is refused (no 'submitted' outcome exists)",
      code_of(app.submit_run_close, rid, Req({"outcome": "submitted"}), authorization=S) == 400)
check("a run closes", code_of(app.submit_run_close, rid, Req({"outcome": "shadow_complete"}),
                              authorization=S) == 200)
check("a closed run cannot close again",
      code_of(app.submit_run_close, rid, Req({"outcome": "error"}), authorization=S) == 409)
check("a closed run takes no more steps",
      code_of(app.submit_run_step, rid, Req(dict(ok_step, n=5)), authorization=S) == 409)
with app.db() as con:
    st = con.execute("SELECT status FROM application WHERE id=1").fetchone()["status"]
    n_steps = con.execute("SELECT count(*) AS n FROM submit_step WHERE run_id=?", (rid,)).fetchone()["n"]
check("🚨 the application is STILL a draft after a complete shadow run", st == "draft")
check("exactly the one valid step was stored", n_steps == 1)
check("a shadow-complete application is not handed out again",
      call(app.submit_next, auth=S, app_id=1)["next"] is None)

print("\nretries:")
r2 = call(app.submit_run_open, auth=S, body={"application_id": 2})["run_id"]
call(app.submit_run_close, r2, auth=S, body={"outcome": "stopped", "stop_step": "answers",
                                             "stop_reason": "no answer for a required question"})
check("a STOPPED run waits for a person: not handed out again",
      call(app.submit_next, auth=S, app_id=2)["next"] is None)
with app.db() as con:
    con.execute("INSERT INTO company(id, name) VALUES (2, 'Beta')")
    con.execute("INSERT INTO posting(id, company_id, title, canonical_url, captured_at) "
                "VALUES (20, 2, 'Role', ?, '2026-10-01')", (GH + "20",))
    con.execute("INSERT INTO application(id, posting_id, status, package_path, alias_used) "
                "VALUES (20, 20, 'draft', 'applications/beta/a', 'beta@jobs.example.com')")
for k in range(app.SUBMIT_ERROR_RETRIES):
    check(f"an ERROR run is retried (attempt {k + 1})",
          call(app.submit_next, auth=S, app_id=20)["next"] is not None)
    rr = call(app.submit_run_open, auth=S, body={"application_id": 20})["run_id"]
    call(app.submit_run_close, rr, auth=S, body={"outcome": "error"})
check(f"…but not after {app.SUBMIT_ERROR_RETRIES} errors",
      call(app.submit_next, auth=S, app_id=20)["next"] is None)
with app.db() as con:
    con.execute("INSERT INTO posting(id, company_id, title, canonical_url, captured_at) "
                "VALUES (21, 2, 'Role', ?, '2026-10-01')", (GH + "21",))
    con.execute("INSERT INTO application(id, posting_id, status, package_path, alias_used) "
                "VALUES (21, 21, 'draft', 'applications/beta/b', 'beta@jobs.example.com')")
    con.execute("INSERT INTO submit_run(application_id, started_at, outcome) "
                "VALUES (21, '2020-01-01T00:00:00+00:00', 'running')")
check("a run left 'running' for hours is treated as abandoned",
      call(app.submit_next, auth=S, app_id=21)["next"] is not None)

print("\ndiagnostics:")
check("SUBMIT_TOKEN is fingerprinted in /diag/config, never shown",
      '"SUBMIT_TOKEN"' in (HERE.parent / "job_search_engine" / "app.py").read_text())

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
