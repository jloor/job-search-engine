#!/usr/bin/env python3
"""A company he APPLIED to could have a board nobody ever swept.

🚨 THE ONE-WAY DOOR. inbox_register_board enables a board when he MAILS IN a posting, on the
reasoning that a forward is strong evidence. Nothing did the same when he APPLIED, which is
stronger evidence still: a forward is interest, an application is a decision.

⚠️ MEASURED 2026-09-21, AND THE NAMES ARE THE ARGUMENT. Nine boards were dark at companies
with a real application on file: Anthropic, Phreesia (the boomerang at his former employer),
Cognition, Deepgram, Cortex, Snapdocs on two platforms, Leap and Simon Data. All nine came
from the aggregator import as enabled=0 and were never turned on.

⭐ WHY IT WAS INVISIBLE. The ghosting rule puts a company on WATCH when a requisition dies,
so the next opening is caught. A dark board cannot watch anything, so the watch was silently
inert at exactly the companies he had chosen. Nothing failed; nothing happened.

📌 The audit that found it also PROVED the enabled=0 policy is otherwise sound: zero dark
boards had ever produced a scored candidate, so nothing was being fetched and then binned.
Only the application signal was missing.

Run:  python3 tests/test_board_enable.py
"""
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_parse                                             # noqa: E402

relay = test_parse.load_app()
SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


print("the rule exists and runs where every route is caught:")
check("enable_boards_for_applied_companies exists",
      "def enable_boards_for_applied_companies()" in SRC)
check("job_track calls it", "lit = enable_boards_for_applied_companies()" in SRC)
fn = SRC.split("def enable_boards_for_applied_companies", 1)[1].split("\ndef ", 1)[0]
body = fn.split('"""', 2)[2]
check("it is set-based, joining applications to boards",
      "JOIN application a ON a.posting_id = p.id" in body)
check("it only looks at DARK boards", "WHERE b.enabled = 0" in body)
# 🚨 The dangerous inverse. enabled=0 elsewhere is deliberate policy (a Fantastic match is
# weaker evidence than a forward) and this rule is not entitled to overrule it.
check("it never sets enabled=0", "enabled=0" not in body and "enabled = 0, " not in body)
check("it records WHY each board was lit", "he applied at this company" in body)

print("\nit runs on every pass, not only when something moved:")
track = SRC.split("def job_track", 1)[1].split("\ndef ", 1)[0]
call_i = track.index("enable_boards_for_applied_companies()")
early = track.index('return "nothing to track"')
check("the call sits after the early return, so it is not skipped by it",
      call_i > early)

print("\nbehaviour, against a real temporary database:")
_d = tempfile.mkdtemp()
_old = os.environ.get("DB_PATH")
try:
    os.environ["DB_PATH"] = str(pathlib.Path(_d) / "t.db")
    relay.DB_PATH = os.environ["DB_PATH"]
    relay.init_db()
    now = relay.now()
    with relay.db() as con:
        # A company he applied to, whose board is dark.
        con.execute("INSERT INTO company(id,name,ats_platform,ats_token) VALUES (1,'Anthropic','lever','anthropic')")
        con.execute("INSERT INTO posting(id,company_id,title,captured_at) VALUES (1,1,'Role',?)", (now,))
        con.execute("INSERT INTO application(id,posting_id,status) VALUES (1,1,'submitted')")
        con.execute("INSERT INTO scan_board(platform,token,api_url,source,added_at,enabled) "
                    "VALUES ('lever','anthropic','https://api.lever.co/v0/postings/anthropic','agg',?,0)", (now,))
        # A company he never applied to, whose board is ALSO dark. Must stay dark.
        con.execute("INSERT INTO company(id,name,ats_platform,ats_token) VALUES (2,'Unrelated','lever','unrelated')")
        con.execute("INSERT INTO scan_board(platform,token,api_url,source,added_at,enabled) "
                    "VALUES ('lever','unrelated','https://api.lever.co/v0/postings/unrelated','agg',?,0)", (now,))

    # 🚨 PROBE THE BOARD, NEVER ASSUME IT ANSWERS. The first version of this rule shipped
    # without a probe and lit nine boards of which SEVEN returned 404: the aggregator had
    # written several guesses per company and the broken ones sat disabled BECAUSE they were
    # broken. Stub the fetch so the test is deterministic and offline.
    _real_fetch = relay._board_reqs
    relay._board_reqs = lambda plat, url: (
        [{"req_id": "1", "title": "Role"}] if "anthropic" in url
        else (_ for _ in ()).throw(RuntimeError("HTTP Error 404: Not Found")))

    lit = relay.enable_boards_for_applied_companies()
    check("it lit the applied-to board that ANSWERED", lit == ["lever|anthropic"])
    with relay.db() as con:
        st = {r["token"]: r["enabled"] for r in con.execute("SELECT token, enabled FROM scan_board")}
        note = con.execute("SELECT note FROM scan_board WHERE token='anthropic'").fetchone()["note"]
    check("anthropic is now enabled", st["anthropic"] == 1)
    # 🚨 THE CHECK THAT MATTERS MOST. A rule that lights everything would also "pass" the
    # test above, and would quietly overrule a deliberate policy across 13,000 boards.
    check("the unrelated dark board STAYED dark", st["unrelated"] == 0)
    check("the note says why it was lit", "applied at this company" in (note or ""))

    print("\n  a board that does NOT answer is left dark, with the reason recorded:")
    with relay.db() as con:
        con.execute("INSERT INTO company(id,name,ats_platform,ats_token) VALUES (3,'Dead','lever','deadco')")
        con.execute("INSERT INTO posting(id,company_id,title,captured_at) VALUES (3,3,'Role',?)", (now,))
        con.execute("INSERT INTO application(id,posting_id,status) VALUES (3,3,'submitted')")
        con.execute("INSERT INTO scan_board(platform,token,api_url,source,added_at,enabled) "
                    "VALUES ('lever','deadco','https://api.lever.co/v0/postings/deadco','agg',?,0)", (now,))
    lit2 = relay.enable_boards_for_applied_companies()
    with relay.db() as con:
        d = dict(con.execute("SELECT enabled, note FROM scan_board WHERE token='deadco'").fetchone())
    check("a 404 board is NOT enabled", d["enabled"] == 0 and "lever|deadco" not in lit2)
    check("the reason is written on the row", "did not answer a probe" in (d["note"] or ""))

    print("\n  it is idempotent, so a 10-minute job does not churn:")
    again = relay.enable_boards_for_applied_companies()
    check("a second run lights nothing", again == [])
    # ⚠️ A dead board must not be re-probed forever against somebody else's infrastructure.
    probed = []
    relay._board_reqs = lambda plat, url: probed.append(url) or []
    relay.enable_boards_for_applied_companies()
    check("a board already proven dead is never probed again", probed == [])
    relay._board_reqs = _real_fetch
finally:
    if _old is None:
        os.environ.pop("DB_PATH", None)
    else:
        os.environ["DB_PATH"] = _old

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
