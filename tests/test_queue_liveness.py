#!/usr/bin/env python3
"""The queue offered work that no longer existed, and nothing ever re-read it.

🚨 WHAT IT COST, MEASURED 2026-09-18. Fifteen leads were worked by hand off the queue in one
session. Nine were already dead: GE HealthCare, Kalepa, Cordial, GeneDx, Mercury, Marqeta and
others. Two of them had been listed as that morning's shortlist. Each one cost an archive
attempt, a board probe and a decision, for a requisition the employer had already pulled.

⭐ WHY job_verify DID NOT COVER IT. That job reads the postings behind LIVE APPLICATIONS on
purpose: the expensive failure it was built for is a requisition dying underneath a package
already sent. Nothing was wrong with that reasoning. The queue is the other half, and it was
never read, because re-probing thousands of scored rows would spend requests on employers who
are owed none.

⭐ THE FIX IS NARROW BY DESIGN. job_verify_queue probes only what would be OFFERED: triaged,
at or above the score floor, not already applied to, not passed. Everything below that is
never touched, because nobody was going to open it.

Run:  python3 tests/test_queue_liveness.py
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
SCHEMA = (HERE.parent / "job_search_engine" / "schema.sql").read_text()
fails = []


def check(label, got, want=True):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:62} {got!r}")
    if not ok:
        fails.append(label)


job = SRC[SRC.index("def job_verify_queue"):SRC.index("# The interaction log.")]

print("\nthe job exists, is registered, and is paced:")
check("job_verify_queue is defined", "def job_verify_queue() -> str:" in SRC)
check("registered in the job table", '("verify_queue", QVERIFY_EVERY_MIN * 60, job_verify_queue)' in SRC)
check("paced like job_verify", "time.sleep(VERIFY_PACE)" in job)
check("uses the shared liveness reader", "posting_liveness(" in job)

print("\nit probes only what would be offered:")
check("score floor applied", "cast(c.score as int) >= ?" in job)
check("untriaged rows skipped", "c.triaged = 1" in job)
check("out_of_scope and duplicates skipped", "out_of_scope" in job)
check("rows with no url skipped", "c.url IS NOT NULL" in job)
check("already applied rows left to job_verify", "FROM posting p WHERE p.canonical_url = c.url" in job)
check("passed roles skipped", "FROM role_passed rp WHERE rp.url = c.url" in job)
check("a fresh reading is not re-asked", "c.live_checked_at IS NULL OR c.live_checked_at < ?" in job)
check("never-checked rows go first", "ORDER BY c.live_checked_at IS NOT NULL" in job)

print("\nit records a fact about the requisition and nothing else:")
check("writes scan_candidate only", "UPDATE scan_candidate SET live_status=?" in job)
check("does not touch the score", "score=" not in job.split("UPDATE scan_candidate")[1][:200])
check("blocked reads become unknown, not the old verdict",
      '{"ok": "live", "gone": "dead"}.get(res["state"], "unknown")' in job)
check("evidence is stored with the verdict", "live_evidence" in job)
check("the run is logged", 'log_event(con, "verify_queue"' in job)

print("\nthe verdict is actually spent where rows are offered:")
check("search_queue hides dead rows", SRC.count("COALESCE(c.live_status,'') <> 'dead'") >= 2)
check("morning report shortlist hides dead rows",
      "AND COALESCE(c.live_status,'') <> 'dead'" in SRC)
check("only a confirmed dead row is hidden", "<> 'dead'" in SRC and "!= 'live'" not in SRC)

print("\nthe columns are declared, not only migrated:")
for col in ("live_status", "live_evidence", "live_checked_at"):
    check(f"schema.sql declares {col}", col in SCHEMA)
    check(f"migration adds {col}", f"ALTER TABLE scan_candidate ADD COLUMN {col}" in SRC)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
