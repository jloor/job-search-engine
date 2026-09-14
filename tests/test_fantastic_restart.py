#!/usr/bin/env python3
"""A restart makes every job due again, and this one spends money per row.

🚨 WHY, MEASURED 2026-09-14. The scheduler keeps `last` in memory and seeds it to 0.0 on
boot, so every pod restart runs everything at once. Three `fantastic` runs landed inside 25
minutes (14:28, 14:44, 14:53), two of them from restarts. `time_frame=1h` is a ROLLING
window, so a run ten minutes after the last re-reads the SAME hour and every row in it is
BILLED AGAIN. The dedupe catches the duplicates only after they are paid for.

⭐ The guard is job-local. Persisting `last` in the shared scheduler would change all twenty
other jobs, several of which SHOULD run on boot.

⚠️ It reads fantastic_run rather than a clock, so it survives the restart an in-memory timer
cannot.

Run:  python3 tests/test_fantastic_restart.py
"""

import importlib.util, json, os, pathlib, sqlite3, sys, tempfile
from datetime import datetime, timedelta, timezone
HERE = pathlib.Path("/home/bullwinkle/job-search-engine"); SRC = HERE/"job_search_engine"
DB = tempfile.mkdtemp()+"/g.db"; os.environ["DB_PATH"]=DB
os.environ["CANDIDATE_CONFIG"]="/home/bullwinkle/job-search/config/candidate.toml"
os.environ["FANTASTIC_API_KEY"]="x"; os.environ["FANTASTIC_EVERY_MIN"]="60"
sys.path.insert(0,str(SRC)); sys.path.insert(0,str(HERE/"tests"))
import test_posting_age as TPA
app = TPA.load_app(); sys.modules["app"]=app
con=sqlite3.connect(DB); con.executescript((SRC/"schema.sql").read_text())
for m in app.MIGRATIONS:
    try: con.execute(m)
    except Exception: pass
con.commit(); con.close()

fails=[]
def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:56} {got!r}")
    if not ok: fails.append(label)

def seed(label, minutes_ago, status="ok"):
    at = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO fantastic_run (at,endpoint,query_label,returned,inserted,"
              "duplicate,gated,status) VALUES (?,?,?,0,0,0,0,?)",
              (at, "active-ats", label, status)); c.commit(); c.close()

check("no prior run at all -> may run", app._fantastic_too_soon("integration", 60), 0)
seed("integration", 9)
r = app._fantastic_too_soon("integration", 60)
check("🚨 ran 9m ago on a 60m interval -> DECLINED", r > 0, True)
check("...and it reports the real age in seconds", 500 < r < 600, True)
seed("implementation", 50)
check("ran 50m ago -> declined, well inside the window",
      app._fantastic_too_soon("implementation", 60) > 0, True)
seed("escalation-ops", 59)
# ⚠️ 59m IS ALLOWED AND THAT IS THE POINT OF THE TOLERANCE. The threshold is interval-120s,
# so the scheduler drifting a minute early cannot block a legitimate hourly run. Refusing a
# real run is worse than occasionally allowing one a minute early.
check("ran 59m ago -> ALLOWED, the 2m drift tolerance",
      app._fantastic_too_soon("escalation-ops", 60), 0)
seed("onboarding", 61)
check("ran 61m ago -> ALLOWED, the window has moved",
      app._fantastic_too_soon("onboarding", 61 and 60), 0)
seed("ehr", 58)
check("58m with a 2m tolerance -> allowed, scheduler drift must not block a real run",
      app._fantastic_too_soon("ehr", 60), 0)
seed("healthcare", 5, status="interrupted")
check("an INTERRUPTED run does not block a retry",
      app._fantastic_too_soon("healthcare", 5 and 60), 0)
check("manual-only (interval 0) always runs: a human asked",
      app._fantastic_too_soon("integration", 0), 0)
print()
raise SystemExit(f"{len(fails)} failure(s)" if fails else 0)
