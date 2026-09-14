#!/usr/bin/env python3
"""A killed pod leaves git debris, and the volume outlives the pod.

🚨 WHY THIS EXISTS, MEASURED 2026-09-14. Two concurrent set-prod-env runs restarted the pod
repeatedly, one restart landed mid-git-operation, and /data/repo/.git/index.lock survived on
the volume. sync_repo then failed on EVERY attempt with "Another git process seems to be
running", and would have failed forever: ensure_repo had no recovery and the lock outlives
the process that made it.

⭐ THE COST IS NOT A RED CHECK. The engine reads the operator's profile from that working
copy, so a permanently wedged sync means production keeps running a stale config while
every other diagnostic stays green.

⚠️ Clearing a git lock is normally WRONG. It is right here because nothing else in this
container runs git and the process is restarted routinely, so a lock still present at
startup cannot have a live owner.

Run:  python3 tests/test_gitsync_locks.py
"""
import importlib.util, pathlib, subprocess, sys, tempfile
SRC = pathlib.Path("/home/bullwinkle/job-search-engine/job_search_engine")
tmp = pathlib.Path(tempfile.mkdtemp())
repo = tmp / "repo"
repo.mkdir()
subprocess.run(["git", "init", "-q", str(repo)], check=True)
(repo / "f.txt").write_text("x")
import os
os.environ["DATA_DIR"] = str(tmp)
spec = importlib.util.spec_from_file_location("gitsync", SRC / "gitsync.py")
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:54} {got!r}")
    if not ok: fails.append(label)

# the exact debris a killed pod leaves
(repo / ".git" / "index.lock").write_text("")
(repo / ".git" / "HEAD.lock").write_text("")
(repo / ".git" / "refs" / "heads").mkdir(parents=True, exist_ok=True)
(repo / ".git" / "refs" / "heads" / "main.lock").write_text("")

# git genuinely refuses while the lock is there
r = subprocess.run(["git", "add", "f.txt"], cwd=repo, capture_output=True, text=True)
check("git REFUSES to work with index.lock present", r.returncode != 0, True)
check("...and says why", "index.lock" in (r.stderr or ""), True)

cleared = sorted(g.clear_stale_locks())
check("index.lock cleared", "index.lock" in cleared, True)
check("HEAD.lock cleared", "HEAD.lock" in cleared, True)
check("a ref lock cleared too", any("main.lock" in c for c in cleared), True)
check("nothing else touched", (repo / "f.txt").exists(), True)

r = subprocess.run(["git", "add", "f.txt"], cwd=repo, capture_output=True, text=True)
check("git works again afterwards", r.returncode, 0)
check("a second call is a no-op", g.clear_stale_locks(), [])
print()
raise SystemExit(f"{len(fails)} failure(s)" if fails else 0)
