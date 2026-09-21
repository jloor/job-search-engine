#!/usr/bin/env python3
"""remote_verdict answers two questions at once, which made it impossible to test a model.

🚨 THE OVERLOAD, MEASURED 2026-09-21. The model writes how a job's work is ARRANGED. The
commute router then overwrites the same column with whether the operator can REACH it,
spending 'onsite' to mean "145 minutes away". Two Collingswood NJ postings say "This is a
hybrid role" in their own words and carry #LI-HYBRID; the column reads 'onsite'.

⚠️ SO ANY MODEL ASKED THE ARRANGEMENT QUESTION IS MARKED WRONG ON THOSE ROWS WHILE BEING
RIGHT. That is not a model problem. It is a column problem, and it was found only because a
replacement was measured before being committed.

⭐ WHAT THE MEASUREMENT SHOWED over 94 rows the old model had decided. With criteria that
state the engine's intent, agreement was 76%, and every residual disagreement adjudicable
from the posting text went Jev's way: it separates a CITY (Nashville, Salt Lake City) from
a REGION (East Coast) in BOTH directions at 0.94 to 1.00, where the old model had them
backwards. No case was found where the old model was right and Jev was wrong.

🚨 AND THE CRITERIA THEMSELVES ARE A MEASURED ARTEFACT. A first wording defined
fully_remote as "anywhere in the country" and remote_with_residency as "residents of a
named country", so every "Remote - US" posting satisfied BOTH and the model correctly chose
the narrower one. 14 of 20 disagreed for that reason alone. Saying that a US-only rule is
not a restriction FOR A US CITIZEN took that group from 6/20 to 20/20. Changing this
wording changes the answers.

Run:  python3 tests/test_jev_remote.py
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
import jev                                                    # noqa: E402

SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
SCHEMA = (HERE.parent / "job_search_engine" / "schema.sql").read_text()
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


print("the columns exist and are separate from remote_verdict:")
for col in ("work_arrangement", "work_arrangement_conf", "work_arrangement_at"):
    check(f"schema.sql declares {col}", col in SCHEMA)
    check(f"migration adds {col}", f"ALTER TABLE scan_candidate ADD COLUMN {col}" in SRC)

print("\n🚨 THE GUARANTEE: the job must NEVER write remote_verdict:")
job = SRC.split("def job_jev_remote", 1)[1].split("\ndef ", 1)[0]
check("job_jev_remote exists", "def job_jev_remote" in SRC)
# ⚠️ CHECK THE CODE, NOT THE PROSE. The docstring names remote_verdict on purpose, to say
# why it is left alone, so a bare substring test fails on its own explanation. Strip the
# docstring first and test what actually executes.
body = job.split('"""', 2)[2] if job.count('"""') >= 2 else job
check("the executable body never names remote_verdict", "remote_verdict" not in body)
check("the executable body never names remote_evidence", "remote_evidence" not in body)
check("...and the docstring DOES explain why, so the reason survives a refactor",
      "remote_verdict" in job.split('"""', 2)[1])
flat = " ".join(job.split()).replace('" "', "")
check("its UPDATE touches only the three arrangement columns",
      "SET work_arrangement=?, work_arrangement_conf=?, work_arrangement_at=? WHERE id=?"
      in flat)
check("only ONE update statement in the whole job", job.count("UPDATE ") == 1)

print("\nit refuses to ask a question it cannot ask properly:")
check("no commute origin means no call", "no commute origin configured" in job)
check("it returns before spending", job.index("no commute origin") < job.index("read_arrangement"))
check("a disabled key returns early", "_JEV.enabled()" in job)
check("a failed call writes nothing", "failed += 1" in job and "continue" in job)

print("\nthe criteria carry the measured wording, not a dictionary definition:")
c = jev.ARRANGEMENT_CRITERIA
check("all six verdicts are offered",
      set(c) == {"fully_remote", "remote_in_metro", "remote_with_residency",
                 "hybrid", "onsite", "unclear"})
check("fully_remote states that US-only is NOT a restriction",
      "NOT a restriction" in c["fully_remote"])
check("fully_remote names the US-wide spellings that broke v1",
      "Remote - US" in c["fully_remote"] and "US Remote" in c["fully_remote"])
check("remote_with_residency EXCLUDES a plain US-wide role",
      "Do NOT use this for a plain" in c["remote_with_residency"])
check("remote_with_residency names a state, a region and a non-US country",
      all(w in c["remote_with_residency"] for w in ("Michigan", "East Coast", "Canada")))
check("remote_in_metro is about ONE named metro",
      "ONE NAMED METRO" in c["remote_in_metro"])

print("\nthe question carries the two facts that changed the answers:")
q = jev.arrangement_questions("Dumont, New Jersey 07628")
ins = q["arrangement"]["instructions"]
check("it says the candidate is a US CITIZEN", "US CITIZEN" in ins)
check("it carries the actual origin", "Dumont, New Jersey 07628" in ins)
check("it asks for what is REQUIRED, not preferred", "REQUIRES, not what it prefers" in ins)
check("it is a Choice, so the answer set is closed", q["arrangement"]["type"] == "choice")
check("criteria is a mapping, which Choice requires",
      isinstance(q["arrangement"]["criteria"], dict))

print("\nread_arrangement sends the same state shape the old model was given:")
import inspect                                                # noqa: E402
src = inspect.getsource(jev.read_arrangement)
check("title, location and description", all(w in src for w in ("title", "location", "description")))
check("description truncated like the old payload", "[:9000]" in src)

print("\nthe job is scheduled, and apart from the level reader:")
check("registered in the scheduler",
      '("jev_remote", JEV_REMOTE_EVERY_MIN * 60, job_jev_remote)' in SRC)
check("its own interval knob", "JEV_REMOTE_EVERY_MIN" in SRC)
check("a different default interval from jev_level",
      'JEV_REMOTE_EVERY_MIN", "37"' in SRC and 'JEV_EVERY_MIN", "41"' in SRC)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
