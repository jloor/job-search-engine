#!/usr/bin/env python3
"""The stored posting must be the WHOLE posting.

Why this exists: both `INSERT INTO scan_candidate` sites clipped `description` to
AI_MAX_BODY_CHARS before writing it. That constant is a model-input budget of 6,000
characters. Applied at INSERT it destroyed the tail of every long requisition at capture
time, and the employer's board is the only other copy.

🚨 WHAT IT COST, MEASURED 2026-09-03. Of 101 postings captured for one application batch,
48 stopped at exactly 6,000 characters, cut mid-word. Forty-eight cover letters were written
against half a requisition by an author who could not know the half was missing. Nothing
failed, nothing was logged, and every downstream check passed: a truncated posting reads
exactly like a short one.

⭐ THE TWO LIMITS ANSWER DIFFERENT QUESTIONS, WHICH IS THE WHOLE LESSON.
Truncating a model's input is a cost decision and it is reversible: send more next time.
Truncating at INSERT is destruction, because a requisition disappears from its board and
the row is the archive. Send a slice to the model; never store a slice of the board.

🚨 THE SOURCE IS THE SUBJECT, NOT A DATABASE. The bug was one identifier inside one slice
expression, in code that runs only against a live Bunny database. A round-trip test could
not have caught it without one, and the suite must pass with nothing installed.
"""
import pathlib
import re

SRC = (pathlib.Path(__file__).resolve().parent.parent
       / "job_search_engine" / "app.py").read_text()

fails = []


def check(label, got, want):
    if got != want:
        fails.append(f"{label}: got {got!r}, want {want!r}")


def insert_blocks():
    """Each `INSERT INTO scan_candidate` call with the argument tuple that follows it."""
    return [SRC[m.start():m.start() + 2500]
            for m in re.finditer(r"INSERT INTO scan_candidate\b", SRC)]


blocks = insert_blocks()

# A third insert site would need the same rule. Failing here is the prompt to read it.
check("two scan_candidate insert sites", len(blocks), 2)

for _i, _b in enumerate(blocks, 1):
    check(f"insert {_i} does not store at the model-input budget",
          "AI_MAX_BODY_CHARS" in _b, False)
    check(f"insert {_i} caps storage with the storage constant",
          "SCAN_MAX_DESCRIPTION_CHARS" in _b, True)

_m = re.search(r'SCAN_MAX_DESCRIPTION_CHARS = int\(os\.environ\.get\(\s*'
               r'"SCAN_MAX_DESCRIPTION_CHARS",\s*"(\d+)"\)\)', SRC)
check("the storage cap is defined with an env default", bool(_m), True)
# A safety valve against a pathological page, never a budget. The longest posting observed
# in the corpus is about 40,000 characters.
check("the storage cap is far above any real posting",
      bool(_m) and int(_m.group(1)) >= 100_000, True)

# ⚠️ The fix must not remove the cost control it was never about. Sending an unbounded body
# to a model is a separate, real problem, and the mail reader still needs this cap.
check("the model-send paths still truncate", SRC.count("AI_MAX_BODY_CHARS") >= 5, True)

print()
if fails:
    for f in fails:
        print("  " + f)
    raise SystemExit(f"{len(fails)} failure(s)")
print("all passed")
