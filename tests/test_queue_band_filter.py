#!/usr/bin/env python3
"""A pay floor used to hide every posting that published no band at all.

🚨 WHAT IT COST. search_queue required comp_max whenever min_pay was set, so a role stating
no range was dropped exactly like one paying too little. Measured 2026-09-18: PathPoint's
Technical Implementation Analyst, fit 82 and fully remote, never appeared in any list built
that day. Diagnocat publishes no range and says it never will, and it is the
furthest-advanced conversation in the pipeline.

⚠️ THE SORT HID THEM A SECOND TIME. `comp_max DESC NULLS LAST` puts every silent posting
below every noisy one, so a role could survive the filter and still fall off the end of a
limited page. A published band should not buy visibility twice.

⭐ WHAT THE FLOOR MEANS NOW. "Nothing I know pays too little." A band below the floor is
still dropped, hourly bands are still excluded rather than annualised, and an unbanded row
is kept and labelled so the reader knows which it is.

Run:  python3 tests/test_queue_band_filter.py
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
fails = []


def check(label, got, want=True):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:64} {got!r}")
    if not ok:
        fails.append(label)


sec = SRC[SRC.index('if name == "search_queue"'):SRC.index('if name == "commute_check"')]

print("\nthe floor keeps what it does not know:")
check("an unbanded row survives min_pay", "c.comp_max IS NULL OR (c.comp_max >= ?" in sec)
check("a band below the floor is still dropped", "c.comp_max >= ?" in sec)
check("hourly bands are still excluded", "NOT LIKE '%/hour'" in sec)
check("the footer says what the floor now means", "a silent band is not a low one" in sec)
check("the tool description matches the behaviour",
      "a role that publishes NO band is kept and labelled" in SRC)

print("\nthe sort does not hide them a second time:")
check("with a pay floor the band leads",
      '" ORDER BY c.comp_max DESC NULLS LAST, cast(c.score as int) DESC LIMIT ?"' in sec)
check("without one, fit leads",
      '" ORDER BY cast(c.score as int) DESC, c.comp_max DESC NULLS LAST LIMIT ?"' in sec)
check("the choice is made on min_pay", 'if args.get("min_pay") else' in sec)

print("\nthe old behaviour is gone:")
check("no unconditional comp_max requirement",
      'w.append("c.comp_max IS NOT NULL AND c.comp_max >= ? "' not in sec)
check("the old footer is gone", "excludes every role with no published band" not in SRC)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
