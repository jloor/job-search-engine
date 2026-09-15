#!/usr/bin/env python3
"""The morning report's section 3 was a raw list and had to be re-filtered by hand.

🚨 WHAT IT SHOWED ON 2026-09-15, BEFORE THIS. A single report carried a role at
$58,000-$70,000 against a $100,000 floor, two rows whose location had never been judged, and
Destinationknot, which has been on exclude_companies since 2026-08-29 AND carries a
company-scope role_passed entry. Every morning a human re-applied the same four filters by
hand, and the logic to do it existed only in tools/ease-rank.py on the operator's laptop.

⭐ NOTHING NEW IS INVENTED. comp_floor() and comp.annual for the band, gates.question_class
for the gates, candidate.excluded_company for the employer, excluded_title() for the title,
harvest_tier for the writing cost. This test guards that they are all actually applied.

⚠️ THE EXCLUSIONS MUST BE LIVE, not read off decide_excluded. job_decide writes that column
on its own interval, so a row scored minutes ago has decided_at = NULL and walks straight
past a decision the operator already made.

Run:  python3 tests/test_shortlist.py
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:60} {got!r}")
    if not ok:
        fails.append(label)


# The section is source-checked: it runs inside the MCP handler against a live database,
# and a round-trip test would need one. What matters is that each rule is REACHED.
i = SRC.index("3. SHORTLIST")
sec = SRC[SRC.index("# 3. What the sweep surfaced"):SRC.index("# 4. The shape")]

print("\nevery filter a human was applying by hand is now applied here:")
check("the pay floor", "comp_floor()" in sec, True)
check("🚨 ...ANNUALISED, so hourly bands are not all read as under-floor",
      "_CMP.annual(" in sec, True)
check("the location must have been judged", 'if not r["remote_verdict"]' in sec, True)
check("a BLOCKING gate drops the row", "question_class" in sec, True)
check("...and only a blocking one", '== "blocking"' in sec, True)
check("the employer exclusion list", "excluded_company" in sec, True)
# ⚠️ ASSERT ON USE, NOT ON PROSE. The comment above the check explains WHY the column is
# not read, so a plain substring test for the column name matches the explanation and fails.
# That is the same trap as testing for the word "ghost" in a docstring that says it never
# marks anything ghosted.
check("🚨 ...applied LIVE: the column is never SELECTed or read",
      "c.decide_excluded" not in sec and 'r["decide_excluded"]' not in sec, True)
check("the title exclusion list", "excluded_title()" in sec, True)
check("considered nos are skipped", "role_passed" in sec, True)
check("already-applied postings are skipped", "FROM posting p WHERE p.canonical_url" in sec, True)

print("\nit reports what it removed, so a wrong rule is noticeable:")
check("dropped reasons are counted", "dropped[" in sec, True)
check("...and printed", '"   (filtered: "' in sec, True)

print("\nit shows the writing cost, which decides what to do first:")
check("the harvest tier is joined", "LEFT JOIN harvest" in sec, True)
check("...and rendered", "not harvested" in sec, True)

print("\nit does not quietly change what it selects:")
check("still excludes out_of_scope/duplicate/error verdicts",
      "'out_of_scope','duplicate','error'" in sec, True)
check("⚠️ selects MORE than it shows, so filtering cannot empty the list",
      "LIMIT 60" in sec and "kept[:25]" in sec, True)

print()
if fails:
    for f in fails:
        print("  " + f)
    raise SystemExit(f"{len(fails)} failure(s)")
print("all passed")
