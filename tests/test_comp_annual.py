#!/usr/bin/env python3
"""A floor compared against a raw number hides every hourly posting.

🚨 WHY THIS EXISTS, MEASURED 2026-09-14. Hourly bands store as WHOLE DOLLARS: $70/hour is
stored as 70. The salary floor compared that raw against $100,000, so `70 < 100000` marked it
under the floor, and EVERY hourly posting was excluded from the shortlist regardless of rate.
On the live queue: 241 rows carried an hourly band, 220 genuinely under the floor, and 21
hidden wrongly. The best scored 91, near the top of the entire queue, at $40-$50/hour, and
had never once been shown.

⚠️ THIS IS THE SECOND DEFECT OF EXACTLY THIS SHAPE IN THE SAME COMPARISON. On 2026-09-03 it
tested comp_min instead of comp_max and hid 148 rows, including two employers with live
interviews. Both were found the same way: by asking what the filter EXCLUDES, never by
reading what it returns.

📌 The rule lives in comp.py so the engine's floor check and tools/ease-rank.py's bucket()
share ONE implementation. They must agree: one is the shortlist he reads, the other the mail
he gets.

Run:  python3 tests/test_comp_annual.py
"""
import importlib.util
import pathlib

SRC = pathlib.Path(__file__).resolve().parent.parent / "job_search_engine"
_s = importlib.util.spec_from_file_location("comp", SRC / "comp.py")
comp = importlib.util.module_from_spec(_s); _s.loader.exec_module(comp)

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:56} {got!r}")
    if not ok:
        fails.append(label)


FLOOR = 100000
print("\nthe conversion:")
check("an hourly rate becomes a year at 2,080 hours", comp.annual(70, "hourly/hour"), 145600)
check("🚨 a BARE 'hourly' works too, not only the /hour suffix",
      comp.annual(70, "hourly"), 145600)
check("...and every other spelling in the live corpus",
      [comp.annual(50, b) for b in ("base/hour", "unverified_numbers/hour", "hourly/hour")],
      [104000, 104000, 104000])
check("an annual figure is untouched", comp.annual(150000, "base"), 150000)
check("...including an unclear basis, which is 2,067 rows", comp.annual(120000, "unclear"), 120000)
check("...and a missing basis", comp.annual(120000, None), 120000)
check("monthly", comp.annual(8000, "base/month"), 96000)
check("weekly", comp.annual(2000, "base/week"), 104000)
check("daily", comp.annual(500, "base/day"), 130000)
check("None in, None out", comp.annual(None, "base"), None)
check("junk in, None out, never a crash", comp.annual("abc", "base"), None)

print("\nthe decision it feeds, against the real cases that were wrong:")
check("🚨 $40-$50/hr (scored 91) now CLEARS the floor",
      comp.annual(50, "hourly/hour") >= FLOOR, True)
check("$65-$75/hr clears it", comp.annual(75, "hourly/hour") >= FLOOR, True)
check("⭐ $16/hr security work is STILL excluded, correctly",
      comp.annual(16, "base/hour") >= FLOOR, False)
check("$23/hr is still excluded", comp.annual(23, "hourly") >= FLOOR, False)
check("a genuine $95,000 salary is still excluded",
      comp.annual(95000, "base") >= FLOOR, False)
check("a $120,000 salary still clears", comp.annual(120000, "base") >= FLOOR, True)

print("\nboth call sites use it, so the two cannot drift:")
APP = (SRC / "app.py").read_text()
check("the engine's floor check annualises", "_CMP.annual(raw" in APP, True)
EASE = (pathlib.Path.home() / "job-search" / "tools" / "ease-rank.py")
if EASE.exists():
    src = EASE.read_text()
    check("the shortlist's bucket() annualises", "_CMP.annual(v," in src, True)
    check("...and the min/max sanity check stays RAW, needing no conversion",
          'if (r["comp_max"] or 0) < lo(r):' in src, True)
else:
    print("  skip  the operator's ease-rank.py is not present (public checkout)")

print()
if fails:
    for f in fails:
        print("  " + f)
    raise SystemExit(f"{len(fails)} failure(s)")
print("all passed")
