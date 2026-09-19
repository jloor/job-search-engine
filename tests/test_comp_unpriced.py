#!/usr/bin/env python3
"""A band without a dollar sign was read as no band at all.

🚨 WHAT IT COST, MEASURED 2026-09-19. Four postings were opened by hand off a list of 214
roles the queue reported as "no band published". THREE of them published a band in prose:

    Businessolver  "The pay range for this position is 67K to 105K per year"
    Feathr         "$55,000 annually, and up to a 10% bonus potential"
    Bluesight      "$60,000 - $75,000/yr"

Against a $100,000 floor those are not silent employers, they are low bands wearing a
disguise, and they reached a shortlist as unpriced opportunities. The whole point of keeping
unpriced roles visible (v0.72.0) is that a silent band is not a low one; that promise only
holds if the reader can tell the two apart.

⚠️ THE NEW PATTERNS ARE NARROW ON PURPOSE. A bare integer in a job posting is usually not
money: "7+ years", "2,000 clients", "1998". So only a K suffix or explicit comma-thousands
counts, only inside a sentence that already mentions pay, and the priced pattern always runs
first so "$67,000 to $105,000" can never be read as "67 to 105".

📌 The negative cases below are REAL SENTENCES from the GiveCampus posting read the same
morning. Both sit near pay language in a document that states no band at all.

Run:  python3 tests/test_comp_unpriced.py
"""
import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("comp", HERE.parent / "job_search_engine" / "comp.py")
comp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comp)
fails = []


def check(label, text, want):
    got = comp.from_body(text)
    g = (got["min"], got["max"]) if got else None
    ok = g == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:<40} {str(g):<20} want {want}")
    if not ok:
        fails.append(label)


print("\nbands that were being missed:")
check("bare K range", "The pay range for this position is 67K to 105K per year.", (67000, 105000))
check("single annual amount", "The salary is $55,000 annually, and up to a 10% bonus.", (55000, 55000))
check("bare comma range", "Salary: 80,000 - 100,000 depending on experience.", (80000, 100000))
check("single amount after a colon", "Compensation: $92,000", (92000, 92000))

print("\nbands that already worked, and must not change:")
check("priced range", "The base salary range is $120,000 to $150,000 per year.", (120000, 150000))
check("priced wins over bare", "Salary $67,000 to $105,000 per year.", (67000, 105000))
check("hourly keeps its units", "The hourly rate is $18.70 - $21.25 per hour.", (18, 21))

print("\nnumbers that are not pay, and must stay unmatched:")
check("charitable giving", "We will facilitate $100 billion in charitable giving over the decade.", None)
check("growth investment", "In 2025 we celebrated a $140 million growth investment and a liquidity event.", None)
check("years of experience", "Compensation is competitive. We require 7+ years project management experience.", None)
check("client counts", "Our compensation philosophy serves 2,000 clients and 1,500 partners.", None)
check("a year in prose", "Since 1998, salary transparency has mattered to us.", None)

print("\nthe archiver holds the same line, when it is installed:")
try:
    a_spec = importlib.util.spec_from_file_location(
        "arc", pathlib.Path.home() / "fetch_job_description" / "fetch_job_description" / "archive.py")
    arc = importlib.util.module_from_spec(a_spec)
    a_spec.loader.exec_module(arc)
except Exception:                                                 # noqa: BLE001
    print("  skip  archiver not importable here (CI); drift is checked on his machine")
else:
    for label, text in (("bare K range", "The pay range for this position is 67K to 105K per year."),
                        ("single annual amount", "The salary is $55,000 annually, and up to a 10% bonus."),
                        ("charitable giving", "We will facilitate $100 billion in charitable giving.")):
        a = arc.body_comp(text)[0]
        c = comp.from_body(text)
        agree = (a is None) == (c is None)
        print(f"  {'ok  ' if agree else 'FAIL'} both readers agree on {label:<24} archiver={a}")
        if not agree:
            fails.append(f"drift: {label}")

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
