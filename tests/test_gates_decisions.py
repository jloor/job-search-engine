#!/usr/bin/env python3
"""Regression test for req_key, question_class and location_conflict.

Why this exists: all three moved up from a laptop-only script on 2026-09-01, and each was
moved because a real mistake had already been made without it.

    req_key            an application went to `.../acme/jobs/4000000001` while the scanner
                       held `...?gh_jid=4381957009`. Same Greenhouse id, different host, so a
                       string compare offered a role applied to four days earlier as the best
                       new lead in the queue.
    question_class     dropping every gate-shaped question excluded "Are you legally
                       authorized to work in the United States?", which is a routine yes. All
                       fourteen rows that reached the send list that day were rangeless,
                       because a US authorisation question sits on every posting with a band.
    location_conflict  one board tagged a requisition Georgia and Massachusetts while its body
                       said Remote in United States; another's location field was the literal
                       string "USA - Update Location".

🚨 THE CONFIG IS PASSED EXPLICITLY, NEVER LOADED. The suite must pass with nothing installed
and with no candidate config on disk, and these functions must not need a real person to be
testable. That is also the point of the split: the LOGIC is here, the PERSON is in the config.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "job_search_engine"))
import gates                                                            # noqa: E402

CFG = {
    "work_authorization": {"eligible_countries": ["US"]},
    "remote": {"reject_timezones": ["Pacific Time", "Pacific Standard Time", "PST",
                                    "Mountain Time", "MST"]},
    "commute": {"metro_places": ["new york", "manhattan", "brooklyn", "newark", "jersey city"],
                "near_states": ["NY", "NJ", "CT", "PA"]},
}

fails = []


def check(label, got, want):
    ok = got == want
    if not ok:
        fails.append(f"{label}: got {got!r}, wanted {want!r}")
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")


# ── req_key: one requisition, however it is linked ───────────────────────────────────────
gh_board = gates.req_key("https://job-boards.greenhouse.io/acme/jobs/4000000001")
gh_embed = gates.req_key("https://www.acme.example.com/careers/job?gh_jid=4000000001")
check("greenhouse board and employer embed collapse to one key", gh_board, gh_embed)
check("  and that key names the ATS and the id", gh_board, "gh:4000000001")
check("ashby uuid", gates.req_key("https://jobs.ashbyhq.com/acme/11111111-2222-3333-4444-555555555555"),
      "ashby:11111111-2222-3333-4444-555555555555")
check("lever uuid", gates.req_key("https://jobs.lever.co/acme/66666666-7777-8888-9999-000000000000"),
      "lever:66666666-7777-8888-9999-000000000000")
check("workday tenant and req, scheme excluded",
      gates.req_key("https://acme.wd3.myworkdayjobs.com/1/job/Ohio/Support-Analyst_R0000001-1"),
      "wd:acme:support-analyst_r0000001-1")
check("an unknown board still yields a key rather than None",
      bool(gates.req_key("https://careers.example.com/roles/17")), True)
check("empty url is None", gates.req_key(""), None)

# ── question_class: the country named decides, not the shape ─────────────────────────────
for q, want in [
    ("Are you legally authorized to work in the United States without sponsorship?", "benign"),
    ("Will you now or in the future require visa sponsorship to work in the United States?", "benign"),
    ("Are you authorized to work in Canada?", "blocking"),
    ("Do you reside in the United Kingdom?", "blocking"),
    ("Do you live in the Pacific Standard Time Zone?", "blocking"),
    ("Technical Support Specialist - German Speaking", "blocking"),
    ("Are you willing to submit to a background check?", "benign"),
    ("Are you comfortable commuting to Manhattan, NYC and working hybrid?", "decide"),
    ("This role requires onsite training at our Lehi, UT HQ.", "decide"),
    ("", "benign"),
]:
    check(f"question_class {q[:52]!r}", gates.question_class(q, CFG), want)

# 🚨 The default must be `decide`. A gate nobody anticipated has to cost a human a glance,
# because the failure that matters is a role he cannot take reaching the send queue.
check("an unrecognised gate defaults to decide",
      gates.question_class("Do you own a reliable pickup truck?", CFG), "decide")

# ── location_conflict: raises a hand, never decides ──────────────────────────────────────
check("placeholder field is flagged",
      "placeholder" in (gates.location_conflict("USA - Update Location", "fully_remote", CFG) or ""),
      True)
check("unjudged remote_verdict is flagged",
      "never judged" in (gates.location_conflict("New York, NY", None, CFG) or ""), True)
check("a foreign city against fully_remote is flagged",
      "disagree" in (gates.location_conflict("Sherwood Park, Alberta", "fully_remote", CFG) or ""),
      True)
check("plain US remote is quiet",
      gates.location_conflict("Remote, United States", "fully_remote", CFG), None)
check("his own metro is quiet",
      gates.location_conflict("New York, NY", "hybrid_commutable", CFG), None)
check("a blank field is quiet, because absence is not a rejection",
      gates.location_conflict("", "fully_remote", CFG), None)
# 🚨 Production, 2026-09-01: 29 of 157 flags were a bare country on an already-remote role.
# A flag that fires on the common case is a flag nobody reads.
for bare in ("US", "USA", "United States", "North America", "Remote - US", "Anywhere"):
    check(f"bare region {bare!r} is quiet", gates.location_conflict(bare, "fully_remote", CFG), None)
check("his own timezone is quiet",
      gates.location_conflict("Eastern Time zone", "fully_remote", CFG), None)
check("a rejected timezone as a location IS flagged",
      "reject list" in (gates.location_conflict("Pacific Time zone", "fully_remote", CFG) or ""),
      True)
check("a specific city outside the metro is still flagged",
      "disagree" in (gates.location_conflict("Austin, TX", "fully_remote", CFG) or ""), True)

print()
if fails:
    for f in fails:
        print("  " + f)
    raise SystemExit(f"{len(fails)} failure(s)")
print("all passed")
