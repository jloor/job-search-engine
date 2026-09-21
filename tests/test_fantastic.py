#!/usr/bin/env python3
"""The Fantastic Jobs discovery source: the field map, the dedupe, and the money.

🚨 WHY THIS EXISTS. This is the first source in the pipeline that COSTS MONEY PER ROW. One
job credit per record returned, so a filter applied after the response has already been
paid for saves nothing at all, and a widened query does not fail, it just bills. Nothing
here can watch the invoice, so these tests guard the three things that would move it: the
window a request asks for, the cap that stops paging, and the ledger that records what a
pull cost.

🚨 AND THE SECOND REASON, WHICH IS NOT ABOUT MONEY. Their AI fields are derived, and one of
them has already been measured WRONG on a real posting: `ai_work_arrangement` reported
On-site while the employer's own SmartRecruiters record said `remote: true, hybrid: false`.
Remote is a hard filter, so taking that field as a verdict deletes viable roles in silence.
The mapper must therefore write NULL and the test must hold it there, because the field
looks authoritative and the next reader will be tempted.

Every fixture is the SHAPE of a real response with synthetic ids.

Run:  python3 tests/test_fantastic.py
"""
import importlib.util
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC_DIR = HERE.parent / "job_search_engine"
APP_SRC = (SRC_DIR / "app.py").read_text()

sys.path.insert(0, str(SRC_DIR))
_spec = importlib.util.spec_from_file_location("fantastic", SRC_DIR / "fantastic.py")
F = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(F)

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:52} {got!r}")
    if not ok:
        fails.append(f"{label}: got {got!r}, want {want!r}")


ROW = {
    "id": 2361242150,
    "date_posted": "2026-09-12T00:00:00",
    "date_created": "2026-09-12T23:22:43.3619",
    "title": "Clinical Implementation Manager",
    "organization": "Example Health",
    "date_valid_through": None,
    "url": "https://jobs.ashbyhq.com/Example/f466cecd-8451-4a2b",
    "source": "ashby",
    "locations_derived": ["New York, New York, United States"],
    "ai_salary_currency": "USD",
    "ai_salary_min_value": 80000,
    "ai_salary_max_value": 85000,
    "ai_salary_unit_text": "YEAR",
    "ai_experience_level": "2-5",
    "ai_work_arrangement": "On-site",
    # 🚨 THE REAL FIELD NAME, verified against a live response 2026-09-14. Reading
    # `description` would have stored nothing, silently, on every row.
    "description_text": "We are looking for an implementation manager.",
}

print("\nthe field map:")
p = F.to_posting(ROW)
check("req_id carries the source and their id", p["req_id"], "fantastic|ashby:2361242150")
check("board is the source, so a row says where it came from", p["board"], "fantastic|ashby")
check("their id survives the round trip through req_id",
      F.their_id(p["req_id"]), "2361242150")
check("the employer name is taken verbatim", p["company"], "Example Health")
check("...and recorded as a NAME, never a token opened out",
      p["company_source"], "fantastic")
check("location is the first normalised one", p["location"], "New York, New York, United States")
check("the stated seniority becomes a column of its own", p["stated_level"], "2-5")
check("the discovery link is recorded separately from anything canonical",
      (p["discovery_url"], p["discovery_source"]),
      ("https://jobs.ashbyhq.com/Example/f466cecd-8451-4a2b", "fantastic"))

# 🚨 THE ONE THAT MATTERS MOST. This field was measured wrong on a live posting.
print("\ntheir derived fields never become our verdicts:")
check("is_remote is NULL even when they state an arrangement", p["is_remote"], None)
check("...and it stays NULL when they say Remote Solely too",
      F.to_posting({**ROW, "ai_work_arrangement": "Remote Solely"})["is_remote"], None)
check("the arrangement is still RECORDED, so the disagreement is readable",
      p["work_arrangement"], "On-site")
check("their comp is not passed off as the board's own field", p["comp"], None)

# 🚨 THE ONE THAT WOULD HAVE FAILED SILENTLY. An empty description reads exactly like a
# short posting, so triage would have scored on titles alone and every check would pass.
check("the description is read from description_text",
      p["description"], "We are looking for an implementation manager.")
check("...and the plain `description` spelling still works if they ever send it",
      F.to_posting({**ROW, "description_text": None,
                    "description": "fallback"})["description"], "fallback")
check("...and an absent description is empty, never None",
      F.to_posting({k: v for k, v in ROW.items()
                    if k != "description_text"})["description"], "")
check("🚨 a request that omits description_format gets NO description at all, so it is "
      "always sent", "description_format" in F.params({}, {}), True)

print("\nthe pay band, which is somebody else's extraction:")
band = F.comp_band(ROW)
check("the numbers come through", (band[0], band[1]), (80000, 85000))
check("a yearly figure is a base salary", band[2], "base")
check("🚨 the SOURCE is its own value, never 'board'", band[4], "fantastic_ai")
check("an hourly rate carries the period on the basis",
      F.comp_band({**ROW, "ai_salary_unit_text": "HOUR"})[2], "base/hour")
check("a foreign currency yields NOTHING rather than an unconverted number",
      F.comp_band({**ROW, "ai_salary_currency": "EUR"}), None)
check("no salary at all yields nothing",
      F.comp_band({**ROW, "ai_salary_min_value": None, "ai_salary_max_value": None}), None)
check("a single value is used when there is no range",
      F.comp_band({**ROW, "ai_salary_min_value": None, "ai_salary_max_value": None,
                   "ai_salary_value": 120000})[0], 120000)

print("\ndedupe, because the sweep and the API find the same requisition:")
check("query strings and case do not make two URLs",
      F.norm_url("https://Boards.io/JOB/7?utm_source=x"), "https://boards.io/job/7")
check("a trailing slash does not either",
      F.norm_url("https://boards.io/job/7/"), "https://boards.io/job/7")
check("containment beats equality on a real pair",
      F.contains("Invisibletech", "Invisible Technologies"), True)
check("🚨 a short name never matches by containment", F.contains("H", "Highspot"), False)
check("...and two short names must be equal", F.contains("IBM", "IBM"), True)
check("unrelated employers do not match", F.contains("Stripe", "Databricks"), False)

print("\nthe request, where the only real cost control lives:")
q = F.params({"title": "integration"}, {"location": "United States"})
check("the default window is the rolling hour", q["time_frame"], "1h")
check("descriptions are asked for, or triage has nothing to read",
      q["description_format"], "text")
check("the shared filters are merged in", q["location"], "United States")
gap = F.params({"title": "integration"}, {}, since="2026-09-13T00:00:00")
check("replaying a gap switches to the 7-day window", gap["time_frame"], "7d")
check("...and asks only for what was indexed after the watermark",
      gap["date_created_gte"], "2026-09-13T00:00:00")

print("\nthe cost ledger, read off the response headers:")
qh = F.quota({"x-api-jobs-this-request": "40", "x-api-jobs-remaining": "19960",
              "x-api-jobs-limit": "20000", "x-api-requests-remaining": "9998"})
check("what this one call cost", qh["jobs_spent"], 40)
check("what is left in the period", qh["jobs_remaining"], 19960)
check("a missing header is None, never zero", F.quota({})["jobs_spent"], None)
check("...because zero spent and unknown are different facts",
      F.quota({"x-api-jobs-this-request": "0"})["jobs_spent"], 0)

# 🚨 THE REGRESSION THAT COST REAL MONEY. A `--cap 40` run spent 100 credits because the
# cap was tested AFTER the page had returned and been billed. The budget must bound the
# `limit` that goes out on the wire.
print("\nthe budget bounds the REQUEST, not just the loop:")
_asked = []


def _fake_call(endpoint, params, key, timeout=60):
    _asked.append((params.get("limit"), params.get("offset")))
    n = min(int(params["limit"]), 250 - int(params["offset"]))
    return [{"id": i} for i in range(max(0, n))], {"jobs_spent": max(0, n)}


_real_call = F.call
F.call = _fake_call
try:
    _asked.clear()
    list(F.pages("active-ats", {"limit": 200}, "k", budget=40))
    check("a budget of 40 never asks for more than 40", _asked, [(40, 0)])
    _asked.clear()
    got = sum(len(r) for r, _ in F.pages("active-ats", {"limit": 100}, "k", budget=250))
    check("a budget larger than a page still pages", len(_asked) >= 2, True)
    check("...and stops exactly at the budget", got, 250)
    check("...asking only the remainder on the last page", _asked[-1][0] <= 100, True)
    check("offset counts ROWS, not pages, so clamped pages skip nothing",
          [o for _, o in _asked], [0, 100, 200])
    _asked.clear()
    list(F.pages("active-ats", {"limit": 100}, "k"))
    check("no budget keeps the old behaviour", _asked[0][0], 100)
finally:
    F.call = _real_call

print("\nthe guards in the module itself:")
check("paging refuses to run away", F.MAX_PAGES <= 50, True)
check("a tier boundary is its own exception, not a failure",
      issubclass(F.Denied, RuntimeError), True)

print("\nwhat the engine declares (source-level, so it needs no database):")
for col in ("stated_level", "date_modified", "modified_fields"):
    check(f"scan_candidate.{col} is a migration, not only a schema edit",
          f"ALTER TABLE scan_candidate ADD COLUMN {col}" in APP_SRC, True)
for col in ("discovery_url", "discovery_source"):
    check(f"posting.{col} is a migration too",
          f"ALTER TABLE posting ADD COLUMN {col}" in APP_SRC, True)
check("the run ledger is declared", "CREATE TABLE IF NOT EXISTS fantastic_run" in APP_SRC, True)
# 🚨 The inline CREATE TABLE and schema.sql are two definitions of one table and they have
# drifted before: an index the spec declared and the live database never had.
SCHEMA = (SRC_DIR / "schema.sql").read_text()
for col in ("discovery_url", "discovery_source"):
    check(f"...and posting.{col} is in schema.sql as well", col in SCHEMA, True)
for col in ("stated_level", "date_modified", "modified_fields"):
    check(f"...and scan_candidate.{col} is in schema.sql as well", col in SCHEMA, True)
check("fantastic_run is in schema.sql", "CREATE TABLE IF NOT EXISTS fantastic_run" in SCHEMA, True)

print("\nthe jobs are registered where a job must be registered:")
tbl = APP_SRC[APP_SRC.index("def job_table() -> list:"):]
for name in ("fantastic", "fantastic_expired", "fantastic_modified"):
    check(f"{name} is in the one job table", f'("{name}", ' in tbl, True)
check("🚨 the paid job defaults to MANUAL ONLY",
      'os.environ.get("FANTASTIC_EVERY_MIN", "0")' in APP_SRC, True)
check("the complimentary feeds default to manual too",
      'os.environ.get("FANTASTIC_EXPIRED_EVERY_MIN", "0")' in APP_SRC, True)
check("a run is capped in ROWS, not only in pages",
      'os.environ.get("FANTASTIC_MAX_ROWS"' in APP_SRC, True)

print("\nthe insert site, checked as source because it needs a live database to run:")
blk = APP_SRC[APP_SRC.index("def _fantastic_store"):]
blk = blk[:blk.index("def job_fantastic(")]
check("it stores the whole posting, not a model-input slice",
      "SCAN_MAX_DESCRIPTION_CHARS" in blk and "AI_MAX_BODY_CHARS" not in blk, True)
check("it lands untriaged, so the existing scorer owns the score", "triaged" in blk, True)
check("the free local reader is tried BEFORE their extraction",
      blk.index("_comp_at_insert") < blk.index("comp_band"), True)
_ins = blk[blk.index("INSERT INTO scan_candidate"):]
check("every named column has a placeholder",
      len(re.search(r"VALUES \(([?,0]+)\)", _ins).group(1).split(",")),
      len(re.search(r"INSERT INTO scan_candidate \((.*?)\) VALUES",
                    re.sub(r'"\s*\n\s*"', "", _ins), re.S).group(1).split(",")))

# 🚨 THE GATED ROWS ARE PAID FOR. Seeding must happen BEFORE the gates or ~75% of what the
# feed returns is billed and then discarded whole.
print("\nboard seeding, which is what makes a gated row worth something:")
seed = APP_SRC[APP_SRC.index("def _fantastic_seed_board"):]
seed = seed[:seed.index("def _fantastic_store")]
store = APP_SRC[APP_SRC.index("def _fantastic_store"):]
store = store[:store.index("def job_fantastic(")]
check("a seeded board is DISABLED, unlike a board he mailed in",
      "enabled,note) \"\n                \"VALUES (?,?,?,?,?,0,?)" in seed
      or "VALUES (?,?,?,?,?,0,?)" in seed, True)
check("🚨 seeding runs BEFORE the gates, so a gated row still yields its board",
      store.index("_fantastic_seed_board") < store.index("gate_posting"), True)
check("source_slug is preferred over parsing the URL",
      seed.index("source_slug") < seed.index("board_from_url"), True)
check("...and it is only trusted for greenhouse, the one platform it is populated for",
      'row.get("source") or "").lower() == "greenhouse"' in seed, True)
check("a board write cannot kill the run that paid for the rows",
      "except Exception" in seed, True)
check("the note records whether the token was verified or guessed",
      "VERIFIED from source_slug" in seed, True)
# ⚠️ ONE implementation of ATS URL parsing. Two copies is how the Ashby suffix fix reached
# one reader and not the other.
check("the URL parser is shared, not copied",
      APP_SRC.count("def board_from_url") == 1
      and "board_from_url(url)" in APP_SRC[APP_SRC.index("def inbox_register_board"):], True)

print("\nthe expired feed never decides anything a human owns:")
exp = APP_SRC[APP_SRC.index("def job_fantastic_expired"):]
exp = exp[:exp.index("def job_fantastic_modified")]
check("🚨 it never writes the application table", "UPDATE application" in exp, False)
# ⚠️ The word appears in the docstring, explaining what this job deliberately does NOT do.
# The test is about the WRITE, so it looks for a write.
check("...and never sets a ghosted status", "'ghosted'" in exp, False)
check("the only status it writes is on the posting",
      exp.count("SET status=") == 1 and "UPDATE posting SET status='dead'" in exp, True)
check("it records the evidence, so a row says WHY", "status_evidence" in exp, True)
check("it uses the STABLE daily snapshot, not a rolling window",
      '"time_frame": "1d"' in exp, True)

print()
if fails:
    for f in fails:
        print("  " + f)
    raise SystemExit(f"{len(fails)} failure(s)")
print("all passed")


# ---------------------------------------------------------------------------------------
# 🚨 THE LINKEDIN FEED IS A SECOND ENDPOINT, AND THE ENGINE ONLY EVER CALLED THE FIRST.
# Measured 2026-09-21 across eleven queries over 7 days: 2,043 rows on /v1/active-ats and
# 4,823 on /v1/active-jb, with ZERO linkedin.com URLs anywhere in the queue.
# ⚠️ It is LinkedIn ONLY. Probed by source: linkedin 1,296 of 1,303; indeed, ziprecruiter,
# monster, glassdoor, dice and builtin all return 0.
print("\nthe LinkedIn feed is separate, remote-filtered, and marked as an aggregator:")
JBSRC = APP_SRC.split("def job_fantastic_jb", 1)[1].split("\ndef ", 1)[0] if "def job_fantastic_jb" in APP_SRC else ""
check("job_fantastic_jb exists", bool(bool(JBSRC)), True)
check("it calls the active-jb endpoint, not active-ats", bool('"active-jb"' in JBSRC), True)
check("it never calls active-ats", bool('"active-ats"' not in JBSRC), True)
# 🚨 THE FILTER THAT MAKES IT AFFORDABLE. 1,279 rows unfiltered vs 173 remote on one query.
# A config that forgets it costs 7x per run and the failure is invisible: more rows look
# like more value.
check("the remote filter is FORCED in code, not left to config", bool('"ai_work_arrangement": FANTASTIC_JB_ARRANGEMENT' in JBSRC), True)
check("...and it includes Remote OK, because their arrangement field is 21% wrong", bool("Remote OK" in APP_SRC.split("FANTASTIC_JB_ARRANGEMENT", 1)[1][:400]), True)
# ⚠️ 35% of rows are already reachable through the ATS endpoint. Dropping them before the
# store saves triage, which bills ~7,313 input tokens per row that lands.
check("ats_duplicate rows are dropped BEFORE the shared ingest", bool("if not r.get(\"ats_duplicate\")" in JBSRC
      and JBSRC.index("ats_duplicate") < JBSRC.index("_fantastic_store")), True)
check("every landed row is marked url_kind='aggregator'", bool("SET url_kind='aggregator'" in JBSRC), True)
check("schema.sql declares url_kind", bool("url_kind" in SCHEMA), True)
check("a migration adds url_kind", bool('ALTER TABLE scan_candidate ADD COLUMN url_kind TEXT' in APP_SRC), True)
# 📌 A new PAID feed must not switch itself on during a deploy.
check("it is scheduled OFF by default", bool('FANTASTIC_JB_EVERY_MIN", "0"' in APP_SRC), True)
check("it is registered so it can be run by hand", bool('("fantastic_jb", FANTASTIC_JB_EVERY_MIN * 60, job_fantastic_jb)' in APP_SRC), True)
check("it has its own budget cap", bool("FANTASTIC_JB_MAX_ROWS" in JBSRC), True)

# ⭐ THE LOCAL PASS IS THE INVERSE OF THE NATIONAL ONE, and it does NOT contradict the
# "United States is the only correct location" rule. That rule exists because a remote
# posting derives its location from the employer's OFFICE, so a state filter deletes the
# remote roles he wants. Re-measured 2026-09-21, title=integration, 7 days:
#     New York + Remote Solely   ATS 0    LinkedIn 4     <- the rule holds
#     New York + On-site         ATS 27   LinkedIn 27
#     New York + Hybrid          ATS 8    LinkedIn 21
# A location filter is wrong for REMOTE and right for ON-SITE, because an on-site role's
# derived office is where the work actually happens.
print("\nthe local commutable pass:")
check("a local arrangement knob exists", bool("FANTASTIC_JB_LOCAL_ARRANGEMENT" in APP_SRC), True)
check("it asks for On-site and Hybrid, the inverse of the national pass",
      bool("On-site,Hybrid" in APP_SRC), True)
check("the states come from candidate.toml near_states, never hardcoded",
      bool('"near_states"' in JBSRC or "near_states" in JBSRC), True)
check("one pass per state, because the filter takes one place",
      bool("for st in near" in JBSRC), True)
check("the national pass is still remote-filtered",
      bool('("national", {**base, "ai_work_arrangement": FANTASTIC_JB_ARRANGEMENT})' in JBSRC), True)
check("each pass is labelled, so a run is attributable",
      bool('f"{pass_name}/' in JBSRC), True)

# 🚨 A SOURCE-LEVEL STRING CHECK CANNOT SEE A WRONG CALL SIGNATURE. The first run of
# job_fantastic_jb died on TypeError: _fantastic_close() takes 1 positional argument but 2
# were given, after twelve source checks had passed. The shape was copied from job_fantastic
# and the keyword was dropped. This inspects the real signature instead of the text.
print("\nthe run-bookkeeping helpers are called correctly:")
import inspect as _insp                                       # noqa: E402
sys.path.insert(0, str(SRC_DIR))
import test_parse as _tp                                      # noqa: E402
_relay = _tp.load_app()
_sig = _insp.signature(_relay._fantastic_close)
check("_fantastic_close takes run_id then KEYWORDS only",
      bool([p.kind for p in _sig.parameters.values()].count(_insp.Parameter.VAR_KEYWORD) == 1
           and len([p for p in _sig.parameters.values()
                    if p.kind == _insp.Parameter.POSITIONAL_OR_KEYWORD]) == 1), True)
check("no call site passes status positionally",
      bool('_fantastic_close(run_id, "' not in APP_SRC), True)

# 🚨 A WRONG LOCATION VALUE IS A SILENT FAILURE. The vendor wants full state names and
# near_states holds two-letter codes. Measured 2026-09-21, 6m, on-site+hybrid:
#     "NY" -> 0 rows      "New York" -> 280 rows
# Zero rows, zero credits, no error: indistinguishable from an empty window. The first
# local backfill reported twelve passes of "0 returned, 0 new" and looked like it worked.
print("\nstate codes are expanded to the names the vendor accepts:")
check("a code->name map exists", bool("_US_STATE_NAMES" in APP_SRC), True)
check("all four near_states are covered",
      bool(all(f'"{c}": "' in APP_SRC for c in ("NY", "NJ", "CT", "PA"))), True)
check("the local pass expands the code", bool("_US_STATE_NAMES.get(st.upper()" in APP_SRC), True)
check("the label keeps the CODE, so a run is readable",
      bool('f"local:{st}"' in APP_SRC), True)
