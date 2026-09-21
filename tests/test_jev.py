#!/usr/bin/env python3
"""The score could not see seniority, and 363 rows proved it.

🚨 WHAT IT COST, MEASURED 2026-09-20. Every live, unworked, scored row in the queue was read.
46% were entry level. The keyword score carried no level signal at all: mean 80.8 for entry,
80.0 for mid, 79.6 for senior, 76.0 for lead. Flat, with a slight tilt TOWARD entry. Of the
fifty highest-scoring rows in the queue, THIRTY were entry level and four were senior. The
operator has twenty years of experience. 130 support applications had produced one interview,
and this is the measured reason.

⭐ WHY A MODEL AND NOT ANOTHER REGEX. TARGET_TITLE is a recall filter whose own pattern
contains "support", and the level lives in the requirement list as often as in the title.
"Technical Support Engineer I" and "Senior Technical Support Engineer" are not separable by
the machinery already here.

🚨 THE BUG THIS FILE EXISTS TO PREVENT. TypeSafe's Choice takes a MAPPING of answer to
meaning. Score takes a LIST whose index IS the score. A mapping passed to Score serialises
happily, sends happily, and comes back 422 naming ["body","questions","a","score","criteria"].
That cost a full scan run to find. The builders in jev.py make it unavailable; these checks
keep the builders honest.

Run:  python3 tests/test_jev.py
"""
import json
import pathlib
import sys
import urllib.error

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
import jev                                                    # noqa: E402

SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
SCHEMA = (HERE.parent / "job_search_engine" / "schema.sql").read_text()
JEVSRC = (HERE.parent / "job_search_engine" / "jev.py").read_text()
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


def raises(label, fn, exc=Exception):
    try:
        fn()
    except exc:
        check(label, True)
        return
    except Exception as e:                                    # noqa: BLE001
        check(f"{label} (raised {type(e).__name__} instead)", False)
        return
    check(f"{label} (nothing raised)", False)


print("the two criteria shapes are not interchangeable, and the API does not forgive it:")
raises("Score refuses a mapping, which is the 422",
       lambda: jev.score("How many years?", {"0": "0-2", "1": "3-5"}), ValueError)
raises("Choice refuses a list",
       lambda: jev.choice("What level?", ["entry", "senior"]), ValueError)
raises("Score refuses empty criteria", lambda: jev.score("q", []), ValueError)
raises("Choice refuses empty criteria", lambda: jev.choice("q", {}), ValueError)

print("\nthe builders emit what the API accepts:")
c = jev.choice("What level?", {"entry": "junior", "senior": "5+ years"})
s = jev.score("How many years?", ["0-2", "3-5"])
n = jev.noul("Is a degree required?")
check("choice criteria is a mapping", isinstance(c["criteria"], dict))
check("score criteria is a list", isinstance(s["criteria"], list))
check("noul carries no criteria", "criteria" not in n)
check("the whole question set survives json", bool(
    json.loads(json.dumps({"questions": {"a": c, "b": s, "c": n}}))))

print("\nthe posting question set is well formed:")
q = jev.posting_questions()
check("asks exactly level, min_years, degree_hard",
      set(q) == {"level", "min_years", "degree_hard"})
check("level is a choice with a mapping", isinstance(q["level"]["criteria"], dict))
check("min_years is a score with a list", isinstance(q["min_years"]["criteria"], list))
check("the four levels are the ones the columns document",
      set(jev.LEVEL_CRITERIA) == {"entry", "mid", "senior", "lead"})

print("\nenabled() needs BOTH the flag and a key, never either:")
_flag, _key = jev.ENABLED, __import__("os").environ.get("JEV_API_KEY")
try:
    jev.ENABLED = True
    __import__("os").environ.pop("JEV_API_KEY", None)
    check("flag on, no key -> disabled", jev.enabled() is False)
    __import__("os").environ["JEV_API_KEY"] = "sk-test"
    check("flag on, key set -> enabled", jev.enabled() is True)
    jev.ENABLED = False
    check("flag off, key set -> disabled", jev.enabled() is False)
finally:
    jev.ENABLED = _flag
    if _key is None:
        __import__("os").environ.pop("JEV_API_KEY", None)
    else:
        __import__("os").environ["JEV_API_KEY"] = _key

print("\nno key means no connection, not a failed one:")
_real = jev.urllib.request.urlopen


def _explode(*a, **k):
    raise AssertionError("ask() opened a connection with no key set")


try:
    jev.urllib.request.urlopen = _explode
    __import__("os").environ.pop("JEV_API_KEY", None)
    raises("ask() refuses before it dials",
           lambda: jev.ask("state", {"a": jev.noul("q")}), jev.JevError)
finally:
    jev.urllib.request.urlopen = _real
    if _key is not None:
        __import__("os").environ["JEV_API_KEY"] = _key

print("\nanswers parse, and a partial response does not take down a batch:")
res = {"answers": {"lvl": {"type": "choice", "choice": "senior", "confidence": 0.97},
                   "yrs": {"type": "score", "score": 2.0, "confidence": 0.8},
                   "deg": {"type": "noul", "noul": 0.85}}}
check("choice returns value and confidence", jev.answer(res, "lvl") == ("senior", 0.97))
check("score returns value and confidence", jev.answer(res, "yrs") == (2.0, 0.8))
check("noul returns a value and no confidence", jev.answer(res, "deg") == (0.85, None))
check("a missing question is (None, None)", jev.answer({"answers": {}}, "nope") == (None, None))
check("an empty response is (None, None)", jev.answer({}, "x") == (None, None))
check("a None response is (None, None)", jev.answer(None, "x") == (None, None))

print("\ncost matches the published rate:")
check("$0.042 per million input tokens", abs(jev.cost_usd(1_000_000) - 0.042) < 1e-9)
check("the measured 2026-09-20 run costs $0.0216",
      abs(jev.cost_usd(514_529) - 0.0216) < 0.0002)
check("no usage block reads as zero, not a crash", jev.input_tokens({}) == 0)


class _Resp:
    def __init__(self, payload):
        self._p = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self._p).encode()


print("\na long posting is truncated, never rejected:")
seen = {}


def _capture(req, timeout=None):
    seen["len"] = len(json.loads(req.data)["state"])
    return _Resp({"answers": {"a": {"type": "noul", "noul": 0.5}},
                  "usage": {"input_tokens": 1}})


try:
    jev.urllib.request.urlopen = _capture
    __import__("os").environ["JEV_API_KEY"] = "sk-test"
    jev.ask("x" * 50_000, {"a": jev.noul("q")})
    check("state is cut to MAX_STATE_CHARS", seen.get("len") == jev.MAX_STATE_CHARS)
finally:
    jev.urllib.request.urlopen = _real

print("\nthe key never reaches a log line, and a bad request is not retried:")
calls = {"n": 0}


def _http422(req, timeout=None):
    calls["n"] += 1
    raise urllib.error.HTTPError("u", 422, "Unprocessable", {}, None)


try:
    jev.urllib.request.urlopen = _http422
    __import__("os").environ["JEV_API_KEY"] = "sk-super-secret-value"
    try:
        jev.ask("state", {"a": jev.noul("q")}, retries=3)
        check("a 422 raises", False)
    except jev.JevError as e:
        check("a 422 raises JevError", True)
        check("the key is absent from the message", "sk-super-secret-value" not in str(e))
    check("a 4xx that is not 429 is sent once, not three times", calls["n"] == 1)
finally:
    jev.urllib.request.urlopen = _real
    if _key is None:
        __import__("os").environ.pop("JEV_API_KEY", None)
    else:
        __import__("os").environ["JEV_API_KEY"] = _key

print("\nthe module refuses to become a writing model:")
# ⚠️ Check the ENDPOINT, not the word. "completion" appears in this module's own docstring
# explaining that Jev has none, and a naive substring test failed on its own documentation.
_urls = [ln for ln in JEVSRC.splitlines() if "https://" in ln and "API_URL" in ln]
check("the only endpoint is /v1/systemone",
      len(_urls) == 1 and "/v1/systemone" in _urls[0])
check("no chat or completions endpoint is reachable",
      "chat/completions" not in JEVSRC and "/v1/messages" not in JEVSRC)
check("it is off by default", 'JEV_ENABLED", "0"' in JEVSRC)
check("it declares no third-party dependency",
      "import requests" not in JEVSRC and "import anthropic" not in JEVSRC)

print("\nthe columns are declared, migrated, and written by the job:")
for col in ("jev_level", "jev_level_conf", "jev_min_years", "jev_degree_hard", "jev_checked_at"):
    check(f"schema.sql declares {col}", col in SCHEMA)
    check(f"migration adds {col}", f"ALTER TABLE scan_candidate ADD COLUMN {col}" in SRC)

print("\nthe job is wired and stays inside its lane:")
check("job_jev_level exists", "def job_jev_level()" in SRC)
check("it is registered in the scheduler", '("jev_level", JEV_EVERY_MIN * 60, job_jev_level)' in SRC)
check("it returns early when disabled", "_JEV.enabled()" in SRC)
check("it skips rows already known dead", "COALESCE(c.live_status,'') <> 'dead'" in SRC)
check("it skips rows with no body to read", "length(c.description) > 200" in SRC)
check("it never asks about an applied-to row", "FROM posting p WHERE p.canonical_url = c.url" in SRC)
job = SRC.split("def job_jev_level()", 1)[1].split("\ndef ", 1)[0]
# The SQL is split across adjacent string literals, so compare on a whitespace-normalised
# copy rather than on the source's own line wrapping.
_flat = " ".join(job.split()).replace('" "', "")
check("it updates ONLY the five jev columns",
      "SET jev_level=?, jev_level_conf=?, jev_min_years=?, "
      "jev_degree_hard=?, jev_checked_at=? WHERE id=?" in _flat)
check("it writes no score, verdict or comp", "SET score" not in job and "comp_max=" not in job)
check("a failed call writes nothing at all", "continue" in job and "failed += 1" in job)

# 🚨 THE ERROR PATH MUST BE EXERCISED, NOT JUST WRITTEN. Both Jev jobs called log() on a
# failed call. log() does not exist in app.py; the house function is audit(). Neither job had
# crashed because no Jev call had yet failed, so a NameError sat in production across six
# releases behind a branch nothing took. A test that only exercises the happy path cannot
# see this, and neither can a green deploy.
print("\nthe FAILURE path of each job calls something that exists:")
for job in ("job_jev_level", "job_jev_remote"):
    body = SRC.split(f"def {job}", 1)[1].split("\ndef ", 1)[0]
    check(f"{job} does not call the non-existent log()", "log(" not in body
          or "audit(" in body and " log(" not in body.replace("audit(", ""))
    check(f"{job} records the failure with audit()", "audit(" in body)
    check(f"{job} counts the failure rather than swallowing it", "failed += 1" in body)
check("app.py defines audit()", "def audit(" in SRC)
check("app.py does NOT define log(), so calling it would raise",
      "\ndef log(" not in SRC)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
