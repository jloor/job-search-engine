"""Jev, TypeSafe AI's System One model: typed decisions about a state.

🚨 WHAT THIS IS NOT. Jev does not generate text. It takes a `state` and a set of typed
`questions`, and returns a value per question plus, for Choice and Score, a confidence.
There is no completion, no reasoning string, no extraction of spans. Anything that needs
prose or a substring out of a page belongs to `comp.py` or to the writing model, and a
caller that reaches for this module to do either of those is in the wrong file.

⭐ WHY IT EARNED A PLACE. Nothing in the engine could judge the SENIORITY of a posting.
`stated_level` was populated on 261 of 14,773 rows and nothing read it, and the keyword
score turned out to carry no level signal at all: measured 2026-09-20 over 363 live rows,
the mean score was 80.8 for entry, 80.0 for mid, 79.6 for senior and 76.0 for lead. Flat,
with a slight tilt TOWARD entry. Of the fifty highest-scoring rows in the queue, thirty
were entry level and four were senior. That is the whole explanation for 130 support
applications and one interview, and no filter change fixes it.

⚠️ ZERO DEPENDENCIES, ON PURPOSE. The engine's suite must pass with nothing installed, so
this uses `urllib` from the standard library and never imports a vendor SDK. Importing this
module with no key set must also succeed: `enabled()` answers the question, and the network
is only touched inside `ask()`.

🚨 CALIBRATION IS MEASURED ACROSS GROUPS, NOT PER ANSWER. TypeSafe say so themselves. A
confidence of 0.98 does not mean this answer is right. It means answers at that confidence
are right at about that rate. Use it to route a review queue. Never use it to authorise an
action, which is the same rule `classify()` already lives under: a label is a hint, never
an authorisation.
"""
import json
import os
import time
import urllib.error
import urllib.request

API_URL = os.environ.get("JEV_API_URL", "https://api.typesafe.ai/v1/systemone")
MODEL = os.environ.get("JEV_MODEL", "jev-latest")

# 🚨 DEFAULT OFF. This is a new vendor, and turning a paid external call on by default is
# how a deploy starts spending money nobody approved. The operator opts in.
ENABLED = os.environ.get("JEV_ENABLED", "0").strip() not in ("0", "false", "no", "")

# The 32k budget covers the state plus the single longest question, so leave room. Postings
# average about 4,900 characters and the longest run well past that.
MAX_STATE_CHARS = int(os.environ.get("JEV_MAX_STATE_CHARS", "14000"))
TIMEOUT_S = int(os.environ.get("JEV_TIMEOUT_S", "90"))


class JevError(RuntimeError):
    """A call failed in a way the caller has to decide about."""


def enabled() -> bool:
    """True when the operator opted in AND a key is present. Both, never either."""
    return bool(ENABLED and os.environ.get("JEV_API_KEY", "").strip())


# ---------------------------------------------------------------- question builders
# 🚨 THESE EXIST BECAUSE THE TWO CRITERIA SHAPES ARE NOT THE SAME AND THE API DOES NOT
# FORGIVE IT. Choice takes a MAPPING of answer -> when to pick it. Score takes a LIST,
# where the index IS the score. Passing a mapping to Score returns 422 with
# `{"type":"list_type","loc":[...,"score","criteria"]}`, which cost a full scan run to
# find. Building the questions through these functions makes that mistake unavailable.


def choice(instructions: str, criteria: dict) -> dict:
    """One answer from a named set. `criteria` maps each answer to when it applies."""
    if not isinstance(criteria, dict) or not criteria:
        raise ValueError("choice criteria must be a non-empty mapping of answer -> meaning")
    return {"type": "choice", "instructions": instructions, "criteria": dict(criteria)}


def score(instructions: str, criteria: list) -> dict:
    """A rung on an ordered scale. `criteria[i]` describes what a score of i means."""
    if not isinstance(criteria, (list, tuple)) or not criteria:
        raise ValueError("score criteria must be a non-empty LIST; the index is the score")
    return {"type": "score", "instructions": instructions, "criteria": list(criteria)}


def noul(instructions: str) -> dict:
    """Is this statement true? Returns a value from 0 to 1.

    ⚠️ ASK ONE THING. A compound question measured 0.57 to 0.80 across obviously different
    postings and separated nothing, while the plain Choice on the same postings separated
    cleanly. If the sentence contains "and" or names two facts, it is two questions.
    """
    return {"type": "noul", "instructions": instructions}



# ---------------------------------------------------------------- spend hook
# 🚨 A LEDGER THAT COVERS ONE VENDOR IS NOT A LEDGER. `ai_spend` was built hours before this
# hook, to fix two jobs that spent money and recorded nothing. Then Jev shipped as a SECOND
# paid vendor that did not go through _read_openai_compat, and within the same day it had
# made 480 calls that the "every paid call" table could not see. The same failure, reproduced
# against a new vendor, by the person who had just fixed it.
#
# ⚠️ jev.py CANNOT IMPORT app.py. The engine's modules import each other by bare name and
# app.py imports this one, so a direct import is a cycle. A hook keeps the dependency
# pointing one way while still recording at the point of spending rather than at the call
# sites, which is the property that made the OpenRouter ledger trustworthy.
#
# 📌 Unset means no recording and no error. This module must stay importable and usable with
# nothing else present, including its own suite.
SPEND_HOOK = None

# Which reader is running, so the ledger can attribute a call without every caller
# threading a purpose argument through. Set by read_posting / read_arrangement.
_PURPOSE = {"name": ""}


def _record(purpose: str, res: dict) -> None:
    """Report one paid call to whatever set SPEND_HOOK. Never raises."""
    if SPEND_HOOK is None:
        return
    try:
        SPEND_HOOK(purpose, {"input_tokens": input_tokens(res),
                             "output_tokens": int(((res or {}).get("usage") or {})
                                                  .get("output_tokens") or 0),
                             "cache_read": 0,
                             "model": (res or {}).get("model") or MODEL})
    except Exception:                                         # noqa: BLE001
        pass


# ---------------------------------------------------------------- the call


def ask(state: str, questions: dict, *, retries: int = 3) -> dict:
    """Put one state and its questions to Jev. Returns {"answers": ..., "usage": ...}.

    Every question is evaluated in parallel against the same state in one request, so
    asking three costs barely more than asking one. Batch them rather than looping.

    ⚠️ Raises JevError rather than returning a sentinel. A caller that writes a column
    needs to know the difference between "the model said entry" and "the call failed",
    and a None that flows into a database is how a failure becomes a fact.
    """
    key = os.environ.get("JEV_API_KEY", "").strip()
    if not key:
        raise JevError("JEV_API_KEY is not set")
    if not questions:
        raise ValueError("no questions")

    body = json.dumps({
        "state": (state or "")[:MAX_STATE_CHARS],
        "model": MODEL,
        "questions": questions,
    }).encode()

    last = None
    for attempt in range(1, max(1, retries) + 1):
        req = urllib.request.Request(
            API_URL, data=body,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                res = json.loads(resp.read().decode())
            # Recorded HERE, not at the call sites, for the same reason the OpenRouter
            # ledger is: a caller that forgets is the failure this replaces.
            _record(_PURPOSE.get("name", ""), res)
            return res
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode()[:300]
            except Exception:                                 # noqa: BLE001
                pass
            # 429 is the documented rate limit and carries retry-after. 5xx is theirs, not
            # ours. A 4xx that is not 429 is a bad request and retrying it just repeats it.
            if e.code == 429 and attempt < retries:
                time.sleep(_retry_after(e, attempt))
                continue
            if 500 <= e.code < 600 and attempt < retries:
                time.sleep(min(2 ** attempt, 15))
                continue
            # ⚠️ The key must never reach a log line or an exception message.
            raise JevError(f"HTTP {e.code} {detail}") from None
        except Exception as e:                                # noqa: BLE001
            last = e
            if attempt < retries:
                time.sleep(min(2 ** attempt, 15))
                continue
            raise JevError(f"{type(e).__name__}: {e}") from None
    raise JevError(f"exhausted retries: {last}")


def _retry_after(err, attempt: int) -> float:
    try:
        return max(1.0, float(err.headers.get("retry-after") or 0)) or 2.0 ** attempt
    except Exception:                                         # noqa: BLE001
        return min(2.0 ** attempt, 15.0)


def answer(res: dict, name: str):
    """Pull one answer's value out of a response, whatever its type.

    Returns (value, confidence). Confidence is None for a Noul, which does not carry one.
    """
    a = ((res or {}).get("answers") or {}).get(name) or {}
    t = a.get("type")
    if t == "choice":
        return a.get("choice"), a.get("confidence")
    if t == "score":
        return a.get("score"), a.get("confidence")
    if t == "noul":
        return a.get("noul"), None
    return None, None


def input_tokens(res: dict) -> int:
    """Billed tokens for one call. Output tokens are free and are not counted."""
    return int(((res or {}).get("usage") or {}).get("input_tokens") or 0)


def cost_usd(tokens: int) -> float:
    """Jev 1.13 is $42 per billion input tokens, which is $0.042 per million."""
    return tokens * 0.042 / 1_000_000


# ---------------------------------------------------------------- the level question
# ⭐ THE QUESTION SET THAT MEASURED THE QUEUE. Kept here rather than at the call site so
# the wording is one thing, versioned with the code, and a later run is comparable with
# the 2026-09-20 baseline. Changing the wording changes the answers; do it deliberately.

LEVEL_CRITERIA = {
    "entry": "Entry level or junior. Asks for 0 to 2 years, or uses I, Associate, "
             "Tier 1, Intern, Trainee, Junior.",
    "mid": "Mid level. Asks for roughly 3 to 5 years and works with some independence.",
    "senior": "Senior individual contributor. Asks for 5+ years, leads complex work "
              "independently, mentors others.",
    "lead": "Lead, principal, or people manager. Owns a team, a function, or direct reports.",
}

YEARS_CRITERIA = [
    "States no experience requirement, or 0 to 2 years",
    "Requires about 3 to 5 years",
    "Requires about 5 to 8 years",
    "Requires more than 8 years",
]


def posting_questions() -> dict:
    """The three questions asked of every posting. One call, evaluated in parallel."""
    return {
        "level": choice("What seniority level is this job posting written for?",
                        LEVEL_CRITERIA),
        "min_years": score("How many years of professional experience does this posting "
                           "require at minimum?", YEARS_CRITERIA),
        "degree_hard": noul("Does this posting require a bachelor's degree with NO stated "
                            "equivalent-experience alternative?"),
    }


def read_posting(description: str) -> dict:
    """Ask the three questions about one posting. Returns a dict ready for the columns."""
    _PURPOSE["name"] = "JEV_LEVEL"
    res = ask(description, posting_questions())
    lvl, conf = answer(res, "level")
    yrs, _ = answer(res, "min_years")
    deg, _ = answer(res, "degree_hard")
    return {"level": lvl, "level_conf": conf, "min_years": yrs,
            "degree_hard": deg, "tokens": input_tokens(res)}


# ---------------------------------------------------------------- work arrangement
# 🚨 THIS DOES NOT WRITE remote_verdict, AND THAT IS THE WHOLE DESIGN. Measured 2026-09-21
# over 94 rows the model had decided: `remote_verdict` carries TWO different meanings in one
# column. The model writes "how is the work arranged" (hybrid, onsite, remote) and the
# commute router OVERWRITES it with "can he reach it" (too far = onsite). Two postings in
# Collingswood NJ say "This is a hybrid role" in their own words and carry #LI-HYBRID, and
# the column reads `onsite`, because the router measured 145 minutes against a 90 minute
# ceiling and said so in the only field it had.
#
# ⚠️ SO A MODEL THAT ANSWERS THE ARRANGEMENT QUESTION WILL LOOK WRONG ON THOSE ROWS, AND IT
# IS NOT. Jev called all three of them hybrid and was marked as disagreeing. It was right.
# The comparison was wrong because the column is overloaded.
#
# ⭐ Same rule the `place` table already enforces by keeping judged, address and measured in
# separate columns: collapsing a guess and a measurement into one field makes the guess
# indistinguishable from the fact, and the guess is the one that gets quoted later.
#
# 📌 THE CRITERIA BELOW ARE THE MEASURED ONES, NOT A FIRST DRAFT. An earlier wording defined
# fully_remote as "anywhere in the country" and remote_with_residency as "residents of a
# named country", so every "Remote - US" posting satisfied BOTH and the model correctly
# chose the narrower one: 14 of 20 disagreed for that reason alone. Stating that a US-only
# rule is not a restriction for a US citizen took that group from 6/20 to 20/20.

ARRANGEMENT_CRITERIA = {
    "fully_remote":
        "Remote with no office attendance required, AND no location requirement that "
        "excludes a US citizen living at the candidate's address. THIS INCLUDES nationwide "
        "and US-only remote roles ('Remote - US', 'Remote, United States', 'US Remote'), and "
        "roles open to anywhere in the world. A US-only rule is NOT a restriction here.",
    "remote_in_metro":
        "Remote, but the worker must live in or near ONE NAMED METRO AREA or city, for "
        "example 'Remote - must be in the NYC area' or 'Boston-based, remote'.",
    "remote_with_residency":
        "Remote, but restricted to a SPECIFIC STATE, a MULTI-STATE REGION, or a country "
        "OTHER THAN the United States. Examples: 'Remote, Michigan', 'US East Coast only', "
        "'Remote within Canada', 'Remote - European Union'. Do NOT use this for a plain "
        "US-wide remote role.",
    "hybrid":
        "Requires attending an office on a regular schedule while working from home the "
        "rest of the time.",
    "onsite":
        "Requires working at an office, a lab, or customer sites, with no meaningful remote "
        "arrangement.",
    "unclear":
        "The posting genuinely does not say enough to place it in any of the above.",
}


def arrangement_questions(origin: str) -> dict:
    """The location question, with the candidate's own address in it.

    ⚠️ "US CITIZEN" IS LOAD-BEARING AND WAS MISSING FROM THE FIRST VERSION. Without it,
    "Remote - US" reads as a residency restriction. With it, the restriction excludes
    nobody relevant and the row is simply remote.
    """
    return {
        "arrangement": choice(
            f"The candidate is a US CITIZEN living at {origin}. He will only take work he "
            "can do from that address. Classify how this job's work location is arranged. "
            "Judge what the posting REQUIRES, not what it prefers.",
            ARRANGEMENT_CRITERIA),
    }


def read_arrangement(title: str, location: str, description: str, origin: str) -> dict:
    """Ask how one posting's work is arranged. Returns a dict ready for the columns.

    The state is the same shape the previous model was given: title, location, description.
    A comparison against a differently-shaped input would measure the input, not the model.
    """
    state = json.dumps({"title": title or "", "location": location or "",
                        "description": (description or "")[:9000]})
    _PURPOSE["name"] = "JEV_REMOTE"
    res = ask(state, arrangement_questions(origin))
    val, conf = answer(res, "arrangement")
    return {"arrangement": val, "conf": conf, "tokens": input_tokens(res)}
