#!/usr/bin/env python3
"""Two jobs spent money and recorded nothing, so the database's account of cost was false.

🚨 WHAT WAS WRONG, FOUND 2026-09-21. job_comp and job_remote_check both read their usage
into a variable named `_u` and dropped it. 126 pay bands and 844 locations had been judged
by the model with no token record anywhere.

⚠️ THE DAMAGE WAS NOT THE MISSING ROWS, IT WAS THE CONFIDENT WRONG ANSWER. When the shared
key hit its cap, "what spent it?" was answered from the database as triage 96%, mail 2.5%,
audits 1.0%. That was a census of the three jobs that happened to record themselves. The two
silent ones were not a small slice of the total; they were absent from it, and the total was
presented as complete.

⭐ SO THE LEDGER SITS WHERE THE SPENDING HAPPENS. note_spend() is called inside
_read_openai_compat, not at the six call sites, so a new caller cannot forget and a caller
that drops the returned usage is still counted.

Run:  python3 tests/test_ai_spend.py
"""
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_parse                                             # noqa: E402

relay = test_parse.load_app()
SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
SCHEMA = (HERE.parent / "job_search_engine" / "schema.sql").read_text()
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


print("the ledger is declared and migrated:")
check("schema.sql declares ai_spend", "CREATE TABLE IF NOT EXISTS ai_spend" in SCHEMA)
check("a migration creates it too", SRC.count("CREATE TABLE IF NOT EXISTS ai_spend") >= 1)
check("it is indexed by purpose", "idx_ai_spend_purpose" in SCHEMA)

print("\nthe recording happens where the SPENDING happens, not at the call sites:")
spend_fn = SRC.split("def _read_openai_compat", 1)[1].split("\ndef ", 1)[0]
check("_read_openai_compat calls note_spend", "note_spend(purpose, usage)" in spend_fn)
check("...and still returns the usage to its caller", "return text, usage" in spend_fn)
# ⚠️ EXPRESS THE INVARIANT, NOT A COUNT. An earlier version asserted note_spend appeared
# exactly three times, and adding the Jev hook made it five and failed a check that was
# measuring nothing. What must hold is narrower: exactly ONE unconditional call on the
# OpenRouter path, and every other mention is a hook binding at a vendor boundary.
check("exactly one call on the OpenRouter path",
      SRC.count("    note_spend(purpose, usage)") == 1)
_hookbinds = SRC.count("note_spend(p, u, key_name=")
check("every other call is a vendor hook binding, and there are two",
      _hookbinds == 2)

print("\nit records the VARIABLE that paid, never a key value:")
note_fn = SRC.split("def note_spend", 1)[1].split("\ndef ", 1)[0]
check("key_name comes from ai_key_name", "ai_key_name(purpose)" in note_fn)
check("no os.environ lookup of a key value", "os.environ[" not in note_fn)
check("bookkeeping cannot raise", "except Exception:" in note_fn and "pass" in note_fn)

print("\nbehaviour, against a real temporary database:")
import tempfile                                               # noqa: E402
_d = tempfile.mkdtemp()
_old_db, _old_key = os.environ.get("DB_PATH"), os.environ.get("AI_API_KEY")
try:
    os.environ["DB_PATH"] = str(pathlib.Path(_d) / "t.db")
    relay.DB_PATH = os.environ["DB_PATH"]
    os.environ["AI_API_KEY"] = "shared"
    os.environ["AI_API_KEY_COMP"] = "comp-key"
    relay.init_db()

    relay.note_spend("COMP", {"input_tokens": 1200, "output_tokens": 30,
                              "cache_read": 0, "model": "m1"})
    relay.note_spend("REMOTE", {"input_tokens": 800, "output_tokens": 20,
                                "cache_read": 5, "model": "m1"})
    relay.note_spend("", {"input_tokens": 10, "output_tokens": 1,
                          "cache_read": 0, "model": "m1"})
    with relay.db() as con:
        rows = {r["purpose"]: dict(r) for r in con.execute(
            "SELECT purpose, key_name, input_tokens, output_tokens FROM ai_spend")}
    check("COMP was recorded", rows.get("COMP", {}).get("input_tokens") == 1200)
    check("REMOTE was recorded", rows.get("REMOTE", {}).get("input_tokens") == 800)
    check("COMP names its OWN key variable",
          rows.get("COMP", {}).get("key_name") == "AI_API_KEY_COMP")
    check("REMOTE names the shared one it actually used",
          rows.get("REMOTE", {}).get("key_name") == "AI_API_KEY")
    check("an unlabelled call is recorded as SHARED", "SHARED" in rows)

    # 🚨 THE DEFECT MEASURING FOUND. note_spend used to ALWAYS resolve the key itself, so a
    # JEV_REMOTE call looked for AI_API_KEY_JEV_REMOTE, missed, and fell back to AI_API_KEY.
    # 63 production rows recorded the OpenRouter variable as having paid a TypeSafe bill.
    relay.note_spend("JEV_REMOTE", {"input_tokens": 1600, "output_tokens": 12,
                                    "model": "jev-1.13.0"},
                     key_name="JEV_API_KEY", vendor="typesafe")
    with relay.db() as con:
        j = dict(con.execute("SELECT vendor, key_name FROM ai_spend "
                             "WHERE purpose='JEV_REMOTE'").fetchone())
    check("a second vendor records ITS OWN key, not the OpenRouter one",
          j["key_name"] == "JEV_API_KEY")
    check("...and its own vendor, so the two token pools stay separable",
          j["vendor"] == "typesafe")
    with relay.db() as con:
        o = dict(con.execute("SELECT vendor FROM ai_spend WHERE purpose='COMP'").fetchone())
    check("an OpenRouter call still defaults to openrouter", o["vendor"] == "openrouter")

    print("\n  a broken ledger must never discard a paid answer:")
    _real = relay.db

    def _boom(*a, **k):
        raise RuntimeError("database gone")

    relay.db = _boom
    try:
        relay.note_spend("COMP", {"input_tokens": 1, "output_tokens": 1})
        check("note_spend swallowed a database failure", True)
    except Exception:                                         # noqa: BLE001
        check("note_spend swallowed a database failure", False)
    finally:
        relay.db = _real
finally:
    for k in ("AI_API_KEY_COMP",):
        os.environ.pop(k, None)
    if _old_db is None:
        os.environ.pop("DB_PATH", None)
    else:
        os.environ["DB_PATH"] = _old_db
    if _old_key is None:
        os.environ.pop("AI_API_KEY", None)
    else:
        os.environ["AI_API_KEY"] = _old_key

print("\nthe two jobs that used to discard usage now cannot:")
for job in ("job_comp", "job_remote_check"):
    body = SRC.split(f"def {job}", 1)[1].split("\ndef ", 1)[0]
    # They may still name the variable `_u`; what matters is that the spend is recorded
    # upstream of them now, so discarding the return value no longer loses the record.
    check(f"{job} still calls through _read_openai_compat",
          "_read_openai_compat(" in body)

# 🚨 THE LEDGER MUST COVER EVERY VENDOR, NOT THE FIRST ONE. ai_spend was built to fix two
# jobs that spent money and recorded nothing. Jev then shipped the SAME DAY as a second paid
# vendor that does not go through _read_openai_compat, and made 480 calls the table could not
# see. The same failure, reproduced against a new vendor, hours after fixing it.
print("\nthe ledger reaches the SECOND vendor too:")
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
import jev as _jev                                            # noqa: E402

JEVSRC = (HERE.parent / "job_search_engine" / "jev.py").read_text()
check("jev.py exposes a spend hook", hasattr(_jev, "SPEND_HOOK"))
check("it is unset by default, so the module stands alone", _jev.SPEND_HOOK is None)
check("an unset hook records nothing and raises nothing",
      _jev._record("X", {"usage": {"input_tokens": 1}}) is None)

seen = []
_old_hook = _jev.SPEND_HOOK
try:
    _jev.SPEND_HOOK = lambda pu, u: seen.append((pu, u["input_tokens"]))
    _jev._PURPOSE["name"] = "JEV_LEVEL"
    _jev._record(_jev._PURPOSE["name"], {"usage": {"input_tokens": 1417, "output_tokens": 9}})
    check("a call is reported to the hook with its purpose", seen == [("JEV_LEVEL", 1417)])

    def _hook_boom(pu, u):
        raise RuntimeError("ledger down")

    _jev.SPEND_HOOK = _hook_boom
    _jev._record("JEV_REMOTE", {"usage": {"input_tokens": 1}})
    check("a broken hook cannot discard a paid answer", True)
except Exception:                                             # noqa: BLE001
    check("a broken hook cannot discard a paid answer", False)
finally:
    _jev.SPEND_HOOK = _old_hook
    _jev._PURPOSE["name"] = ""

check("ask() records where the spending happens, not at the call sites",
      "_record(_PURPOSE" in JEVSRC)
check("both readers name their purpose",
      '_PURPOSE["name"] = "JEV_LEVEL"' in JEVSRC
      and '_PURPOSE["name"] = "JEV_REMOTE"' in JEVSRC)
check("both jev jobs bind the hook with Jev's own key and vendor",
      SRC.count('key_name="JEV_API_KEY"') == 2
      and SRC.count('vendor="typesafe"') == 2)
check("jev.py never imports app, which would be a cycle", "import app" not in JEVSRC)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed (including the second vendor)")
