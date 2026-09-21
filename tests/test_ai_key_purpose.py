#!/usr/bin/env python3
"""One key paid for every job, so the bill could not be read and one job starved the rest.

🚨 WHAT IT COST, MEASURED 2026-09-21. The single production key hit its $5 cap. Answering
"what spent it?" took a token count across three tables, because every call arrived under
the same key: triage 16,067,581 input tokens (96%), mail reading 422,391 (2.5%), form
audits 174,156 (1.0%). The dashboard could not have said that.

⚠️ A SHARED CAP IS A SHARED OUTAGE. Triage exhausted the key and mail reading stopped with
it, having spent forty times less. 1,996 refused calls over six days, during which the
regex classifier ran alone. That classifier is already on record for missing three real
interview confirmations on wording.

⭐ WORSE, AND THIS IS THE PART NOTHING COULD SEE: the container and the laptop held two
DIFFERENT OpenRouter keys, $5 and $20, with different balances. The e2e check named
"relay.env and production agree on every shared secret" PASSED throughout, because it
compares by variable NAME and these were named AI_API_KEY and OPENROUTER_API_KEY.

📌 THE FALLBACK IS THE DESIGN. An unset per-purpose key resolves to the shared one, so
this release changes nothing until a key is actually split out.

Run:  python3 tests/test_ai_key_purpose.py
"""
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_parse                                             # noqa: E402

relay = test_parse.load_app()
SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


_SAVED = {k: os.environ.get(k) for k in
          ("AI_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
           "AI_API_KEY_TRIAGE", "AI_API_KEY_MAIL")}


def clear():
    for k in _SAVED:
        os.environ.pop(k, None)


def restore():
    for k, v in _SAVED.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


try:
    print("with no keys at all, it says so instead of guessing:")
    clear()
    check("ai_key_name('TRIAGE') is empty", relay.ai_key_name("TRIAGE") == "")
    try:
        relay.ai_key("TRIAGE")
        check("ai_key raises when nothing is set", False)
    except RuntimeError as e:
        check("ai_key raises when nothing is set", True)
        check("the error names the per-purpose variable it looked for",
              "AI_API_KEY_TRIAGE" in str(e))

    print("\nthe fallback is the design: an unsplit purpose uses the shared key:")
    clear()
    os.environ["AI_API_KEY"] = "shared-value"
    check("TRIAGE falls back to AI_API_KEY", relay.ai_key_name("TRIAGE") == "AI_API_KEY")
    check("MAIL falls back to AI_API_KEY", relay.ai_key_name("MAIL") == "AI_API_KEY")
    check("no purpose at all resolves too", relay.ai_key_name() == "AI_API_KEY")
    check("and returns the shared value", relay.ai_key("TRIAGE") == "shared-value")

    print("\na split key wins for ITS purpose and only its purpose:")
    clear()
    os.environ["AI_API_KEY"] = "shared-value"
    os.environ["AI_API_KEY_TRIAGE"] = "triage-value"
    check("TRIAGE uses its own key", relay.ai_key_name("TRIAGE") == "AI_API_KEY_TRIAGE")
    check("...and its own value", relay.ai_key("TRIAGE") == "triage-value")
    check("MAIL is unaffected", relay.ai_key_name("MAIL") == "AI_API_KEY")
    check("...and still gets the shared value", relay.ai_key("MAIL") == "shared-value")
    check("the bare call is unaffected", relay.ai_key() == "shared-value")

    print("\ntwo split keys do not bleed into each other:")
    os.environ["AI_API_KEY_MAIL"] = "mail-value"
    check("TRIAGE stays on its key", relay.ai_key("TRIAGE") == "triage-value")
    check("MAIL moves to its key", relay.ai_key("MAIL") == "mail-value")
    check("COMP still shares", relay.ai_key("COMP") == "shared-value")

    print("\nan EMPTY per-purpose variable is not a key, it is a typo:")
    clear()
    os.environ["AI_API_KEY"] = "shared-value"
    os.environ["AI_API_KEY_TRIAGE"] = "   "
    check("blank does not shadow the shared key",
          relay.ai_key_name("TRIAGE") == "AI_API_KEY")

    print("\nthe legacy names still resolve, so nothing needs a coordinated deploy:")
    clear()
    os.environ["OPENROUTER_API_KEY"] = "legacy-value"
    check("OPENROUTER_API_KEY still works", relay.ai_key("TRIAGE") == "legacy-value")
    clear()
    os.environ["OPENAI_API_KEY"] = "openai-value"
    check("OPENAI_API_KEY still works", relay.ai_key() == "openai-value")
finally:
    restore()

print("\nevery paid call site declares what it is paying for:")
for purpose in ("TRIAGE", "MAIL", "MATCH", "COMP", "REMOTE", "GATE_AUDIT"):
    check(f"a call site declares purpose={purpose}", f'purpose="{purpose}"' in SRC)
check("six call sites are labelled, which is all of them",
      SRC.count('purpose="') == 6)
check("the old inline key lookup is gone",
      'os.environ.get("AI_API_KEY")\n           or os.environ.get' not in SRC)

print("\nthe diagnostic answers 'which key pays for what', by name:")
check("/diag/ai reports key_by_purpose", '"key_by_purpose"' in SRC)
check("...built from ai_key_name, never from a value", "ai_key_name(p)" in SRC)
check("no key VALUE is ever put in the response",
      'out["key_by_purpose"] = {\n            p: (ai_key_name(p) or "NONE")' in SRC)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
