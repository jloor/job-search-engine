#!/usr/bin/env python3
"""How the submitter decides each answer, and when it refuses to.

🚨 WHAT MUST NEVER HAPPEN: a required question answered by a guess; two disagreeing rules
resolved by picking one; a select answered with a value none of its options can match; a
package answer ignored in favour of a general rule.

Every value below is invented. The candidate config here is a test fixture, not a person.

Run:  python3 tests/test_submit_answers.py
"""
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
import answers as A                                             # noqa: E402

fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


CFG = {
    "identity": {"first_name": "Alex", "last_name": "Rivera", "phone": "555-010-0199",
                 "country": "United States"},
    "eeo": {"gender": "Female", "veteran_status": "I am not a protected veteran"},
    "form_rule": [
        {"match": r"require.*sponsorship", "answer": "No", "kind": "select"},
        {"match": r"legally authori[sz]ed", "answer": "Yes", "kind": "select"},
        {"match": r"linkedin", "answer": "https://www.example.com/in/alex", "kind": "text"},
        {"match": r"how did you hear", "answer": "Company website",
         "spellings": ["Careers page"], "kind": "select"},
        {"match": r"relocat", "answer": "No", "kind": "select"},
        {"match": r"open to relocation|located in", "answer": "Yes", "kind": "select"},
    ],
    "form_spellings": {"Female": ["Woman"]},
}
pkg = pathlib.Path(tempfile.mkdtemp())
(pkg / "resume.pdf").write_bytes(b"%PDF-1.4 test")
(pkg / "form-answers.json").write_text(
    '{"_note": "ignored", "question_77": "Because the product is good.", '
    '"How did you hear about us?": "A friend"}')

F = lambda i, kind="text", label="", req=False: {"id": i, "kind": kind, "label": label,   # noqa: E731
                                                  "required": req, "visible": True}


def d(f, api=None):
    return A.decide(f, api, CFG, pkg, A.load_package_answers(pkg), "acme@jobs.example.com")


print("standard fields:")
check("first name from [identity]", d(F("first_name", req=True)).value == "Alex")
check("email is the application's alias, never a config value",
      d(F("email", req=True)).value == "acme@jobs.example.com")
check("no alias means no email answer",
      A.decide(F("email", req=True), None, CFG, pkg, {}, "").problem)
check("phone from [identity]", d(F("phone", "tel", req=True)).value == "555-010-0199")
check("the résumé field gets the package's résumé.pdf",
      d(F("resume", "file", req=True)).value == str(pkg / "resume.pdf"))
check("a cover-letter slot with no letter in the package is a problem",
      d(F("cover_letter", "file")).problem)
# ⚠️ 2026-10-09: a custom Ashby file question is keyed by a UUID, so only its label can say what
# it wants. Assured's "Cover Letter" was left empty on the sheet before this.
_UID = "c0ffee00-0000-4000-8000-000000000009"
check("a custom file question labelled 'Cover Letter' wants the package's letter",
      d(F(_UID, "file", "Cover Letter")).problem == "no cover-letter.pdf in the package")
check("a custom file question labelled 'Resume/CV:' gets the résumé",
      d(F(_UID, "file", "Resume/CV:")).value == str(pkg / "resume.pdf"))
check("'Autofill from resume' is never the résumé (whole-label match only)",
      not d(F(_UID, "file", "Autofill from resume")).answered)
check("'Upload any other documents' is not mapped",
      d(F(_UID, "file", "Upload any other documents")).problem == "a file field this runner does not know")
g = d(F("gender", "select"), {"label": "Gender", "options": ["Male", "Woman", "Decline"]})
check("EEO gender comes from [eeo] and carries its configured spellings",
      g.value == "Female" and g.spellings == ["Female", "Woman"] and not g.problem)

print("\nrules over the question text:")
s = d(F("question_1", "select", "Will you now or in the future require sponsorship?", True),
      {"options": ["Yes", "No"]})
check("a matching rule answers a required select", s.value == "No" and not s.problem)
li = d(F("question_2", "text", "LinkedIn Profile"))
check("a text rule answers a text field", li.value == "https://www.example.com/in/alex")
check("a text rule never answers a select",
      d(F("question_3", "select", "LinkedIn Profile", True), {"options": ["a"]}).problem)
both = d(F("question_4", "select", "Are you located in NYC or open to relocation?", True),
         {"options": ["Yes", "No"]})
check("🚨 two rules that disagree STOP rather than pick", both.problem and both.value is None)

print("\nthe package's own answers:")
check("a package answer by field id is used",
      d(F("question_77", "textarea", "Why us?", True)).value == "Because the product is good.")
check("a package answer by exact label beats a general rule",
      d(F("question_5", "select", "How did you hear about us?"), {"options": ["A friend", "Other"]}).value
      == "A friend")
check("keys starting with _ are notes, not answers", "_note" not in A.load_package_answers(pkg))

print("\nrefusals:")
r = d(F("question_6", "select", "Have you worked here before?", True), {"options": ["Yes", "No"]})
check("🚨 a required question with no rule stops, it is never guessed",
      r.problem and r.value is None)
check("a required written answer missing from the package says so",
      "written answer" in d(F("question_7", "textarea", "Describe a hard problem", True)).problem)
o = d(F("question_8", "text", "Preferred pronouns", False))
check("an optional question with no rule is simply left blank", o.value is None and not o.problem)
bad = d(F("question_9", "select", "Are you legally authorized to work here?", True),
        {"options": ["I am authorized", "I am not authorized"]})
check("an answer no option can match is a problem before the browser opens", bad.problem)
check("required checkboxes are refused by this runner (not yet supported)",
      d(F("consent", "checkbox", "I agree", True)).problem)
try:
    A.decide(F("x", "text", "y"), None, {"form_rule": [{"match": "("}]}, pkg, {}, "a@b.c")
    check("a broken rule pattern is an error, not a silent skip", False)
except ValueError:
    check("a broken rule pattern is an error, not a silent skip", True)

print("\noption matching (the same tiers form.js uses):")
M = A._option_match
check("🚨 'No' does NOT match 'I am not a veteran' (whole words only)",
      M("No", ["I am not a veteran", "I am a veteran"]) is None)
check("'No' picks 'No' exactly", M("No", ["Yes", "No"]) == "No")
check("'No' picks the one option that starts with the word", M("No", ["No, I do not", "Yes, I do"]) == "No, I do not")
check("'Male' never matches 'Female'", M("Male", ["Female", "Male (he/him)"]) == "Male (he/him)")
check("two options that both start with the wording are ambiguous: no match",
      M("Decline", ["Decline (a)", "Decline (b)"]) is None)

print("\nthe plan and the fill command:")
fields = [F("first_name", req=True), F("email", req=True), F("resume", "file", req=True),
          F("question_6", "select", "Have you worked here before?", True),
          {"id": "hidden_x", "kind": "text", "label": "x", "required": True, "visible": False}]
decisions, stops = A.plan(fields, {}, CFG, pkg, "acme@jobs.example.com")
check("the plan reports the one required question it cannot answer",
      len(stops) == 1 and "worked here before" in stops[0])
check("an invisible field is not planned", all(x.id != "hidden_x" for x in decisions))
cmd = A.fill_command(decisions)
check("the fill command carries files, and text, and nothing unanswered",
      cmd["files"] and {t["id"] for t in cmd["texts"]} == {"first_name", "email"}
      and not cmd["selects"])
check("🚨 the fill command has no submit in it", "submit" not in str(cmd).lower())

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)
