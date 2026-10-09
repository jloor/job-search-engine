"""Decide the answer to each field of an application form, or refuse and say why.

🚨 IT NEVER GUESSES. An answer comes from one of three places, in this order, or there is no
answer:
  1. the package's own `form-answers.json`, written for this one application;
  2. a standard field (name, email, phone, résumé...) read from the candidate config;
  3. a `[[form_rule]]` in the candidate config whose pattern matches the question.
A required field with no answer stops the run. Picking "the closest option" is how a knockout
question gets answered backwards, and a form that looks complete is worse than one that stops.

⚠️ TWO RULES THAT DISAGREE ALSO STOP THE RUN. Rules are regular expressions over question text,
and two of them can match one question. When they resolve to different answers, choosing either
is a guess.

📌 Nothing about a person is in this file. Every value is read from `candidate.toml`:
  [identity]          first_name, last_name, phone, country, linkedin, github, website
  [eeo]               the candidate's self-identification answers
  [[form_rule]]       match (regex), answer OR from ("section.key"), spellings, kind, note
  [form_spellings]    "<answer>" = ["<other wording>", ...], for selects that word it differently
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Standard field ids on Greenhouse forms, mapped to a "section.key" in the candidate config.
STANDARD = {
    "first_name": "identity.first_name",
    "last_name": "identity.last_name",
    "phone": "identity.phone",
    "country": "identity.country",
    "gender": "eeo.gender",
    "race": "eeo.race_ethnicity",
    "veteran_status": "eeo.veteran_status",
    "disability_status": "eeo.disability_status",
}
FILE_FIELDS = {"resume": "resume.pdf", "cover_letter": "cover-letter.pdf",
               # Ashby's system fields (2026-10-08). Its "Autofill from resume" input is NOT one of
               # these: uploading there runs their parser over typed fields.
               "_systemfield_resume": "resume.pdf", "_systemfield_coverLetter": "cover-letter.pdf"}
EMAIL_IDS = ("email", "_systemfield_email")
# Fields a board names only by label (Ashby ids are per-posting UUIDs). Whole label, anchored.
LABEL_STANDARD = [
    (re.compile(r"^(phone|phone number|mobile( phone)?( number)?)$", re.I), "identity.phone"),
]
YESNO = ("yes", "no")


@dataclass
class Decision:
    id: str
    kind: str                      # text | textarea | select | file | check | email | tel ...
    label: str
    required: bool
    value: str | None = None       # the answer, or the file path for a file
    spellings: list = field(default_factory=list)   # select: every acceptable wording, in order
    source: str = ""               # where the answer came from
    problem: str = ""              # why there is no answer (empty when there is one)

    @property
    def answered(self) -> bool:
        return self.value not in (None, "") and not self.problem


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip().lower().rstrip("*").strip()


def _lookup(cfg: dict, dotted: str):
    sec, _, key = dotted.partition(".")
    v = (cfg.get(sec) or {}).get(key)
    return None if v in (None, "") else str(v)


def load_package_answers(pkg: Path) -> dict:
    """`form-answers.json`: {"<field id or exact question label>": "<answer>"}. Optional."""
    p = Path(pkg) / "form-answers.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text())
    out = {}
    for k, v in data.items():
        if not str(k).startswith("_"):
            out[str(k)] = out[_norm(str(k))] = str(v)       # a field id, or a question label
    return out


def _rules(cfg: dict) -> list:
    out = []
    for r in cfg.get("form_rule") or []:
        try:
            out.append((re.compile(r["match"], re.I), r))
        except (KeyError, re.error) as e:
            raise ValueError(f"bad [[form_rule]] {r!r}: {e}") from e
    return out


TEXTLIKE = ("text", "textarea", "email", "tel", "url", "number")


def _kind_ok(rule_kind: str | None, field_kind: str) -> bool:
    if rule_kind in (None, "", "any"):
        return True
    if rule_kind == "text":
        return field_kind in TEXTLIKE
    if rule_kind == "select":
        # An Ashby yes/no is a two-option choice: a select rule answering Yes or No applies. The
        # answer itself is checked to be exactly yes or no in decide().
        # An Ashby radio group is a one-of-several choice, so a select rule applies to it too.
        return field_kind in ("select", "native_select", "yesno", "radiogroup")
    return rule_kind == field_kind


def spellings_for(answer: str, cfg: dict, extra=()) -> list:
    seen, out = set(), []
    for s in [answer, *extra, *((cfg.get("form_spellings") or {}).get(answer) or [])]:
        if s and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


def decide(f: dict, api: dict | None, cfg: dict, pkg: Path, pkg_answers: dict,
           alias: str, rules=None) -> Decision:
    """One field. `f` is a harvested field {id, kind, label, required}; `api` is the API's
    description of the same field name, when it has one."""
    rules = _rules(cfg) if rules is None else rules
    label = (api or {}).get("label") or f.get("label") or ""
    required = bool(f.get("required") or (api or {}).get("required"))
    kind = f.get("kind") or "text"
    d = Decision(id=f["id"], kind=kind, label=label, required=required)

    if kind == "file":
        name = FILE_FIELDS.get(f["id"])
        path = Path(pkg) / name if name else None
        if path and path.exists():
            d.value, d.source = str(path), "package"
        else:
            d.problem = (f"no {name} in the package" if name
                         else "a file field this runner does not know")
        return d
    if kind in ("checkbox", "radio"):
        d.problem = "checkbox and radio questions are not filled by this runner yet"
        return d
    if kind == "checkgroup":
        # 🚨 ONLY AN EXPLICIT ANSWER. A group ("how did you hear", "which apply") is answered from
        # this application's own form-answers.json, never from a rule: picking options from a
        # question's wording is a guess. Options separated by " | ", each one the page offers.
        raw = next((pkg_answers[k] for k in (f["id"], _norm(label)) if k in pkg_answers), None)
        if raw in (None, ""):
            if required:
                d.problem = "a required checkbox group with no answer in form-answers.json"
            return d
        offered = {o.strip().lower(): o for o in f.get("options") or []}
        picks = [p.strip() for p in str(raw).split("|") if p.strip()]
        bad = [p for p in picks if p.lower() not in offered]
        if bad or not picks:
            d.problem = f"answer {bad or raw!r} is not among the options {list(offered.values())[:12]}"
            return d
        d.spellings = [offered[p.lower()] for p in picks]
        d.value, d.source = " | ".join(d.spellings), "package form-answers.json"
        return d

    # 1. this application's own answers
    for key in (f["id"], _norm(label)):
        if key in pkg_answers:
            d.value, d.source = pkg_answers[key], "package form-answers.json"
            break
    # 2. standard fields
    if d.value is None:
        if f["id"] in EMAIL_IDS:
            d.value, d.source = alias or None, "the application's alias"
            if not alias:
                d.problem = "no alias on the application"
        elif f["id"] in STANDARD:
            d.value = _lookup(cfg, STANDARD[f["id"]])
            d.source = f"candidate config {STANDARD[f['id']]}"
        else:
            for rx, dotted in LABEL_STANDARD:
                if label and rx.match(label.strip()):
                    d.value, d.source = _lookup(cfg, dotted), f"candidate config {dotted}"
                    break
    # 3. rules over the question text
    extra: list = []
    if d.value is None and label:
        hits = []
        for rx, r in rules:
            if rx.search(label) and _kind_ok(r.get("kind"), kind):
                v = r.get("answer") if r.get("answer") is not None else (
                    _lookup(cfg, r["from"]) if r.get("from") else None)
                hits.append((v, r))
        answers = {str(v) for v, _ in hits if v is not None}
        if len(answers) > 1:
            d.problem = f"rules disagree on this question: {sorted(answers)}"
            return d
        if answers:
            v, r = next((v, r) for v, r in hits if v is not None)
            d.value, d.source = str(v), f"form_rule /{r['match']}/"
            extra = list(r.get("spellings") or [])

    if d.value in (None, ""):
        d.value = None
        if required:
            d.problem = d.problem or ("a required question with no recorded answer"
                                      if kind != "textarea" else
                                      "a required written answer that the package does not contain")
        return d

    if kind == "yesno":
        v = str(d.value).strip().lower()
        if v not in YESNO:
            d.problem = f"a yes/no question answered {d.value!r}; it must be exactly Yes or No"
        else:
            d.value = v
        return d
    if kind in ("select", "native_select", "radiogroup"):
        d.spellings = spellings_for(d.value, cfg, extra)
        # A radio group carries its options from the page itself; a select gets them from the API.
        options = (api or {}).get("options") or f.get("options") or []
        if options and not any(_option_match(s, options) for s in d.spellings):
            d.problem = (f"the answer {d.value!r} matches none of the options "
                         f"{options[:12]}; add a spelling or a package answer")
    return d


def _option_match(want: str, options: list) -> str | None:
    """The one option this wording names, or None. Same tiers as form.js, in the same order:
    exact, then starts-with, then a whole-word match. A tier with two hits is ambiguous and
    counts as no match. ⚠️ Whole words only: a plain substring test lets "No" match
    "I am not a veteran"."""
    w = want.strip().lower()
    word = re.compile(r"(?<!\w)" + re.escape(w) + r"(?!\w)")
    for tier in ([o for o in options if o.strip().lower() == w],
                 [o for o in options if o.strip().lower().startswith(w) and word.match(o.strip().lower())],
                 [o for o in options if word.search(o.lower())]):
        if len(tier) == 1:
            return tier[0]
        if len(tier) > 1:
            return None
    return None


def plan(fields: list, api_q: dict, cfg: dict, pkg: Path, alias: str) -> tuple[list, list]:
    """Decisions for every visible field, and the problems that must stop the run.

    A problem stops the run only when the field is required; an optional field with no answer
    is left blank and recorded as such."""
    pkg_answers = load_package_answers(pkg)
    rules = _rules(cfg)
    decisions, stops = [], []
    for f in fields:
        if not f.get("visible", True) and f.get("kind") != "file":
            continue
        d = decide(f, api_q.get(f.get("name") or f["id"]) or api_q.get(f["id"]), cfg, pkg,
                   pkg_answers, alias, rules)
        decisions.append(d)
        if d.problem and d.required:
            stops.append(f"{d.label or d.id}: {d.problem}")
    return decisions, stops


def fill_command(decisions: list) -> dict:
    """The `fill` command for form.js, from the answered decisions."""
    cmd = {"cmd": "fill", "files": [], "selects": [], "yesnos": [], "groups": [], "radios": [],
           "checks": [], "texts": []}
    for d in decisions:
        if not d.answered:
            continue
        if d.kind == "file":
            cmd["files"].append({"id": d.id, "path": d.value})
        elif d.kind == "yesno":
            cmd["yesnos"].append({"id": d.id, "value": d.value})
        elif d.kind == "checkgroup":
            cmd["groups"].append({"id": d.id, "values": d.spellings})
        elif d.kind == "radiogroup":
            cmd["radios"].append({"id": d.id, "values": d.spellings or [d.value]})
        elif d.kind in ("select", "native_select"):
            cmd["selects"].append({"id": d.id, "values": d.spellings or [d.value]})
        else:
            cmd["texts"].append({"id": d.id, "value": d.value})
    return cmd
