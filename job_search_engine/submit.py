"""The browser submitter's runner, SHADOW MODE: fill one application form, prove what it holds,
and stop before submit. Runs on the submitter's own host user, never in the container.

    python -m job_search_engine.submit once [--app N]

One run, start to finish (each step is recorded through the relay, with its screenshot):
   1 claim      the next eligible draft from /submit/next (or the one named by --app)
   2 liveness   the Greenhouse job still exists on a board that still answers
   3 gates      remote, no excluded time zones, a pay range stated, no office obligation
   4 package    the archived posting, the résumé, the letter when the form takes one, and the
                application's alias inside each PDF
   5 open       the form, headed on the submitter's virtual screen
   6 answers    every field decided from the package and the candidate config, or the run stops
   7 fill       files, then choices, then free text
   8 readback   every field read back off the page and compared with the decision
   9 review     a full-page screenshot of the filled form. THE RUN ENDS HERE.
  10 record     fields.json for the submission record, the run closed, one phone alert

🚨 THIS BUILD CANNOT SUBMIT. form.js has no submit command and blocks submission on the page;
the relay accepts only mode "shadow" and no submit route changes an application's status. A live
mode is a separate, later change.

Environment (from the submitter host's env file, never from the repository):
  SUBMIT_RELAY_URL      the relay, e.g. https://relay.example.com
  SUBMIT_TOKEN          the submit-scope token
  SUBMIT_REPO_DIR       the checkout holding the application packages and candidate config
  SUBMIT_EVIDENCE_DIR   where screenshots go (default ~/evidence)
  SUBMIT_NODE           node binary (default: node)
  SUBMIT_HEADED         1 to draw on $DISPLAY (default 1 when DISPLAY is set)
  SUBMIT_DISABLED       1 stops every run before it starts (the kill switch)
  SUBMIT_KILL_FILE      a file whose existence is the same kill switch
  NTFY_URL, NTFY_TOKEN  the phone alert (optional)
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import answers as A                                             # noqa: E402
import greenhouse as GH                                         # noqa: E402

FORM_JS = HERE / "browser" / "form.js"


class Stop(Exception):
    """The run must stop at this step for a person. Not an error: the reason is the output."""


# ── the relay ─────────────────────────────────────────────────────────────────────────────
class Relay:
    def __init__(self, url: str, token: str, opener=None):
        if not (url and token):
            raise SystemExit("SUBMIT_RELAY_URL and SUBMIT_TOKEN must be set")
        self.url, self.token = url.rstrip("/"), token
        self.op = opener or urllib.request.urlopen

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(
            self.url + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
                     "User-Agent": "job-search-engine submitter"})
        try:
            with self.op(req, timeout=30) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"relay {method} {path}: {e.code} {e.read()[:300]!r}") from e

    def next(self, app_id: int | None = None) -> dict | None:
        q = f"?app_id={int(app_id)}" if app_id is not None else ""
        return self._call("GET", "/submit/next" + q).get("next")

    def open(self, **kw) -> int:
        return self._call("POST", "/submit/run", kw)["run_id"]

    def step(self, run_id: int, **kw) -> None:
        self._call("POST", f"/submit/run/{run_id}/step", kw)

    def close(self, run_id: int, **kw) -> None:
        self._call("POST", f"/submit/run/{run_id}/close", kw)


# ── the browser ───────────────────────────────────────────────────────────────────────────
class Browser:
    """form.js as a child process: one JSON line out, one JSON line back."""

    def __init__(self, node: str = "node", env: dict | None = None):
        self.p = subprocess.Popen([node, str(FORM_JS)], cwd=str(FORM_JS.parent), text=True,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)

    def __call__(self, cmd: str, **kw) -> dict:
        self.p.stdin.write(json.dumps({"cmd": cmd, **kw}) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError(f"form.js exited during {cmd!r}")
        r = json.loads(line)
        if not r.get("ok"):
            raise RuntimeError(f"form.js {cmd}: {r.get('error')}")
        return r

    def quit(self):
        try:
            self("close")
            self.p.stdin.close()
            self.p.wait(timeout=20)
        except Exception:                                           # noqa: BLE001
            self.p.kill()


# ── checks with no browser ────────────────────────────────────────────────────────────────
# A location that names the whole eligible country and nothing smaller.
COUNTRY_WIDE = re.compile(r"^(united states( of america)?|u\.?s\.?a?\.?)$", re.I)


def check_gates(job_doc: dict, cfg: dict) -> None:
    import comp as COMP
    import gates as G
    desc = GH.description(job_doc)
    loc = ((job_doc.get("location") or {}).get("name") or "").strip()
    keep, why = G.gate({"location": loc, "title": job_doc.get("title") or "", "description": desc}, cfg)
    # ⚠️ THE RUNNER MUST NOT BE STRICTER THAN THE DECISION IT CARRIES OUT. gate() is the cheap
    # first filter: it keeps on evidence and leaves the rest to the remote reader, which an
    # approved posting has already passed. A posting located only "United States" reads as
    # "out on geography" there, while it names no city at all. Found 2026-10-08 on an
    # approved role whose body said "our remote implementation model". A country-wide
    # location passes here; the office-obligation check below still runs on its text.
    if not keep and why == "out on geography" and COUNTRY_WIDE.match(loc):
        keep = True
    if not keep:
        raise Stop(f"the remote gate fails: {why} (location {loc!r})")
    ob = G.office_obligation(desc)
    if ob:
        raise Stop(f"the posting states an office obligation: {ob!r}")
    tz = G._tz_re(cfg)
    m = tz.search(desc) if tz else None
    if m:
        raise Stop(f"the posting names an excluded time zone: {m.group(0)!r}")
    if not COMP.extract(None, desc):
        raise Stop("the posting states no pay range")


def pdf_text(path: Path) -> str:
    """The text of a PDF (poppler's pdftotext). A module function so a test can replace it."""
    try:
        return subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True,
                              timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"pdftotext failed on {path.name}: {e}") from e


def check_package(pkg: Path, alias: str, needs_letter: bool) -> list:
    """The package files this run will attach. Raises Stop on anything missing."""
    jd = pkg / "job-description.md"
    if not jd.exists() or "verbatim" not in jd.read_text(errors="replace").lower():
        raise Stop("job-description.md is missing or has no verbatim posting text")
    # A letter that exists is always checked, because the fill attaches it wherever the form
    # offers a slot; a letter the form requires must exist.
    letter = pkg / "cover-letter.pdf"
    files = [pkg / "resume.pdf"] + ([letter] if needs_letter or letter.exists() else [])
    for f in files:
        if not f.exists() or f.stat().st_size == 0:
            raise Stop(f"{f.name} is missing or empty")
        text = pdf_text(f)
        if alias.lower() not in re.sub(r"\s+", "", text).lower():
            raise Stop(f"{f.name} does not carry the application's alias {alias}")
    return files


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def compare(decisions: list, fill_results: list, page: list) -> list:
    """What the page holds against what was decided. Returns the mismatches as sentences."""
    got = {f["id"]: f for f in page}
    chosen = {r["id"]: r for r in fill_results}
    bad = []
    for d in decisions:
        if not d.answered:
            continue
        r, f = chosen.get(d.id, {}), got.get(d.id)
        if r.get("status") not in ("set",):
            extra = f" (options: {r.get('options')})" if r.get("options") else ""
            bad.append(f"{d.label or d.id}: fill reported {r.get('status', 'nothing')}{extra}")
            continue
        if f is None:
            bad.append(f"{d.label or d.id}: the field is gone from the page after the fill")
        elif d.kind == "file":
            name = Path(d.value).name
            if not any(x["name"] == name and x["size"] > 0 for x in f.get("files") or []):
                bad.append(f"{d.label or d.id}: the page does not hold {name}")
        elif d.kind in ("select", "native_select"):
            if (f.get("value") or "") != r.get("chosen"):
                bad.append(f"{d.label or d.id}: reads {f.get('value')!r}, chose {r.get('chosen')!r}")
        elif d.kind == "tel":
            if not _digits(f.get("value")).endswith(_digits(d.value)[-10:]):
                bad.append(f"{d.label or d.id}: reads {f.get('value')!r}, wanted {d.value!r}")
        elif " ".join((f.get("value") or "").split()) != " ".join(d.value.split()):
            bad.append(f"{d.label or d.id}: reads {(f.get('value') or '')[:80]!r}, "
                       f"wanted {d.value[:80]!r}")
    return bad


def required_empty(page: list, fields: list) -> list:
    req = {f["id"]: f for f in fields if f.get("required")}
    out = []
    for f in page:
        if f["id"] not in req:
            continue
        empty = (not f.get("files")) if f.get("kind") == "file" else (
            not f.get("checked") if f.get("kind") in ("checkbox", "radio") else not (f.get("value") or "").strip())
        if empty:
            out.append(req[f["id"]].get("label") or f["id"])
    return out


# ── one run ───────────────────────────────────────────────────────────────────────────────
class Run:
    def __init__(self, relay, browser_factory, cfg: dict, repo: Path, evidence: Path,
                 headed: bool, opener=None, version: str = "", notify=None):
        self.relay, self.browser_factory, self.cfg = relay, browser_factory, cfg
        self.repo, self.evidence, self.headed = repo, evidence, headed
        self.opener, self.version, self.notify = opener, version, notify
        self.n = 0

    def _step(self, name: str, outcome: str, detail: str = "", shot: Path | None = None):
        self.n += 1
        sha = hashlib.sha256(shot.read_bytes()).hexdigest() if shot and shot.exists() else None
        self.relay.step(self.run_id, n=self.n, name=name, outcome=outcome, detail=detail[:4000],
                        screenshot_path=str(shot) if sha else None, sha256=sha)

    def _shot(self, br, name: str) -> Path:
        p = self.dir / f"{self.n + 1:02d}-{name}.png"
        br("shot", path=str(p))
        return p

    def go(self, item: dict) -> dict:
        app_id = item["application_id"]
        alias = item["alias_used"]
        pkg = self.repo / item["package_path"]
        self.run_id = self.relay.open(application_id=app_id, ats="greenhouse", mode="shadow",
                                      engine_version=self.version, host=socket.gethostname(),
                                      evidence_dir="")
        self.dir = self.evidence / str(app_id) / str(self.run_id)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._step("claim", "ok", f"application {app_id} {item['url']} evidence {self.dir}")
        br, step = None, "liveness"
        try:
            token, jid = GH.resolve(item["url"], self.opener)
            try:
                job_doc = GH.job(token, jid, self.opener)
            except GH.NotFound:
                if GH.board_exists(token, self.opener):
                    raise Stop(f"the job is gone from board {token!r} (the board answers)")
                raise RuntimeError(f"board {token!r} does not answer; cannot judge liveness")
            self._step(step, "ok", f"{token}/{jid}: {job_doc.get('title')}")

            step = "gates"
            check_gates(job_doc, self.cfg)
            self._step(step, "ok")

            step = "package"
            api_q = GH.questions(job_doc)
            # The letter is checked when the form takes one: required, or offered and written.
            letter_slot = "cover_letter" in api_q
            needs_letter = letter_slot and api_q["cover_letter"]["required"]
            files = check_package(pkg, alias, needs_letter=needs_letter)
            self._step(step, "ok", ", ".join(f.name for f in files))

            step = "open"
            br = self.browser_factory()
            o = br("open", url=GH.hosted_url(token, jid), headed=self.headed, settle=4500)
            h = br("harvest")
            if h.get("captcha"):
                raise Stop("a CAPTCHA is on the page before any input; a person must solve it")
            shot = self._shot(br, "loaded")
            self._step(step, "ok", f"{o['url']} · {len(h['fields'])} fields", shot)

            step = "answers"
            decisions, stops = A.plan(h["fields"], api_q, self.cfg, pkg, alias)
            unanswered = [d.label or d.id for d in decisions if not d.answered and not d.required]
            if stops:
                raise Stop("; ".join(stops))
            self._step(step, "ok", f"{sum(d.answered for d in decisions)} answered; "
                       f"optional left blank: {unanswered}")

            step = "fill"
            fr = br(**A.fill_command(decisions))
            shot = self._shot(br, "filled")
            self._step(step, "ok", json.dumps(fr["results"])[:3900], shot)

            step = "readback"
            rb = br("readback")
            if any(rb["blocked_submits"].values()):
                raise RuntimeError(f"a submit was attempted and blocked: {rb['blocked_submits']}")
            bad = compare(decisions, fr["results"], rb["fields"]) + [
                f"{x}: required and still empty" for x in required_empty(rb["fields"], h["fields"])]
            if bad:
                raise Stop("; ".join(bad))
            self._step(step, "ok", f"{len(rb['fields'])} fields read back, all as decided")

            step = "review"
            shot = self._shot(br, "review")
            self._step(step, "ok", "the filled form, as it would be submitted. NOT submitted.", shot)

            step = "record"
            by_id = {f["id"]: f for f in rb["fields"]}
            record = [{"label": d.label or d.id,
                       "value": Path(d.value).name if d.kind == "file" else (
                           by_id.get(d.id, {}).get("value") or ""),
                       "verified_len": len(by_id.get(d.id, {}).get("value") or "")
                       if d.kind != "file" else None,
                       "source": d.source}
                      for d in decisions if d.answered]
            (self.dir / "fields.json").write_text(json.dumps(record, indent=1))
            self._step(step, "ok", f"fields.json with {len(record)} fields")
            self.relay.close(self.run_id, outcome="shadow_complete")
            return self._done(app_id, "shadow_complete", "")
        except Stop as e:
            self._safe_step(step, "stop", str(e), br)
            self.relay.close(self.run_id, outcome="stopped", stop_step=step, stop_reason=str(e))
            return self._done(app_id, "stopped", f"{step}: {e}")
        except Exception as e:                                        # noqa: BLE001
            self._safe_step(step, "error", repr(e), br)
            self.relay.close(self.run_id, outcome="error", stop_step=step, stop_reason=repr(e)[:2000])
            return self._done(app_id, "error", f"{step}: {e!r}")
        finally:
            if br is not None:
                br.quit()

    def _safe_step(self, name, outcome, detail, br):
        shot = None
        try:
            if br is not None:
                shot = self._shot(br, f"{name}-{outcome}")
        except Exception:                                             # noqa: BLE001
            shot = None
        try:
            self._step(name, outcome, detail, shot)
        except Exception as e:                                        # noqa: BLE001
            print(f"could not record the {name} step: {e}", file=sys.stderr)

    def _done(self, app_id, outcome, why) -> dict:
        if self.notify:
            self.notify({"title": f"Submitter (shadow): APP {app_id} {outcome}"[:200],
                         "message": (why or "filled to review, not submitted")[:400],
                         "priority": 3 if outcome == "shadow_complete" else 4,
                         "tags": ["robot"]})
        return {"application_id": app_id, "run_id": self.run_id, "outcome": outcome, "why": why}


# ── the command line ──────────────────────────────────────────────────────────────────────
def killed() -> str | None:
    if os.environ.get("SUBMIT_DISABLED", "").strip() not in ("", "0"):
        return "SUBMIT_DISABLED is set"
    kf = os.environ.get("SUBMIT_KILL_FILE", "/etc/jobsubmit/disabled")
    return f"{kf} exists" if kf and os.path.exists(kf) else None


def cmd_once(a) -> int:
    why = killed()
    if why:
        print(f"kill switch: {why}; no run")
        return 0
    repo = Path(os.environ.get("SUBMIT_REPO_DIR", "")).expanduser()
    if not (repo / "config" / "candidate.toml").exists():
        raise SystemExit("SUBMIT_REPO_DIR must be the checkout holding config/candidate.toml")
    os.environ.setdefault("CANDIDATE_CONFIG", str(repo / "config" / "candidate.toml"))
    import candidate as C
    cfg = C.load()
    evidence = Path(os.environ.get("SUBMIT_EVIDENCE_DIR", "~/evidence")).expanduser()
    evidence.mkdir(parents=True, exist_ok=True)
    lock = open(evidence / ".lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)            # one run at a time
    except BlockingIOError:
        print("another run holds the lock; no run")
        return 0
    relay = Relay(os.environ.get("SUBMIT_RELAY_URL", ""), os.environ.get("SUBMIT_TOKEN", ""))
    item = relay.next(a.app)
    if not item:
        print("nothing eligible")
        return 0
    headed = os.environ.get("SUBMIT_HEADED", "1" if os.environ.get("DISPLAY") else "0") == "1"
    node = os.environ.get("SUBMIT_NODE", "node")
    notify = None
    if os.environ.get("NTFY_URL"):
        import notify as N
        notify = lambda payload: N.send(os.environ["NTFY_URL"], os.environ.get("NTFY_TOKEN", ""), payload)  # noqa: E731
    m = re.search(r'__version__\s*=\s*"([^"]+)"', (HERE / "__init__.py").read_text())
    version = m.group(1) if m else ""
    r = Run(relay, lambda: Browser(node), cfg, repo, evidence, headed,
            version=version, notify=notify).go(item)
    print(json.dumps(r))
    return 0 if r["outcome"] == "shadow_complete" else 3


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m job_search_engine.submit",
                                 description="The browser submitter, shadow mode.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("once", help="take one eligible draft and run it to the review screenshot")
    o.add_argument("--app", type=int, help="this application only (it must still be eligible)")
    o.set_defaults(fn=cmd_once)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
