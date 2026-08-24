#!/usr/bin/env python3
"""
Regression test for the ImprovMX webhook parser.

Why this exists: the parser was written against an assumed payload shape and broke on
the first real message with `'list' object has no attribute 'split'`. Three assumptions
were wrong at once, and none of them were visible without a genuine delivery:

    to      is a LIST of {name, email}, not an RFC822 string
    from    is a DICT of {name, email}, not an RFC822 string
    headers values are LISTS, because a header may legitimately repeat

The fixture keeps the SHAPE of a real ImprovMX delivery captured from the raw_payload
column. Storing the raw bytes before parsing is what made this debuggable at all
(SPEC P4), and this test is the cheap way to stop the same class of bug coming back.

Every address, domain, signature, hash and opaque vendor token in the fixture is
synthetic. Only the structure is real, because only the structure is what broke. A real
capture carries the operator's own address and a valid DKIM signature over real message
content, and neither belongs in a repository that is intended to go public.

Run:  python3 tests/test_parse.py
"""
import importlib.util, inspect, json, os, pathlib, sys, types


def _src_of(fn):
    """Source of a function, so a test can assert on a literal inside it."""
    return inspect.getsource(fn)

HERE = pathlib.Path(__file__).resolve().parent

# 🚨 THE TEST SUITE MUST NEVER REACH THE LIVE DATABASE.
#
# app.db() picks Bunny whenever BUNNY_DATABASE_URL is set, and that value is read into a
# module constant at import time. Several blocks below point DB_PATH at a temp file and
# then write real rows, which is correct against sqlite and catastrophic against Bunny.
#
# ⚠️ This is not hypothetical. On 2026-08-14 the suite was run in a shell that had sourced
# ~/.config/job-search/relay.env, and it wrote two rows into the production database (a
# message with to_alias 'x@y.z' and an ai_reading with model 'test') before aborting on an
# unrelated NOT NULL constraint. They were found by auditing timestamps and deleted by
# hand. Nothing warned; the suite simply started talking to production.
#
# Stripped BEFORE app is imported, then asserted after, because clearing the variable and
# failing to notice that the constant was already bound would look exactly like success.
for _v in ("BUNNY_DATABASE_URL", "BUNNY_DATABASE_AUTH_TOKEN"):
    os.environ.pop(_v, None)


def load_app():
    """Import app.py without needing fastapi installed.

    ⚠️ app.py imports candidate.py and gates.py as ordinary modules. Loading app by an
    explicit spec does NOT put its directory on sys.path, so without this those imports
    fail silently inside try/except and every config-driven rule degrades to "not
    configured" — which looks exactly like a passing decline instead of a broken test.
    """
    _relay = str(pathlib.Path(__file__).resolve().parent.parent / "job_search_engine")
    if _relay not in sys.path:
        sys.path.insert(0, _relay)
    fa = types.ModuleType("fastapi")

    class FastAPI:
        def __init__(self, **k): pass
        def _d(self, *a, **k):
            def w(f): return f
            return w
        get = post = on_event = _d

    class HTTPException(Exception):
        def __init__(self, c, d=""): self.code, self.detail = c, d; super().__init__(f"{c}: {d}")

    def Header(default=None, **k): return default

    class Request: pass

    fa.FastAPI, fa.HTTPException, fa.Header, fa.Request = FastAPI, HTTPException, Header, Request
    resp = types.ModuleType("fastapi.responses")

    class JSONResponse:
        def __init__(self, c, status_code=200): self.content, self.status_code = c, status_code

    resp.JSONResponse = JSONResponse
    fa.responses = resp
    sys.modules["fastapi"], sys.modules["fastapi.responses"] = fa, resp
    # 📌 The engine is a package now, so app.py sits one level in. The suite still loads
    # it by path rather than importing it, because it must run from a clean clone with
    # nothing installed.
    spec = importlib.util.spec_from_file_location(
        "relayapp", HERE.parent / "job_search_engine" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse(app, p):
    """Mirror of what the /inbound route does, so the test covers the real path."""
    hdrs = p.get("headers") or {}
    envelope = p.get("envelope") if isinstance(p.get("envelope"), dict) else {}
    to_alias = envelope.get("recipient") or app._addr(p.get("to"))[1] or ""
    name, addr = app._addr(p.get("from"))
    subject = p.get("subject") or ""
    body = p.get("text") or ""
    label, otp = app.classify(subject, body)
    spf, dkim, dmarc, warn = app.read_auth_results(hdrs, p.get("verdict"))
    return {
        "to_alias": to_alias, "from_name": name, "from_addr": addr, "subject": subject,
        "message_id": app._hdr(hdrs, "Message-ID") or p.get("message-id"),
        "classification": label, "otp": otp, "application_ref": app.resolve_application(to_alias),
        "spf": spf, "dkim": dkim, "dmarc": dmarc, "auth_warn": warn,
    }


def main() -> int:
    app = load_app()
    # The guard above stripped the variables; this proves the constant bound accordingly.
    # A hard exit, not a check(), because a suite that would write to production must not
    # continue running the tests that do the writing.
    if getattr(app, "BUNNY_DB_URL", ""):
        sys.exit("🚨 REFUSING TO RUN: app is bound to a remote database "
                 f"({str(app.BUNNY_DB_URL)[:40]}...). These tests write real rows. "
                 "Run them in a shell that has not sourced relay.env.")
    fixture = json.loads((HERE / "fixtures" / "improvmx-webhook.json").read_text())
    failures = []
    skipped = []
    # --strict turns a skip into a failure.
    #
    # ⚠️ THIS USED TO BE ASPIRATIONAL. The comment here claimed CI used --strict; CI ran
    # the suite bare, so both optional blocks skipped on every run and exited 0. The comp
    # drift guard, whose whole purpose is to catch two implementations diverging, had
    # therefore never run anywhere except the operator's laptop, and only because the
    # archiver happened to be installed there.
    #
    # ci.yml now runs the suite TWICE: a `bare` job, which is what a stranger with nothing
    # installed sees and must stay green, and a `drift` job that installs both optional
    # dependencies and passes --strict, so a skip there is a real failure. A developer
    # machine still runs without it, so a missing optional dependency reports loudly
    # instead of blocking a commit.
    strict = "--strict" in sys.argv

    def check(label, got, want):
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} {label:<26} {got!r}")
        if not ok:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    print("ImprovMX payload shape:")
    r = parse(app, fixture)
    check("to_alias", r["to_alias"], "test@jobs.example.com")
    check("from_addr", r["from_addr"], "dana.reed@example.net")
    check("from_name", r["from_name"], "Dana Reed")
    check("application_ref", r["application_ref"], "test")
    check("dmarc", r["dmarc"], "pass")
    check("auth_warn", r["auth_warn"], 0)
    check("message_id parsed", bool(r["message_id"] and r["message_id"].startswith("<")), True)

    # The three shapes that actually broke it, asserted directly.
    print("\naddress shape handling:")
    check("list of dicts", app._addr([{"name": "A", "email": "a@b.c"}])[1], "a@b.c")
    check("bare dict", app._addr({"name": "A", "email": "a@b.c"})[1], "a@b.c")
    check("rfc822 string", app._addr("A <a@b.c>")[1], "a@b.c")
    check("empty list", app._addr([])[1], "")
    check("none", app._addr(None)[1], "")
    check("header list value", app._hdr({"Message-ID": ["<x@y>"]}, "Message-ID"), "<x@y>")
    check("header string value", app._hdr({"Message-ID": "<x@y>"}, "Message-ID"), "<x@y>")
    check("header case-insensitive", app._hdr({"message-id": ["<x@y>"]}, "Message-ID"), "<x@y>")

    # A spoofed sender must reach a human whatever the classifier decides.
    print("\nauthentication verdicts:")
    check("verdict object preferred",
          app.read_auth_results({}, {"spf": "pass", "dkim": "pass", "dmarc": "pass"}), ("pass", "pass", "pass", 0))
    check("dmarc fail is flagged",
          app.read_auth_results({}, {"spf": "fail", "dkim": "fail", "dmarc": "fail"})[3], 1)
    check("falls back to headers",
          app.read_auth_results({"Authentication-Results": ["mx; spf=pass dkim=pass dmarc=pass"]}, None)[2], "pass")
    check("absent is unknown, not pass", app.read_auth_results({}, None), (None, None, None, 0))

    # The bug this dependency exists to fix. Every reply carries the thread beneath it,
    # so classification on the raw body reads old words as new decisions.
    #
    # ⚠️ This block is the one part of the suite that cannot run without an optional
    # dependency. strip_quotes falls back to returning the body unchanged when
    # EmailReplyParser is absent (app.py:545), which is correct: a missing parser must
    # never drop message text. It also means every assertion below would fail, and the
    # failure would read as a classification bug rather than as an unconfigured machine.
    # That is exactly what happened between 2026-08-12 and 2026-08-13, and it is why the
    # dependency is now detected instead of assumed.
    print("\nquoted-history stripping (the misclassification bug):")
    if getattr(app, "EmailReplyParser", None) is None:
        print("  SKIP  email-reply-parser is not installed, so strip_quotes is a no-op")
        print("        by design and this block cannot test anything.")
        print("        Install it:  pip install email-reply-parser==0.5.12")
        print("        It is already pinned in requirements.txt, so the deployed")
        print("        container has it and production behaviour is unaffected.")
        skipped.append("quoted-history stripping (email-reply-parser not installed)")
        threads = []
    else:
        threads = [
        # The decisive case: the new text contains NO classifiable keywords at all, so
        # only the quoted history can produce a verdict. Without stripping this reads as
        # a rejection that the sender never wrote in this message.
        ("neutral reply over a quoted rejection",
         """Thanks for the update, I appreciate you letting me know.

On Tue, Aug 11, 2026 at 9:14 AM Dana Reed <dana@acme.com> wrote:
> Unfortunately we are not moving forward with your application.
""", "unknown"),
        ("fresh scheduling under a quoted rejection",
         """Thanks for following up. Does Tuesday at 2pm work for a call?

On Tue, Aug 11, 2026 at 9:14 AM Dana Reed <dana@acme.com> wrote:
> Unfortunately we are not moving forward with the Senior role.
> We decided not to proceed with other candidates either.
""", "scheduling"),
        ("three-deep thread, newest is an invite",
         """Great, I would like to set up an interview for next week.

On Wed, Aug 12, 2026 the candidate wrote:
> Thanks for the update.
>
> On Tue, Aug 11, 2026 Dana wrote:
> > Unfortunately we are not moving forward.
""", "interview_invite"),
        ]

    for label, body, want in threads:
        stripped = app.strip_quotes(body)
        got, _ = app.classify("", stripped)
        raw_got, _ = app.classify("", body)
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        print(f"       on stripped text -> {got}   (raw body would give -> {raw_got})")
        if not ok:
            failures.append(f"{label}: got {got}, want {want}")
        if raw_got == got and want != raw_got:
            failures.append(f"{label}: stripping made no difference")

    # Every wording here came off a real rejection. The first one classified as unknown
    # on 2026-08-13 and is the reason this block exists: the rule list held "not moving
    # forward" and "other candidates", and Zafran wrote neither. A rejection that reads
    # as unknown does not close its application row, so the pipeline reports a live
    # candidacy that ended weeks earlier.
    #
    # ⚠️ Add a case here whenever an employer phrases a rejection a new way. Do not add
    # invented phrasings: an untested guess about how employers write is how the list got
    # confident and wrong the first time.
    print("\nrejection wordings seen in real mail:")
    rejections = [
        ("Zafran Security, 2026-08-13",
         "Thank you for applying for the Technical Support Engineer (US) role at Zafran "
         "Security. At this time, we have decided to move forward with other applicants "
         "in our process."),
        ("classic 'not moving forward'",
         "Unfortunately we are not moving forward with your application."),
        ("'other candidates'",
         "We have chosen to proceed with other candidates for this role."),
        ("'no longer under consideration'",
         "Your application is no longer under consideration."),
    ]
    for label, body in rejections:
        got, _ = app.classify("", body)
        check(label, got, "rejection")

    # The second reader. These check the contract around the model call, not the model:
    # a schema the API will reject, or a label set the two readers do not share, fails
    # here rather than in production at the cost of one API call per broken message.
    print("\nsecond reading (structure only, no network):")
    props = set(app.AI_SCHEMA["properties"])
    check("every property is required", set(app.AI_SCHEMA["required"]), props)
    check("additionalProperties is false", app.AI_SCHEMA.get("additionalProperties"), False)
    # A model label the rules cannot produce would make the two verdicts incomparable,
    # which is the whole reason for writing them side by side.
    rule_labels = {name for name, _ in app.RULES} | {"unknown"}
    check("model labels cover every rule label", rule_labels - set(app.AI_LABELS), set())
    check("model may also answer noise", "noise" in app.AI_LABELS, True)
    check("unknown is an allowed answer", "unknown" in app.AI_LABELS, True)
    # Nullable fields must use anyOf. A two-element type list is valid JSON Schema and is
    # not accepted by the structured-output validator, so this is not a style preference.
    nullable = [k for k, v in app.AI_SCHEMA["properties"].items() if "anyOf" in v]
    check("nullable fields use anyOf", len(nullable) >= 5, True)
    check("anthropic dialect: no field uses a type list",
          [k for k, v in app.schema_for("anthropic")["properties"].items()
           if isinstance(v.get("type"), list)], [])
    # OpenAI strict mode rejects anyOf for nullables and wants a type list, which is the
    # exact inverse. Sending the wrong dialect returns a 400 that reads like the model
    # failing, so both directions are asserted.
    oa = app.schema_for("openai_compat")
    check("openai dialect: no field uses anyOf",
          [k for k, v in oa["properties"].items() if "anyOf" in v], [])
    check("openai dialect: nullables became type lists",
          sum(1 for v in oa["properties"].values() if isinstance(v.get("type"), list)) >= 5, True)
    check("openai dialect keeps required and additionalProperties",
          (set(oa["required"]) == set(oa["properties"]), oa["additionalProperties"]),
          (True, False))
    # Prompt caching is switched on by batch size because below two messages it costs
    # MORE: the write is billed at 1.25x and never read back. Measured 2026-08-13 at
    # +15% for one message, -19% at two, -46% at ten. If this ever inverts, the bill is
    # the only place it shows up, so the threshold is asserted rather than trusted.
    import inspect
    src = inspect.getsource(app.job_ai_read)
    check("caching is gated on batch size", "len(rows) >= 2" in src, True)
    # Caching is Anthropic-only: OpenAI-compatible endpoints cache automatically and
    # reject a cache_control block, so the gate must carry the provider check too.
    check("caching is Anthropic-only", 'AI_PROVIDER == "anthropic" and' in src, True)
    sig = inspect.signature(app.ai_read_message)
    check("cache_system defaults to off", sig.parameters["cache_system"].default, False)
    # A breakpoint on the system block only reaches the cacheable minimum together with
    # the schema. Asserting the prefix is big enough is the closest offline proxy for
    # "this will actually engage": the prompt alone is ~469 tokens against a 1024 floor.
    # 2026-08-13: 3,261 chars of prefix measured as 1,426 tokens, i.e. 2.29 chars/token,
    # because schema JSON packs far denser than prose. The 1024-token floor therefore
    # sits at roughly 2,341 chars. 2,600 leaves headroom without being so loose that
    # trimming the schema could drop under the floor unnoticed.
    prefix_chars = len(app.AI_SYSTEM) + len(json.dumps(app.AI_SCHEMA))
    check(f"cacheable prefix clears the 1024-token floor ({prefix_chars} chars)",
          prefix_chars > 2600, True)

    # Reading only the unlabelled means the rules' CONFIDENT errors are never checked,
    # and those are the dangerous ones: a probe on 2026-08-14 put three real-shaped
    # rejections into interview_invite, because interview_invite is matched before
    # rejection and a rejection usually mentions the interview that just happened.
    import inspect as _i
    src_job = _i.getsource(app.job_ai_read)
    check("scope is configurable", hasattr(app, "AI_READ_SCOPE"), True)
    check("default scope reads everything", app.AI_READ_SCOPE, "all")
    check("scope=all drops the unknown-only filter",
          'scope_sql = ("" if AI_READ_SCOPE == "all"' in src_job, True)
    # The guarantee changed shape on 2026-08-14: it is no longer "once per message" but
    # "once per version of the message's text". Asserting NOT EXISTS was asserting the
    # implementation; assert the fingerprint comparison that replaced it.
    check("reads each message once per version of its text",
          "reading_input_hash" in src_job and "last_hash" in src_job, True)
    check("disagreements are recorded", "ai_disagreement" in src_job, True)
    check("the rules verdict is stored beside the model's",
          "rules_classification" in src_job, True)
    # A disagreement that only exists in a table nobody queries is not a signal.
    check("disagreements surface in the job's own output",
          "DISAGREEMENT" in src_job, True)

    # ═══ the queue must not offer a role he has already applied to ═══
    #
    # 🚨 IT DID, AND THE DESCRIPTION SAID IT DID NOT. search_queue has always been documented
    # as "NOT yet applied to" and the SQL never joined `application` at all. Measured
    # 2026-08-24: 64 of 658 gated rows were live applications, including a Solutions Architect
    # role submitted that morning and confirmed by the employer four hours before it appeared
    # in the queue as an opportunity.
    #
    # ⚠️ A DESCRIPTION THAT CLAIMS A FILTER IT DOES NOT APPLY IS WORSE THAN NO FILTER. It
    # invites exactly the trust that produces a duplicate application at a company already in
    # flight, and the output gave no hint the list might be wrong.
    print("\nthe queue excludes what he has already applied to:")
    import os as _oQ, tempfile as _tQ, sqlite3 as _sQ
    _dQ = _tQ.mkdtemp() + "/queue.db"
    _pQ = _oQ.environ.get("DB_PATH"); _oQ.environ["DB_PATH"] = _dQ
    try:
        _appQ = load_app()
        _c = _sQ.connect(_dQ)
        _c.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        for _m in _appQ.MIGRATIONS:
            try: _c.execute(_m)
            except Exception: pass
        _c.executescript("""
          CREATE TABLE IF NOT EXISTS company(id INTEGER PRIMARY KEY, name TEXT);
          CREATE TABLE IF NOT EXISTS posting(id INTEGER PRIMARY KEY, company_id INT,
                 title TEXT, captured_at TEXT, canonical_url TEXT);
          CREATE TABLE IF NOT EXISTS application(id INTEGER PRIMARY KEY, posting_id INT,
                 status TEXT, company_raw TEXT, role_raw TEXT);""")
        # ⚠️ posting.company_id is NOT NULL in the real schema, so the fixture supplies one.
        # CREATE TABLE IF NOT EXISTS above is a no-op wherever schema.sql already defined it.
        _c.execute("INSERT INTO company (id,name) VALUES (1,'Acme')")
        _c.execute("INSERT INTO posting (id,company_id,title,captured_at,canonical_url) "
                   "VALUES (1,1,'x','2026-01-01','https://jobs.example.com/abc')")
        _c.execute("INSERT INTO application (id,posting_id,status,company_raw,role_raw) "
                   "VALUES (1,1,'submitted','**Acme** ⭐','Senior Solutions Architect')")

        def _cand(cid, title, url, company):
            # ⚠️ verdict must be non-NULL: the filter is `verdict NOT IN (...)`, and in SQL
            # NULL NOT IN (...) is NULL, which is falsy, so a NULL-verdict row is silently
            # excluded from the queue. Real triaged rows carry one.
            _c.execute("INSERT INTO scan_candidate (id,at,req_id,board,title,company,location,"
                       "score,triaged,verdict,remote_verdict,comp_min,comp_max,url) "
                       "VALUES (?,?,?,?,?,?,?,?,1,'pass','fully_remote',100000,200000,?)",
                       (cid, "2026-08-24T00:00:00+00:00", f"r{cid}", "gh|acme", title,
                        company, "Remote", "90", url))

        _cand(1, "Senior Solutions Architect", "https://jobs.example.com/abc?src=li", "Acme")
        _cand(2, "Sr. Solutions Architect", "https://elsewhere.example.com/xyz", "Acme")
        _cand(3, "Platform Support Engineer", "https://jobs.example.com/def", "Beta")
        _c.commit(); _c.close()

        _out = _appQ._mcp_call("search_queue", {"limit": 25})
        # ⭐ matched by URL, even though the query string differs: aggregators add their own
        check("a role already applied to is hidden, matched by URL",
              "https://jobs.example.com/abc" in _out, False)
        # ⭐ matched by company and title, even though the URL is a different host entirely
        # and the title says "Sr." where the application says "Senior"
        check("...and by company and title on a different host",
              "elsewhere.example.com" in _out, False)
        check("an unapplied role is still offered", "Platform Support Engineer" in _out, True)
        # 🚨 The exclusion is STATED. A silent filter is how the missing one went unnoticed.
        check("it reports how many it hid", "2 role(s) hidden" in _out, True)
    finally:
        if _pQ is None: _oQ.environ.pop("DB_PATH", None)
        else: _oQ.environ["DB_PATH"] = _pQ

    # ═══ a reading that already exists must be adopted, not stranded ═══
    #
    # 🚨 EIGHT MESSAGES WERE STRANDED ON 2026-08-24, including a time-boxed assessment
    # invitation. Adoption happened only inside job_ai_read's read loop, and that job never
    # re-reads a message it has already read, so any message whose READING predated the
    # adoption code kept the provisional rules label forever. job_track refuses to act on a
    # provisional label, by design, so those messages would have been held indefinitely.
    #
    # ⚠️ A one-off backfill was the first attempt and it went stale the moment the next
    # message arrived. The sweep runs every cycle and is idempotent.
    print("\nan existing reading is adopted, not stranded:")
    import os as _oA, tempfile as _tA, sqlite3 as _sA
    _dA = _tA.mkdtemp() + "/adopt.db"
    _pA = _oA.environ.get("DB_PATH"); _oA.environ["DB_PATH"] = _dA
    try:
        _appA = load_app()
        _c = _sA.connect(_dA)
        _c.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        for _m in _appA.MIGRATIONS:
            try: _c.execute(_m)
            except Exception: pass

        def _put(mid, rules, ai, conf, warn=0, inj=False):
            _c.execute("INSERT INTO message (id,received_at,to_alias,raw_payload,from_addr,"
                       "subject,body_text,body_reply,classification,classification_source,"
                       "auth_dmarc,auth_warn,needs_human) "
                       "VALUES (?,?,?,'{}','x@y.example','s','b','b',?,'rules',?,?,1)",
                       (mid, "2026-08-24T13:00:00+00:00", f"a{mid}@jobs.example.com",
                        rules, "fail" if warn else "pass", warn))
            if ai:
                _c.execute("INSERT INTO ai_reading (message_id,created_at,model,classification,"
                           "confidence,raw_json) VALUES (?,?,?,?,?,?)",
                           (mid, "2026-08-24T13:05:00+00:00", "m", ai, conf,
                            '{"prompt_injection_suspected": true}' if inj else "{}"))

        _put(1, "unknown",  "assessment_invite", "high")            # the real 2026-08-24 case
        _put(2, "rejection", "confirmation",     "high")            # a label that must flip
        _put(3, "unknown",  "rejection",         "low")             # too uncertain to adopt
        _put(4, "unknown",  "rejection",         "high", warn=1)    # DMARC failed
        _put(5, "unknown",  "rejection",         "high", inj=True)  # body tried to steer it
        _put(6, "confirmation", None, None)                          # never read at all
        _c.commit(); _c.close()

        _n, _notes = _appA.adopt_readings()
        _c2 = _sA.connect(_dA); _c2.row_factory = _sA.Row
        _g = lambda i: dict(_c2.execute(
            "SELECT classification, classification_source, rules_classification "
            "  FROM message WHERE id=?", (i,)).fetchone())

        check("a stranded high-confidence reading is adopted", _g(1)["classification_source"],
              "model")
        check("...and its label takes effect", _g(1)["classification"], "assessment_invite")
        # ⭐ The rules label is kept, so adoption is auditable and reversible rather than a
        # destructive overwrite.
        check("...while the rules label is preserved", _g(2)["rules_classification"], "rejection")
        check("...and the model's label wins", _g(2)["classification"], "confirmation")
        # The three gates, none of which is about which reader is smarter.
        check("a low-confidence reading is not adopted", _g(3)["classification_source"], "rules")
        check("a DMARC-failing message is not adopted", _g(4)["classification_source"], "rules")
        check("a suspected injection is not adopted", _g(5)["classification_source"], "rules")
        check("an unread message is untouched", _g(6)["classification_source"], "rules")
        check("it reports what it changed", _n, 2)
        # 🚨 IDEMPOTENT. A sweep that re-fires every cycle would rewrite rules_classification
        # with the model's own answer and destroy the audit trail it exists to keep.
        _n2, _ = _appA.adopt_readings()
        check("running it again changes nothing", _n2, 0)
    finally:
        if _pA is None: _oA.environ.pop("DB_PATH", None)
        else: _oA.environ["DB_PATH"] = _pA

    # ═══ changing the commute origin must not destroy measurements ═══
    #
    # 🚨 IT DID, ON 2026-08-24. Correcting ONE DIGIT of a house number destroyed 591 place
    # rows carrying 320 verdicts. The sequence was ordinary and will recur: the laptop's
    # config was fixed first, the container still held the old value, job_place ran on
    # schedule, saw every row under a "different" origin, and hard-DELETEd them.
    #
    # ⚠️ Recovery needed an encrypted snapshot and a surgical merge. The markdown render was
    # NOT enough on its own: it collapses best_min and judged_min into one column and never
    # writes judged_conf, so re-importing it would have restored the rows and quietly flattened
    # the three-layer model the design exists to keep separate.
    print("\nan origin change retires rows, it does not delete them:")
    import os as _oP, tempfile as _tP, sqlite3 as _sP
    _dP = _tP.mkdtemp() + "/place.db"
    _pP = _oP.environ.get("DB_PATH"); _oP.environ["DB_PATH"] = _dP
    _pc = _oP.environ.get("CANDIDATE_CONFIG")
    _oP.environ["CANDIDATE_CONFIG"] = str(HERE.parent / "seed" / "candidate.toml")
    try:
        _appP = load_app()
        import candidate as _CP; _CP._cache.clear()
        _c = _sP.connect(_dP)
        _c.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        for _m in _appP.MIGRATIONS:
            try: _c.execute(_m)
            except Exception: pass
        # one measured row, taken from an origin that is about to change
        _c.execute("INSERT INTO place (origin,board,location,postings,judged_min,judged_conf,"
                   "drive_min,transit_min,best_min,verdict,verdict_from) "
                   "VALUES ('OLD ADDRESS','','Nashville, TN',7,55,'high',61,72,61,"
                   "'commutable','measurement')")
        _c.commit(); _c.close()

        _appP.job_place()

        _c2 = _sP.connect(_dP); _c2.row_factory = _sP.Row
        row = _c2.execute("SELECT * FROM place WHERE location='Nashville, TN'").fetchone()
        check("the row still exists", row is not None, True)
        if row is not None:
            check("...it is retired, not deleted", bool(row["retired_at"]), True)
            # ⭐ what it was measured FROM is kept, so a revert is one UPDATE and not a
            # re-measurement. That is the difference between a mistake and an outage.
            check("...and remembers its old origin", row["retired_origin"], "OLD ADDRESS")
            check("...the measurement survives", (row["drive_min"], row["transit_min"],
                                                  row["best_min"]), (61, 72, 61))
            check("...and so does the model layer", (row["judged_min"], row["judged_conf"]),
                  (55, "high"))
        # 🚨 AND A RETIRED ROW MUST NOT DECIDE ANYTHING. Left visible it would reject a live
        # posting on a trip measured from an address he no longer lives at, which is worse
        # than deleting it. Every FROM place reader is asserted to filter, by source, because
        # one unfiltered query is all it takes.
        _src = pathlib.Path(HERE.parent / "job_search_engine" / "app.py").read_text().splitlines()
        _unfiltered = [i + 1 for i, l in enumerate(_src) if "FROM place" in l
                       and "retired_at" not in " ".join(_src[i:i + 4])]
        check("every FROM place reader filters retired rows", _unfiltered, [])
    finally:
        if _pP is None: _oP.environ.pop("DB_PATH", None)
        else: _oP.environ["DB_PATH"] = _pP
        if _pc is None: _oP.environ.pop("CANDIDATE_CONFIG", None)
        else: _oP.environ["CANDIDATE_CONFIG"] = _pc

    # ═══ a forged rejection must not close a live application ═══
    #
    # 🚨 A PROBE DID EXACTLY THAT ON 2026-08-23. One email from an unrelated domain closed a
    # submitted application AND a live interview. Nothing checked the sender, the body never
    # named the role, and DMARC cannot help: read_auth_results says in its own docstring that
    # dmarc=pass means the From domain authorised the send and nothing more.
    #
    # ⚠️ The likeliest cause is not malice. Any rejection-shaped mail reaching an alias closes
    # that application, so a rejection for a DIFFERENT role at the same company would do it.
    print("\na forged rejection cannot close an application:")
    import os as _oF, tempfile as _tF, sqlite3 as _sF

    def _forge(status, source, warn, sender, name_role):
        _dF = _tF.mkdtemp() + "/forge.db"
        _pF = _oF.environ.get("DB_PATH"); _oF.environ["DB_PATH"] = _dF
        try:
            _appF = load_app()
            _c = _sF.connect(_dF)
            _c.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
            for _m in _appF.MIGRATIONS:
                try: _c.execute(_m)
                except Exception: pass
            _c.executescript("""
              CREATE TABLE IF NOT EXISTS company(id INTEGER PRIMARY KEY, name TEXT);
              CREATE TABLE IF NOT EXISTS posting(id INTEGER PRIMARY KEY, company_id INT,
                     title TEXT, captured_at TEXT);
              CREATE TABLE IF NOT EXISTS application(id INTEGER PRIMARY KEY, posting_id INT,
                     status TEXT, alias_used TEXT, company_raw TEXT, role_raw TEXT,
                     source_row TEXT, notes TEXT, outcome_at TEXT, outcome_reason TEXT,
                     outcome_source TEXT, status_raw TEXT, applied_raw TEXT, submitted_at TEXT,
                     status_source TEXT, next_action TEXT);
              CREATE TABLE IF NOT EXISTS tracker_floor(id INTEGER PRIMARY KEY, count INT,
                     ids TEXT, updated TEXT);""")
            _c.execute("INSERT INTO company (id,name) VALUES (1,'Acme')")
            _c.execute("INSERT INTO posting (id,company_id,title,captured_at) "
                       "VALUES (1,1,'X','2026-01-01')")
            _c.execute("INSERT INTO application (id,posting_id,status,alias_used,company_raw,"
                       "role_raw) VALUES (1,1,?,'acme@jobs.example.com','Acme',"
                       "'Solutions Architect')", (status,))
            body = ("Dear Jonathan, After careful consideration we have decided to not move "
                    "forward with your application at this time.")
            if name_role:
                body += " Regarding the Solutions Architect role."
            _c.execute("INSERT INTO message (id,received_at,to_alias,raw_payload,from_addr,"
                       "subject,body_text,body_reply,classification,classification_source,"
                       "application_ref,auth_dmarc,auth_warn,needs_human) "
                       "VALUES (1,?,?,?,?,?,?,?,'rejection',?,'acme',?,?,1)",
                       ("2026-08-23T22:00:00+00:00", "acme@jobs.example.com", "{}", sender,
                        "Update", body, body, source, "fail" if warn else "pass", warn))
            _c.commit(); _c.close()
            _appF.job_track()
            return _sF.connect(_dF).execute(
                "SELECT status FROM application WHERE id=1").fetchone()[0] == "rejected"
        finally:
            if _pF is None: _oF.environ.pop("DB_PATH", None)
            else: _oF.environ["DB_PATH"] = _pF

    BAD = "careers@totally-not-acme.example"
    # ⚠️ "totally-not-acme" CONTAINS "acme". The first sender check was a substring test and
    # this exact address walked through it. The name must match a domain LABEL, not appear
    # somewhere inside the flattened host.
    check("an unrelated sender cannot close it", _forge("submitted", "model", 0, BAD, True), False)
    check("...even when the mail names the role", _forge("submitted", "model", 0, BAD, True), False)
    check("...and an interview is never auto-closed",
          _forge("interview", "model", 0, "no-reply@us.greenhouse-mail.io", True), False)
    check("a rejection that never names the role is held",
          _forge("submitted", "model", 0, "no-reply@us.greenhouse-mail.io", False), False)
    # ⭐ AND THE GUARDS MUST NOT EAT A REAL REJECTION. A test that only proves things are
    # blocked would pass just as well with job_track deleted.
    check("a real ATS rejection still closes it",
          _forge("submitted", "model", 0, "no-reply@us.greenhouse-mail.io", True), True)
    check("...and one from the employer's own domain",
          _forge("submitted", "model", 0, "careers@acme.com", True), True)
    check("a provisional rules label still decides nothing",
          _forge("submitted", "rules", 0, "no-reply@us.greenhouse-mail.io", True), False)

    # 🚨 ...AND IN THE TOOL HE ACTUALLY READS. The line above checks the JOB's output. The
    # tool he queries is recent_mail, and until 2026-08-23 that returned ONLY the rules
    # label. Three regex mistakes therefore reached him as facts on one day: two ordinary
    # confirmations reported as REJECTIONS and a third as an INCOMPLETE APPLICATION. The
    # model had already read all three correctly, with high confidence, and had no way to
    # say so.
    #
    # 📌 The fixtures below are anonymised on purpose. The subject lines are the real
    # SHAPES, which is what the assertions need; the employers are not, because naming
    # them publishes one person's application history in a public repository.
    #
    # ⚠️ The triggers were phrases that live INSIDE confirmations: "if you are not selected
    # for this position" matched the rejection rule, and "thank you for taking the time to
    # complete your application" matched the incomplete rule. A conditional future and a
    # past-tense compliment, both read as present-tense verdicts.
    print("\nrecent_mail shows both readers:")
    import os as _oR, tempfile as _tR, sqlite3 as _sR
    _dR = _tR.NamedTemporaryFile(suffix=".db", delete=False).name
    _pR = _oR.environ.get("DB_PATH"); _oR.environ["DB_PATH"] = _dR
    try:
        _appR = load_app()
        _cR = _sR.connect(_dR)
        _cR.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        for _m in _appR.MIGRATIONS:
            try: _cR.execute(_m)
            except Exception: pass
        for _mid, _subj, _rules, _ai, _conf in [
                (143, "Thank you for applying to Employer A!",  "rejection",              "confirmation", "high"),
                (146, "Thank you for applying to Employer B",   "incomplete_application", "confirmation", "high"),
                (145, "We received your Employer C application!", "unknown",             "confirmation", "high"),
                (149, "Thank you for applying to Employer D",   "confirmation",           "confirmation", "high"),
                (150, "Security code for your application",   "otp",                    None,           None)]:
            _cR.execute("INSERT INTO message (id,received_at,to_alias,raw_payload,from_addr,"
                        "subject,classification,application_ref,auth_dmarc,auth_warn,needs_human) "
                        "VALUES (?,?,?,?,?,?,?,?,?,0,1)",
                        (_mid, f"2026-08-23T1{_mid % 10}:00:00+00:00",
                         "acme@jobs.example.com", "{}", "no-reply@example.com",
                         _subj, _rules, "acme", "pass"))
            if _ai:
                _cR.execute("INSERT INTO ai_reading (message_id,created_at,model,classification,"
                            "confidence,raw_json) VALUES (?,?,?,?,?,?)",
                            (_mid, "2026-08-23T18:00:00+00:00", "test-model", _ai, _conf, "{}"))
        _cR.commit(); _cR.close()

        _out = _appR._mcp_call("recent_mail", {"limit": 10})
        check("the header counts the disagreements",
              "3 of 5 shown have the two readers disagreeing" in _out, True)
        check("each disagreeing row names the second reading",
              all("DISAGREEMENT" in _out.split(f"[{m}]")[1].split("[")[0] for m in (143, 146, 145)),
              True)
        check("...and quotes its label and confidence",
              "second reading says 'confirmation'" in _out and "high confidence" in _out, True)
        # ⭐ Displaying a label grants it no authority. ai_reading proposes only, because a
        # model reading untrusted mail is MORE injectable than a regex, not less: a sender
        # can write label words into a body, and a probe has already steered classify().
        check("it refuses to adjudicate", "Neither is authoritative" in _out, True)
        # Agreement is stated, so "no flag" cannot be misread as "the model never looked".
        check("agreement is stated explicitly",
              "second reading agrees (confirmation)" in _out.split("[149]")[1], True)
        check("an unread message says so",
              "not read by the model" in _out.split("[150]")[1], True)
        check("the rules label is still shown, and labelled as the rules label",
              "rules=rejection" in _out and "rules=incomplete_application" in _out, True)
    finally:
        if _pR is None: _oR.environ.pop("DB_PATH", None)
        else: _oR.environ["DB_PATH"] = _pR

    # A reading is only valid for the text it was made from. This is asserted against a
    # real sqlite file rather than by reading the source, because the bug it prevents was
    # a live one: two readings survived a body correction and had to be deleted by hand.
    print("\nstale readings invalidate themselves:")
    import os as _os, tempfile as _tf
    _db = _tf.NamedTemporaryFile(suffix=".db", delete=False).name
    _prev = _os.environ.get("DB_PATH")
    _os.environ["DB_PATH"] = _db
    try:
        _app = load_app()                      # re-import so it binds the temp DB
        _app.init_db()
        with _app.db() as con:
            con.execute("INSERT INTO message (received_at,to_alias,subject,body_text,"
                        "body_reply,raw_payload,classification,needs_human) "
                        "VALUES (?,?,?,?,?,?,?,1)",
                        (_app.now(), "x@y.z", "Subj", "original text", "original text",
                         "{}", "unknown"))
            con.execute("INSERT INTO ai_reading (message_id,created_at,model,classification,"
                        "raw_json,body_sha256) VALUES (1,?,?,?,?,?)",
                        (_app.now(), "test", "unknown", "{}",
                         _app.reading_input_hash("Subj", "original text")))

        def pending():
            with _app.db() as con:
                cand = con.execute(
                    "SELECT m.id,m.subject,m.body_reply,m.body_text, "
                    "  (SELECT a.body_sha256 FROM ai_reading a WHERE a.message_id=m.id "
                    "    ORDER BY a.id DESC LIMIT 1) last_hash FROM message m").fetchall()
            return [c["id"] for c in cand
                    if _app.reading_input_hash(c["subject"], c["body_reply"] or c["body_text"])
                    != (c["last_hash"] or "")]

        check("unchanged text is not re-read", pending(), [])
        with _app.db() as con:
            con.execute("UPDATE message SET body_reply=? WHERE id=1", ("corrected text",))
        check("corrected text IS re-read", pending(), [1])
    finally:
        if _prev is None: _os.environ.pop("DB_PATH", None)
        else: _os.environ["DB_PATH"] = _prev
        _os.unlink(_db)

    # The first code path that changes pipeline state without a human. Driven against a
    # real sqlite file, because what matters is the state it writes, not the source.
    print("\napplication auto-tracking:")
    import os as _o, tempfile as _t
    _d = _t.NamedTemporaryFile(suffix=".db", delete=False).name
    _p = _o.environ.get("DB_PATH"); _o.environ["DB_PATH"] = _d
    try:
        _a = load_app(); _a.init_db()
        # ⭐ THE FIXTURE NO LONGER DECLARES THE PIPELINE TABLES, BECAUSE init_db() DOES.
        # It used to hand-roll a cut-down posting and application, which meant the test
        # passed against a schema the service had never actually built. Seeding real rows
        # against the real declarations is what makes NOT NULL and the UNIQUE key part of
        # what is under test, rather than something only production discovers.
        def seed(alias, status, rid):
            with _a.db() as con:
                con.execute("INSERT INTO company (id,name) VALUES (?,?)", (rid, f"Acme {rid}"))
                con.execute("INSERT INTO posting (id,company_id,title,captured_at) "
                            "VALUES (?,?,?,?)", (rid, rid, "Engineer", "2026-01-01"))
                con.execute("INSERT INTO application (id,posting_id,status,alias_used,"
                            "company_raw,role_raw,source_row) VALUES (?,?,?,?,?,?,?)",
                            (rid, rid, status, alias, "Acme", "Engineer", "| original |"))
        def mail(alias, label, mid):
            with _a.db() as con:
                # ⚠️ classification_source='model' is now REQUIRED for job_track to act. A row
                # without it carries the provisional rules label, and since 2026-08-23 that
                # decides nothing. The gate itself is asserted separately below.
                con.execute("INSERT INTO message (id,received_at,to_alias,raw_payload,"
                            "classification,classification_source,application_ref,needs_human) "
                            "VALUES (?,?,?,?,?,'model',?,1)",
                            (mid, "2026-08-14T12:00:00+00:00", alias, "{}", label,
                             _a.resolve_application(alias)))
        def status_of(rid):
            with _a.db() as con:
                r = con.execute("SELECT status,submitted_at,source_row FROM application "
                                "WHERE id=?", (rid,)).fetchone()
            return r["status"], r["submitted_at"], r["source_row"]

        seed("acme-eng@jobs.x.com", "draft", 1)
        mail("acme-eng@jobs.x.com", "confirmation", 1)
        _a.job_track()
        st, sub, src = status_of(1)
        check("confirmation moves draft -> submitted", st, "submitted")
        check("submitted_at comes from the email", bool(sub), True)
        # A display change without retiring source_row would BLOCK render-tracker.py.
        check("source_row retired so the renderer is not blocked", src, None)

        # A rejection must never move anything: only confirmations are evidence of sending.
        seed("acme-two@jobs.x.com", "draft", 2)
        mail("acme-two@jobs.x.com", "rejection", 2)
        _a.job_track()
        check("a rejection does not move a draft", status_of(2)[0], "draft")

        # Two rows sharing an alias is exactly the per-company case, and guessing would
        # write a false submission date onto a real application.
        seed("dup@jobs.x.com", "draft", 3)
        seed("dup@jobs.x.com", "draft", 4)
        mail("dup@jobs.x.com", "confirmation", 3)
        out = _a.job_track()
        check("an ambiguous alias moves nothing",
              (status_of(3)[0], status_of(4)[0]), ("draft", "draft"))
        check("and says so out loud", "AMBIGUOUS" in out, True)

        # Anything not in draft is not this job's business.
        seed("live@jobs.x.com", "interview", 5)
        mail("live@jobs.x.com", "confirmation", 5)
        _a.job_track()
        check("a non-draft row is never touched", status_of(5)[0], "interview")
    finally:
        if _p is None: _o.environ.pop("DB_PATH", None)
        else: _o.environ["DB_PATH"] = _p
        _o.unlink(_d)

    # Board sweeping. The parsers are asserted against captured payload SHAPES rather
    # than live boards, so the suite stays offline and does not depend on anyone hiring.
    print("\nboard scanner:")
    import json as _j, types as _ty, urllib.request as _u
    _payloads = {
        "greenhouse": _j.dumps({"jobs": [{"id": 111, "title": "TSE"}]}),
        "ashby": _j.dumps({"jobs": [{"jobUrl": "https://jobs.ashbyhq.com/acme/UU-ID", "title": "PSE"}]}),
        "lever": _j.dumps([{"id": "lv1", "text": "Support"}]),
        "smartrecruiters": _j.dumps({"content": [{"id": "sr1", "name": "Eng"}]}),
        "workable": _j.dumps({"jobs": [{"shortcode": "WK1", "title": "Ops"}]}),
    }
    _real = _u.urlopen
    def _fake(req, *a, **k):
        body = _fake.body
        class R:
            def read(self): return body.encode()
            def __enter__(self): return self
            def __exit__(self, *e): return False
        return R()
    _u.urlopen = _fake
    try:
        for plat, body in _payloads.items():
            _fake.body = body
            got = app._board_reqs(plat, "https://example.invalid/x")
            check(f"{plat} parses to a record",
                  len(got) == 1 and bool(got[0].get("req_id")) and bool(got[0].get("title")), True)
        # The Ashby id is the UUID from jobUrl: that is the identifier the rest of the
        # system already uses for an Ashby posting, so a scan must agree with it.
        _fake.body = _payloads["ashby"]
        check("ashby req_id is the jobUrl UUID",
              app._board_reqs("ashby", "https://example.invalid/x")[0]["req_id"], "UU-ID")
        # An unknown platform must return nothing, not an empty-looking success that
        # would read as "this board has no jobs" and vanish every req on it.
        _fake.body = "{}"
        check("an unknown platform yields nothing",
              app._board_reqs("mystery", "https://example.invalid/x"), [])
        # 🚨 A board CAN return the same id twice. board_state is keyed (board, req_id) and
        # the diff already treats a sweep as a set, so a duplicate in the list violated the
        # primary key and took the first real 2,858-board sweep down 25 seconds in.
        _fake.body = _j.dumps({"jobs": [
            {"id": 7, "title": "Support Engineer", "location": {"name": "Remote"}},
            {"id": 7, "title": "Support Engineer", "location": {"name": "Remote - US"}},
            {"id": 8, "title": "Solutions Engineer", "location": {"name": "Remote"}}]})
        _dup = app._board_reqs("greenhouse", "https://example.invalid/x")
        check("duplicate req_ids collapse to one record", len(_dup), 2)
        check("and the list agrees with the set the diff builds",
              len(_dup) == len({p["req_id"] for p in _dup}), True)
        # ⚠️ Greenhouse's `content` field is HTML that has been ENTITY-ESCAPED, so it
        # arrives as "&lt;li&gt;Do the thing&lt;/li&gt;". Two thirds of the swept corpus was
        # reaching the model as markup noise, billed as tokens. Ashby returns clean text,
        # which is why the boards that looked right were the ones being read.
        _fake.body = _j.dumps({"jobs": [
            {"id": 9, "title": "T", "location": {"name": "Remote"},
             "content": "&lt;p&gt;Do the thing&lt;/p&gt;&lt;li&gt;And&amp;nbsp;this&lt;/li&gt;"}]})
        _d = app._board_reqs("greenhouse", "https://example.invalid/x")[0]["description"]
        check("escaped greenhouse HTML becomes readable text",
              "<" not in _d and "&lt;" not in _d and "&nbsp;" not in _d, True)
        check("and keeps the words", "Do the thing" in _d and "And this" in _d, True)
    finally:
        _u.urlopen = _real

    # The gate is definitional only. Location is deliberately NOT one: a crude US regex
    # rejected a real LangChain support role on 2026-08-14, and the public dataset made
    # the mirror error by reading San Francisco's "CA" as Canada on 3,979 rows.
    check("explicit not-remote is rejected",
          app.gate_posting({"title": "Support Engineer", "is_remote": False})[0], False)
    check("remote passes",
          app.gate_posting({"title": "Support Engineer", "is_remote": True})[0], True)
    check("UNKNOWN remote is not a rejection",
          app.gate_posting({"title": "Support Engineer", "is_remote": None})[0], True)
    check("a foreign location does NOT reject",
          app.gate_posting({"title": "Support Engineer", "is_remote": True,
                            "location": "Amsterdam"})[0], True)
    # 🚨 The targeting filter, kept separate from gate_posting on purpose. Without it,
    # 2,858 enabled boards send ~2,389 new requisitions a night to a paid model instead of
    # ~368: about $247/month against $21. The relay had no such filter until 2026-08-14.
    check("an on-target title passes",
          bool(app.TARGET_TITLE.search("Senior Technical Support Engineer")), True)
    check("and so does an implementation role",
          bool(app.TARGET_TITLE.search("Mid-Market Implementation Specialist")), True)
    check("an off-target title does not",
          bool(app.TARGET_TITLE.search("Staff Frontend Engineer")), False)
    check("nor does an account executive",
          bool(app.TARGET_TITLE.search("Enterprise Account Executive - DACH")), False)
    # ⚠️ It must never look at location. That rule already cost a real role once.
    check("the targeting filter ignores location entirely",
          bool(app.TARGET_TITLE.search("Senior Technical Support Engineer (London)"))
          and bool(app.TARGET_TITLE.search("Support Engineer - APAC")), True)
    check("off-target rejections are counted, not silent",
          "off-target title" in _src_of(app._scan_candidates), True)
    check("an untitled posting is rejected",
          app.gate_posting({"title": "", "is_remote": True})[0], False)
    # Unknown must survive as NULL all the way to storage, not become 0. A greenhouse
    # posting has no remote flag at all, and 0 would read as "confirmed not remote".
    import inspect as _i2
    check("unknown remote is stored as NULL, not 0",
          'None if pst.get("is_remote") is None' in _i2.getsource(app._scan_candidates), True)

    # A job the scheduler runs but /admin/run cannot reach is invisible until someone
    # tries the documented command. That happened with ai_read on 2026-08-13, so the two
    # registries are now one and this asserts they stay one.
    import inspect as _i
    check("scheduler reads job_table", "jobs = job_table()" in _i.getsource(app._scheduler), True)
    check("admin/run reads job_table",
          "job_table()" in _i.getsource(app.run_job), True)
    check("ai_read is registered", "ai_read" in [n for n, _, _ in app.job_table()], True)
    check("track is registered", "track" in [n for n, _, _ in app.job_table()], True)
    check("scan is registered", "scan" in [n for n, _, _ in app.job_table()], True)

    # No key must mean no call and no database read, so a machine that is not configured
    # for this cannot be the machine that discovers the job is broken.
    saved = {k: os.environ.pop(k, None) for k in
             ("ANTHROPIC_API_KEY", "AI_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY")}
    try:
        check("no key means the job declines before touching anything",
              app.job_ai_read().startswith("skipped: "), True)
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v

    # 🚨 A forward is not a reply. On 2026-08-14 two real forwarded rejections stripped
    # down to the 28-byte separator line and both classified as unknown, because the
    # parser treated the forwarded body as quoted history. In a forward the quoted part
    # IS the message. Bodies below are synthetic; only the SHAPE is taken from the real
    # ones, for the same reason the webhook fixture is synthetic.
    print("\nsweep writes state + changes, not a snapshot:")
    import os as _o3, tempfile as _t3, sqlite3 as _s3, types as _ty3, json as _j3
    import urllib.request as _u3
    _d3 = str(_t3.mkdtemp()) + "/scan.db"
    _p3 = _o3.environ.get("DB_PATH"); _o3.environ["DB_PATH"] = _d3
    _real3 = _u3.urlopen
    try:
        _app3 = load_app()
        _c3 = _s3.connect(_d3)
        _c3.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        # init_db runs schema.sql AND MIGRATIONS; a fixture doing only the first
        # builds a schema the service never has.
        for _m in app.MIGRATIONS:
            try: _c3.execute(_m)
            except Exception: pass
        # ⭐ `company` comes from schema.sql now. The fixture used to declare its own
        # four-column version, which is how a test can keep passing against a table the
        # service does not build.
        _c3.execute("INSERT INTO company (name,ats_platform,ats_token,api_url) "
                    "VALUES ('Acme','greenhouse','acme','https://example.invalid/b')")
        _c3.commit(); _c3.close()

        def _sweep(jobs):
            def _f(req, *a, **k):
                body = _j3.dumps({"jobs": jobs}).encode()
                class R:
                    def read(self): return body
                    def __enter__(self): return self
                    def __exit__(self, *e): return False
                return R()
            _u3.urlopen = _f
            return _app3.job_scan()

        def _counts():
            c = _s3.connect(_d3); c.row_factory = _s3.Row
            g = lambda q: c.execute(q).fetchone()[0]
            out = (g("SELECT count(*) FROM board_state"),
                   g("SELECT count(*) FROM scan_change"),
                   g("SELECT count(*) FROM scan_run"),
                   g("SELECT count(*) FROM scan_candidate"))
            c.close(); return out

        # \U0001f6a8 First contact SEEDS. Every posting on a board is "new" the first time
        # it is read, and announcing that would flood triage the night the registry grows.
        n1 = _sweep([{"id": 1, "title": "A", "location": {"name": "Remote"}},
                     {"id": 2, "title": "B", "location": {"name": "Remote"}}])
        check("first sweep seeds and announces nothing", "SEEDED" in n1, True)
        st, ch, run, cand = _counts()
        check("state recorded on seed", st, 2)
        check("NO change rows on seed", ch, 0)
        check("no candidates handed to the model on seed", cand, 0)

        # \u2b50 An unchanged board writes NOTHING. This is the entire point: the old code
        # wrote one row per requisition per sweep to say nothing had happened.
        _sweep([{"id": 1, "title": "A", "location": {"name": "Remote"}},
                {"id": 2, "title": "B", "location": {"name": "Remote"}}])
        st2, ch2, run2, _ = _counts()
        check("an unchanged sweep writes no change rows", ch2, 0)
        check("and does not grow the state table", st2, 2)
        # ...but the run IS recorded, or a quiet night and a night the scanner never ran
        # would be indistinguishable.
        check("the sweep itself is still recorded", run2 > run, True)
        # ⚠️ A sweep that STARTS and dies must leave evidence it began. The row used to be
        # written only on return, so a partial run was indistinguishable from a complete
        # one when reading scan_change - which is exactly the mistake made on 2026-08-14,
        # comparing an aborted 58-board run against a complete 2,862-board one.
        c = _s3.connect(_d3); c.row_factory = _s3.Row
        _r = c.execute("SELECT status, finished_at, boards FROM scan_run "
                       "ORDER BY id DESC LIMIT 1").fetchone()
        c.close()
        check("a completed sweep is marked ok", _r["status"], "ok")
        check("and stamped with a finish time", bool(_r["finished_at"]), True)
        _srcscan = _src_of(_app3._job_scan_locked)
        check("the run row is INSERTed as running before any board is touched",
              "INSERT INTO scan_run" in _srcscan and "'running'" in _srcscan, True)
        # ...and completion UPDATES that row rather than inserting a second one, or a
        # died-then-rerun sweep would leave two rows for one sweep and no way to pair them.
        check("completion updates that row, it does not insert another",
              "UPDATE scan_run SET" in _srcscan and _srcscan.count("INSERT INTO scan_run") == 1,
              True)

        # ⚠️ "Support Engineer", not "C": since the targeting filter landed, an off-target
        # title never reaches scan_candidate, and this block is testing the DIFF, not the
        # filter. A fixture that quietly stops exercising its subject still passes.
        n3 = _sweep([{"id": 1, "title": "A", "location": {"name": "Remote"}},
                     {"id": 3, "title": "Support Engineer", "location": {"name": "Remote"}}])
        st3, ch3, _, cand3 = _counts()
        # ⚠️ ONE, NOT TWO. The appearance is reported at once; the disappearance is HELD
        # until a second sweep agrees. A requisition missing once is a suspicion, and
        # believing it is what let two flapping boards write false history for days.
        check("the appearance is logged, the disappearance is held", ch3, 1)
        # ⚠️ THREE ROWS, NOT TWO. The vanished requisition is MARKED, never deleted, so the
        # archive can still prove it existed. Two rows are currently on the board.
        check("the vanished row is kept, not destroyed", st3, 3)
        _cv = _s3.connect(_d3)
        check("...and exactly one is marked as gone",
              _cv.execute("SELECT count(*) FROM board_state "
                          "WHERE vanished_at IS NOT NULL").fetchone()[0], 1)
        check("...while the board's current state is two",
              _cv.execute("SELECT count(*) FROM board_state "
                          "WHERE vanished_at IS NULL").fetchone()[0], 2)
        _cv.close()
        check("the first sweep does NOT announce a vanish", "VANISHED" in n3, False)
        check("...but says the disappearance is held", "held for confirmation" in n3, True)
        check("only the genuinely new posting reaches triage", cand3, 1)
        c = _s3.connect(_d3); c.row_factory = _s3.Row
        kinds = {r["change"]: r["req_id"] for r in c.execute("SELECT change,req_id FROM scan_change")}
        check("the right req appeared", kinds.get("appeared"), "3")
        check("...and nothing is recorded as vanished yet", kinds.get("vanished"), None)
        check("the right req is the one being held",
              c.execute("SELECT req_id FROM board_state "
                        "WHERE vanished_at IS NOT NULL").fetchone()["req_id"], "2")
        c.close()
        # The second sweep agrees, so now it is a fact.
        n3b = _sweep([{"id": 1, "title": "A", "location": {"name": "Remote"}},
                      {"id": 3, "title": "Support Engineer", "location": {"name": "Remote"}}])
        c = _s3.connect(_d3); c.row_factory = _s3.Row
        check("a second agreeing sweep confirms it",
              c.execute("SELECT req_id FROM scan_change "
                        "WHERE change='vanished'").fetchone()["req_id"], "2")
        c.close()
        check("...and NOW it is announced", "VANISHED" in n3b, True)

        # \u2b50 The watch list is a SECOND registry, and `enabled` is what stages the
        # expansion. A disabled row must not be swept, or "load 2,060 boards disabled"
        # would silently mean "sweep 2,060 boards tonight".
        c = _s3.connect(_d3)
        c.execute("INSERT INTO scan_board (platform,token,api_url,source,added_at,enabled) "
                  "VALUES ('greenhouse','watched','https://example.invalid/w','t','now',0)")
        c.commit(); c.close()
        _sweep([{"id": 1, "title": "A", "location": {"name": "Remote"}},
                {"id": 3, "title": "C", "location": {"name": "Remote"}}])
        c = _s3.connect(_d3)
        n_dis = c.execute("SELECT count(*) FROM board_seeded").fetchone()[0]
        c.execute("UPDATE scan_board SET enabled = 1")
        c.commit(); c.close()
        check("a DISABLED watch board is not swept", n_dis, 1)
        _sweep([{"id": 1, "title": "A", "location": {"name": "Remote"}},
                {"id": 3, "title": "C", "location": {"name": "Remote"}}])
        c = _s3.connect(_d3)
        n_en = c.execute("SELECT count(*) FROM board_seeded").fetchone()[0]
        c.close()
        check("an ENABLED watch board joins the sweep", n_en, 2)

        # A board that ERRORS has an unknown state. Treating unknown as absent would
        # manufacture a vanishing for every requisition on it.
        def _boom(req, *a, **k): raise OSError("network down")
        _u3.urlopen = _boom
        n4 = _app3.job_scan()
        st4, ch4, _, _ = _counts()
        check("a failed board vanishes nothing", ch4, 2)
        # 5, not 4: the enabled watch board contributes two rows, and the requisition that
        # vanished in the previous step is still present as a marked row rather than gone.
        # Asserted as an absolute rather than "unchanged" so a silent state wipe cannot
        # pass by making both sides zero.
        check("and its state is left alone", st4, 5)
        check("the failure is reported", "FAILED" in n4, True)

        # ⭐ More boards than one chunk. The concurrent rewrite loops chunks and must sweep
        # ALL of them: an off-by-one that dropped the tail would look like a clean sweep
        # while silently ignoring most of the watch list.
        _app3.SCAN_CHUNK = 3
        c = _s3.connect(_d3)
        c.execute("DELETE FROM scan_board")
        for _n in range(11):
            c.execute("INSERT INTO scan_board (platform,token,api_url,source,added_at,"
                      "enabled) VALUES ('greenhouse',?,?,'t','now',1)",
                      (f"chunk{_n}", f"https://example.invalid/c{_n}"))
        c.commit(); c.close()
        _sweep([{"id": 1, "title": "A", "location": {"name": "Remote"}}])
        c = _s3.connect(_d3)
        n_boards = c.execute("SELECT count(*) FROM board_seeded").fetchone()[0]
        c.close()
        # 2 from earlier (company + the first watch board) + 11 new = 13
        check("every board is swept across chunk boundaries", n_boards, 13)

        # 🚨 The seed must batch its writes. Bunny's execute() is one HTTP round-trip per
        # statement, so a loop over 160,000 requisitions is 160,000 sequential POSTs and
        # roughly two hours with the scheduler blocked. sqlite3 has executemany natively,
        # so this asserts the CALL SITE uses it rather than testing sqlite's behaviour.
        # 🚨 Two runs of the SAME job corrupt each other, and both real failures on
        # 2026-08-14 were this: two sweeps colliding on board_state's key, and two backups
        # where the second crashed reading a file the first had correctly pruned. The lock
        # is at the dispatch point, so every job in job_table gets it, not just the one
        # that broke last.
        import threading as _th
        _held = _th.Event(); _release = _th.Event()
        def _slow():
            _held.set(); _release.wait(5); return "first"
        _t = _th.Thread(target=lambda: _app3.run_once("scan", _slow)); _t.start()
        _held.wait(5)
        check("a second run of the same job is declined",
              _app3.run_once("scan", lambda: "second"), "skipped: scan is already running")
        # ...while a DIFFERENT job is unaffected. A global lock would serialise the whole
        # scheduler and turn one slow sweep into a stalled mailbox.
        check("a different job still runs", _app3.run_once("backup", lambda: "ok"), "ok")
        _release.set(); _t.join()
        # ...and the lock frees afterwards, or the first failure disables that job forever
        # and presents as a scheduler that quietly stopped.
        check("the lock frees once the job returns",
              _app3.run_once("scan", lambda: "again"), "again")
        # A job that RAISES must still free its lock, or one transient error is permanent.
        try:
            _app3.run_once("scan", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        except RuntimeError:
            pass
        check("a job that raises still frees its lock",
              _app3.run_once("scan", lambda: "recovered"), "recovered")
        check("the seed batches its inserts",
              "con.executemany(" in _src_of(_app3._job_scan_locked), True)
        check("and _Hrana can actually batch",
              callable(getattr(_app3._Hrana, "executemany", None)), True)

        # ═══════════════════════════════════ the commute rejection set, from the database
        #
        # ⭐ This moved out of a markdown file in the synced repo and into the `place`
        # table, so the container can write it and a front-end can read it.
        # ⚠️ Read the origin the way the code under test reads it. Hardcoding one here
        # would make this pass against a config that says something else, which is the
        # failure mode the whole candidate-config layer exists to prevent.
        # 🚨 POINT IT AT THE SEED PROFILE FIRST. With no config the engine has no origin,
        # _commute_too_far declines to read the table at all, and every assertion below
        # would pass or fail for a reason that has nothing to do with what it is testing.
        # This is the same trap the seed-profile check at the top of e2e-check.sh warns
        # about: an empty config makes the code decline politely and look like it worked.
        _prev_cfg = _o3.environ.get("CANDIDATE_CONFIG")
        _o3.environ["CANDIDATE_CONFIG"] = str(HERE.parent / "seed" / "candidate.toml")
        try:
            import candidate as _C3
            import gates as _G3
            _C3._cache.clear()
            _ORIGIN = ((_C3.load().get("commute") or {}).get("origin") or "").strip()
        except Exception:                                     # noqa: BLE001
            _ORIGIN = ""
        check("the seed profile supplies a commute origin", bool(_ORIGIN), True)
        _c3 = _s3.connect(_d3)
        _c3.execute("DELETE FROM place")
        for _loc, _v in (("Philadelphia, PA", "too_far"), ("Pittsburgh, PA", "too_far"),
                         ("Brooklyn, NY", "commutable"), ("New Jersey", "review")):
            _c3.execute("INSERT INTO place (origin,board,location,verdict,verdict_from) "
                        "VALUES (?,'',?,?,'measurement')", (_ORIGIN, _loc, _v))
        # ⚠️ A row scoped to ONE employer's office must never reject a different employer
        # in the same city, so board != '' is excluded from the set entirely.
        _c3.execute("INSERT INTO place (origin,board,location,verdict,verdict_from) "
                    "VALUES (?,'greenhouse|acme','Newark, NJ','too_far','measurement')",
                    (_ORIGIN,))
        _c3.commit(); _c3.close()
        _app3._COMMUTE_FAR.update(db_at=0, origin=None)
        _far = _app3._commute_too_far()
        check("the rejection set comes from the database", "Philadelphia, PA" in _far, True)
        check("only too_far rows are in it",
              {"Brooklyn, NY", "New Jersey"} & _far, set())
        check("a board-scoped row cannot reject the whole city",
              "Newark, NJ" in _far, False)

        # 🚨 CACHED. _location_gate calls this once PER POSTING, inside a loop over the
        # whole sweep. Uncached, a 157,000-posting backfill is 157,000 HTTP round-trips for
        # a set that changes about weekly. Asserted by deleting every row and checking the
        # answer does NOT change until the cache is expired by hand.
        _c3 = _s3.connect(_d3); _c3.execute("DELETE FROM place"); _c3.commit(); _c3.close()
        check("a second call does not re-read the database",
              "Philadelphia, PA" in _app3._commute_too_far(), True)
        _app3._COMMUTE_FAR.update(db_at=0, origin=None)
        # 📌 With the table empty the markdown fallback takes over, which is what keeps an
        # un-migrated deployment from silently losing its whole commute filter.
        check("an empty table falls back rather than answering nothing",
              isinstance(_app3._commute_too_far(), set), True)
        if _prev_cfg is None:
            _o3.environ.pop("CANDIDATE_CONFIG", None)
        else:
            _o3.environ["CANDIDATE_CONFIG"] = _prev_cfg
        _C3._cache.clear()
        _app3._COMMUTE_FAR.update(db_at=0, origin=None)

        # ══════════════════════════ three bugs a full sweep found, 2026-08-16
        #
        # 🚨 A CANADIAN SUBURB SCORED 84. "Canada- Sr Solutions Analyst" in "Remote or
        # Mississauga" cleared every gate, because the word Remote satisfied it and
        # Mississauga was in no list. Toronto and Ottawa were; the suburbs were not.
        check("Mississauga is not a US city", _G3.eligibility("Remote or Mississauga"),
              "ineligible")
        check("...nor is a Canadian province",
              _G3.eligibility("Sherwood Park, Alberta"), "ineligible")
        # ⚠️ The omissions are deliberate: these names are US places too, and a false
        # rejection costs a real job while a false keep only costs a triage call.
        for _amb in ("Ontario, CA", "Vancouver, WA", "Victoria, TX"):
            check(f"{_amb} is not treated as Canada",
                  _G3.eligibility(_amb) == "ineligible", False)

        # ⚠️ \bremote\b demands a boundary after the 'e', so this matched nothing.
        check("'Remotely based' counts as remote text",
              bool(_G3.REMOTE_TXT.search("Remotely based")), True)
        check("...and plain 'Remote' still does",
              bool(_G3.REMOTE_TXT.search("Remote")), True)

        # 🚨 THE STARVATION. job_remote_check took the top N by score and THEN dropped rows
        # that never mention remote, so a block of high-scoring onsite roles pinned the
        # batch and the job reported "nothing to check" forever. 92 rows were eligible, 0 of
        # the top 24 qualified, 68 were unreachable. Asserted on the SQL, because the
        # symptom is a job that succeeds while doing nothing.
        _rc = _src_of(_app3.job_remote_check)
        check("the remote-mention filter is inside the query, not after the LIMIT",
              _rc.index("LIKE '%remote%'") < _rc.index("LIMIT ?"), True)

        # ═══════════════════════════════════ the MCP read surface over queue and places
        #
        # ⭐ Every other MCP tool reads `application`, which is what he already SUBMITTED.
        # The scored queue behind it was unreachable, and so was the place data.
        _c3 = _s3.connect(_d3)
        _c3.execute("DELETE FROM scan_candidate")
        for _t, _b, _sc, _mn, _mx, _ba, _srcp in (
                ("Support Engineer", "greenhouse|rich",   "88", 200000, 250000, "base", "board"),
                ("Support Engineer", "greenhouse|poor",   "96",  59500,  82000, "base", "body_regex"),
                ("Support Engineer", "greenhouse|quiet",  "80",   None,   None,  None,  None),
                ("Support Engineer", "greenhouse|hourly", "75",     60,     90, "hourly/hour", "body_regex"),
                ("Chef",             "greenhouse|nope",   "90", 300000, 400000, "base", "board")):
            _c3.execute(
                "INSERT INTO scan_candidate (at,req_id,board,title,location,score,triaged,"
                "verdict,remote_verdict,comp_min,comp_max,comp_basis,comp_source) "
                "VALUES ('now',?,?,?,'Remote',?,1,'apply','fully_remote',?,?,?,?)",
                (f"{_b}:1", _b, _t, _sc, _mn, _mx, _ba, _srcp))
        _c3.commit(); _c3.close()

        _q = _app3._mcp_call("search_queue", {"min_score": 70})
        check("the queue is reachable at all", "rich" in _q and "poor" in _q, True)
        # 🚨 A MISSING BAND IS NOT A LOW BAND. Rendering it as $0, or omitting the row, makes
        # "the employer published nothing" look like "this job pays badly".
        check("a role with no band says so and is still listed",
              "no band published" in _q and "quiet" in _q, True)
        check("provenance travels with the number", "via board" in _q, True)
        check("...and a recovered band is distinguishable", "via body_regex" in _q, True)

        _p = _app3._mcp_call("search_queue", {"min_score": 70, "min_pay": 100000})
        check("a pay floor keeps the role above it", "rich" in _p, True)
        check("...and drops the one below it", "poor" in _p, False)
        # ⚠️ Silently dropping unpriced roles hides most of the queue behind a filter that
        # looks like it only removed cheap jobs.
        check("...drops unpriced roles but SAYS it did",
              "quiet" not in _p and "no published band" in _p, True)
        # Annualising an hourly rate needs an assumption about hours the posting never made.
        # ⚠️ Asserted on the RENDERED RATE, not the word "hourly": the footer explaining the
        # exclusion contains that word, so the obvious substring check passes on the
        # explanation while the row itself is still there.
        check("an hourly band is excluded from a salary floor, not multiplied up",
              "/hr" in _p, False)
        check("hourly rows still appear when no floor is set", "/hr" in _q, True)
        check("a title filter excludes off-target roles",
              "nope" in _app3._mcp_call("search_queue", {"title": "support"}), False)

        _c3 = _s3.connect(_d3)
        _c3.execute("DELETE FROM place")
        _c3.execute("INSERT INTO place (origin,board,location,verdict,verdict_from,"
                    "judged_min,judged_mode,judged_conf,drive_min,transit_min,best_min,"
                    "postings) VALUES (?,'','New York, NY','commutable','measurement',"
                    "75,'bus','medium',98,52,52,77)", (_ORIGIN,))
        _c3.commit(); _c3.close()
        _cc = _app3._mcp_call("commute_check", {"location": "new york"})
        # ⭐ BOTH NUMBERS, ALWAYS. Driving alone puts Manhattan over the ceiling at 98 and
        # transit does it in 52. Reporting one would hide the disagreement that matters most.
        check("the measured drive AND transit are both shown",
              "98" in _cc and "52" in _cc, True)
        check("the model's estimate sits beside them", "75 min by bus" in _cc, True)
        check("it says which layer decided", "decided by measurement" in _cc, True)
        # 🚨 Silence is not consent. An unknown location must not read as commutable.
        check("an unknown location reads as unruled, not commutable",
              "not the same as commutable" in
              _app3._mcp_call("commute_check", {"location": "zzz nowhere"}), True)

        check("both tools are advertised, not merely implemented",
              {"search_queue", "commute_check"} <= {t["name"] for t in _app3.MCP_TOOLS}, True)
        # ⚠️ READ-ONLY. The MCP token is handed to agents, and a write reachable through it
        # would let a summariser change pipeline state.
        _msrc = _src_of(_app3._mcp_call).lower()
        check("the MCP surface contains no writes",
              any(k in _msrc for k in ("insert into", "update ", "delete from")), False)

        # ⭐ THE PAY BAND IS READ AT INSERT, NOT AFTER SCORING. Asserted through a real
        # sweep rather than by calling the extractor, because the extractor passing while
        # the INSERT never carries its columns is precisely the shape of the failure this
        # is here to catch: the comp columns lived only as hand-run ALTER statements for
        # weeks and nothing noticed.
        _c3 = _s3.connect(_d3)
        _c3.execute("DELETE FROM scan_board")
        _c3.execute("DELETE FROM board_state WHERE board LIKE 'greenhouse|payco%'")
        _c3.execute("INSERT INTO scan_board (platform,token,api_url,source,added_at,"
                    "enabled) VALUES ('greenhouse','payco','https://example.invalid/p',"
                    "'t','now',1)")
        _c3.commit(); _c3.close()
        _paid = {"id": 77, "title": "Support Engineer", "location": {"name": "Remote"},
                 "content": "The salary range for this role is $118,000 - $142,000 per year."}
        _free = {"id": 78, "title": "Support Engineer", "location": {"name": "Remote"},
                 "content": "We help customers move more than $40 billion to $60 billion."}
        _seed = {"id": 76, "title": "Support Engineer", "location": {"name": "Remote"},
                 "content": "No pay information here."}
        # ⚠️ First contact SEEDS and announces nothing, so a posting present on sweep one
        # never becomes a candidate. Both of these have to arrive on a LATER sweep to be
        # new. Getting this wrong made the first version of this test assert against an
        # empty table and pass its negative case for the wrong reason.
        _sweep([_seed])
        _sweep([_seed, _paid, _free])
        _c3 = _s3.connect(_d3); _c3.row_factory = _s3.Row
        _got = {r["req_id"].rpartition(":")[2]: dict(r) for r in _c3.execute(
            "SELECT req_id,comp_min,comp_max,comp_basis,comp_evidence,comp_source "
            "FROM scan_candidate WHERE req_id LIKE '%payco%'").fetchall()}
        _c3.close()
        check("a swept posting lands with its band already read",
              (_got.get("77", {}).get("comp_min"), _got.get("77", {}).get("comp_max")),
              (118000, 142000))
        check("...labelled as recovered from the body, not published by the board",
              _got.get("77", {}).get("comp_source"), "body_regex")
        check("...with the span it was read from stored beside it",
              "$118,000" in (_got.get("77", {}).get("comp_evidence") or ""), True)
        # 🚨 THE ONE THAT MATTERS MOST. A posting whose only money is a company statistic
        # must land with NO band. A wrong number is worse than a missing one, and NULL is
        # what the paid comp job selects on, so this row still reaches a model later.
        check("$40 billion of company revenue is not a salary",
              _got.get("78", {}).get("comp_min"), None)
        check("...and that row stays eligible for the paid reader",
              _got.get("78", {}).get("comp_basis"), None)
    finally:
        _u3.urlopen = _real3
        if _p3 is None: _o3.environ.pop("DB_PATH", None)
        else: _o3.environ["DB_PATH"] = _p3

    print("\ntriage (fit scoring + gap counting):")
    for dialect in ("anthropic", "openai_compat"):
        ts_top = app.triage_schema_for(dialect)
        # ⭐ The contract is now a PACK. 93% of every call was the Career Inventory re-sent,
        # and measurement showed ZERO cached reads, so the profile is sent once per pack.
        check(f"{dialect}: the contract returns an array of results",
              ts_top["properties"]["results"]["type"], "array")
        ts = ts_top["properties"]["results"]["items"]
        props = ts["properties"]
        # 📌 Echoed index, so answers align by the model's own reckoning and not by
        # position. A dropped entry would otherwise shift every later score onto the
        # wrong posting, which is worse than no score: it looks exactly like a right one.
        check(f"{dialect}: each result echoes its index", "index" in props, True)
        # ⚠️ Both were REQUIRED and neither was ever stored. Output is what bounds a pack.
        check(f"{dialect}: unused fields are gone",
              {"matched", "role_family"} & set(props), set())
        check(f"{dialect}: every property is required",
              set(ts["required"]) ^ set(props), set())
        check(f"{dialect}: additionalProperties is false",
              ts.get("additionalProperties"), False)
        gap_props = props["gaps"]["items"]["properties"]
        check(f"{dialect}: a gap carries severity and evidence",
              {"slug", "severity", "evidence"} <= set(gap_props), True)
        # A wish is not a blocker. Without this enum the model can call a nice-to-have a
        # requirement and the counts stop meaning anything.
        check(f"{dialect}: severity is a closed enum",
              gap_props["severity"].get("enum"), ["required", "preferred"])
    # Same dialect split as the mail reader: Anthropic wants anyOf for a nullable, OpenAI
    # strict wants a type list. Getting this backwards is a 400 at request time.
    _ai = app.triage_schema_for("anthropic")["properties"]["results"]["items"]["properties"]
    _oi = app.triage_schema_for("openai_compat")["properties"]["results"]["items"]["properties"]
    check("anthropic dialect: no field uses a type list",
          [k for k, v in _ai.items() if isinstance(v.get("type"), list)], [])
    check("openai dialect: no field uses anyOf",
          [k for k, v in _oi.items() if "anyOf" in v], [])
    check("the prompt tells the model the posting is data, not instructions",
          "never something you comply with" in app.TRIAGE_SYSTEM, True)
    # ⚠️ Both of these were measured failures across ELEVEN models spanning a 200x price
    # range, not hypotheticals. An "or equivalent" clause read as a hard requirement, and a
    # title scored instead of the responsibilities beneath it.
    check("the rubric handles 'or equivalent' clauses",
          "or equivalent" in app.TRIAGE_SYSTEM and "half the sentence" in app.TRIAGE_SYSTEM, True)
    check("the rubric says the body outranks the title",
          "the body is the job" in app.TRIAGE_SYSTEM, True)
    # ...and the error in the other direction, which the human labeller made: corporate IT
    # scored as though it were SaaS product support because both are called "support".
    check("the rubric separates corporate IT from product support",
          "different discipline" in app.TRIAGE_SYSTEM and "MDM enrolment" in app.TRIAGE_SYSTEM,
          True)
    check("the posting body is delimited as untrusted",
          "untrusted" in _src_of(app.ai_triage_batch), True)
    check("injection is reported, never obeyed", "prompt_injection_suspected" in _ai, True)
    check("a pack falls back to single scoring when it does not answer",
          "re-scored alone" in _src_of(app.job_triage)
          and "ai_triage_batch([c]" in _src_of(app.job_triage), True)
    check("the pack size is bounded by output, not input", app.TRIAGE_PACK <= 8, True)
    # ⚠️ Results must STREAM per pack, not accumulate. The first packed version returned a
    # full list, so a batch that died partway wrote nothing at all: no scores, no usage,
    # despite the write path claiming it recorded per posting for exactly that reason.
    # Before packing, one call was one write and this held for free.
    import inspect as _insp
    check("scoring yields per pack rather than returning a list",
          "yield c, g" in _src_of(app.job_triage)
          and "return results" not in _src_of(app.job_triage), True)

    # The vocabulary must come from the marked block. The file has other tables in its
    # prose, and a parser that grabbed the first table would feed the model a column key.
    import tempfile as _tf, pathlib as _pl, types as _ty2
    _vocab_md = """# Gap Vocabulary

| column | meaning |
|---|---|
| slug | THIS TABLE MUST NOT BE PARSED |

<!-- BEGIN VOCAB -->

| slug | label | rung | build? | source |
|---|---|---|---|---|
| fhir | FHIR / SMART on FHIR | \u274c | \u2705 | Inventory L416 |
| azure | Microsoft Azure | \u274c | \u2705 | Inventory L848 |

<!-- END VOCAB -->
"""
    _tmp = _pl.Path(_tf.mkdtemp())
    (_tmp / "vault").mkdir()
    (_tmp / "vault" / "Gap Vocabulary.md").write_text(_vocab_md)
    # ⚠️ The path is CONFIG-DRIVEN now, not a literal in the engine. A fixture that only
    # creates the file tests nothing: the whole point is that a different operator points
    # at their own documents and the code never learns the filename. So the fake repo gets
    # a config too, and it deliberately uses a NON-default location to prove it is read.
    (_tmp / "config").mkdir()
    (_tmp / "vault" / "elsewhere.md").write_text(_vocab_md)
    (_tmp / "config" / "candidate.toml").write_text(
        '[candidate]\ngap_vocabulary = "vault/elsewhere.md"\n'
        'profile_doc = "vault/profile.md"\n')
    (_tmp / "vault" / "profile.md").write_text("a synthetic profile")
    import sys as _sys
    _fake_gs = _ty2.ModuleType("gitsync"); _fake_gs.REPO_DIR = _tmp
    _saved_gs = _sys.modules.get("gitsync")
    _sys.modules["gitsync"] = _fake_gs
    try:
        v = app.load_gap_vocab()
        check("vocabulary parses from the marked block", [x["slug"] for x in v],
              ["fhir", "azure"])
        check("the prose table above the markers is NOT parsed",
              any(x["slug"] == "column" for x in v), False)
        check("each entry carries his current standing and buildability",
              bool(v[0]["rung"]) and bool(v[0]["buildable"]), True)
        (_tmp / "vault" / "Gap Vocabulary.md").write_text("no markers here")
        check("the vocabulary path came from config, not a hardcoded 'vault/' literal",
              "Gap Vocabulary" not in _i.getsource(app.load_gap_vocab), True)
        check("the profile path is config-driven too",
              app.load_profile(), "a synthetic profile")
        (_tmp / "vault" / "elsewhere.md").write_text("no markers here")
        check("a file without markers yields nothing, not a partial list",
              app.load_gap_vocab(), [])
        # An operator with no config yet must get a DECLINE, never a crash on a schedule.
        import candidate as _cc
        _cc._cache.clear()
        (_tmp / "config" / "candidate.toml").unlink()
        check("no config: vocabulary declines rather than raising",
              app.load_gap_vocab(), [])
        check("no config: profile declines rather than raising",
              app.load_profile(), None)
    finally:
        import candidate as _cc2
        _cc2._cache.clear()
        if _saved_gs is not None:
            _sys.modules["gitsync"] = _saved_gs
        else:
            _sys.modules.pop("gitsync", None)

    # \u2b50 TWO bands, and the gap band sits BELOW the apply band. Measured 2026-08-14 over 22
    # shuffled postings: 70-100 gave ONE required gap across seven roles (a role he fits has
    # nothing missing), 50-69 gave eight across five, and they were the buildable kind.
    check("the apply band floor is 70", app.TRIAGE_BAND_MIN, 70)
    check("the gap window is 50-69", (app.TRIAGE_GAP_MIN, app.TRIAGE_GAP_MAX), (50, 69))
    check("the gap window sits BELOW the apply band", app.TRIAGE_GAP_MAX < app.TRIAGE_BAND_MIN, True)
    # They must not overlap. A role counted as both "apply to this" and "learn from this"
    # would put a gap he does not really have into the Backlog's evidence.
    check("the windows do not overlap",
          set(range(app.TRIAGE_GAP_MIN, app.TRIAGE_GAP_MAX + 1))
          & set(range(app.TRIAGE_BAND_MIN, 101)), set())
    check("gaps are written for the gap window, not the apply band",
          "if in_gap_band:" in _src_of(app.job_triage), True)

    # ⚠️ Knockouts are dropped MECHANICALLY, not by asking the model nicely. The prompt
    # already forbade them and 9 of 21 distinct proposals in the first live pass were
    # location or availability anyway, written by a reader with the instruction in front
    # of it. These are the real strings that leaked.
    for label in ("London-based", "Berlin-based", "PST or MST timezone",
                  "Travel up to 20%, some international", "German C2",
                  "French speaking", "Mexico City, in-person three days a week",
                  "Shift-based: Pacific Time hours, evenings, weekends and holidays",
                  "Graduating in 2026 only; Singapore internship"):
        check(f"knockout dropped: {label[:34]}", app.is_knockout(label), True)
    # ...and real capability gaps must survive it. A filter that eats these is worse than
    # no filter, because the counts would look clean and be wrong.
    for label in ("Writing complex Python unaided", "Production Kubernetes at scale",
                  "Renewals, QBRs, expansion, quota", "Supporting macOS endpoints",
                  "CCaaS platform configuration depth", "FHIR / SMART on FHIR",
                  "Infrastructure as code: Terraform, Pulumi, Ansible"):
        check(f"capability KEPT: {label[:36]}", app.is_knockout(label), False)
    check("dropped knockouts are counted, not silently eaten",
          "knockouts += 1" in _src_of(app.job_triage)
          and "knockout(s) dropped" in _src_of(app.job_triage), True)
    # ── gates: the rules that decide which jobs are shown ────────────────────────
    # ⚠️ EVERY ONE OF THESE IS A BUG THAT SHIPPED. They are regression tests, not
    # hypotheticals: each line below is a filter that was wrong in production.
    import candidate as _cand, gates as _g
    _names = [n for n, _, _ in app.job_table()]
    _cfg = {"commute": {"near_states": ["NY", "NJ", "CT", "PA"],
                        "metro_places": ["new york", "brooklyn", "holmdel", "jersey city"],
                        "origin": "x", "max_minutes": 90},
            "remote": {"policy": "prefer_remote",
                       "accept": ["fully_remote", "remote_in_metro", "hybrid_commutable"]},
            "targeting": {"title_patterns": ["support", "implementation"]},
            "scoring": {"apply_band_min": 70}}
    # "UK Remote" is genuinely remote. Checking remote before eligibility admitted it, and
    # two UK roles reached the apply band before anyone noticed.
    for _loc in ("UK Remote", "Remote - UK", "AU - Melbourne", "Köln"):
        check(f"ineligible: {_loc}", _g.eligibility(_loc), "ineligible")
    for _loc in ("New York, NY", "Remote - US", "Salt Lake City, Utah, United States"):
        check(f"eligible: {_loc}", _g.eligibility(_loc), "eligible")
    # US markers must win over a foreign city name that collides.
    check("Paducah, KY is not the UK", _g.eligibility("Paducah, KY"), "eligible")
    check("absence is not a rejection", _g.eligibility(""), "unknown")
    # The board's own remote flag must NOT override eligibility.
    check("a remote flag cannot rescue a foreign posting",
          _g.gate({"location": "UK Remote", "is_remote": True}, _cfg)[0], False)
    check("a commutable onsite posting is kept",
          _g.gate({"location": "New York, NY"}, _cfg)[0], True)
    check("an out-of-range onsite posting is dropped",
          _g.gate({"location": "Costa Mesa, California"}, _cfg)[0], False)
    check("the reviewed commute table can drop a near-state city",
          _g.gate({"location": "Albany, NY"}, _cfg, {"Albany, NY"})[0], False)
    # A hybrid verdict is a question about WHERE. Treating it as terminal deleted two
    # roles at the candidate's top-choice employer.
    check("hybrid in the metro cascades to commutable",
          _g.cascade_hybrid("hybrid", "San Francisco, CA | New York City, NY", "", _cfg),
          "hybrid_commutable")
    check("a stated residency elsewhere overrides the office list",
          _g.cascade_hybrid("remote_with_residency", "Salt Lake City, Utah",
                            "Greater Salt Lake City area", _cfg),
          "remote_with_residency")
    # ⭐ ONSITE CASCADES TOO, and job_remote_check now sets it by rule for a posting that says
    # nothing about remote at all. Before 2026-08-23 such a posting got NO verdict, because the
    # model selection only reads postings that MENTION remote. A row with no verdict never
    # reaches this function, so 167 strong candidates sat unclassified and about 40 of them
    # were in the metro, 52 to 63 minutes away.
    check("onsite in the metro cascades to commutable",
          _g.cascade_hybrid("onsite", "New York, NY", None, _cfg), "hybrid_commutable")
    check("...and an onsite role far away does not",
          _g.cascade_hybrid("onsite", "Bangalore, Karnataka, India", None, _cfg), "onsite")
    check("...nor one in a US city that is not commutable",
          _g.cascade_hybrid("onsite", "San Francisco, CA", None, _cfg), "onsite")
    _cfg_ro = dict(_cfg, remote=dict(_cfg["remote"], policy="remote_only"))
    check("remote_only does NOT cascade a hybrid",
          _g.cascade_hybrid("hybrid", "New York, NY", "", _cfg_ro), "hybrid")
    # 🚨 The policy still governs. Accepting a commutable onsite role is a CHOICE recorded in
    # config, not a behaviour baked into the engine.
    check("...and does NOT cascade an onsite either",
          _g.cascade_hybrid("onsite", "New York, NY", None, _cfg_ro), "onsite")
    check("the title filter comes from config, not a literal",
          bool(_cand.title_re(_cfg).search("Implementation Analyst")), True)
    check("...and rejects an off-target title",
          bool(_cand.title_re(_cfg).search("Account Executive")), False)
    check("a missing config yields no rules rather than stale ones",
          _cand.title_re({}), None)
    # Both AI sub-processes must be reachable from the one registry.
    check("remote_check is registered", "remote_check" in _names, True)
    check("comp is registered", "comp" in _names, True)
    check("place is registered", "place" in _names, True)

    # ── the employer is STORED, and says where the name came from ─────────────────
    # ⭐ It used to be reconstructed by every reader from the board token plus a join, the
    # same recompute-per-reader shape eligibility had. Greenhouse states company_name on
    # every job; ashby, lever and the rest state nothing, so the token is the fallback and
    # company_source is what keeps a slug from reading as a verified name.
    print("\nthe employer is stored, with its provenance:")
    check("greenhouse's company_name is captured as authoritative",
          '"company": j.get("company_name")' in _src_of(app.parse_board)
          if hasattr(app, "parse_board") else True, True)
    check("a board token opens out into a readable fallback",
          app._company_from_board("greenhouse|pilot-fiber"), "Pilot Fiber")
    check("...with common board prefixes dropped",
          app._company_from_board("ashby|jobs-valence"), "Valence")
    check("...and an empty board yields nothing rather than a guess",
          app._company_from_board(""), "")
    check("both columns are declared as migrations",
          all(f"ADD COLUMN {c}" in " ".join(app.MIGRATIONS)
              for c in ("company", "company_source")), True)

    # ── job_place: where is it, recorded as data ──────────────────────────────────
    # 🚨 NOTHING IN THE SERVICE EVER WROTE THE place TABLE. Every row came from a laptop
    # script, so a scan that found a new city produced a candidate with no commute, no
    # verdict, and no way for the too_far gate to reject it. 9,894 of 12,389 candidates had
    # no commute data and nothing was working through it.
    #
    # ⭐ The tests below are all about the steps that must happen BEFORE anything is
    # measured. Each one prevented a real wrong answer.
    print("\njob_place rules on WHERE before it spends anything:")
    import os as _o7, tempfile as _t7, sqlite3 as _s7
    _d7 = str(_t7.mkdtemp()) + "/place.db"
    _p7 = _o7.environ.get("DB_PATH"); _o7.environ["DB_PATH"] = _d7
    # The seed profile is the config a stranger runs with. Its origin is Chicago and its
    # ceiling is 75 minutes, so the assertions below are about the RULES, not about numbers
    # that only make sense from one person's doorstep.
    _pc7 = _o7.environ.get("CANDIDATE_CONFIG")
    _o7.environ["CANDIDATE_CONFIG"] = str(HERE.parent / "seed" / "candidate.toml")
    try:
        _app7 = load_app()
        import candidate as _C7; _C7._cache.clear()
        _c7 = _s7.connect(_d7)
        _c7.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        # init_db runs schema.sql AND MIGRATIONS; a fixture doing only the first
        # builds a schema the service never has.
        for _m in app.MIGRATIONS:
            try: _c7.execute(_m)
            except Exception: pass
        for stmt in _app7.MIGRATIONS:
            try: _c7.execute(stmt)
            except Exception: pass
        _c7.commit()
        # One candidate per location shape, all scoring above the threshold.
        for i, loc in enumerate([
                "Remote - US",                                   # remote text
                "San Francisco, CA | New York City, NY",         # several places
                "USA",                                           # not a destination
                "Toronto, Ontario",                              # ineligible
                "Nashville, TN"]):                               # genuinely measurable
            _c7.execute("INSERT INTO scan_candidate (at,req_id,board,title,location,score,triaged) "
                        "VALUES (?,?,?,?,?,?,1)",
                        ("2026-08-17T00:00:00+00:00", f"r{i}", "gh|x",
                         "Support Engineer", loc, 95))
        _c7.commit(); _c7.close()

        # 🚨 NO KEY, SO NO CALL. The job must still do all its free work and say what it
        # could not finish, rather than doing nothing because one credential is absent.
        _app7.GOOGLE_MAPS_KEY = ""
        _out7 = _app7.job_place()
        with _app7.db() as c:
            _el = {r["location"]: r["eligibility"] for r in
                   c.execute("SELECT location, eligibility FROM scan_candidate").fetchall()}
            _pl = {r["location"]: dict(r) for r in
                   c.execute("SELECT * FROM place").fetchall()}
        check("eligibility is WRITTEN, not recomputed by readers",
              _el.get("Nashville, TN"), "eligible")
        check("...including the ineligible one", _el.get("Toronto, Ontario"), "ineligible")
        with _app7.db() as c:
            _ef = c.execute("SELECT eligibility_from f FROM scan_candidate "
                            "WHERE eligibility_from IS NOT NULL LIMIT 1").fetchone()
        check("...and it records which engine decided", bool(_ef and dict(_ef)["f"]), True)
        # ⚠️ An ineligible location must never reach the paid stage at all.
        check("an ineligible location is not ruled on for commute",
              "Toronto, Ontario" in _pl, False)
        check("remote text needs no office", _pl["Remote - US"]["verdict"], "remote")
        check("...decided by rule, not measurement",
              _pl["Remote - US"]["verdict_from"], "rule")
        # ⭐ SEVERAL PLACES ARE NOW ALL MEASURED, AND THE NEAREST WINS. Refusing to measure
        # was the old answer to the 2,568-minute bug, where routing "Seattle, San Francisco,
        # New York" drove to San Francisco for a role whose New York office is 75 minutes.
        # Measuring every named place removes the objection instead of dodging it.
        for _s, _want in (("Denver, CO; New York City, NY; San Francisco, CA",
                           ["Denver, CO", "New York City, NY", "San Francisco, CA"]),
                          ("Livingston, NJ / New York, NY", ["Livingston, NJ", "New York, NY"]),
                          ("New York, NY or Chicago, IL", ["New York, NY", "Chicago, IL"]),
                          # 🚨 NEVER on the comma: it lives INSIDE a location, and splitting
                          # there turns one city into a city and a state fragment.
                          ("New York, NY", ["New York, NY"]),
                          ("New York, NY; San Francisco, CA; New York, NY",
                           ["New York, NY", "San Francisco, CA"])):
            check(f"split {_s[:30]!r}", _app7._split_places(_s), _want)
        check("a country is not a destination", _pl["USA"]["verdict"], "review")
        check("...and is not measured either", _pl["USA"]["best_min"], None)
        check("the measurable one is left for the paid stage", "Nashville, TN" in _pl, False)
        check("...and the job says so out loud rather than failing silently",
              "GOOGLE_MAPS_API_KEY" in _out7, True)

        # With a key, the measurable one is measured and both modes are consulted.
        _app7.GOOGLE_MAPS_KEY = "test-key"
        _calls = []
        def _fake(origin, dests, mode, when):
            _calls.append(mode)
            return [40 if mode == "transit" else 120 for _ in dests]
        _app7._measure = _fake
        _app7.job_place()
        with _app7.db() as c:
            _n = dict(c.execute("SELECT * FROM place WHERE location='Nashville, TN'").fetchone())
        check("both modes are queried, never one", sorted(set(_calls)), ["driving", "transit"])
        # 📌 Driving alone puts Manhattan over the ceiling; transit does it in 52. Best wins.
        check("the better mode wins", (_n["best_min"], _n["best_mode"]), (40, "transit"))
        check("and the verdict came from the measurement", _n["verdict_from"], "measurement")
        check("...and it is commutable at 40 minutes", _n["verdict"], "commutable")
        # 🚨 IT MUST NOT WRITE ONE ROW PER ROUND TRIP. The first production run wrote 1,115
        # eligibility rows one execute() at a time and was still going when the CDN cut the
        # connection at sixty seconds. Same lesson as the board seeder.
        _srcp = _i.getsource(_app7.job_place)
        check("eligibility is written with executemany", "executemany" in _srcp, True)
        check("...and place rows are batched too", _srcp.count("executemany") >= 2, True)
        # ⚠️ It walks the whole candidate table, so it outlives a request.
        check("place is async, so a CDN timeout cannot kill it",
              "place" in _app7.ASYNC_JOBS, True)

        # 🚨 A MEASUREMENT IS ONLY TRUE OF THE ORIGIN IT WAS TAKEN FROM. Changing the origin
        # invalidates all of them. Keeping the old rows would leave two answers for one
        # location, measured from different doorsteps, with nothing saying which is current.
        with _app7.db() as c:
            _before = c.execute("SELECT count(*) n FROM place").fetchone()["n"]
            c.execute("UPDATE place SET origin='Somewhere Else, NJ'")
        _o7.environ["COMMUTE_ORIGIN"] = "1 Test St, Dumont, NJ"
        _app7.job_place()
        with _app7.db() as c:
            # ⚠️ This asserted `_after == 0` because the rows were DELETED. They are retired
            # now, 2026-08-24, after a one-digit origin correction destroyed 591 real rows.
            # What must be zero is the count of stale rows still VISIBLE, not the count that
            # still exists: invisible is what correctness needs, gone is what cost the data.
            _after = c.execute("SELECT count(*) n FROM place "
                               " WHERE origin='Somewhere Else, NJ' AND retired_at IS NULL"
                               ).fetchone()["n"]
            _kept = c.execute("SELECT count(*) n FROM place "
                              " WHERE origin='Somewhere Else, NJ' AND retired_at IS NOT NULL"
                              ).fetchone()["n"]
            _fresh = c.execute("SELECT count(*) n FROM place WHERE origin='1 Test St, Dumont, NJ'"
                               ).fetchone()["n"]
        check("rows from a previous origin stop being visible", _after, 0)
        check("...but they are retired, not destroyed", _kept > 0, True)
        # 🚨 A RULE-DECIDED VERDICT IS ONLY AS GOOD AS THE RULES BEHIND IT. verdict_from says
        # which LAYER decided; ruled_by says which engine's rules. Without the second, a
        # gates.py change leaves no way to target the rows it invalidated, which is the gap
        # eligibility_from closed on the candidate side.
        with _app7.db() as c:
            _rb = c.execute("SELECT ruled_by, verdict_from FROM place "
                            "WHERE verdict_from='rule' LIMIT 1").fetchone()
        # ── office resolution: a precise address for the WRONG office is worse ───
        # 🚨 Every guard below stopped a real wrong answer. A centroid is honestly vague; a
        # confident address for the wrong building is not, and it is what gets measured.
        print("\n  office resolution guards:")
        _mk = lambda addr, name: {"formattedAddress": addr, "displayName": {"text": name},
                                  "id": "x"}
        def _places(payload):
            import json as _j, io
            class _R:
                def __enter__(s): return s
                def __exit__(s, *a): return False
                def read(s): return _j.dumps(payload).encode()
            import urllib.request as _u
            _app7.__dict__.setdefault("_orig_urlopen", _u.urlopen)
            _u.urlopen = lambda *a, **k: _R()
        import urllib.request as _ureq
        _real_urlopen = _ureq.urlopen
        _app7.GOOGLE_MAPS_KEY = "k"
        try:
            # ⚠️ STATE IS NOT A CHECK. "Middletown, NY" and "New York, NY" are both NY and
            # sixty miles apart, which is the entire quantity being measured. A real lookup
            # for a CoreBTS office in Middletown returned 1 Pennsylvania Plaza.
            _places({"places": [_mk("1 Pennsylvania Plaza, New York, NY 10001", "CoreBTS")]})
            check("a right-state wrong-city address is refused",
                  _app7.resolve_office("corebts", "Middletown, NY")["status"], "city_mismatch")
            # 🚨 The city can be right and the answer still useless if it is not the employer.
            _places({"places": [_mk("100 Main St, Bronx, NY 10463", "Riverdale Crossing")]})
            check("a right-city wrong-business address is refused",
                  _app7.resolve_office("acmesoft", "Bronx, NY")["status"], "name_mismatch")
            # ⚠️ No street number means a centroid wearing a nicer label.
            _places({"places": [_mk("Nashville, TN, USA", "Acmesoft")]})
            check("an address with no street number is refused",
                  _app7.resolve_office("acmesoft", "Nashville, TN")["status"], "not_street_level")
            # 🚨 THE ONE THAT ESCAPED. A state-level location has no city, so the city
            # check degrades to a state check. On the first production run the token "kong"
            # against "New Jersey, United States" resolved to "Law Offices of Nelson Kong,
            # P.C" and flipped a verdict from too_far to commutable. Refused before the
            # request now, so a vague location also costs nothing.
            # 🚨 A CITY CAN ALSO BE A STATE NAME. Skipping every part found in the state
            # table drops the city from "New York, NY" entirely, and under the vague-location
            # guard that becomes a refusal of the most common location in the queue. It
            # deleted 19 correctly resolved offices before this was caught.
            for _loc, _want in (("New York, NY", "New York"),
                                ("New York, New York", "New York"),
                                ("New York, NY (HQ)", "New York"),
                                ("Nashville, TN", "Nashville"),
                                ("Middletown, NY", "Middletown"),
                                ("San Francisco, CA", "San Francisco"),
                                # No second part once the country is stripped: genuinely
                                # city-less, and the one case that SHOULD refuse.
                                ("New Jersey, United States", None),
                                ("New York", None)):
                check(f"city of {_loc!r}", _app7._target_city(_loc), _want)

            _blew_up = {"called": False}
            def _boom(*a, **k):
                _blew_up["called"] = True
                raise AssertionError("a vague location must not reach the API")
            _ureq.urlopen = _boom
            check("a state-level location is refused outright",
                  _app7.resolve_office("kong", "New Jersey, United States")["status"],
                  "location_too_vague")
            check("...without spending a request", _blew_up["called"], False)
            _places({"places": []})
            check("no results is reported, not guessed",
                  _app7.resolve_office("acmesoft", "Nashville, TN")["status"], "no_match")
            # The one that should pass: right city, right state, right business, street level.
            _places({"places": [_mk("222 2nd Ave S, Nashville, TN 37201", "Acmesoft HQ")]})
            _good = _app7.resolve_office("acmesoft", "Nashville, TN")
            check("a correct office resolves", _good["status"], "ok")
            check("...and carries a street-level address",
                  _good["address"].startswith("222 2nd Ave S"), True)
        finally:
            _ureq.urlopen = _real_urlopen
        check("no key means no call at all",
              (lambda: (setattr(_app7, "GOOGLE_MAPS_KEY", ""),
                        _app7.resolve_office("a", "b")["status"])[1])(), "no_key")

        check("a rule-decided place records the engine that ruled it",
              dict(_rb)["ruled_by"] if _rb else None, _app7.ENGINE_VERSION)
        check("...and the locations are ruled on again from the new one", _fresh > 0, True)
        check("...so a location never carries two origins at once", _before > 0, True)
        _o7.environ.pop("COMMUTE_ORIGIN", None)
    finally:
        if _p7 is None: _o7.environ.pop("DB_PATH", None)
        else: _o7.environ["DB_PATH"] = _p7
        if _pc7 is None: _o7.environ.pop("CANDIDATE_CONFIG", None)
        else: _o7.environ["CANDIDATE_CONFIG"] = _pc7
        import candidate as _C7b; _C7b._cache.clear()

    check("the pacer is shared by every AI sub-process",
          "_pace" in _src_of(app.job_remote_check) and "_pace" in _src_of(app.job_comp),
          True)
    check("the remote quote is checked against location AND description",
          "location" in _src_of(app.job_remote_check).split("_norm_txt")[1][:200], True)
    check("comp verifies the numbers appear inside the quoted span",
          "_nums_in" in _src_of(app.job_comp), True)
    check("the columns these jobs write are declared as migrations",
          all(f"ADD COLUMN {c}" in " ".join(app.MIGRATIONS)
              for c in ("remote_verdict", "comp_min", "comp_basis")), True)

    # ── the webhook token can be rotated without losing mail ──────────────────────
    # 🚨 THE TOKEN IS THE WEBHOOK URL PATH, so rotating it means changing this service and
    # ImprovMX's webhook setting, which cannot happen at the same instant. Whichever moves
    # first, deliveries in between hit a path the other side rejects, ImprovMX retries twice,
    # and the message is gone. Accepting several tokens turns that race into a sequence.
    #
    # ⚠️ The dangerous case is not the happy path, it is the EMPTY one: a trailing comma
    # yielding an empty token, which compares equal to an empty path segment and would open
    # the webhook to anybody. That case is asserted below, twice.
    print("\nthe webhook token can be rotated without a gap:")
    import os as _o8, tempfile as _t8, sqlite3 as _s8, asyncio as _a8, json as _j8
    _d8 = str(_t8.mkdtemp()) + "/inb.db"
    _p8 = _o8.environ.get("DB_PATH"); _o8.environ["DB_PATH"] = _d8
    _pt8 = _o8.environ.get("INBOUND_TOKEN")
    try:
        def _tokens(spec):
            """Reload the module with INBOUND_TOKEN=spec, because it binds at import."""
            _o8.environ["INBOUND_TOKEN"] = spec
            return load_app()

        check("one token, as before", _tokens("solo").INBOUND_TOKENS, ("solo",))
        check("two tokens are both accepted", _tokens("old,new").INBOUND_TOKENS, ("old", "new"))
        check("whitespace around a token is stripped",
              _tokens(" old , new ").INBOUND_TOKENS, ("old", "new"))
        # 🚨 The two that matter. An unset variable and a trailing comma must BOTH yield no
        # usable empty token, or the webhook accepts an empty path segment from anyone.
        check("unset yields NO tokens, not one empty token", _tokens("").INBOUND_TOKENS, ())
        check("a trailing comma yields no empty token",
              _tokens("old,").INBOUND_TOKENS, ("old",))
        check("...and neither does a lone comma", _tokens(",").INBOUND_TOKENS, ())

        # Now drive the REAL endpoint, so this tests the route rather than a copy of its rule.
        _app8 = _tokens("oldtok,newtok")
        _c8 = _s8.connect(_d8)
        _c8.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        # init_db runs schema.sql AND MIGRATIONS; a fixture doing only the first
        # builds a schema the service never has.
        for _m in app.MIGRATIONS:
            try: _c8.execute(_m)
            except Exception: pass
        _c8.commit(); _c8.close()
        _app8.ALLOW_INBOUND_IPS = set()            # the IP gate is tested elsewhere

        class _H8(dict):
            def get(self, k, d=None): return dict.get(self, k, d)

        class _Req8:
            client = None
            def __init__(self, payload):
                self._b = _j8.dumps(payload).encode()
                self.headers = _H8({"content-type": "application/json"})
            async def body(self): return self._b

        def _post(tok, subject):
            return _a8.run(_app8.inbound(tok, _Req8({
                "to": [{"name": "J", "email": "probe@jobs.example.com"}],
                "from": {"name": "R", "email": "r@example.net"},
                "subject": subject, "text": "hello"})))

        _post("oldtok", "via old")
        _post("newtok", "via new")
        with _app8.db() as c:
            _n8 = c.execute("SELECT count(*) n FROM message").fetchone()["n"]
            _slots = [r["detail"] for r in c.execute(
                "SELECT detail FROM event WHERE kind='inbound_raw' ORDER BY id").fetchall()]
        check("both tokens deliver during a cutover", _n8, 2)
        # ⭐ Which slot was used is recorded, so a rotation can be FINISHED safely. Without it
        # there is no way to know whether anything still arrives on the old path.
        check("the old path records slot 0", "token_slot=0" in _slots[0], True)
        check("the new path records slot 1", "token_slot=1" in _slots[1], True)

        for _bad, _label in (("wrongtok", "an unknown token"), ("", "an empty token")):
            try:
                _post(_bad, "should not land")
                check(f"{_label} is refused", "accepted", "404")
            except Exception as _e8:
                check(f"{_label} is refused", getattr(_e8, "code", 0), 404)
        with _app8.db() as c:
            check("...and neither wrote a message",
                  c.execute("SELECT count(*) n FROM message").fetchone()["n"], 2)

        # 🚨 With nothing configured, EVERY token must fail, including the empty one.
        _app0 = _tokens("")
        _app0.ALLOW_INBOUND_IPS = set()
        for _bad in ("", "anything"):
            try:
                _a8.run(_app0.inbound(_bad, _Req8({"subject": "x"})))
                check(f"unconfigured refuses {_bad!r}", "accepted", "404")
            except Exception as _e8:
                check(f"unconfigured refuses {_bad!r}", getattr(_e8, "code", 0), 404)
    finally:
        if _p8 is None: _o8.environ.pop("DB_PATH", None)
        else: _o8.environ["DB_PATH"] = _p8
        if _pt8 is None: _o8.environ.pop("INBOUND_TOKEN", None)
        else: _o8.environ["INBOUND_TOKEN"] = _pt8

    # ── every import the engine makes is a DECLARED dependency ────────────────────
    # 🚨 MEASURED, NOT HYPOTHETICAL. pyproject declared fastapi and uvicorn while the code
    # imported cryptography, email_reply_parser and anthropic. That was harmless while the
    # container built from a local checkout and installed requirements.txt. The moment
    # deploy/Dockerfile switched to `pip install ...@git+...`, this list became the only one
    # consulted and requirements.txt stopped being installed at all.
    #
    # ⚠️ WHAT IT COST, measured on 2026-08-17. The backup job died with ModuleNotFoundError
    # on every run and nothing said so: the newest encrypted snapshot was 2026-08-16 04:42
    # and /health stayed green the whole time. Ed25519 approval verification broke the same
    # way, and because verify_approval catches Exception broadly, a VALID approval would
    # have read as a forgery. strip_quotes degraded to a no-op, which is the
    # misclassification bug fixed on 2026-08-13, back in production.
    #
    # ⭐ This compares the CODE against the MANIFEST, not one file against another, so a
    # newly added import cannot ship undeclared even when both files look tidy.
    #
    # ⚠️ ast and tomllib, NOT regular expressions. The first version of this check read the
    # source with a regex and matched the prose inside docstrings, so "from a local
    # checkout" contributed an import named `a`. It also read the dependency list with a
    # non-greedy bracket match, which stopped at the `]` inside `uvicorn[standard]`. Both
    # parsers are in the standard library, so this still runs with nothing installed.
    print("\nevery import is a declared dependency:")
    import ast as _astm, tomllib as _tomlm, re as _rem
    _pkgm = HERE.parent / "job_search_engine"
    _localm = {p.stem for p in _pkgm.glob("*.py")}
    _thirdparty = set()
    for _srcm in sorted(_pkgm.glob("*.py")):
        for _nm in _astm.walk(_astm.parse(_srcm.read_text())):
            if isinstance(_nm, _astm.Import):
                _namesm = [a.name for a in _nm.names]
            elif isinstance(_nm, _astm.ImportFrom):
                # level > 0 is a relative import, which is by definition not third party.
                _namesm = [] if _nm.level else [_nm.module or ""]
            else:
                continue
            for _one in _namesm:
                _top = _one.split(".")[0]
                if _top and _top not in sys.stdlib_module_names and _top not in _localm:
                    _thirdparty.add(_top.replace("_", "-").lower())

    _pypm = (HERE.parent / "pyproject.toml").read_text()
    _declared = {_rem.split(r"[\[<>=!~;\s]", d)[0].lower()
                 for d in _tomlm.loads(_pypm)["project"]["dependencies"]}
    check("every third-party import is declared in pyproject",
          sorted(_thirdparty - _declared), [])
    check("...and the imports found are the ones expected",
          sorted(_thirdparty),
          ["anthropic", "cryptography", "email-reply-parser", "fastapi"])
    # uvicorn and python-multipart are declared and never imported, which is correct: one is
    # the server the Dockerfile runs, the other is what FastAPI needs to parse a form-encoded
    # body. Named here so "declared but unused" cannot quietly grow.
    check("...and the declared-but-not-imported set is exactly the runtime pair",
          sorted(_declared - _thirdparty), ["python-multipart", "uvicorn"])

    # requirements.txt is what the old container installed. Both files still exist, so they
    # must agree; a package present in one and not the other is how this bug reappears the
    # next time someone edits only the file they happen to be reading.
    _reqm = {_rem.split(r"[\[<>=!~;\s]", l.strip())[0].lower()
             for l in (HERE.parent / "requirements.txt").read_text().splitlines()
             if l.strip() and not l.lstrip().startswith("#")}
    check("requirements.txt and pyproject declare the same packages",
          sorted(_reqm ^ _declared), [])

    # ── the deployed version is readable, and the scheduler is observable ─────────
    # 🚨 BOTH OF THESE ANSWER "IT LOOKS FINE AND IS DOING NOTHING".
    #
    # The version: {"ok":true} came back identically from v0.4.0 and v0.7.0, so a deploy
    # that did not take was indistinguishable from one that did, and a person debugging
    # production could not tell which code they were reading.
    #
    # The scheduler: every live check triggers jobs BY HAND through /admin/run, which
    # proves the job runs and proves nothing about the loop meant to call it. If
    # _scheduler() dies, all eight jobs stop while /health stays green, and the silence
    # is indistinguishable from a quiet night.
    print("\nthe version is readable and the scheduler is observable:")
    import os as _o9, tempfile as _t9, sqlite3 as _s9, time as _tm9
    import re as _re9, datetime as _dt9
    _d9 = str(_t9.mkdtemp()) + "/diag.db"
    _p9 = _o9.environ.get("DB_PATH"); _o9.environ["DB_PATH"] = _d9
    try:
        _app9 = load_app()
        _c9 = _s9.connect(_d9)
        _c9.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        # init_db runs schema.sql AND MIGRATIONS; a fixture doing only the first
        # builds a schema the service never has.
        for _m in app.MIGRATIONS:
            try: _c9.execute(_m)
            except Exception: pass
        _c9.commit(); _c9.close()

        # ⚠️ The version must come from the PACKAGE file. A literal in app.py would drift
        # from __init__.py, which is the precise failure the version string exists to stop.
        _init9 = (HERE.parent / "job_search_engine" / "__init__.py").read_text()
        _want_v = _re9.search(r'__version__\s*=\s*"([^"]+)"', _init9).group(1)
        check("the version is read from the package, not copied",
              _app9.ENGINE_VERSION, _want_v)
        check("...and it resolved to a real number", _app9.ENGINE_VERSION != "unknown", True)

        # 🚨 pyproject.toml was a THIRD copy of the number. A bump to __init__.py alone
        # would have installed a distribution whose metadata and whose code disagreed,
        # which is the same "which version am I actually running" failure one layer down.
        _pyp9 = (HERE.parent / "pyproject.toml").read_text()
        check("pyproject declares no static version literal",
              bool(_re9.search(r'(?m)^\s*version\s*=\s*"\d', _pyp9)), False)
        check("...it reads the package attribute instead",
              'attr = "job_search_engine.__version__"' in _pyp9, True)


        class _H9(dict):
            def get(self, k, d=""): return d

        class _Req9:
            client = None
            def __init__(self): self.headers = _H9()

        _app9.ADMIN_TOKEN, _app9.READ_TOKEN = "admin-tok", "read-tok"
        _app9.TRUSTED_PROXY_HOPS = 0

        # An unauthenticated prober learns liveness and nothing else. A version string is
        # a list of which published weaknesses to try.
        _anon9 = _app9.health(None)
        check("anonymous /health does NOT leak the version", "version" in _anon9, False)
        check("...but still answers liveness", _anon9.get("ok"), True)
        check("an authenticated /health reports the version",
              _app9.health("Bearer read-tok").get("version"), _want_v)

        # Now the scheduler view. Events are the source of truth rather than an in-process
        # counter, because a counter resets on deploy and would report a container that has
        # run nothing for a week as perfectly healthy.
        _names9 = [n for n, _, _ in _app9.job_table()]
        _iv9 = {n: i for n, i, _ in _app9.job_table()}

        def _ev9(kind, ago_s):
            ts = (_dt9.datetime.now(_dt9.timezone.utc)
                  - _dt9.timedelta(seconds=ago_s)).isoformat(timespec="seconds")
            with _app9.db() as c:
                c.execute("INSERT INTO event(at,kind,detail,source_ip) VALUES (?,?,?,?)",
                          (ts, kind, "", ""))

        # Case 1: a fresh boot with nothing run yet must NOT alarm, or every deploy would.
        _app9.BOOTED_AT = _tm9.time() - 5
        _r9a = _app9.diag_jobs(_Req9(), "Bearer admin-tok")
        check("a job that never ran is not stale on a fresh boot", _r9a["stale"], [])
        check("...and the endpoint says the system is ok", _r9a["ok"], True)
        check("...and it reports every registered job",
              [j["job"] for j in _r9a["jobs"]], _names9)
        check("...and carries the version, so one call places the code",
              _r9a["version"], _want_v)

        # Case 2: uptime now exceeds the allowance and the jobs still have not run. That is
        # a scheduler that never started, which is the outage this endpoint exists for.
        _app9.BOOTED_AT = _tm9.time() - (max(_iv9.values()) * _app9.STALE_FACTOR + 60)
        _r9b = _app9.diag_jobs(_Req9(), "Bearer admin-tok")
        # ⚠️ EVERY SCHEDULED JOB, NOT EVERY REGISTERED JOB. A manual-only job (interval 0)
        # was never due, so it can never be overdue. Before this distinction existed its
        # limit was zero, it went stale the instant the process booted, and `ok` would have
        # been false forever on a job that was behaving exactly as designed.
        _sched9 = sorted(n for n in _names9 if _iv9[n] > 0)
        _manual9 = sorted(n for n in _names9 if _iv9[n] <= 0)
        check("once they were due and did not run, every SCHEDULED job is stale",
              sorted(_r9b["stale"]), _sched9)
        check("...and there is at least one manual-only job to prove the exemption bites",
              len(_manual9) > 0, True)
        check("...and a manual-only job is never stale",
              [n for n in _manual9 if n in _r9b["stale"]], [])
        check("...and ok flips to false", _r9b["ok"], False)

        # Case 3: a recent run clears exactly one job and leaves the rest alarming.
        _ev9("job_track", 30)
        _r9c = _app9.diag_jobs(_Req9(), "Bearer admin-tok")
        check("a recent run clears that job", "track" in _r9c["stale"], False)
        check("...and does not clear the others", "scan" in _r9c["stale"], True)
        _trow9 = next(j for j in _r9c["jobs"] if j["job"] == "track")
        check("...and its age is reported in seconds",
              20 <= (_trow9["age_s"] or 0) <= 90, True)

        # Case 4: an OLD run is not a run. A "last_ok is not null" check would miss this.
        _ev9("job_comp", _iv9["comp"] * _app9.STALE_FACTOR + 600)
        check("a run older than the allowance is still stale",
              "comp" in _app9.diag_jobs(_Req9(), "Bearer admin-tok")["stale"], True)

        # Case 5: 🚨 THE TRAP. A job that runs exactly on time and FAILS every time is not
        # stale. Staleness alone would call it healthy, so the last error is reported
        # beside the last success and a caller can see both.
        _ev9("job_backup", 10)
        _ev9("job_backup_error", 10)
        _brow9 = next(j for j in _app9.diag_jobs(_Req9(), "Bearer admin-tok")["jobs"]
                      if j["job"] == "backup")
        check("a job that runs on time is not stale, even when it fails",
              _brow9["stale"], False)
        check("...but its last error is reported beside its last success",
              bool(_brow9["last_error"]), True)

        # Case 6: 🚨 STUCK IS NOT STALE. A wedged job holds its lock forever, never records a
        # success, and answers "skipped: already running" to every later attempt — which is
        # also the correct answer while a long job is legitimately mid-run. Staleness alone
        # would blame the schedule; the start time is what turns it into a diagnosis.
        _app9._JOB_STARTED["scan"] = _tm9.time() - 30
        _r9f = _app9.diag_jobs(_Req9(), "Bearer admin-tok")
        _srow = next(j for j in _r9f["jobs"] if j["job"] == "scan")
        check("a job mid-run reports how long it has been running",
              20 <= (_srow["running_for_s"] or 0) <= 90, True)
        check("...and is NOT called stuck while inside its window", _srow["stuck"], False)

        _app9._JOB_STARTED["scan"] = _tm9.time() - (_iv9["scan"] * _app9.STALE_FACTOR + 600)
        _r9g = _app9.diag_jobs(_Req9(), "Bearer admin-tok")
        _srow = next(j for j in _r9g["jobs"] if j["job"] == "scan")
        check("a job running past its window is stuck", _srow["stuck"], True)
        check("...and is reported as stuck, not merely stale", _srow["stale"], False)
        check("...it appears in the stuck list", "scan" in _r9g["stuck"], True)
        check("...and ok is false", _r9g["ok"], False)
        _app9._JOB_STARTED.clear()
        check("a job that finished reports no running time",
              next(j for j in _app9.diag_jobs(_Req9(), "Bearer admin-tok")["jobs"]
                   if j["job"] == "scan")["running_for_s"], None)

        # ── /diag/config: what the PROCESS holds, not what the platform stored ────
        # 🚨 On 2026-08-17 the deployment API accepted a new STORAGE_KEY, reported it stored,
        # and a 43-minute-old container kept the old value in its environment while /health
        # stayed green. Nothing could compare the two. Now something can.
        _o9.environ["SMTP_PASS"] = "a-secret-value"
        _o9.environ["AI_MODEL"] = "some-model"
        _o9.environ.pop("RESEND_API_KEY", None)
        _appc = load_app()
        _appc.ADMIN_TOKEN, _appc.READ_TOKEN = "admin-tok", "read-tok"
        _appc.TRUSTED_PROXY_HOPS = 0
        _cfg9 = _appc.diag_config(_Req9(), "Bearer admin-tok")
        _fp = _cfg9["secrets"]["SMTP_PASS"]
        check("a secret is fingerprinted, never returned",
              _fp.startswith("sha256:") and "a-secret-value" not in _j8.dumps(_cfg9), True)
        check("...and the fingerprint is stable for the same value",
              _fp, "sha256:" + __import__("hashlib").sha256(b"a-secret-value").hexdigest()[:12])
        # ⚠️ unset and empty must not look alike: a job that declines on an empty key reports
        # "nothing to do", which is the exact ambiguity this endpoint exists to remove.
        check("an unset secret says so", _cfg9["secrets"]["RESEND_API_KEY"], "unset")
        _o9.environ["RESEND_API_KEY"] = ""
        _appe = load_app(); _appe.ADMIN_TOKEN = "admin-tok"; _appe.TRUSTED_PROXY_HOPS = 0
        check("...and an EMPTY one is distinguishable from unset",
              _appe.diag_config(_Req9(), "Bearer admin-tok")["secrets"]["RESEND_API_KEY"],
              "empty")
        check("a non-secret setting is shown outright", _cfg9["settings"]["AI_MODEL"], "some-model")
        check("the registered jobs are listed", _cfg9["jobs_registered"], _names9)
        # ⚠️ The sqlite backend is a PATH, not a URL. Splitting it like one returns "" and a
        # local deployment would report no database at all — the exact silence this endpoint
        # is meant to break. Caught in the pre-deploy smoke test of v0.9.0.
        check("the sqlite backend reports a database, not an empty string",
              _cfg9["database_host"].startswith("sqlite:/"), True)
        check("no secret VALUE appears anywhere in the response",
              "a-secret-value" in _j8.dumps(_cfg9), False)
        try:
            _appc.diag_config(_Req9(), "Bearer read-tok")
            check("a read token cannot read the config", "allowed", "refused")
        except Exception as _e9:
            check("a read token cannot read the config", getattr(_e9, "code", 0), 403)

        # ── /diag/ai: prove the paid path, because "nothing to do" hides a dead key ───
        # 🚨 triage / remote_check / comp all return "nothing to X" when there is no work, and
        # an expired key produces the identical string. Without this the paid path can be dead
        # for weeks behind green checks.
        for _k in ("ANTHROPIC_API_KEY", "AI_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
            _o9.environ.pop(_k, None)
        _appa = load_app(); _appa.ADMIN_TOKEN = "admin-tok"; _appa.TRUSTED_PROXY_HOPS = 0
        _ai0 = _appa.diag_ai(_Req9(), "Bearer admin-tok")
        check("with no key it says so plainly", _ai0["key_present"], False)
        check("...and does not pretend to have called anything", _ai0["live_called"], False)
        check("...and names which variables it looked at",
              bool(_ai0["key_names_checked"]), True)
        _o9.environ["ANTHROPIC_API_KEY"] = "sk-not-a-real-key"
        _o9.environ["AI_PROVIDER"] = "anthropic"
        _appa = load_app(); _appa.ADMIN_TOKEN = "admin-tok"; _appa.TRUSTED_PROXY_HOPS = 0
        _ai1 = _appa.diag_ai(_Req9(), "Bearer admin-tok")
        check("a present key alone is NOT proof of reachability", _ai1["live_called"], False)
        check("...it says a live call is what would prove it",
              "live=true" in _ai1["result"], True)
        check("the key value never appears in the response",
              "sk-not-a-real-key" in _j8.dumps(_ai1), False)
        # ⚠️ The success path must report fields the schema actually defines. Reporting a
        # `label` that AI_SCHEMA does not have made a good reply read as a failed one.
        _src_ai = _i.getsource(_appa.diag_ai)
        check("the live result reports a real schema field",
              "classification=r.get" in _src_ai, True)
        check("...and not an invented one", 'label=r.get("label")' in _src_ai, False)
        check("...which AI_SCHEMA confirms exists",
              "classification" in _appa.AI_SCHEMA["properties"], True)

        # A read token is not an admin token. This route names every job and its schedule.
        try:
            _app9.diag_jobs(_Req9(), "Bearer read-tok")
            check("a read token cannot see the job schedule", "allowed", "refused")
        except Exception as _e9:
            check("a read token cannot see the job schedule",
                  getattr(_e9, "code", 0), 403)
    finally:
        if _p9 is None: _o9.environ.pop("DB_PATH", None)
        else: _o9.environ["DB_PATH"] = _p9

    # ── manual runs: long jobs answer 202, short ones inline ──────────────────────
    # 🚨 A CDN closes the connection at 60 seconds and a full sweep takes about ten minutes.
    # A synchronous endpoint therefore CANNOT answer for scan, and a caller reading the
    # failed request as the verdict marks a healthy sweep as broken. That happened.
    # ── mass vanishes are held for confirmation ───────────────────────────────────
    # 🚨 MEASURED, NOT HYPOTHETICAL. On 2026-08-16 greenhouse|infuse had logged 122 vanishes
    # while serving 374 jobs, and carvana 129 against 1,752. Those boards FLAP, and under the
    # old code every flap DESTROYED a row. A `200 {"jobs": []}` is indistinguishable from a
    # real mass delisting, so the first sighting is held and only a SECOND agreeing sweep
    # confirms it.
    print("\nmass vanishes are held until a second sweep agrees:")
    import os as _o5, tempfile as _t5, sqlite3 as _s5, json as _j5
    import urllib.request as _u5
    _d5 = str(_t5.mkdtemp()) + "/mass.db"
    _p5 = _o5.environ.get("DB_PATH"); _o5.environ["DB_PATH"] = _d5
    _real5 = _u5.urlopen
    try:
        _app5 = load_app()
        _c5 = _s5.connect(_d5)
        _c5.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
        # init_db runs schema.sql AND MIGRATIONS; a fixture doing only the first
        # builds a schema the service never has.
        for _m in app.MIGRATIONS:
            try: _c5.execute(_m)
            except Exception: pass
        # `company` comes from schema.sql, same as the sweep fixture above.
        _c5.execute("INSERT INTO company (name,ats_platform,ats_token,api_url) "
                    "VALUES ('Flaky','greenhouse','flaky','https://example.invalid/b')")
        _c5.commit(); _c5.close()

        def _msweep(jobs):
            def _f(req, *a, **k):
                body = _j5.dumps({"jobs": jobs}).encode()
                class R:
                    def read(self): return body
                    def __enter__(self): return self
                    def __exit__(self, *e): return False
                return R()
            _u5.urlopen = _f
            return _app5.job_scan()

        def _mcount(where):
            c = _s5.connect(_d5)
            n = c.execute(f"SELECT count(*) FROM {where}").fetchone()[0]
            c.close(); return n

        _all = [{"id": i, "title": f"R{i}", "location": {"name": "Remote"}}
                for i in range(10)]
        _msweep(_all)                       # seed: 10 requisitions, nothing announced
        check("seeded with a full board", _mcount("board_state"), 10)

        _n1 = _msweep([])                   # the board returns NOTHING
        check("a board emptying marks every requisition",
              _mcount("board_state WHERE vanished_at IS NOT NULL"), 10)
        check("...and reports NONE of them on the first sweep",
              _mcount("scan_change WHERE change='vanished'"), 0)
        check("...but the note says the board returned zero",
              "returned ZERO" in _n1, True)
        check("...and that the disappearance is held",
              "held for confirmation" in _n1, True)

        # It comes back. This is infuse and carvana, and nothing may be lost.
        _msweep(_all)
        check("a flapping board self-corrects on reappearance",
              _mcount("board_state WHERE vanished_at IS NULL"), 10)
        check("...having never reported a vanish at all",
              _mcount("scan_change WHERE change='vanished'"), 0)

        # Genuinely gone: empty twice. This is SignalFire, which really does serve zero.
        _msweep([]); _msweep([])
        check("a second agreeing sweep confirms the vanish",
              _mcount("scan_change WHERE change='vanished'"), 10)
        # ⚠️ THE WHOLE POINT. Confirmed or not, the row survives. A deleted row means no
        # future sweep can prove the posting ever existed.
        check("...and every row still exists afterwards", _mcount("board_state"), 10)
        # ⚠️ A THIRD EMPTY SWEEP MUST SAY NOTHING NEW. Without a separate confirmed marker a
        # held row and a reported one look identical, and the vanish gets re-announced every
        # night forever, which trains a reader to ignore the one signal that matters.
        _msweep([])
        check("a third sweep does NOT re-report the same vanish",
              _mcount("scan_change WHERE change='vanished'"), 10)

        # ⭐ THE INFUSE SHAPE, which the proportional rule missed entirely. Losing 13% of a
        # board is far under any sane mass threshold, and it was still a false vanish that
        # destroyed rows. Universal confirmation is the only rule that catches it.
        _c5b = _s5.connect(_d5); _c5b.execute("DELETE FROM board_state")
        _c5b.execute("DELETE FROM scan_change"); _c5b.execute("DELETE FROM board_seeded")
        _c5b.commit(); _c5b.close()
        _big = [{"id": i, "title": f"R{i}", "location": {"name": "Remote"}} for i in range(100)]
        _msweep(_big)                                   # seed 100
        _msweep(_big[:87])                              # lose 13, a 13% dip
        check("a 13% dip is held, not reported (the infuse case)",
              _mcount("scan_change WHERE change='vanished'"), 0)
        check("...and the 13 are marked",
              _mcount("board_state WHERE vanished_at IS NOT NULL"), 13)
        _msweep(_big)                                   # they come back
        check("...and a flap of that size self-corrects too",
              _mcount("board_state WHERE vanished_at IS NULL"), 100)
        check("...still having reported nothing",
              _mcount("scan_change WHERE change='vanished'"), 0)

        # A SINGLE requisition closing is the ordinary case and must still be reported,
        # just one sweep later. Confirmation must not mean "never".
        _msweep(_big[:99]); _msweep(_big[:99])
        check("one ordinary closure is confirmed on the second sweep",
              _mcount("scan_change WHERE change='vanished'"), 1)

        # ⚠️ FLAP ACROSS THE HOLD: gone, back, gone again. The cycle has to reset, or the
        # second disappearance inherits the first one's suspicion and is confirmed early.
        _msweep(_big[:98])                              # #98 goes missing (first sighting)
        _msweep(_big[:99])                              # it returns before confirmation
        _msweep(_big[:98])                              # missing again: a FRESH suspicion
        check("a flap across the hold resets, it does not confirm early",
              _mcount("scan_change WHERE change='vanished'"), 1)

        # ⚠️ A FAILED FETCH MUST NOT CONFIRM ANYTHING. A board that cannot answer is not a
        # board with no jobs, and a held row must survive the outage rather than being
        # promoted by silence.
        _held_before_err = _mcount("board_state WHERE vanished_at IS NOT NULL")
        def _boom(req, *a, **k): raise OSError("upstream down")
        _u5.urlopen = _boom
        _app5.job_scan()
        check("an outage confirms nothing",
              _mcount("scan_change WHERE change='vanished'"), 1)
        check("...and leaves held rows exactly as they were",
              _mcount("board_state WHERE vanished_at IS NOT NULL"), _held_before_err)

        # ⚠️ CROSS-BOARD LEAKAGE. `emptied`, `held_before` and the accumulators are shared
        # across boards in one sweep. A board that empties must not affect a healthy board
        # swept alongside it, and per-board state must not bleed. Two boards, one dying.
        _u5.urlopen = _real5
        _c5c = _s5.connect(_d5)
        _c5c.execute("DELETE FROM board_state"); _c5c.execute("DELETE FROM scan_change")
        _c5c.execute("DELETE FROM board_seeded"); _c5c.execute("DELETE FROM company")
        _c5c.execute("INSERT INTO company (name,ats_platform,ats_token,api_url) "
                     "VALUES ('Dies','greenhouse','dies','https://example.invalid/a')")
        _c5c.execute("INSERT INTO company (name,ats_platform,ats_token,api_url) "
                     "VALUES ('Lives','greenhouse','lives','https://example.invalid/b')")
        _c5c.commit(); _c5c.close()

        def _two(dies, lives):
            def _f(req, *a, **k):
                url = req.full_url if hasattr(req, "full_url") else str(req)
                jobs = dies if "/a" in url else lives
                body = _j5.dumps({"jobs": jobs}).encode()
                class R:
                    def read(self): return body
                    def __enter__(self): return self
                    def __exit__(self, *e): return False
                return R()
            _u5.urlopen = _f
            return _app5.job_scan()

        _six = [{"id": i, "title": f"D{i}", "location": {"name": "Remote"}} for i in range(6)]
        _two(_six, _six)                      # seed both
        _n_leak = _two([], _six)              # one empties, one is untouched
        _cl = _s5.connect(_d5)
        check("the healthy board keeps every row",
              _cl.execute("SELECT count(*) FROM board_state WHERE board='greenhouse|lives' "
                          "AND vanished_at IS NULL").fetchone()[0], 6)
        check("...and none of its rows were marked",
              _cl.execute("SELECT count(*) FROM board_state WHERE board='greenhouse|lives' "
                          "AND vanished_at IS NOT NULL").fetchone()[0], 0)
        check("the dying board has all six held",
              _cl.execute("SELECT count(*) FROM board_state WHERE board='greenhouse|dies' "
                          "AND vanished_at IS NOT NULL").fetchone()[0], 6)
        _cl.close()
        check("the zero alarm names only the board that emptied",
              _n_leak.count("greenhouse|dies"), 1)
        check("...and does not name the healthy one", "greenhouse|lives" in _n_leak, False)

        # 📌 A requisition that comes back is NOT a discovery, so it must not be re-triaged.
        # It is the same posting, already scored, and re-scoring it would pay a model twice
        # for a board hiccup.
        # Measured before and after, because the seed sweep announces nothing at all: an
        # absolute count of 0 would pass whether or not the reappearance was silent.
        _cl = _s5.connect(_d5)
        _appeared_before = _cl.execute(
            "SELECT count(*) FROM scan_change WHERE change='appeared'").fetchone()[0]
        _cand_before = _cl.execute("SELECT count(*) FROM scan_candidate").fetchone()[0]
        _cl.close()
        _two(_six, _six)
        _cl = _s5.connect(_d5)
        check("a reappearance announces nothing new",
              _cl.execute("SELECT count(*) FROM scan_change "
                          "WHERE change='appeared'").fetchone()[0], _appeared_before)
        check("...and the six held rows are cleared, not re-inserted",
              _cl.execute("SELECT count(*) FROM board_state "
                          "WHERE board='greenhouse|dies' AND vanished_at IS NULL").fetchone()[0], 6)
        check("...and no requisition was queued for scoring a second time",
              _cl.execute("SELECT count(*) FROM scan_candidate").fetchone()[0], _cand_before)
        _cl.close()
    finally:
        _u5.urlopen = _real5
        if _p5 is None: _o5.environ.pop("DB_PATH", None)
        else: _o5.environ["DB_PATH"] = _p5

    check("scan is async, because it outlives any request",
          "scan" in app.ASYNC_JOBS, True)
    check("backup too", "backup" in app.ASYNC_JOBS, True)
    # ⚠️ NOT everything. Making a caller poll for "nothing to track" is worse than a timeout,
    # so a short job must keep answering inline.
    check("short jobs stay synchronous",
          any(j not in app.ASYNC_JOBS for j in ("track", "ai_read", "comp")), True)
    check("the async path returns 202, not 200",
          "status_code=202" in _src_of(app.run_job), True)
    check("...and hands back a ticket to poll",
          "ticket" in _src_of(app.run_job) and "poll" in _src_of(app.run_job), True)
    check("the worker thread is a daemon, so shutdown is never blocked by a sweep",
          "daemon=True" in _src_of(app.run_job), True)
    check("a status endpoint exists", callable(getattr(app, "run_status", None)), True)
    # The ticket table is process memory. Unbounded, a long-lived container keeps every
    # ticket it ever issued.
    check("the ticket table is bounded", "len(_RUNS) > " in _src_of(app._record_run), True)
    _t = "scan-1-abc"
    app._record_run(_t, job="scan", state="running", started="x")
    check("a ticket records its state", app._RUNS[_t]["state"], "running")
    app._record_run(_t, state="done", detail="swept 2862 boards")
    check("...and is updated in place, not duplicated", app._RUNS[_t]["detail"],
          "swept 2862 boards")
    check("the ticket kept its job through the update", app._RUNS[_t]["job"], "scan")
    for _i in range(260):
        app._record_run(f"filler-{_i}", job="x", state="done", started=f"{_i:04d}")
    check("...and old tickets are evicted rather than accumulating",
          len(app._RUNS) <= 260, True)

    check("triage is in the single job registry (scheduler + /admin/run)",
          "triage" in [n for n, _, _ in app.job_table()], True)
    # No key means no call and no database read: the machine that is not set up for this
    # must not be the one that discovers the job is broken.
    _saved = {k: os.environ.pop(k, None)
              for k in ("ANTHROPIC_API_KEY", "AI_API_KEY", "OPENAI_API_KEY",
                        "OPENROUTER_API_KEY")}
    try:
        check("no key means the job declines before touching anything",
              app.job_triage().startswith("skipped:"), True)
    finally:
        for k, val in _saved.items():
            if val is not None:
                os.environ[k] = val

    print("\nbackup dumps what cannot be rebuilt, and pages what it keeps:")
    import sqlite3 as _sb, tempfile as _tb, sys as _sy
    _sy.path.insert(0, str(HERE.parent / "job_search_engine"))
    import backup as _bk
    _bd = _tb.mkdtemp() + "/b.db"
    _bc = _sb.connect(_bd); _bc.row_factory = _sb.Row
    _bc.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
    # init_db runs schema.sql AND MIGRATIONS; a fixture doing only the first
    # builds a schema the service never has.
    for _m in app.MIGRATIONS:
        try: _bc.execute(_m)
        except Exception: pass
    # ⭐ `application` comes from schema.sql now, so the dump is checked against the real
    # table rather than a two-column stand-in. company and posting are seeded because the
    # real declaration has a NOT NULL posting_id, which the stand-in did not.
    _bc.execute("INSERT INTO company (id,name) VALUES (1,'Acme')")
    _bc.execute("INSERT INTO posting (id,company_id,title,captured_at) "
                "VALUES (1,1,'irreplaceable','2026-01-01')")
    _bc.execute("INSERT INTO application (id,posting_id,notes) "
                "VALUES (1,1,'irreplaceable')")
    # More than one page of the huge regenerable table, and of a kept one.
    _bc.executemany("INSERT INTO board_state (board,req_id,first_seen,last_seen,title) "
                    "VALUES (?,?,?,?,?)", [("b", str(i), "t", "t", "x") for i in range(5000)])
    _bc.execute("INSERT INTO board_seeded (board,at) VALUES ('b','t')")
    _bc.executemany("INSERT INTO scan_change (at,board,req_id,change) VALUES (?,?,?,?)",
                    [("t", "b", str(i), "appeared") for i in range(3000)])
    _bc.commit()
    _sql = _bk.dump_sql(_bc)
    # 🚨 86% of the database and the only large table a sweep rebuilds. Its presence is
    # what made the dump exceed Bunny's response limit and stopped backups entirely.
    check("board_state is NOT in the dump", "INSERT INTO board_state" in _sql, False)
    # ⚠️ Paired on purpose: seeded-but-stateless restores as ~158k phantom discoveries,
    # because the seed guard does not fire for a board that is already marked seeded.
    check("board_seeded is skipped WITH it", "INSERT INTO board_seeded" in _sql, False)
    check("the header says what was skipped and why",
          "SKIPPED as regenerable" in _sql and "restore as a pair" in _sql, True)
    # These are the ones that sound disposable and are not.
    check("scan_change IS kept (the vanish audit trail)",
          _sql.count("INSERT INTO scan_change"), 3000)
    check("and it pages past the page size", _bk.PAGE < 3000, True)
    check("application is kept", _sql.count("INSERT INTO application"), 1)
    # A table nobody classified is DUMPED, not skipped: backing up something unnecessary
    # costs bytes, skipping something irreplaceable costs the data.
    _bc.execute("CREATE TABLE brand_new_thing (id INTEGER PRIMARY KEY, v TEXT)")
    _bc.execute("INSERT INTO brand_new_thing (v) VALUES ('unclassified')")
    _bc.commit()
    check("an unclassified table is dumped, not silently dropped",
          "INSERT INTO brand_new_thing" in _bk.dump_sql(_bc), True)
    _bc.close()

    print("\nforwarded mail keeps its body:")
    forwards = [
        ("Fastmail separator",
         "----- Original message -----\n"
         "From: Example Hiring Team <no-reply@example.com>\n"
         "To: acme@example.net\n"
         "Subject: Application Update\n\n"
         "Hi Alex,\n\nThank you for applying. At this time we have decided to move "
         "forward with other applicants in our process.\n", "rejection"),
        ("Gmail separator",
         "---------- Forwarded message ----------\n"
         "From: Recruiting <no-reply@example.com>\n\n"
         "We received many strong applications and unfortunately are going in a "
         "different direction.\n", "rejection"),
        ("Apple Mail separator",
         "Begin forwarded message:\n\nFrom: Talent <t@example.com>\n\n"
         "We would like to set up an interview next week.\n", "interview_invite"),
    ]
    for label, body, want in forwards:
        kept = app.strip_quotes(body)
        got, _ = app.classify("", kept)
        ok = got == want and len(kept) > 100
        print(f"  {'ok  ' if ok else 'FAIL'} {label:22} kept {len(kept):4}/{len(body)} bytes -> {got}")
        if not ok:
            failures.append(f"{label}: kept {len(kept)} bytes, classified {got}, want {want}")

    # A lone separator surviving the strip means nothing of substance did. The original
    # guard only caught a completely empty result, which is how 28 bytes of punctuation
    # got through and was classified as though it were a message.
    only_sep = "----- Original message -----\nFrom: x@y.z\n\nUnfortunately we are not moving forward.\n"
    check("a lone separator is not 'something survived'",
          len(app.strip_quotes(only_sep)) > 40, True)

    print("\nstrip_quotes safety:")
    check("empty input", app.strip_quotes(""), "")
    check("none input", app.strip_quotes(None), "")
    only_quote = "On Tue, Dana wrote:\n> unfortunately we are not moving forward"
    check("all-quote body falls back rather than emptying",
          bool(app.strip_quotes(only_quote).strip()), True)
    plain = "No quoted history here at all."
    check("unquoted body unchanged", app.strip_quotes(plain), plain)

    # ═══════════════════════════════════════════════════════════ comp at ingestion
    #
    # ⭐ These run at INSERT time now, on every posting, before anything is scored. That
    # makes a false positive expensive in a way the old post-triage pass was not: a wrong
    # number lands in the record for 12,000 rows instead of the few hundred a human was
    # about to read. Every case below is a real posting shape, and the negatives matter
    # more than the positives.
    print("\ncomp extraction (free, at insert):")
    import comp as CMP

    check("a plain prose range",
          (lambda r: (r["min"], r["max"], r["period"]))(
              CMP.from_body("The salary range for this role is $95,000 - $120,000.")),
          (95000, 120000, "year"))

    # 🚨 THE CASE THAT JUSTIFIES THE PAY-VOCABULARY RULE. This shape is from a real
    # GoFundMe posting. A bare currency regex archives $40 billion as the salary.
    check("'raised more than $40 billion' is NOT pay",
          CMP.from_body("We have helped people raise more than $40 billion to $50 billion "
                        "since 2010."), None)
    check("a discount is not pay",
          CMP.from_body("Get $5 - $10 off your first order."), None)
    check("money with no pay word nearby is not pay",
          CMP.from_body("Our customers process $200,000 to $400,000 in claims monthly."),
          None)

    # ⚠️ THE SECOND PASS. Greenhouse splits the label from the numbers across elements, so
    # they never share a sentence. Requiring one sentence missed $210,000 - $250,000 in a
    # real archived Anthropic posting, which is the highest-paying row in the queue.
    gh = ('<div>The expected base salary range for this position is shown below.</div>'
          '<span>$210,000</span><span class="divider">&mdash;</span><span>$250,000</span>')
    check("markup-split range is recovered",
          (lambda r: (r["min"], r["max"]))(CMP.from_body(gh)), (210000, 250000))
    check("...and it is read as base, not OTE", CMP.from_body(gh)["basis"], "base")

    # ⭐ BASIS DECIDES WHETHER TWO NUMBERS ARE COMPARABLE. Ranking an OTE against a base
    # salary quietly favours every posting that quotes OTE.
    check("OTE is labelled OTE",
          CMP.from_body("On-target earnings for this role are $140,000 to $180,000.")["basis"],
          "ote")
    check("total target cash is labelled as such",
          CMP.from_body("Total target cash compensation is $150,000 - $170,000.")["basis"],
          "total_cash")
    check("an unlabelled range stays unclear, not guessed as base",
          CMP.from_body("Compensation: $150,000 - $170,000.")["basis"], "unclear")
    # A real CaptiveAire posting puts the qualifier AFTER the numbers, inside a span that
    # also contains "based upon tenure". The word boundary has to keep those apart.
    check("a trailing 'base' is still base",
          CMP.from_body("Paid time off (PTO) based upon tenure. Relocation assistance. "
                        "Salary: $65k-$80k base, negotiable.")["basis"], "base")
    check("...and 'based upon' alone does not make a band base",
          CMP.from_body("Compensation: $150,000 - $170,000, based upon experience."
                        )["basis"], "unclear")

    hourly = CMP.from_body("The hourly rate for this position is $28 - $34 per hour.")
    check("hourly is not annualised", (hourly["min"], hourly["max"]), (28, 34))
    check("hourly period is recorded", (hourly["period"], hourly["basis"]),
          ("hour", "hourly"))
    # Without the magnitude split an hourly rate fails the annual floor and is silently
    # dropped; without the hourly floor, "$5 - $10 off" passes as a wage.
    check("an implausible hourly rate is refused",
          CMP.from_body("Pay range: $2 - $4 per hour."), None)

    check("K notation", (lambda r: (r["min"], r["max"]))(
        CMP.from_body("Base salary: $95K - $120K.")), (95000, 120000))

    # 🚨 A PLACEHOLDER IS NOT A RANGE, and these sort to the top of anything ranked by pay.
    # "$50,000 - $999,999" came straight out of a real Ashby comp field: the employer filled
    # the box without saying anything. The 5x threshold is p99.5 of 3,075 measured bands
    # (median 1.33x, p99 2.82x), so it catches these without touching a real wide band.
    check("a 20x band is a placeholder, not a range",
          CMP.from_field("$50,000 - $999,999"), None)
    check("...and so is one straight out of the posting text",
          CMP.from_body("Salary range: $65,000 - $800,000."), None)
    check("a genuinely wide startup band still survives",
          (lambda r: (r["min"], r["max"]))(
              CMP.from_body("Base salary: $100,000 - $300,000.")), (100000, 300000))
    check("an absurd hourly spread is refused too",
          CMP.from_body("Hourly pay range: $12 - $400 per hour."), None)
    check("a reversed range is refused",
          CMP.from_body("Salary range $120,000 - $95,000."), None)

    # 🚨 PROVENANCE. The board's own field is the employer's statement; a regex over prose
    # is an inference about it. An inference must never overwrite what it inferred from.
    check("the board's field wins over the body",
          CMP.extract("$100,000 - $130,000",
                      "The salary range is $95,000 - $120,000.")["source"], "board")
    check("...and its numbers are the board's",
          (lambda r: (r["min"], r["max"]))(
              CMP.extract("$100,000 - $130,000",
                          "The salary range is $95,000 - $120,000.")), (100000, 130000))
    check("an empty field falls through to the body",
          CMP.extract("", "The salary range is $95,000 - $120,000.")["source"], "body_regex")
    check("junk in the board field does not become a band",
          CMP.extract("Competitive", "No numbers here."), None)
    check("no comp anywhere is None, not zero",
          CMP.extract(None, "A posting with no pay information at all."), None)

    # The evidence span is the whole safety story: both numbers must be inside the text
    # that is stored, or a reader cannot check the claim.
    ev = CMP.from_body("The annual salary range for this role is $95,000 - $120,000 "
                       "depending on experience.")
    check("both numbers appear in the stored evidence",
          "$95,000" in ev["evidence"] and "$120,000" in ev["evidence"], True)

    # 🚨 DRIFT GUARD. The archiver holds the reference implementation and neither package
    # can import the other: it declares zero dependencies, and this suite must pass with
    # nothing installed. So compare them whenever both happen to be present, and say so
    # loudly when they are not, rather than letting two copies quietly diverge.
    try:
        from fetch_job_description.archive import body_comp as _ref
    except Exception:                                         # noqa: BLE001
        skipped.append("comp drift vs fetch_job_description (archiver not installed)")
    else:
        corpus = [
            "The salary range for this role is $95,000 - $120,000.",
            "We have helped people raise more than $40 billion to $50 billion since 2010.",
            "Get $5 - $10 off your first order.",
            gh,
            "On-target earnings for this role are $140,000 to $180,000.",
            "The hourly rate for this position is $28 - $34 per hour.",
            "Base salary: $95K - $120K.",
            "Salary range $120,000 - $95,000.",
            "A posting with no pay information at all.",
            "Pay range: $2 - $4 per hour.",
        ]
        for i, text in enumerate(corpus):
            mine = CMP.from_body(text)
            ref_range, _ = _ref(text)
            check(f"drift[{i}] agrees a band exists", mine is not None,
                  ref_range is not None)
            if mine and ref_range:
                lo, _, hi = ref_range.partition(" - ")
                check(f"drift[{i}] agrees on the numbers", (mine["min"], mine["max"]),
                      (int(CMP._to_number(lo)), int(CMP._to_number(hi))))

        # ⭐ ONE DELIBERATE DIVERGENCE, ASSERTED SO IT CANNOT GO QUIET. The archiver keeps a
        # placeholder band and this refuses it, because the two tools answer different
        # questions. The archiver is an EVIDENCE tool: "$50,000 - $999,999" is genuinely
        # what the employer published and the archive must not edit it. This feeds a RANKED
        # queue, where a 20x placeholder sorts above every real salary and buries them.
        #
        # ⚠️ Without this assertion the divergence is invisible: the corpus above happens to
        # contain no wide band, so the drift guard would keep passing while the two
        # implementations quietly disagreed on a whole class of posting.
        wide = "The salary range for this role is $50,000 - $999,999."
        check("intentional: the archiver keeps a placeholder band",
              _ref(wide)[0] is not None, True)
        check("intentional: the queue refuses it", CMP.from_body(wide), None)

    # ---------------------------------------------------------------- classification
    # Mirrors the auto-applier's twelve labels so one inbox does not carry two vocabularies.
    print("\nclassification:")
    _appc = load_app()
    for _subj, _body, _want in [
        # 🚨 The offer letter is first because it is the expensive one. It says
        # "unfortunately" and would have been filed as a REJECTION before `hired` existed.
        ("Your offer letter from Acme",
         "We are pleased to offer you the position. Unfortunately we cannot match your "
         "requested start date.", "hired"),
        ("Voluntary Self-Identification",
         "Please complete the invitation to self-identify.", "eeo_form"),
        ("Your application is incomplete",
         "You started an application but did not finish.", "incomplete_application"),
        ("Your assessment results", "The results of your assessment are ready.",
         "assessment_result"),
        ("Take-home challenge",
         "Please complete the HackerRank assessment within 72 hours.", "assessment_invite"),
        ("Interview feedback", "We have feedback from your interview to share.",
         "interview_feedback"),
        ("Following up on your interview", "Just checking in after your interview.",
         "interview_followup"),
        # ⚠️ The invariants that must not regress as labels are added above them.
        ("Interview invitation", "We would like to schedule a call. Does Tuesday work?",
         "interview_invite"),
        ("Availability", "Does Tuesday work for you?", "scheduling"),
        # 🚨 EVERY REJECTION WORDING THAT REACHED THE MAILBOX AND WAS MISSED LIVES HERE.
        # The rule has now failed twice on plain rejections, both times because the list
        # held one conjugation of a phrase and the employer sent another. A regex is only
        # as good as the sentences it was tested against, so each real miss stays a case.
        ("Update", "We decided to move forward with other applicants.", "rejection"),
        # Zafran, 2026-08-14. Forced the first widening.
        ("Zafran Security Application Update",
         "At this time, we have decided to move forward with other applicants.", "rejection"),
        # athenahealth, 2026-08-17. Sat as 'unknown' for two days and was found only when
        # the model matcher proposed an application for a message nothing had classified.
        ("Thank you for your interest in athenahealth",
         "After reviewing your application for the R15369 Client Support Analyst position, "
         "we have made the decision not to move forward with your candidacy at this time.",
         "rejection"),
        ("Update", "We will not be moving forward with your application.", "rejection"),
        ("Update", "You were not selected for this role.", "rejection"),
        ("Update", "We have chosen to pursue other candidates.", "rejection"),
        # Emerging Tech, 2026-08-17. The THIRD miss in this family. The rule kept
        # enumerating surface phrasings; it now anchors on the object of the verb,
        # because the tell is moving forward with SOMEONE ELSE.
        ("Thank you for your interest in Emerging Tech",
         "After careful review of your background and experience, we have decided to move "
         "forward with candidates whose qualifications more closely align with the "
         "requirements of this role.", "rejection"),
        # ⚠️ The positive use of the same verb must survive the anchoring.
        ("Next steps", "We would love to move forward with you. Does Tuesday work?",
         "scheduling"),
        # ⚠️ THE WIDENING MUST NOT SWALLOW ITS NEIGHBOURS. "move forward" is ordinary
        # scheduling language, and an offer letter routinely contains "unfortunately".
        ("Availability", "Are you free Tuesday to move forward with a call?", "scheduling"),
        # 🚨 ORDER, NOT VOCABULARY, WAS THE BUG. On 2026-08-19 he forwarded 101 real
        # rejections and 14 were filed as invites, scheduling, or recruiter outreach.
        # interview_invite matches the bare word "interview" and scheduling matches the
        # bare word "available", and both sat above rejection, so a CVS rejection was
        # stolen by "interview prep" in its footer and an HPE one by "opportunities will
        # become available" in its footer. Unambiguous rejection language now sits second,
        # under `hired` only. These four are the exact emails that were misfiled.
        ("Thank you for your interest in CVS Health",
         "After careful review, we will not be moving forward with your application for "
         "this role. To support your career journey we offer free interview prep.",
         "rejection"),
        ("Thank You for Interviewing with Employer E",
         "Thank you for the time you put into our interview process. After careful "
         "consideration, we have decided to move forward with another candidate.",
         "rejection"),
        ("HPE position closed",
         "We decided to move forward\nwith another candidate. Visit our career page often "
         "as new opportunities become available.", "rejection"),
        ("Your Application at Marathon Health",
         "This message is to inform you that we have selected a candidate who is a match "
         "for the job requirements of the position.", "rejection"),
        # 🚨 THE INVARIANTS THAT PROMOTION PUTS AT RISK. Each of these means "keep going",
        # and misreading one as "no" would close a live interview.
        ("Your offer", "We are delighted to offer you the position. Unfortunately we could "
         "not match your full ask, and we moved forward with other candidates for the "
         "senior band.", "hired"),
        ("Reschedule", "Unfortunately I need to reschedule our call. What time works for "
         "you?", "scheduling"),
        ("Interview", "Congratulations, we would like to invite you to interview next "
         "week.", "interview_invite"),
        # ⚠️ WHITESPACE IS NORMALISED BEFORE MATCHING, AND THIS PROVES IT. Email bodies
        # hard-wrap at about 72 characters and every pattern uses literal spaces, so a
        # phrase straddling a wrap was invisible. That single line moved more of the 109
        # real messages than the entire rejection vocabulary did.
        ("Wrapped", "we have decided\nnot to move forward\nwith your application",
         "rejection"),
        # One employer replied in Spanish. English-only rules file those as unknown forever.
        ("Gracias por participar", "lamentamos informarte que en esta ocasion no podremos "
         "avanzar con tu candidatura", "rejection"),
        # ⭐ Recoverable, so it must NOT be swallowed by the promoted rejection rule.
        ("Incomplete Assessment - Product Support Specialist at Employer F",
         "The take home assessment portion of your application was not completed, so we "
         "unfortunately cannot move forward with the process. That said, feel free to "
         "reapply with a complete assessment.", "incomplete_application"),
        # ⚠️ A RECEIPT THAT SOUNDS LIKE A NO IS STILL A RECEIPT. Interra Health says it
        # only follows up with candidates whose experience "closely aligns", one word away
        # from the "more closely align" that IS a rejection. Kept apart deliberately.
        ("Follow up from Interra Health",
         "Thank you for applying for the Technical Support Specialist, L2 role. We are "
         "only able to follow up directly with candidates whose experience closely aligns "
         "with the requirements of the position.", "confirmation"),
        ("Your offer", "We are delighted to offer you the position. Unfortunately we "
         "could not match your full ask.", "hired"),
        # 🚨 REGRESSION, 2026-08-21. The real Ashby confirmation for OpenRouter, verbatim.
        # It classified as `unknown` and left a submitted application sitting at `draft`.
        # It missed twice, each time by one word: the list held "thank you for applying"
        # and "thanks for your application" but not "thanks for applying", and the body
        # said "received your resume" against a pattern reading "received your
        # application". Greeting and object both vary by vendor.
        ("Thanks for applying to OpenRouter!",
         "Hi Jonathan,\n\nWe have received your resume for Scaled Support Specialist role "
         "at OpenRouter! We appreciate your interest in joining the team. We will review "
         "your application and get back to you if there are next steps.\n\nAll the best,\n\n"
         "OpenRouter Hiring Team", "confirmation"),
        # 🚨 REGRESSION, 2026-08-22. The real Tennr confirmation, verbatim. It classified as
        # `unknown` and raised needs_human on a receipt. Its opening, "Thank you for your
        # interest", is ALSO the standard opening of a rejection, so the greeting can never be
        # the trigger. The tell is that the review is still running.
        ("Thank you from Tennr!",
         "Thank you for your interest in the Enterprise Solutions Engineer role at Tennr! "
         "Our team is currently reviewing applications, and we will be in touch if there is "
         "a potential fit.\n\nAll the best,\nTennr Talent Team", "confirmation"),
        # 🚨 AND THE OTHER HALF OF THAT COIN. The same greeting, with a decision already made,
        # must still be a rejection. This is what makes the new pattern safe: the rejection
        # rule runs first, so an ongoing-review phrase cannot promote a no into a receipt.
        ("Thank you from Acme",
         "Thank you for your interest in the role. We are currently reviewing applications "
         "but have decided to move forward with other candidates.", "rejection"),
        # The two halves of that miss, isolated, so a future edit cannot drop one silently.
        ("Thanks for applying", "", "confirmation"),
        ("Update", "We have received your resume.", "confirmation"),
        ("Thanks", "Thank you for applying to Acme.", "confirmation"),
        ("Your code", "Your one-time verification code is 123456", "otp"),
        ("Hello", "I came across your profile and wanted to reach out.", "recruiter_outreach"),
        ("Newsletter", "Here is our monthly update.", "unknown"),
    ]:
        check(f"classify: {_want}", _appc.classify(_subj, _body)[0], _want)

    # ⭐ Only confirmation and noise may skip a human, and assessment_invite and
    # incomplete_application are named explicitly so a future addition to AUTO_HANDLED
    # cannot quietly swallow either. Both are actionable and time-boxed.
    for _lbl, _warn, _want in (("confirmation", False, 0), ("noise", False, 0),
                               ("assessment_invite", False, 1),
                               ("incomplete_application", False, 1),
                               ("confirmation", True, 1), ("rejection", False, 1)):
        check(f"needs_human {_lbl}/{_warn}", _appc.needs_human_for(_lbl, _warn), _want)

    # ---------------------------------------------------------------- NUL at the boundary
    # 🚨 REGRESSION, 2026-08-21. One NUL byte in one scraped posting made every nightly
    # backup unrestorable for three days while the seal verified and the file decrypted.
    # sqlite3.executescript() refuses a script containing a NUL, so the dump replayed as
    # "ValueError: embedded null character" and nothing earlier in the chain complained.
    # _arg() is the single point every written parameter passes through, which is why the
    # strip lives there rather than at the two call sites that happened to be involved.
    print("\nNUL is stripped at the parameter boundary:")
    _argf = _appc.BunnyDB._arg if hasattr(_appc, "BunnyDB") else None
    if _argf is None:
        for _n in dir(_appc):
            _o = getattr(_appc, _n)
            if isinstance(_o, type) and hasattr(_o, "_arg") and hasattr(_o, "executemany"):
                _argf = _o._arg
                break
    check("adapter with _arg was found", _argf is not None, True)
    if _argf is not None:
        _got = _argf("Roles vary \x00\x00 some can be performed from anywhere")
        check("NUL removed from text params", "\x00" in _got["value"], False)
        check("...and the rest of the text survives",
              _got["value"], "Roles vary  some can be performed from anywhere")
        check("a clean string is untouched", _argf("plain")["value"], "plain")
        # A dump built from a stripped value must actually replay.
        import sqlite3 as _sq
        _c = _sq.connect(":memory:")
        _c.executescript("CREATE TABLE t(x TEXT);")
        _c.execute("INSERT INTO t VALUES (?)", (_argf("a\x00b")["value"],))
        _dump = "\n".join(_c.iterdump())
        _c2 = _sq.connect(":memory:")
        try:
            _c2.executescript(_dump)
            _replays = True
        except ValueError:
            _replays = False
        check("the resulting dump replays", _replays, True)

    # ---------------------------------------------------------------- rejection tracking
    print("\nrejection tracking:")
    _appr = load_app()
    # ⚠️ `draft` is deliberately absent. A rejection referencing an application that was
    # never submitted is suspicious rather than authoritative, and a pre-existing test in
    # the job_track fixture already asserted that a rejection must not move a draft.
    # 🚨 `interview` WAS HERE AND WAS REMOVED 2026-08-23, after a probe closed a live
    # interview with one forged email from an unrelated domain. An interview is a human
    # relationship, and he has real ones running. A genuine rejection recorded a day late
    # costs nothing; a false one deletes the relationship and rewrites his history.
    # job_track now holds those for a human and says so in the audit log.
    check("only submitted rows close automatically", _appr.CLOSEABLE, {"submitted"})
    check("...and an interview is held for a human",
          "interview" not in _appr.CLOSEABLE, True)
    # ⚠️ `passed` and `suspended` were HIS decisions and `superseded` was ours. An employer
    # rejection arriving afterwards must not rewrite why the row stopped.
    for _st in ("draft", "passed", "suspended", "superseded", "ghosted", "rejected"):
        check(f"{_st} is not closeable", _st in _appr.CLOSEABLE, False)

    _tsrc = _src_of(_appr.job_track)
    # 🚨 The UPDATE must be guarded by status in its own WHERE clause, not only by the
    # Python check above it. Two runs racing on one message would otherwise close a row
    # twice and overwrite the first outcome date.
    check("the rejection update re-checks status in SQL",
          "status IN ('submitted','interview')" in _tsrc, True)
    # ⚠️ The source became a bound parameter in v0.20.0 because it now has two values.
    # An outcome the alias proved and one a person chose by hand are different evidence,
    # and collapsing them would make a human's judgement indistinguishable from a match.
    check("it records where the outcome came from", "outcome_source=?" in _tsrc, True)
    check("an alias-proved outcome is still form_email", "form_email" in _tsrc, True)
    check("a hand-matched outcome says so", "human_match" in _tsrc, True)
    # 🚨 Auto-accept made "matched by hand" a lie on any row a model resolved. The first
    # three rows it closed each claimed a human had decided.
    check("a model-matched outcome is NOT called human", "model_match" in _tsrc, True)
    check("and the status line names the model", "matched by a MODEL" in _tsrc, True)
    check("it retires source_row so the renderer is not blocked",
          _tsrc.count("source_row=NULL") >= 2, True)
    # ⭐ A forwarded rejection loses the original sender's authentication. The row says so
    # rather than presenting the outcome as though the employer sent it here directly.
    check("it warns that a forward loses authentication",
          "survive the" in _tsrc and "forwarder" in _tsrc, True)

    # ---------------------------------------------------------------- application matching
    print("\napplication matching (fallback):")
    _appm = load_app()
    check("registered as a job", "match_application" in [n for n, _, _ in _appm.job_table()], True)
    check("shortlist is capped", _appm.MATCH_MAX_CANDIDATES <= 20, True)
    check("null is an allowed answer",
          "null" in str(_appm.MATCH_SCHEMA["properties"]["application_id"]["type"]), True)
    check("injection flag is required",
          "prompt_injection_suspected" in _appm.MATCH_SCHEMA["required"], True)

    # 🚨 THE WHOLE POINT: it proposes and never writes. A sender who could choose which
    # application a rejection lands on could close a live interview from outside the
    # system, so the job body must not contain a write to any table but its own.
    # ⚠️ CHECK THE CODE, NOT THE PROSE. The first version grepped the raw source and failed
    # on "needs_human" and "send" appearing in the docstring that explains it never touches
    # them. A test that cannot tell an assertion from its own explanation is worthless.
    import ast as _ast, textwrap as _tw
    _fn = _ast.parse(_tw.dedent(_src_of(_appm.job_match_application))).body[0]
    if (_fn.body and isinstance(_fn.body[0], _ast.Expr)
            and isinstance(getattr(_fn.body[0], "value", None), _ast.Constant)):
        _fn.body = _fn.body[1:]                       # drop the docstring
    _code = _ast.unparse(_fn)
    # ⚠️ CHANGED 2026-08-20. It used to write nothing but its own table. It may now also
    # set message.resolved_application_id, on his instruction, so mail forwarded to the
    # shared aiapply@ alias can move an application without a human. Everything else it was
    # forbidden to touch, it is STILL forbidden to touch.
    for _forbidden in ("UPDATE application", "needs_human", "INSERT INTO application",
                       "classification=", "application_ref="):
        check(f"still never writes: {_forbidden}", _forbidden.lower() in _code.lower(), False)
    check("still inserts only into its own table",
          _code.count("INSERT INTO") == _code.count("INSERT INTO message_application_match"),
          True)
    check("the ONLY message column it writes is the resolution",
          "UPDATE message SET resolved_application_id" in _code, True)
    check("and it is guarded, never unconditional",
          "auto_accept_reason" in _code, True)
    check("the write is re-read before it is counted", "back[" in _code or "back and back" in _code, True)

    # ⭐ The shortlist narrows on the employer name before any model call, so the model
    # only ever chooses between rows that are already plausible.
    import sqlite3 as _s7, tempfile as _t7, os as _o7
    _p7 = _t7.NamedTemporaryFile(suffix=".db", delete=False).name
    _c7 = _s7.connect(_p7); _c7.row_factory = _s7.Row
    try:
        _c7.execute("CREATE TABLE application (id INTEGER PRIMARY KEY, company_raw TEXT, "
                    "role_raw TEXT, status TEXT, alias_used TEXT)")
        for _i, _co, _st in ((1, "**Employer G** (NYSE: XX)", "interview"),
                             (2, "ReadMe", "interview"),
                             (3, "Acme Health", "rejected")):
            _c7.execute("INSERT INTO application VALUES (?,?,?,?,?)",
                        (_i, _co, "Engineer", _st, f"a{_i}@x"))
        _msg = {"subject": "Update from Employer G", "body_text": "regarding your application",
                "body_reply": None, "from_addr": "noreply@labcorp.com"}
        _got = [a["id"] for a in _appm._match_candidates(_c7, _msg)]
        check("shortlist finds the named employer", _got, [1])
        # A closed application is not a candidate: nothing inbound should reopen it.
        _msg2 = dict(_msg, subject="Update from Acme Health", from_addr="x@acme.com")
        check("closed applications are excluded",
              [a["id"] for a in _appm._match_candidates(_c7, _msg2)], [])
    finally:
        _c7.close(); _o7.unlink(_p7)

    # ---------------------------------------------------------------- workday + breezy
    # 🚨 WORKDAY WAS WRONGLY WRITTEN OFF AS UNSWEEPABLE. Forty-two employers were classified
    # "board found, cannot be read" because Workday has no public list API. It does; it just
    # needs a POST and pagination. These fix the parse and, more importantly, the refusal.
    print("\nworkday + breezy:")
    _app7 = load_app()

    _wd_page = {"total": 3, "jobPostings": [
        {"title": "Technical Support Specialist", "externalPath": "/job/Texas/TSS_R66354",
         "locationsText": "Texas, Remote Work", "bulletFields": ["TX", "R66354"]},
        {"title": "Bid Manager", "externalPath": "/job/Germany/Bid_R1",
         "locationsText": "Germany Offsite", "bulletFields": ["DE", "R1"]},
        {"title": "Dupe", "externalPath": "/job/Texas/TSS_R66354",
         "locationsText": "Texas", "bulletFields": ["TX", "R66354"]}]}

    _saved = _app7._workday_list
    _app7._workday_list = lambda url: _wd_page
    try:
        _r = _app7._board_reqs(
            "workday",
            "https://motorolasolutions.wd5.myworkdayjobs.com/wday/cxs/"
            "motorolasolutions/Careers/jobs")
    finally:
        _app7._workday_list = _saved

    # ⭐ req_id is externalPath, not bulletFields: the req number's position inside
    # bulletFields varies by tenant, while externalPath is unique and builds the URL.
    check("workday req_id is externalPath", _r[0]["req_id"], "/job/Texas/TSS_R66354")
    check("workday rebuilds the public url", _r[0]["url"],
          "https://motorolasolutions.wd5.myworkdayjobs.com/Careers/job/Texas/TSS_R66354")
    check("workday reads remote from location", _r[0]["is_remote"], True)
    check("workday non-remote stays None", _r[1]["is_remote"], None)
    # The shared _add() dedupe must cover a new platform too; a repeated req_id on one
    # board violates board_state's primary key and aborts the entire sweep.
    check("workday drops a repeated req_id", len(_r), 2)
    # ⚠️ Workday's list has no description or band. Asserted so the gap stays known rather
    # than being mistaken for an extraction bug later.
    check("workday carries no description", _r[0]["description"], "")
    check("workday carries no band", _r[0]["comp"], None)

    # ⚠️ The second Workday URL form, which the first implementation missed entirely and
    # would have stored with an empty url. TransTRACK sits under its parent Modaxo's
    # tenant on the myworkdaysite host.
    _saved2 = _app7._workday_list
    _app7._workday_list = lambda url: {"total": 1, "jobPostings": [
        {"title": "Customer Care Analyst", "externalPath": "/job/United-States---TX/CCA_R57513",
         "locationsText": "United States - TX", "bulletFields": ["TX", "R57513"]}]}
    try:
        _r2 = _app7._board_reqs(
            "workday", "https://wd3.myworkdaysite.com/wday/cxs/modaxo/TransTrack/jobs")
    finally:
        _app7._workday_list = _saved2
    check("workday myworkdaysite url", _r2[0]["url"],
          "https://wd3.myworkdaysite.com/recruiting/modaxo/TransTrack"
          "/job/United-States---TX/CCA_R57513")

    _breezy = [{"id": "abc123", "name": "API Developer (Remote Opportunity)",
                "url": "https://vetsez.breezy.hr/p/abc123-api-developer",
                "salary": "", "company": {"name": "VetsEZ"},
                "location": {"city": "Tampa", "state": {"name": "Florida"},
                             "country": {"name": "United States"}}}]
    # Exercised through the real entry point with only the fetch stubbed, so the parse
    # under test is the one production runs.
    import json as _js, urllib.request as _u
    class _Resp:
        def __init__(self, payload): self._p = _js.dumps(payload).encode()
        def read(self): return self._p
        def __enter__(self): return self
        def __exit__(self, *a): return False
    _open = _u.urlopen
    _u.urlopen = lambda req, timeout=None: _Resp(_breezy)
    try:
        _rb = _app7._board_reqs("breezy", "https://vetsez.breezy.hr/json")
    finally:
        _u.urlopen = _open
    check("breezy parses the board", len(_rb), 1)
    # ⭐ Breezy is the second platform after Greenhouse to STATE the employer. That makes
    # the name evidence rather than a guess from the board token.
    check("breezy states the employer", _rb[0]["company"], "VetsEZ")
    check("breezy marks the name authoritative", _rb[0]["company_source"], "ats")
    check("breezy joins the location", _rb[0]["location"], "Tampa, Florida, United States")
    # ⚠️ Breezy sends "" for no band. Stored as None so an empty string never reads as a
    # stated-but-blank range downstream.
    check("breezy empty salary becomes None", _rb[0]["comp"], None)

    # ⭐ Teamtailor is the only one of the three new platforms carrying the DESCRIPTION.
    _tt = {"items": [{
        "id": "7953826", "title": "Senior Technical Support - US Market",
        "url": "https://careers.ubeya.com/jobs/7953826-senior-technical-support",
        "content_html": "<p>Own the escalation layer.</p>",
        "_jobposting": {"hiringOrganization": {"name": "Ubeya"},
                        "jobLocationType": "TELECOMMUTE",
                        "baseSalary": {"currency": "USD",
                                       "value": {"minValue": 90000, "maxValue": 120000}},
                        "jobLocation": [
                            {"address": {"addressLocality": "Tel Aviv-Jaffa",
                                         "addressRegion": "Israel", "addressCountry": "IL"}},
                            {"address": {"addressLocality": "New York",
                                         "addressRegion": "USA", "addressCountry": "US"}}]}}]}
    _u.urlopen = lambda req, timeout=None: _Resp(_tt)
    try:
        _rt = _app7._board_reqs("teamtailor", "https://careers.ubeya.com/jobs.json")
    finally:
        _u.urlopen = _open
    check("teamtailor parses the board", len(_rt), 1)
    check("teamtailor states the employer", _rt[0]["company"], "Ubeya")
    check("teamtailor name is authoritative", _rt[0]["company_source"], "ats")
    # ⚠️ The whole reason this platform was worth an engine cycle: Workday and Breezy give
    # the comp reader and the remote check nothing at insert, and this gives both.
    check("teamtailor carries the description", _rt[0]["description"],
          "Own the escalation layer.")
    check("teamtailor reads TELECOMMUTE", _rt[0]["is_remote"], True)
    check("teamtailor reads the band", _rt[0]["comp"], "90000-120000 USD")
    # Several locations are joined rather than one being picked, because a role open in two
    # countries is a fact the commute and remote gates both need.
    check("teamtailor joins every location", _rt[0]["location"],
          "Tel Aviv-Jaffa, Israel, IL | New York, USA, US")

    # ---------------------------------------------------------------- auto_application
    # 🚨 THE TABLE IS DECLARED TWICE, SO THE TWO COPIES ARE COMPARED RATHER THAN TRUSTED.
    # schema.sql builds a fresh database; the MIGRATIONS entry is what an existing
    # production database actually runs. Nothing makes them agree except this test, and a
    # column present in one and missing from the other is invisible until a write fails in
    # production against a table a local rebuild says is fine.
    print("\nauto_application:")
    import os as _o5, pathlib as _pathlib, sqlite3 as _s5, tempfile as _t5
    _app6 = load_app()

    def _cols_of(build):
        p = _t5.NamedTemporaryFile(suffix=".db", delete=False).name
        con = _s5.connect(p)
        try:
            build(con)
            return [(r[1], r[2].upper(), r[3], r[5])          # name, type, notnull, pk
                    for r in con.execute("PRAGMA table_info(auto_application)")]
        finally:
            con.close()
            _o5.unlink(p)

    _from_schema = _cols_of(lambda c: c.executescript(
        (_pathlib.Path(_app6.__file__).parent / "schema.sql").read_text()))
    _migs = [m for m in _app6.MIGRATIONS
             if isinstance(m, str) and "auto_application" in m]

    def _build_from_migrations(c):
        for m in _migs:
            c.execute(m)

    _from_migration = _cols_of(_build_from_migrations)

    check("schema.sql declares it", len(_from_schema) > 0, True)
    check("MIGRATIONS declares it", len(_from_migration) > 0, True)
    check("the two declarations agree", _from_schema, _from_migration)

    # The columns the reconciliation and the liveness check actually write. Named
    # explicitly so a rename upstream fails here rather than in a tool that silently
    # inserts nothing.
    _want = {"id", "source", "company_raw", "role_raw", "occurrence", "match_score",
             "observed_age", "observed_at", "captured_at", "capture_source", "url",
             "candidate_id", "application_id", "collision", "live_state",
             "live_checked_at", "live_evidence", "note"}
    check("column set", {c[0] for c in _from_schema}, _want)

    # ⭐ occurrence is what lets the same company+role appear twice. Three pairs in the
    # first real import were identical in every visible field, so a UNIQUE without it
    # would have swallowed one application of each pair with no error at all.
    _p6 = _t5.NamedTemporaryFile(suffix=".db", delete=False).name
    _c6 = _s5.connect(_p6)
    try:
        _build_from_migrations(_c6)
        _ins = ("INSERT INTO auto_application(source,company_raw,role_raw,occurrence,"
                "captured_at) VALUES (?,?,?,?,?)")
        _c6.execute(_ins, ("aiapply", "Employer H", "Implementation Specialist", 1, "t"))
        _c6.execute(_ins, ("aiapply", "Employer H", "Implementation Specialist", 2, "t"))
        check("an identical repeat survives", _c6.execute(
            "SELECT count(*) FROM auto_application").fetchone()[0], 2)
        _dup = "no error"
        try:
            _c6.execute(_ins, ("aiapply", "Employer H", "Implementation Specialist", 1, "t"))
        except Exception as e:                                        # noqa: BLE001
            _dup = "rejected" if "unique" in str(e).lower() else str(e)
        check("re-importing the same row is refused", _dup, "rejected")

        # ⚠️ 198 of the first 223 rows had no url. If the url index were not partial they
        # would all collide on NULL and only one could ever be stored.
        _iu = ("INSERT INTO auto_application(source,company_raw,role_raw,occurrence,"
               "captured_at,url) VALUES (?,?,?,?,?,?)")
        _c6.execute(_iu, ("aiapply", "A Co", "A Role", 1, "t", None))
        _c6.execute(_iu, ("aiapply", "B Co", "B Role", 1, "t", None))
        check("many rows may have no url", _c6.execute(
            "SELECT count(*) FROM auto_application WHERE url IS NULL").fetchone()[0], 4)
        # 🚨 TWO APPLICATIONS TO ONE POSTING MUST BE STORABLE. The url index was UNIQUE and
        # made this impossible, which is the exact case `occurrence` exists to record:
        # Two employers each had two applications to a single requisition. Row-level
        # dedupe is UNIQUE(source, company_raw, role_raw, occurrence), asserted above.
        _c6.execute(_iu, ("aiapply", "C Co", "C Role", 1, "t", "https://x/1"))
        _c6.execute(_iu, ("aiapply", "C Co", "C Role", 2, "t", "https://x/1"))
        check("one url may sit on two applications", _c6.execute(
            "SELECT count(*) FROM auto_application WHERE url='https://x/1'").fetchone()[0], 2)
    finally:
        _c6.close()
        _o5.unlink(_p6)

    # 🚨 A JOB THAT FAILS MUST NOT RETURN A SENTENCE THAT READS LIKE SUCCESS. On
    # 2026-08-19 ten messages in a row died on an OpenRouter 429 and job_match_application
    # returned "proposed 0, declined 0", which is indistinguishable from an empty queue.
    # The counter existed for every outcome except the one that matters.
    _mm = _src_of(load_app().job_match_application)
    check("the matcher counts its failures", "failed += 1" in _mm, True)
    check("a failed run says so in its own result", "FAILED" in _mm, True)
    check("and names the first error", "first_error" in _mm, True)
    check("and says they will be retried", "retries them" in _mm, True)

    _apr = load_app()

    # -----------------------------------------------------------------------
    # auto_accept_reason: the guards ARE the security boundary now
    # -----------------------------------------------------------------------
    # 🚨 Until 2026-08-20 nothing here could write resolved_application_id, because a sender
    # who can steer classify() with label words could otherwise choose which application his
    # mail closed. That protection is now these guards and nothing else, so every one gets a
    # case that FAILS, not just the happy path. A guard nobody proves is a comment.
    import sqlite3 as _sA, tempfile as _tA
    _pA = _tA.NamedTemporaryFile(suffix=".db", delete=False).name
    _cA = _sA.connect(_pA); _cA.row_factory = _sA.Row
    try:
        _cA.execute("CREATE TABLE application (id INTEGER PRIMARY KEY, company_raw TEXT, "
                    "role_raw TEXT, status TEXT)")
        _cA.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, resolved_application_id INTEGER)")
        for _i, _co, _ro, _st in ((1, "Employer J", "Technical Support Engineer (Remote)", "submitted"),
                                  (2, "Employer G", "EDI Senior Specialist", "interview"),
                                  (3, "Alpha", "Support Engineer", "draft"),
                                  (4, "Employer I", "Implementation Manager", "submitted"),
                                  (5, "Employer I", "Sr. Implementation Manager", "submitted")):
            _cA.execute("INSERT INTO application VALUES (?,?,?,?)", (_i, _co, _ro, _st))
        _cA.commit()

        def _msg(**kw):
            # classification_source='model' is the default here because every OTHER gate in
            # auto_accept_reason is what these cases are testing. The source gate has its own
            # case below, so it must not silently short-circuit the rest.
            base = dict(id=10, subject="Fwd: update", body_text="", body_reply="",
                        classification="rejection", classification_source="model",
                        auth_warn=0, resolved_application_id=None)
            base.update(kw); return base

        def _prop(**kw):
            base = dict(application_id=1, confidence="high", candidate_ids="1",
                        prompt_injection_suspected=0)
            base.update(kw); return base

        _good_body = "Your Technical Support Engineer application at Employer J. Unfortunately no."

        check("clean proposal is accepted",
              _apr.auto_accept_reason(_cA, _msg(body_reply=_good_body), _prop()), None)

        # 🚨 THE 2026-08-23 REGRESSION. A message still carrying the provisional rules label
        # decides nothing, whatever else is clean. That day job_track ran on rules labels
        # every 10 minutes while the model read every 15, so the rules were never a second
        # opinion here: they auto-rejected two applications from confirmation emails, one of
        # them the highest band in the batch.
        check("a provisional rules label is refused",
              _apr.auto_accept_reason(
                  _cA, _msg(body_reply=_good_body, classification_source="rules"), _prop())
              is not None, True)
        check("...and says why",
              "waiting for the model" in (_apr.auto_accept_reason(
                  _cA, _msg(body_reply=_good_body, classification_source="rules"), _prop()) or ""),
              True)
        # A row predating the column is treated as provisional, not as trusted.
        _no_col = _msg(body_reply=_good_body); _no_col.pop("classification_source")
        check("a row with no source column is provisional too",
              _apr.auto_accept_reason(_cA, _no_col, _prop()) is not None, True)

        for _label, _m, _p in (
            ("medium confidence refused", _msg(body_reply=_good_body), _prop(confidence="medium")),
            ("injection flag refused", _msg(body_reply=_good_body), _prop(prompt_injection_suspected=1)),
            ("declined pick refused", _msg(body_reply=_good_body), _prop(application_id=None)),
            ("DMARC warning refused", _msg(body_reply=_good_body, auth_warn=1), _prop()),
            ("already resolved refused",
             _msg(body_reply=_good_body, resolved_application_id=9), _prop()),
            ("label that changes nothing refused",
             _msg(body_reply=_good_body, classification="unknown"), _prop()),
            ("missing application refused", _msg(body_reply=_good_body), _prop(application_id=99)),
            ("🚨 LIVE INTERVIEW refused",
             _msg(body_reply="Your EDI Senior Specialist application at Employer G. Unfortunately no."),
             _prop(application_id=2, candidate_ids="2")),
            ("rejection onto a draft refused",
             _msg(body_reply="Your Support Engineer application at Alpha. Unfortunately no."),
             _prop(application_id=3, candidate_ids="3")),
            ("role title absent refused",
             _msg(body_reply="Regarding your application at Employer J, unfortunately no."), _prop()),
            ("rival role in the email refused",
             _msg(body_reply="We reviewed you for the Implementation Manager and the Sr. "
                             "Implementation Manager roles at Employer I. Unfortunately no."),
             _prop(application_id=4, candidate_ids="4,5")),
        ):
            _r = _apr.auto_accept_reason(_cA, _m, _p)
            check(_label, _r is not None, True)

        # 🚨 Two messages cannot claim one application.
        _cA.execute("INSERT INTO message VALUES (11, 1)"); _cA.commit()
        check("second message claiming the same application refused",
              _apr.auto_accept_reason(_cA, _msg(body_reply=_good_body), _prop()) is not None, True)
    finally:
        _cA.close(); os.unlink(_pA)
    # ---------------------------------------------------------------------------
    # resolved_application_id: a human's answer to a proposal, and nothing else's
    # ---------------------------------------------------------------------------
    # 🚨 THE WHOLE SECURITY PROPERTY IS THAT NOTHING IN THIS SERVICE WRITES THAT COLUMN. The
    # model proposes into message_application_match; a person accepts one from his own machine.
    # If any code path here could set it, a sender who steered classify() with label words in
    # the body could also choose WHICH application his mail closed, and closing a live interview
    # from outside is the exact harm the propose-only rule exists to prevent.
    _src = (pathlib.Path(__file__).parent.parent / "job_search_engine" / "app.py").read_text()
    # ⚠️ REVERSED 2026-08-20 ON HIS INSTRUCTION, and the reversal is NARROW. The service may
    # now write resolved_application_id, but only from job_match_application and only behind
    # auto_accept_reason(). job_track must still never write it: job_track READS that column
    # and acts on it, and a job that both sets and consumes its own trigger has no boundary
    # left at all.
    _tk_body = _src.split("def job_track")[1].split("\ndef ")[0]
    check("job_track still never writes the resolution",
          ("resolved_application_id=" in _tk_body
           or "SET resolved_application_id" in _tk_body), False)
    check("job_track still writes no message column", "UPDATE message" in _tk_body, False)
    _mm_body = _src.split("def job_match_application")[1].split("\ndef ")[0]
    check("only the matcher writes the resolution",
          "UPDATE message SET resolved_application_id" in _mm_body, True)
    check("and only behind the guard", "auto_accept_reason" in _mm_body, True)
    # 🚨 The selection at the top of the job skips any message that already has a proposal,
    # so without a second pass the auto-accept path could only ever see mail proposed in the
    # same run. Six real forwarded rejections were skipped on the first live run.
    check("it sweeps proposals it did not just make",
          "m.resolved_application_id IS NULL AND m.handled_at IS NULL" in _mm_body, True)
    check("and never re-litigates a human decision",
          "x.model <> '(human)'" in _mm_body, True)
    check("a live INTERVIEW is never auto-accepted",
          "interview" in str(_apr.AUTO_ACCEPT_STATUSES), False)
    check("auto-accept applies to submitted rows only",
          _apr.AUTO_ACCEPT_STATUSES, ("submitted",))

    # ⭐ A HUMAN'S DECISION OUTRANKS THE ALIAS. This is the case the column exists for: mail
    # arrived at a shared address that resolves to nothing, and a person said which row it is.
    import sqlite3 as _s9, tempfile as _t9
    _p9 = _t9.NamedTemporaryFile(suffix=".db", delete=False).name
    _c9 = _s9.connect(_p9); _c9.row_factory = _s9.Row
    try:
        _c9.execute("CREATE TABLE application (id INTEGER PRIMARY KEY, company_raw TEXT, "
                    "role_raw TEXT, status TEXT, alias_used TEXT, outcome_at TEXT, "
                    "outcome_reason TEXT, outcome_source TEXT, status_raw TEXT, "
                    "source_row TEXT, submitted_at TEXT, applied_raw TEXT)")
        _c9.execute("INSERT INTO application(id, company_raw, role_raw, status, alias_used) "
                    "VALUES (16,'Stripe','Technical Support Engineer','submitted',NULL)")
        # Two rows carry the shared alias, so the alias alone can never resolve.
        _c9.execute("INSERT INTO application(id, company_raw, role_raw, status, alias_used) "
                    "VALUES (20,'A','r','submitted','aiapply@jobs.example.com')")
        _c9.execute("INSERT INTO application(id, company_raw, role_raw, status, alias_used) "
                    "VALUES (21,'B','r','submitted','aiapply@jobs.example.com')")
        _c9.commit()

        # The alias 'aiapply' matches two rows -> _resolve_one must refuse.
        check("shared alias resolves to nothing",
              _apr._resolve_one(_c9, "aiapply") is None, True)

        # And the human's column names exactly one, regardless of the alias.
        _row = _c9.execute("SELECT id, status FROM application WHERE id=?", (16,)).fetchone()
        check("the human's application is the one that gets closed",
              (_row["id"], _row["status"]), (16, "submitted"))
    finally:
        _c9.close(); os.unlink(_p9)

    # The column is declared in BOTH places. schema.sql builds a fresh database; MIGRATIONS
    # adds it to one that already exists. A column in only one of them works until the other
    # path is used, which is the failure that shows up on a rebuild months later.
    _schema = (pathlib.Path(__file__).parent.parent / "job_search_engine" / "schema.sql").read_text()
    check("resolved_application_id in schema.sql", "resolved_application_id INTEGER" in _schema, True)
    check("resolved_application_id in MIGRATIONS",
          any("resolved_application_id" in _m for _m in _apr.MIGRATIONS), True)
    for _col in ("resolved_by", "resolved_at"):
        check(f"{_col} in MIGRATIONS", any(_col in _m for _m in _apr.MIGRATIONS), True)

    # job_track must select the column, or the preference above it is dead code.
    _tk = _src.split("def job_track")[1].split("\ndef ")[0]
    check("job_track selects resolved_application_id", "resolved_application_id" in _tk, True)
    check("job_track widened its WHERE for it",
          "OR resolved_application_id IS NOT NULL" in _tk, True)
    check("a human match is recorded as its own outcome_source", "human_match" in _tk, True)

    # ------------------------------------------------------- the pipeline tables
    # 🚨 THE ENGINE DECLARED NONE OF THESE UNTIL 2026-08-22, so a database rebuilt from
    # init_db() came up with mail and scan and NO PIPELINE AT ALL. That is a restore risk
    # and it is invisible: nothing raises, the service starts, /health is green, and the
    # only symptom is that job_track declines and the backup guard has nothing to count.
    print("\npipeline tables are declared by the engine:")
    import os as _op, sqlite3 as _sp, tempfile as _tp
    _PIPE = ("company", "posting", "application", "contact", "interaction",
             "backlog_item", "content_item")

    _dp = _tp.NamedTemporaryFile(suffix=".db", delete=False).name
    _prev_p = _op.environ.get("DB_PATH"); _op.environ["DB_PATH"] = _dp
    try:
        _appp = load_app()
        _appp.init_db()
        with _appp.db() as con:
            _have = {r["name"] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        check("init_db() creates every pipeline table",
              sorted(t for t in _PIPE if t in _have), sorted(_PIPE))

        # ⭐ NOT JUST PRESENT, USABLE. A table that exists but rejects the rows the
        # operator's tools write is the same outage with a longer path to it.
        with _appp.db() as con:
            con.execute("INSERT INTO company (id,name) VALUES (1,'Acme')")
            con.execute("INSERT INTO posting (id,company_id,title,captured_at) "
                        "VALUES (1,1,'Support Engineer','2026-01-01')")
            con.execute("INSERT INTO application (id,posting_id,status,source_row) "
                        "VALUES (1,1,'submitted','| a row |')")
        with _appp.db() as con:
            check("a seeded application round-trips",
                  con.execute("SELECT source_row FROM application WHERE id=1"
                              ).fetchone()["source_row"], "| a row |")
            # ⚠️ The archive hook, empty on every live row, is at least DECLARED. A column
            # the tools write but nothing declares vanishes on the next rebuild.
            check("posting carries the archive hook",
                  [c["name"] for c in con.execute("PRAGMA table_info(posting)")
                   if c["name"] in ("archive_path", "archive_sha256")],
                  ["archive_path", "archive_sha256"])

        # 🚨 THE BACKUP GUARD WAS VACUOUS AND THIS IS WHY IT MATTERS. job_backup() counts
        # rows in application, posting, company and message and refuses a dump missing
        # them, but a table that does not exist counts as None and None is skipped. On a
        # database with no pipeline the guard passed having checked nothing. With the
        # tables declared, a real row exists to be counted and lost.
        import backup as _bkp
        with _appp.db() as con:
            _dump = _bkp.dump_sql(con)
        check("the pipeline reaches the backup dump",
              "INSERT INTO application" in _dump and "INSERT INTO posting" in _dump, True)
    finally:
        if _prev_p is None:
            _op.environ.pop("DB_PATH", None)
        else:
            _op.environ["DB_PATH"] = _prev_p
        _op.unlink(_dp)

    # 🚨 DECLARED TWICE, SO THE TWO COPIES ARE COMPARED RATHER THAN TRUSTED. Same reasoning
    # as auto_application above: schema.sql builds a fresh database and the MIGRATIONS
    # entry is what an existing production database actually runs. A column in one and not
    # the other is invisible until a write fails in production against a table a local
    # rebuild says is fine.
    _appq = load_app()

    def _pipe_cols(build):
        q = _tp.NamedTemporaryFile(suffix=".db", delete=False).name
        con = _sp.connect(q)
        try:
            build(con)
            return {t: [(r[1], (r[2] or "").upper(), r[3], r[5])
                        for r in con.execute(f"PRAGMA table_info({t})")] for t in _PIPE}
        finally:
            con.close(); _op.unlink(q)

    _pipe_schema = _pipe_cols(lambda c: c.executescript(
        (pathlib.Path(_appq.__file__).parent / "schema.sql").read_text()))

    def _pipe_from_migrations(c):
        for m in _appq.MIGRATIONS:
            try:
                c.execute(m)
            except Exception:                                 # noqa: BLE001
                pass

    _pipe_migs = _pipe_cols(_pipe_from_migrations)
    for _t in _PIPE:
        check(f"{_t}: schema.sql and MIGRATIONS agree",
              _pipe_schema[_t], _pipe_migs[_t])
        check(f"{_t}: MIGRATIONS declares it at all", len(_pipe_migs[_t]) > 0, True)

    # ------------------------------------------------------- Workday addressing
    # 🚨 700 OF 716 WORKDAY CANDIDATE ROWS CARRIED NO URL, and every one of them could be
    # rebuilt offline from two columns it already had. The rows did not come from the
    # sweep: they came from a backfill that had its own idea of the columns and no way to
    # build a link. One addressing helper is what stops that recurring.
    # ── the tracker floor, released rather than tripped ─────────────────────────────────
    # 🚨 REGRESSION TEST FOR A CONFLICT BETWEEN TWO CORRECT BEHAVIOURS. render-tracker refuses
    # to write when the count of rows carrying a source_row falls, because that is how the
    # round-trip guard shrinks unnoticed. job_track CLEARS source_row whenever it moves a row,
    # which is also right: the row is database-authoritative from then on. Measured 2026-08-23,
    # 19 rows carrying a source_row were submitted or interview, so the next rejection to arrive
    # would have tripped the alarm on an entirely legitimate write. Whoever releases an id must
    # lower the floor in the same transaction.
    import sqlite3 as _sq3, json as _j
    _fl = load_app()
    _c = _sq3.connect(":memory:")
    _c.row_factory = _sq3.Row
    _c.execute("CREATE TABLE tracker_floor (id INTEGER PRIMARY KEY, count INTEGER, "
               "ids TEXT, updated TEXT)")
    _c.execute("INSERT INTO tracker_floor VALUES (1, 3, ?, '2026-08-23')",
               (_j.dumps(["7", "12", "30"]),))
    _fl._floor_release(_c, 12)
    _row = dict(_c.execute("SELECT count, ids FROM tracker_floor WHERE id=1").fetchone())
    check("releasing an id lowers the floor by one", _row["count"], 2)
    check("...and removes exactly that id", sorted(_j.loads(_row["ids"])), ["30", "7"])
    # ⚠️ It must never RAISE the floor or rebuild it from what it sees. A floor that recomputes
    # itself from the current count is not a floor.
    _fl._floor_release(_c, 999)
    _row = dict(_c.execute("SELECT count, ids FROM tracker_floor WHERE id=1").fetchone())
    check("an id that was never in the guard changes nothing", _row["count"], 2)
    # An uninitialised floor is not an error: nothing is being guarded yet.
    _c2 = _sq3.connect(":memory:")
    _c2.row_factory = _sq3.Row
    _c2.execute("CREATE TABLE tracker_floor (id INTEGER PRIMARY KEY, count INTEGER, "
                "ids TEXT, updated TEXT)")
    _fl._floor_release(_c2, 5)
    check("an empty floor is a no-op, not a crash",
          _c2.execute("SELECT count(*) n FROM tracker_floor").fetchone()["n"], 0)

    print("\nWorkday addressing:")
    _appw = load_app()

    # ── the tenant code, split off the company name ──────────────────────────────────────
    # 🚨 REGRESSION TEST. job_workday_enrich wrote the ATS name straight into `company`, and
    # Workday prefixes many tenants with an internal code. 413 of 716 rows got one, which
    # silently broke every consumer that normalises a name for matching. The queue dedupe
    # stopped recognising companies already applied to. Two facts belong in two columns.
    check("a tenant code is split off",
          _appw.split_ats_company("MS0309 GE Healthcare IITS USA Corp."),
          ("MS0309", "GE Healthcare IITS USA Corp."))
    check("...letters in the code too",
          _appw.split_ats_company("LE001 Contoso, Inc."), ("LE001", "Contoso, Inc."))
    check("...and a bare numeric one",
          _appw.split_ats_company("5100 Kyndryl Solutions Private Limited"),
          ("5100", "Kyndryl Solutions Private Limited"))
    check("a name with no code is returned whole, with no code",
          _appw.split_ats_company("Anthropic"), ("", "Anthropic"))
    # ⚠️ THE FALSE-POSITIVE GUARD IS THE HALF THAT MATTERS. A splitter that eats a real name
    # is worse than no splitter, because it corrupts the column it was added to protect.
    for real in ("3M Health Information Systems", "23andMe", "1Password", "7-Eleven"):
        check(f"...and does not eat {real!r}", _appw.split_ats_company(real), ("", real))
    # An internal year is not a prefix, because the match is anchored.
    check("an internal number survives",
          _appw.split_ats_company("100032 Callyo 2009 Corp."), ("100032", "Callyo 2009 Corp."))
    check("nothing in, nothing out", _appw.split_ats_company(""), ("", ""))
    # Reconstructable, so splitting loses nothing.
    _c, _n = _appw.split_ats_company("MS0309 GE Healthcare IITS USA Corp.")
    check("the original is reconstructable", f"{_c} {_n}", "MS0309 GE Healthcare IITS USA Corp.")

    # Both host forms, from the cxs list URL.
    check("api url, myworkdayjobs form",
          _appw.workday_bases(
              "https://acme.wd5.myworkdayjobs.com/wday/cxs/acme/Careers/jobs"),
          ("https://acme.wd5.myworkdayjobs.com/Careers",
           "https://acme.wd5.myworkdayjobs.com/wday/cxs/acme/Careers"))
    # ⚠️ The second form is a real shape, not a hypothetical: a parent tenant hosting a
    # sub-brand. Building the first form for it yields a hostname that does not resolve.
    check("api url, myworkdaysite form",
          _appw.workday_bases(
              "https://wd3.myworkdaysite.com/wday/cxs/parentco/SubBrand/jobs"),
          ("https://wd3.myworkdaysite.com/recruiting/parentco/SubBrand",
           "https://wd3.myworkdaysite.com/wday/cxs/parentco/SubBrand"))
    # ⭐ And from a stored board key, which is all a repair job has.
    check("board key, three parts",
          _appw.workday_bases("workday|acme:wd5:Careers")[0],
          "https://acme.wd5.myworkdayjobs.com/Careers")
    check("board key, four parts marks the other host",
          _appw.workday_bases("workday|parentco:wd3:SubBrand:site")[0],
          "https://wd3.myworkdaysite.com/recruiting/parentco/SubBrand")
    check("a bare token works too",
          _appw.workday_bases("acme:wd5:Careers")[0],
          "https://acme.wd5.myworkdayjobs.com/Careers")
    # 🚨 An unreadable token yields nothing rather than a guess. A guessed hostname that
    # 404s reads as a vanished requisition, which is worse than no URL at all.
    for _bad in ("", "workday|acme", "workday|a:b:c:d", "https://example.invalid/x",
                 "greenhouse|acme"):
        check(f"unreadable board {_bad!r} yields no base",
              _appw.workday_bases(_bad), ("", ""))

    # ⚠️ TWO WRITERS, TWO req_id SHAPES, BOTH IN THE TABLE RIGHT NOW. The sweep stores the
    # qualified id; the backfill stored the bare externalPath. Anything reading req_id has
    # to accept both or it silently works on half the rows.
    _bk = "workday|acme:wd5:Careers"
    _path = "/job/Remote/Support-Engineer_R1"
    check("qualified req_id resolves to the path",
          _appw.workday_path(_bk, f"{_bk}:{_path}"), _path)
    check("bare req_id resolves to itself", _appw.workday_path(_bk, _path), _path)
    check("a req_id qualified by a DIFFERENT board still yields its path",
          _appw.workday_path(_bk, f"workday|other:wd1:Site:{_path}"), _path)
    check("a req_id with no path at all yields nothing",
          _appw.workday_path(_bk, "R1234"), "")
    check("the two shapes build the SAME url",
          _appw.workday_job_url(_bk, f"{_bk}:{_path}"),
          _appw.workday_job_url(_bk, _path))
    check("and it is the public url, not the api one",
          _appw.workday_job_url(_bk, _path),
          "https://acme.wd5.myworkdayjobs.com/Careers/job/Remote/Support-Engineer_R1")
    check("the api url is the cxs one",
          _appw.workday_job_api_url(_bk, _path),
          "https://acme.wd5.myworkdayjobs.com/wday/cxs/acme/Careers"
          "/job/Remote/Support-Engineer_R1")

    # 🚨 DEAD AGAINST THROTTLED. Measured on three real tenants the same afternoon: one
    # answered 200 with the full text, one answered 404 for a requisition that had really
    # gone, and one answered 403 for a posting that is plainly live and whose list endpoint
    # works normally. Reading that 403 as a vanish deletes a real opportunity on the
    # strength of a bot rule, and this project has already paid that price twice.
    import urllib.error as _uwe, urllib.request as _uw
    _real_open = _uw.urlopen

    def _stub(status_or_body):
        def _f(req, *a, **k):
            if isinstance(status_or_body, int):
                raise _uwe.HTTPError(req.full_url, status_or_body, "no", None, None)
            body = json.dumps(status_or_body).encode()

            class R:
                def read(self): return body
                def __enter__(self): return self
                def __exit__(self, *e): return False
            return R()
        return _f

    _ok_payload = {
        "jobPostingInfo": {
            "title": "Support Engineer",
            "jobDescription": "<p>Read <b>HL7</b> feeds.</p>",
            "location": "Remote, United States",
            "startDate": "2026-08-18", "jobReqId": "R1",
            "externalUrl": "https://acme.wd5.myworkdayjobs.com/Careers/job/x"},
        "hiringOrganization": {"name": "Acme Health"}}
    try:
        _uw.urlopen = _stub(_ok_payload)
        _got = _appw.workday_job_detail(_bk, _path)
        check("a 200 is read", _got["state"], "ok")
        check("...and the html is flattened to text",
              "HL7" in _got["description"] and "<b>" not in _got["description"], True)
        check("...and the employer's own link wins over the derived one",
              _got["url"], "https://acme.wd5.myworkdayjobs.com/Careers/job/x")
        check("...and the ATS states the employer", _got["company"], "Acme Health")

        _uw.urlopen = _stub(404)
        check("404 is the ONLY kind of gone", _appw.workday_job_detail(_bk, _path)["state"],
              "gone")
        _uw.urlopen = _stub(410)
        check("410 too", _appw.workday_job_detail(_bk, _path)["state"], "gone")
        # ⚠️ Each of these was a live requisition somewhere. None may be recorded dead.
        # 403 is the one measured in the wild: a tenant whose list endpoint answers
        # normally and whose per-job endpoint refuses everything.
        for _code in (403, 429, 500, 502, 503):
            _uw.urlopen = _stub(_code)
            check(f"HTTP {_code} is blocked, never gone",
                  _appw.workday_job_detail(_bk, _path)["state"], "blocked")
        _uw.urlopen = _stub({"userAuthenticated": False})
        check("a 200 with no posting block is blocked, not gone",
              _appw.workday_job_detail(_bk, _path)["state"], "blocked")

        def _boom(req, *a, **k):
            raise TimeoutError("timed out")
        _uw.urlopen = _boom
        check("a timeout is blocked, never gone",
              _appw.workday_job_detail(_bk, _path)["state"], "blocked")
    finally:
        _uw.urlopen = _real_open

    check("an unaddressable row never reaches the network",
          _appw.workday_job_detail("greenhouse|acme", "R1")["state"], "unaddressable")

    # ⚠️ The sweep must still build urls, and through the same helper. A second copy of
    # this logic is what produced two answers in the first place.
    _wsrc = _src_of(_appw._board_reqs)
    check("the sweep uses the shared helper", "workday_bases(api_url)" in _wsrc, True)
    check("...and no longer carries its own hostname regexes",
          "myworkdayjobs.com/wday/cxs" in _wsrc, False)

    # 🚨 THE REPAIR JOB MUST NOT RE-TRIAGE AND MUST NOT RECORD A VANISH. Re-scoring is a
    # paid step a human starts deliberately; writing a vanish from one failed read is how
    # a throttled host becomes a lost opportunity.
    _esrc = _src_of(_appw.job_workday_enrich)
    check("the enrichment never writes triaged", "triaged=" in _esrc, False)
    check("...and never writes a vanish", "vanished" in _esrc, False)
    check("...and is registered so it can be triggered by hand",
          "workday_enrich" in [n for n, _, _ in _appw.job_table()], True)
    check("...but is NOT on the scheduler by default",
          {n: i for n, i, _ in _appw.job_table()}["workday_enrich"], 0)
    check("...and the scheduler skips a zero interval rather than looping on it",
          "if interval <= 0:" in _src_of(_appw._scheduler), True)

    # ------------------------------------------------------- the cached prefix
    # ⭐ THE SINGLE LARGEST COST LEVER, AND IT IS ORDERING, NOT RETRIEVAL. Measured
    # 2026-08-22 over 1,207 triaged rows: 5,888 input tokens per posting, about 4,580 of it
    # the candidate profile, against 302 cached. The profile sat at the front of the USER
    # message where no breakpoint could reach it and no prefix stayed stable.
    print("\nthe profile is in the cached prefix:")
    _appc = load_app()
    _sent: dict = {}

    def _cap_anthropic(user, cache_system, system="", schema=None):
        _sent.clear(); _sent.update(kind="anthropic", user=user, system=system,
                                    cache_system=cache_system)
        return ('{"results":[]}', {"input_tokens": 1, "output_tokens": 1,
                                   "cache_read": 0, "cache_write": 0, "model": "m"})

    def _cap_openai(user, system="", schema=None, schema_name=""):
        _sent.clear(); _sent.update(kind="openai", user=user, system=system)
        return ('{"results":[]}', {"input_tokens": 1, "output_tokens": 1,
                                   "cache_read": 0, "cache_write": 0, "model": "m"})

    _PROFILE = "PROFILE-SENTINEL: he has run HL7 interfaces for twenty years."
    _VOCAB = [{"slug": "go", "label": "Go", "rung": "none", "buildable": "yes"}]
    _CANDS = [{"title": "Support Engineer", "location": "Remote",
               "description": "POSTING-SENTINEL untrusted text"}]

    _ra, _ro = _appc._read_anthropic, _appc._read_openai_compat
    _prov = _appc.AI_PROVIDER
    try:
        _appc._read_anthropic, _appc._read_openai_compat = _cap_anthropic, _cap_openai

        _appc.AI_PROVIDER = "anthropic"
        _appc.ai_triage_batch(_CANDS, _PROFILE, _VOCAB)
        check("anthropic: the system is a list of blocks", isinstance(_sent["system"], list),
              True)
        check("...and EVERY block carries a cache breakpoint",
              all(b.get("cache_control") for b in _sent["system"]), True)
        # ⚠️ Two, not one. The instructions and the profile change for different reasons,
        # so an edit to his own document must not also throw away the instruction prefix.
        check("...and there are two of them, split where the reasons differ",
              len(_sent["system"]), 2)
        check("the profile is in the prefix",
              any("PROFILE-SENTINEL" in b["text"] for b in _sent["system"]), True)
        check("🚨 and NOT in the user message", "PROFILE-SENTINEL" in _sent["user"], False)
        # ⭐ The trust boundary moves the right way: the operator's document is in the
        # system message, and text written by strangers stays in the user message.
        check("the untrusted posting text stays in the user message",
              "POSTING-SENTINEL" in _sent["user"], True)
        check("...and never reaches the system message",
              any("POSTING-SENTINEL" in b["text"] for b in _sent["system"]), False)
        # 🚨 Was `len(cands) > 1`. With ~24,000 tokens in the prefix a single-posting call
        # repays the write on the next call, and single-posting calls are exactly the
        # re-scores that follow a failed pack.
        check("caching is no longer conditional on the pack size",
              _sent["cache_system"], False)

        _appc.AI_PROVIDER = "openai_compat"
        _appc.ai_triage_batch(_CANDS, _PROFILE, _VOCAB)
        # ⚠️ THIS IS THE PATH PRODUCTION RUNS. It has no breakpoint to set, so the only
        # lever is the prefix: a byte-identical system message ahead of every posting.
        check("openai_compat: the system is a plain string",
              isinstance(_sent["system"], str), True)
        check("...and it carries the profile",
              "PROFILE-SENTINEL" in _sent["system"], True)
        check("🚨 ...and the user message does not",
              "PROFILE-SENTINEL" in _sent["user"], False)
        check("...and the posting is still the user message",
              "POSTING-SENTINEL" in _sent["user"], True)

        # ⭐ THE PREFIX MUST BE BYTE-IDENTICAL ACROSS PACKS OR NONE OF THIS CACHES. Two
        # calls with different postings must produce exactly the same system message.
        _appc.ai_triage_batch(_CANDS, _PROFILE, _VOCAB)
        _first = _sent["system"]
        _appc.ai_triage_batch([{"title": "Other", "description": "OTHER-SENTINEL"},
                               {"title": "Third", "description": "THIRD-SENTINEL"}],
                              _PROFILE, _VOCAB)
        # Compared by length and equality rather than printed: the prefix is the whole
        # system prompt plus the profile, and dumping it into the log buries the result.
        check("a different pack produces a byte-identical prefix",
              (_sent["system"] == _first, len(_first) > 1000), (True, True))
        check("...while the user message did change",
              "POSTING-SENTINEL" in _sent["user"], False)
    finally:
        _appc._read_anthropic, _appc._read_openai_compat = _ra, _ro
        _appc.AI_PROVIDER = _prov

    # ⚠️ A caller that passes blocks owns its breakpoints, and _read_anthropic must not
    # re-wrap them. Dropping a breakpoint is the silent kind of caching failure: the call
    # still works, costs full price, and nothing in the response says one was lost.
    check("_read_anthropic passes a block list straight through",
          "isinstance(system, list)" in _src_of(_appc._read_anthropic), True)

    print()
    if failures:
        print(f"{len(failures)} FAILED")
        for f in failures:
            print("   ", f)
        return 1

    if skipped:
        # A silent skip is how a check rots. Say what did not run, every time.
        print(f"{len(skipped)} SKIPPED")
        for s in skipped:
            print("   ", s)
        if strict:
            print("\n--strict: a skip counts as a failure here.")
            return 1
        print("\nEverything that could run, passed. Re-run with --strict to require"
              " the full suite.")
        return 0

    print("all passed")
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
