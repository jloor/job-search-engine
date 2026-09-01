"""Location and commute gates. Free, mechanical, and they run BEFORE any model reads a word.

⭐ ORDER IS THE WHOLE DESIGN. Every filter that failed during the 2026-08-15 backfill failed
the same way: an earlier rule ended a decision that belonged to a later one.

    location beat remote   "Remote" on a Melbourne requisition is TRUE and useless, so
                           checking remote first admitted roles in Australia and the UK.
                           Eligibility must be asked first.
    remote beat commute    "hybrid" was treated as a rejection. It is not a verdict, it is a
                           question about WHERE, and where is what these gates answer. A
                           hybrid role in Manhattan is viable; the same role in Salt Lake
                           City is not.
    a perks line beat the  A regex matched "fully remote" inside "in office Monday,
    whole posting          Wednesday and Thursday, and up to four weeks per year of fully
                           remote work" and kept a hybrid role. 26% of the roles kept on
                           that signal had residency or hybrid language beside the match.

📌 ABSENCE IS NOT A REJECTION. A location is called ineligible only on an explicit signal.
Blank, "Remote", and anything unrecognised are kept for a human or a model to read.

📌 Running these before triage is also what makes the scan affordable: gating first cut a
backfill from $8.20 to $2.23 by never paying to score a job in another country.
"""
import re

import candidate as C

# US markers win outright: "Ontario, CA" is California, "Birmingham, AL" is Alabama and
# "Vancouver, WA" is Washington state. Checking foreign names first discards real US roles.
_US = re.compile(
    r"(,\s*(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|"
    r"MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b)"
    r"|\b(united\s+states|u\.?s\.?a\.?|usa)\b"
    r"|\b(remote\s*[-,–]?\s*(us|usa|united\s+states))\b"
    r"|\b(us|united\s+states)\s*[-–]\s*remote\b", re.I)

# ⚠️ BARE ABBREVIATIONS MATTER. With only spelled-out names here, "UK Remote" and
# "Remote - UK" matched nothing, fell through as unknown, and reached the apply band. Two
# UK roles were removed by hand afterwards while the rule that admitted them stayed broken.
_FOREIGN = re.compile(
    r"\b(uk|u\.k|gb|roi|"
    r"united kingdom|england|scotland|wales|northern ireland|ireland|germany|france|"
    r"spain|italy|netherlands|belgium|luxembourg|switzerland|austria|portugal|poland|"
    r"czech|czechia|slovakia|slovenia|hungary|romania|bulgaria|croatia|serbia|greece|"
    r"turkey|sweden|norway|denmark|finland|iceland|estonia|latvia|lithuania|ukraine|"
    r"russia|israel|united arab emirates|uae|qatar|saudi arabia|egypt|south africa|"
    r"kenya|nigeria|india|pakistan|bangladesh|sri lanka|singapore|malaysia|indonesia|"
    r"philippines|thailand|vietnam|japan|china|hong kong|taiwan|south korea|korea|"
    r"australia|new zealand|canada|mexico|brazil|brasil|argentina|chile|colombia|peru|"
    r"uruguay|costa rica|panama|guatemala|malta|cyprus|morocco|ghana|armenia|"
    r"london|manchester|edinburgh|glasgow|dublin|paris|berlin|munich|münchen|hamburg|"
    r"frankfurt|cologne|köln|amsterdam|brussels|zurich|zürich|geneva|vienna|wien|madrid|"
    r"barcelona|lisbon|milan|milano|rome|roma|warsaw|prague|budapest|bucharest|athens|"
    r"istanbul|stockholm|oslo|copenhagen|helsinki|tallinn|riga|vilnius|kyiv|kiev|moscow|"
    r"tel aviv|dubai|abu dhabi|doha|riyadh|cairo|bengaluru|bangalore|mumbai|new delhi|"
    r"delhi|hyderabad|pune|chennai|kolkata|gurgaon|gurugram|noida|karachi|lahore|dhaka|"
    r"kuala lumpur|jakarta|manila|bangkok|ho chi minh|hanoi|tokyo|osaka|seoul|beijing|"
    r"shanghai|shenzhen|taipei|sydney|melbourne|brisbane|perth|auckland|wellington|"
    r"toronto|montreal|montréal|ottawa|calgary|winnipeg|mexico city|são paulo|sao paulo|"
    r"rio de janeiro|buenos aires|santiago|bogotá|bogota|lima|cape town|johannesburg|"
    r"nairobi|lagos|accra|casablanca|"
    # ⚠️ CANADA NEEDED MORE THAN ITS FOUR BIGGEST CITIES. A full sweep scored a
    # "Canada- Sr Solutions Analyst" in "Remote or Mississauga" at 84, because the word
    # "Remote" satisfied the gate and Mississauga was in no list. The suburbs and the
    # provinces are where these postings actually sit.
    #
    # 🚨 DELIBERATELY OMITTED, because they are US places too and a false rejection is
    # worse than a false keep here: Ontario (California), Vancouver (Washington),
    # Victoria (Texas), Windsor, Waterloo, Markham, Scarborough, Halifax, Regina.
    # Those are caught by "canada" or by the geography rule instead.
    r"mississauga|brampton|etobicoke|gatineau|burnaby|saskatoon|edmonton|oshawa|vaughan|"
    r"kitchener|guelph|kelowna|moncton|sherbrooke|nanaimo|coquitlam|richmond hill|"
    r"north york|british columbia|saskatchewan|manitoba|nova scotia|newfoundland|"
    r"new brunswick|prince edward island|yukon|nunavut|northwest territories|alberta|"
    r"québec|quebec)\b", re.I)

# A region name is a place he cannot cover from one timezone, even when it says remote.
_REGION = re.compile(r"\b(emea|apac|latam|anz|dach|benelux|mena|europe|asia|africa|"
                     r"latin america|oceania|middle east)\b", re.I)

# ⚠️ "remotely" NEEDS THE OPTIONAL SUFFIX. \bremote\b demands a boundary right after the
# 'e', so a posting whose location field reads "Remotely based" matched nothing. One was
# found sitting unread at the top of the remote_check backlog for exactly this reason.
REMOTE_TXT = re.compile(r"\b(remote(?:ly)?|distributed|work from home|wfh|anywhere)\b", re.I)
BODY_REMOTE = re.compile(
    r"\b(fully remote|100% remote|remote[- ]first|remote.friendly|work from anywhere|"
    r"remote (?:role|position|opportunity)|or remote|remote or)\b", re.I)


def eligibility(location: str | None) -> str:
    """'eligible', 'ineligible', or 'unknown'. Unknown is never a rejection."""
    loc = (location or "").strip()
    if not loc:
        return "unknown"
    if _US.search(loc):
        return "eligible"
    if _FOREIGN.search(loc) or _REGION.search(loc):
        return "ineligible"
    return "unknown"


def gate(posting: dict, cfg: dict | None = None, too_far: set | None = None) -> tuple:
    """Return (keep: bool, reason: str) for one posting, before any model is involved."""
    cfg = C.load() if cfg is None else cfg
    loc = (posting.get("location") or "").strip()

    # 1. ELIGIBILITY FIRST, always. See the module docstring: checking remote first is
    #    what let "UK Remote" through, because it is genuinely remote.
    if eligibility(loc) == "ineligible":
        return False, "outside the eligible country"

    if posting.get("is_remote") is True:
        return True, "board flagged remote"
    if REMOTE_TXT.search(loc):
        return True, "remote in the location text"
    if not loc:
        return True, "no location stated"
    if BODY_REMOTE.search(posting.get("description") or ""):
        # ⚠️ Deliberately weak evidence, kept on purpose. It is confirmed later by the
        # remote_check job, which reads the sentence rather than matching a phrase in it.
        return True, "body mentions remote"
    if too_far and loc in too_far:
        return False, "over the commute ceiling"

    near, metro = C.near_state_re(cfg), C.metro_re(cfg)
    if (near and near.search(loc)) or (metro and metro.search(loc)):
        return True, "commutable, or not yet ruled on"
    return False, "out on geography"


def cascade_hybrid(remote_verdict: str, location: str | None, residency: str | None,
                   cfg: dict | None = None) -> str:
    """Turn a hybrid/residency verdict into a WHERE question and answer it.

    🚨 A stated residency OVERRIDES the office list. One posting named Salt Lake City as
    the requirement while the company also has a New York office; honouring the office list
    there would have kept a job he cannot take.
    """
    cfg = C.load() if cfg is None else cfg
    if remote_verdict not in ("hybrid", "remote_with_residency", "onsite"):
        return remote_verdict
    if "hybrid_commutable" not in C.workable_remote(cfg):
        return remote_verdict          # remote_only: no cascade, by policy
    # 🚨 NOT metro_re, and not a bare regex search either. This function ASSERTS
    # commutability, and it got that wrong two separate ways until 2026-08-25:
    #   metro_re ORs in `,\s*(NY|NJ|CT|PA)`, so "Philadelphia, PA" and "Albany, NY" read as
    #     the metro with nothing measured. Philadelphia is 131 measured minutes away.
    #   the place list holds bare tokens, so "Newark, CA" and "Princeton, WV" matched the
    #     New Jersey entries by name.
    # metro_match closes both: a curated token, beside a near state or beside nothing.
    if not C.metro_place_re(cfg):
        return remote_verdict          # no places configured: nothing to cascade against
    resid = (residency or "").strip()
    if resid and not C.metro_match(resid, cfg):
        return remote_verdict
    # 🚨 metro_match, not a bare regex search: the token must sit beside a NEAR state.
    # "Newark, CA" and "Princeton, WV" both read as commutable until 2026-08-25.
    if C.metro_match(f"{resid} {location or ''}", cfg) and eligibility(location) != "ineligible":
        return "hybrid_commutable"
    return remote_verdict

# ── the requisition, the question and the location field ─────────────────────────────────
# 🚨 THESE THREE MOVED UP FROM tools/ease-rank.py, THEY WERE NOT COPIED. Each was computed
# only on the laptop, so the nightly sweep could not use any of them and every list had to be
# re-derived by hand. Same reason harvest_tier moved. Two implementations of one rule is the
# drift this project keeps paying for.
# ⚠️ NOTHING PERSONAL CAME WITH THEM. The country he may work in is `work_authorization`, the
# places he can reach are `commute.metro_places`, and the hours he will accept are
# `remote.accepted_timezones`. All three are read from the config, never written here.

_REQ = (
    (re.compile(r"(?:job-boards|boards)(?:\.eu)?\.greenhouse\.io/[^/]+/jobs/(\d+)"), "gh"),
    (re.compile(r"[?&]gh_jid=(\d+)"),                                                   "gh"),
    (re.compile(r"jobs\.ashbyhq\.com/[^/]+/([0-9a-f-]{36})"),                           "ashby"),
    (re.compile(r"jobs\.lever\.co/[^/]+/([0-9a-f-]{36})"),                              "lever"),
    (re.compile(r"//([^./]+)\.[^.]+\.myworkdayjobs\.com/[^/]+/job/.*?/([^/]+?)/?$"),    "wd"),
)


def req_key(url: str | None) -> str | None:
    """The REQUISITION's identity, from the ATS rather than from the link that reached us.

    🚨 ONE JOB HAS SEVERAL URLS AND A STRING COMPARE CANNOT SEE THAT. Measured 2026-09-01:
    an application was submitted to `job-boards.greenhouse.io/acme/jobs/4000000001` while
    the scanner held the same job as `acme.example.com/careers/job?gh_jid=4000000001`.
    Same Greenhouse id, different host, so the send queue offered a role applied to four days
    earlier as its best new lead.

    ⚠️ Falls back to the normalised URL on an unknown board. That fallback is too narrow and
    can still show a duplicate, which is the right direction to fail: showing one costs a
    minute of reading, hiding a live role costs the role.
    """
    u = (url or "").strip()
    for rx, ats in _REQ:
        m = rx.search(u)
        if m:
            return f"{ats}:" + ":".join(g.lower() for g in m.groups() if g)
    return re.sub(r"^https?://", "", u.lower()).rstrip("/") or None


_AUTH_Q = re.compile(r"authoriz|sponsor|work permit|visa|right to work|"
                     r"legally (?:eligible|able)", re.I)
_LANG_Q = re.compile(r"\b(german|french|spanish|portuguese|mandarin|cantonese|japanese|"
                     r"korean|dutch|italian|hebrew|arabic)[- ]speaking\b|"
                     r"fluent in (?!english)", re.I)
_ROUTINE_Q = re.compile(r"background (?:check|screen)|drug (?:test|screen)|at least 18|"
                        r"reference check|e-?verify", re.I)


def _tz_re(cfg):
    """Timezones he will NOT take, as a pattern. Empty when none are configured."""
    bad = (cfg.get("remote", {}) or {}).get("reject_timezones") or []
    return re.compile("|".join(re.escape(z) for z in bad), re.I) if bad else None


def question_class(q: str | None, cfg: dict | None = None) -> str:
    """'blocking' | 'decide' | 'benign' for one gate-shaped question.

    🚨 A GATE-SHAPED QUESTION IS NOT A DISQUALIFIER, AND TREATING IT AS ONE HID EVERY BANDED
    ROLE. `harvest_tier` flags anything gate-shaped, correctly: it cannot know whose
    application it is. A reader that then drops every flagged row excludes
    "Are you legally authorized to work in the United States?", which is a routine yes.
    Measured 2026-09-01: all fourteen rows reaching the send list were rangeless, because a
    US work-authorisation question sits on every posting that publishes a band.

    ⭐ THE DECIDING FACT IS THE COUNTRY NAMED, NOT THE SHAPE OF THE SENTENCE. The identical
    phrasing is a yes for the United States and a hard no for Canada, and both appeared in
    one sweep.
    ⚠️ THE DEFAULT IS `decide`, NEVER `benign`. An unrecognised gate must cost a human a
    glance, because the failure that matters is a role he cannot take reaching the queue.
    """
    cfg = C.load() if cfg is None else cfg
    s = (q or "").strip()
    if not s:
        return "benign"
    tz = _tz_re(cfg)
    if _LANG_Q.search(s) or (tz and tz.search(s)):
        return "blocking"
    # 📌 _US and _FOREIGN are the module's own lists, reused rather than re-declared. They
    # are far more thorough than anything written beside a single caller, and they already
    # know that "Ontario, CA" is California.
    foreign, us = _FOREIGN.search(s), _US.search(s)
    if foreign and not us:
        return "blocking"
    if _AUTH_Q.search(s):
        auth = cfg.get("work_authorization", {}) or {}
        ok = {str(x).upper() for x in (auth.get("eligible_countries") or [])}
        if us and ok & {"US", "USA", "UNITED STATES"}:
            return "benign"
        return "blocking" if foreign else "benign"
    if _ROUTINE_Q.search(s):
        return "benign"
    return "decide"


# ⚠️ A BLANK FIELD IS NOT A PLACEHOLDER. The first version matched `^\s*$` and flagged every
# posting that simply states no location, which contradicts this module's own rule that
# absence is never a rejection. Caught by test_gates_decisions on its first run.
_PLACEHOLDER = re.compile(r"update location|^-+$|^n/?a$|^tbd$", re.I)


def location_conflict(location: str | None, remote_verdict: str | None,
                      cfg: dict | None = None) -> str | None:
    """A one-line warning about the board's location field, or None. NEVER a decision.

    ⚠️ THE FIELD AND THE BODY DISAGREE, AND THE FIELD IS OFTEN THE LIAR. One board tags a
    requisition "REMGA - Remote Georgia, REMMA - Remote Massachusetts" while its body reads
    "Work From Home (Remote in United States)". another employer's field is the literal string
    "USA - Update Location". Veeva publishes one requisition under three cities. Measured
    2026-09-01: of 316 live rows, 76 named a place outside his metro and 3 were placeholders.

    📌 It raises a hand so a human reads the posting. The verdict order is
    human > measurement > model, and a board's location string is none of the three.
    """
    cfg = C.load() if cfg is None else cfg
    loc = (location or "").strip()
    if not remote_verdict:
        return "location never judged: remote_verdict is empty, and unjudged is not commutable"
    if not loc:
        return None                      # absence is not a rejection
    if _PLACEHOLDER.search(loc):
        return f"location is a placeholder ({loc!r}): read the posting before sending"
    if eligibility(loc) == "eligible" and REMOTE_TXT.search(loc):
        return None
    if C.metro_match(loc, cfg) or REMOTE_TXT.search(loc):
        return None
    return (f"location names {loc!r}, outside his metro, while remote_verdict says "
            f"{remote_verdict}: the field and the verdict disagree")
