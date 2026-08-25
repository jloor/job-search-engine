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
