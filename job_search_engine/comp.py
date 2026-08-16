"""Read a compensation band out of a posting, with no model and no API call.

⭐ WHY THIS RUNS AT INGESTION. Until now the only comp extractor was a model pass gated on
`score >= 70`, so a posting had to be scored before anyone knew what it paid. Measured on
3,563 scored candidates: 651 carried a structured field from the board and 1,077 more state
the number in the body. Coverage at write time was 18%. With this it is 48%, for nothing.

📌 THE POINT IS COVERAGE, NOT COST. Rejecting below-floor postings before triage saves about
seven cents across the whole backfill. That is not a reason to do anything. The reason is
that a queue where four rows in five have no number cannot be ranked by pay at all.

🚨 IT NEVER GATES. This module reports; the caller decides. A band under the floor is still
evidence, and a scanner that silently drops cheap postings destroys the comp intelligence
that tells him what the market actually pays for the title.

⚠️ A BARE MONEY REGEX REPORTS THE WRONG NUMBER, CONFIDENTLY. A real GoFundMe posting says
"raised more than $40 billion since 2010". Currency alone archives that as the salary. So a
match must satisfy all three of: two amounts read as a range, pay vocabulary near them, and
a magnitude that could actually be pay. The span it came from is stored beside the numbers,
so a reader checks rather than trusts.

🚨 THIS LOGIC EXISTS TWICE ON PURPOSE, AND A TEST HOLDS THE TWO TOGETHER.
`fetch_job_description.archive.body_comp` is the reference implementation. Neither package
can import the other without breaking a stated invariant: the archiver declares zero
dependencies so it cannot rot, and this suite must pass with nothing installed. So
`tests/test_comp.py` runs both over the same fixtures whenever the archiver happens to be
importable, and skips when it is not. Drift fails on his machine, where both are present.
"""
import html
import re

# ⚠️ Must not end on a comma. "$125,000, as well as stock options" otherwise captures
# "$125,000," and the trailing punctuation lands in the record.
_AMOUNT = r"\$\s?\d(?:[\d,]*\d)?(?:\.\d+)?\s*[KkMm]?"
_RANGE = re.compile(rf"({_AMOUNT})\s*(?:-|–|—|to|and)\s*({_AMOUNT})")
_PAY_WORDS = re.compile(
    r"salary|compensation|pay range|pay band|base pay|base range|hourly|per hour|"
    r"per year|per annum|annually|annualized|OTE|on[- ]target earnings|"
    r"total target cash|expected pay|range for this (?:role|position)", re.I)
_HOURLY = re.compile(r"hourly|per hour|/\s?hr|an hour", re.I)

# ⭐ BASIS IS NOT OPTIONAL. Anthropic's range "includes both the sales commissions/sales
# bonuses target and annual base salary" and ezCater's is "total target cash compensation",
# while Relocity's is base salary. Ranking those against each other as if they were the same
# number quietly favours every posting that quotes OTE. Each pattern below is checked against
# the SPAN THAT WAS QUOTED, never the whole document, so the basis is as verifiable as the
# numbers are. Anything unmatched stays "unclear" rather than being guessed at as base.
_BASIS = (
    ("ote",        re.compile(r"OTE|on[- ]target earnings|base (?:plus|\+) commission", re.I)),
    ("total_cash", re.compile(r"total target cash|total cash compensation", re.I)),
    # ⚠️ The bare `\bbase\b` alternative is here because postings write the qualifier AFTER
    # the numbers: a real CaptiveAire posting says "Salary: $65k-$80k base, negotiable" and
    # was labelled unclear by a pattern that only looked for "base salary" ahead of them.
    # The word boundary is doing real work: it refuses "based upon tenure" and "database",
    # both of which appear in that same span.
    ("base",       re.compile(r"base (?:salary|pay|range)|annual salary|\bbase\b", re.I)),
)


def detag(h):
    """HTML to text. Ported from the archiver, where the ordering was worked out.

    Unescape to a fixed point FIRST, then strip tags. Several ATS APIs return the
    description entity-escaped, sometimes doubly, and stripping first leaves the markup
    behind as literal words.
    """
    h = h or ""
    for _ in range(3):
        u = html.unescape(h)
        if u == h:
            break
        h = u
    h = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", h)
    h = re.sub(r"(?i)<(br|/p|/div|/li|/h[1-6]|/tr|/table)\s*/?>", "\n", h)
    h = re.sub(r"(?i)<li[^>]*>", "\n- ", h)
    h = re.sub(r"<[^>]+>", " ", h)
    h = html.unescape(h).replace("\xa0", " ").replace("’", "'")
    h = re.sub(r"[ \t]+", " ", h)
    return re.sub(r"\n{3,}", "\n\n", h).strip()


def _to_number(tok):
    """'$95,000' -> 95000 ; '$95K' -> 95000 ; '$1.2M' -> 1200000"""
    t = (tok or "").replace("$", "").replace(",", "").strip()
    mult = 1
    if t and t[-1] in "Kk":
        mult, t = 1_000, t[:-1]
    elif t and t[-1] in "Mm":
        mult, t = 1_000_000, t[:-1]
    try:
        return float(t) * mult
    except ValueError:
        return None


def _plausible(lo, hi, hourly):
    """Could these two numbers be pay? Without this, '$40 billion' and '$5 - $10 off' pass."""
    if lo is None or hi is None or lo > hi:
        return False
    return (10 <= lo <= 500 and 10 <= hi <= 500) if hourly else \
           (15_000 <= lo <= 2_000_000 and 15_000 <= hi <= 2_000_000)


def _basis_of(span, hourly):
    if hourly:
        return "hourly"
    for name, rx in _BASIS:
        if rx.search(span):
            return name
    return "unclear"


def _result(m, span, hourly, source):
    # ⚠️ TRUNCATED TO WHOLE DOLLARS, because the columns are integers. Annual bands never
    # carry cents, but hourly ones do: a real posting reading "$18.70 - $21.25" is stored
    # as 18 - 21. The verbatim span is kept beside the numbers precisely so the exact
    # figures survive, and a reader comparing an offer against the record reads the span.
    return {"min": int(_to_number(m.group(1))), "max": int(_to_number(m.group(2))),
            "period": "hour" if hourly else "year",
            "basis": _basis_of(span, hourly),
            "evidence": " ".join(span.split())[:300],
            "source": source}


def from_body(body):
    """Find a band in the posting text. Returns a dict, or None.

    ⚠️ Deliberately conservative. A missed range leaves the row unknown, which is honest.
    A wrong range is worse than a missing one, because it looks like a record.
    """
    # ⚠️ DETAG FIRST. Greenhouse renders a pay range as
    # "<span>$210,000</span><span class="divider">&mdash;</span><span>$250,000</span>".
    # The numbers are 49 characters apart and the thing between them is not a dash, so a
    # range pattern reading the markup finds nothing. detag is idempotent on clean text.
    body = detag(body) if body and "<" in body else (body or "")

    for sentence in re.split(r"(?<=[.!?])\s+|\n+", body):
        if not _PAY_WORDS.search(sentence):
            continue
        m = _RANGE.search(sentence)
        if not m:
            continue
        hourly = bool(_HOURLY.search(sentence))
        if not _plausible(_to_number(m.group(1)), _to_number(m.group(2)), hourly):
            continue
        return _result(m, sentence, hourly, "body_regex")

    # ⚠️ SECOND PASS, FOR STRUCTURE RATHER THAN PROSE. Greenhouse puts "The annual
    # compensation range for this role is listed below" in one element and the numbers in
    # another, so they are never in the same sentence. Requiring one sentence missed
    # $210,000 - $250,000 in a real archived posting.
    #
    # 🚨 The window is small on purpose. Widening it far enough to be generous reintroduces
    # the exact failure the sentence rule prevents: a document mentioning salary anywhere
    # and "$40 billion" anywhere becomes a match. 240 characters spans a label and its
    # adjacent value without spanning unrelated paragraphs.
    flat = " ".join(body.split())
    for m in _RANGE.finditer(flat):
        before = flat[max(0, m.start() - 240):m.start()]
        if not _PAY_WORDS.search(before):
            continue
        hourly = bool(_HOURLY.search(before))
        if not _plausible(_to_number(m.group(1)), _to_number(m.group(2)), hourly):
            continue
        ctx = flat[max(0, m.start() - 160):m.end() + 40]
        return _result(m, ctx, hourly, "body_regex")
    return None


def from_field(text):
    """Parse the board's own structured compensation field. Returns a dict, or None.

    📌 A SEPARATE ENTRY POINT, because the provenance differs and provenance is the whole
    value of the record. This is what the employer put in the pay field; from_body is what
    a regex recovered from prose. Only the first is a published number.

    ⚠️ The field is short and already means pay, so the vocabulary requirement is dropped
    here. The plausibility check is not: boards do put junk in this field.
    """
    t = (text or "").strip()
    if not t:
        return None
    m = _RANGE.search(t)
    if not m:
        return None
    hourly = bool(_HOURLY.search(t))
    if not _plausible(_to_number(m.group(1)), _to_number(m.group(2)), hourly):
        return None
    return _result(m, t, hourly, "board")


def extract(field, body):
    """The band for one posting: the board's field if it published one, else the body.

    🚨 THE BOARD WINS WHEN IT SPOKE. A published field is the employer's own statement.
    Prose recovered by regex is an inference about that statement, and an inference must
    never overwrite the thing it was inferring.
    """
    return from_field(field) or from_body(body)
