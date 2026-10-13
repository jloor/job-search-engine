#!/usr/bin/env python3
"""Two wrong commute answers the place job gave on 2026-10-13, and the rules that stop them.

🚨 BUG 1, A BOARD THAT NAMES THE ATS WAS READ AS AN EMPLOYER. A `place` row with a board is
ONE employer's office. Every Fantastic posting carries board "fantastic|<ats>", so every
Fantastic employer on Greenhouse shared one "office" per city, and the address lookup searched
for the platform's name: "fantastic|breezy" resolved to Breezy Point, NY. Measured that day:
148 such rows, 13 with a verdict.

🚨 BUG 2, A TIME ZONE WAS MEASURED AS A PLACE. "Eastern or Central Timezone", "United States
(Any Time Zone)" and "Central and Eastern USA" went to the router, came back at 399 to 2,008
minutes to an arbitrary point, and were marked too_far by measurement. too_far is the verdict
the gate rejects on, so a remote role was hidden on a number about nowhere.

⭐ Every assertion below runs against a real temporary sqlite database and a fake router, so
nothing here reaches the network or the live database.

Run:  python3 tests/test_place_rules.py
"""
import os
import pathlib
import sqlite3
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_parse                                             # noqa: E402

relay = test_parse.load_app()
fails = []


def check(label, got, want=True):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got!r})"))
    if not ok:
        fails.append(label)


# ── the rule itself, on strings ───────────────────────────────────────────────────────
print("a time zone or a region with no city is not a destination:")
for s in ("Eastern or Central Timezone",
          "United States (Any Time Zone)",
          "Central and Eastern USA",
          "Eastern Time zone",
          "Pacific Time Zone",
          "Americas timezones",
          "East Coast",
          "Pacific Northwest",
          "Mid-Atlantic",
          "U.S. Central Time",
          "US_Central",
          "Eastern, Central, or Mountain"):
    check(f"{s!r} is a zone or region", relay._zone_or_region(s), True)

# ⚠️ THE NEGATIVES ARE THE POINT. "Central", "Eastern", "Mountain" and "Pacific" all start
# real place names, and a false catch here leaves a real office unmeasured.
print("\nreal places that start with the same words are still measured:")
for s in ("Mountain View, CA",
          "Central Islip, NY",
          "Eastern Shore, MD",
          "North Bergen, NJ",
          "West Orange, NJ",
          "Pacific, MO",
          "Central, SC",
          "South Carolina",
          "West Virginia",
          "Helena, MT",
          "Hartford, CT",
          "New York, NY",
          "Nashville, TN"):
    check(f"{s!r} is a place", relay._zone_or_region(s), False)

print("\nan ATS-named board is no board, an employer's board is kept:")
check("fantastic|greenhouse -> the city row", relay._place_board("fantastic|greenhouse"), "")
check("fantastic|linkedin -> the city row", relay._place_board("fantastic|linkedin"), "")
check("greenhouse|acme stays an office", relay._place_board("greenhouse|acme"), "greenhouse|acme")
check("no board stays no board", relay._place_board(None), "")


# ── the job, against a real temporary database ────────────────────────────────────────
_d = tempfile.mkdtemp()
_saved = {k: os.environ.get(k) for k in ("DB_PATH", "CANDIDATE_CONFIG", "COMMUTE_ORIGIN")}
try:
    os.environ["DB_PATH"] = str(pathlib.Path(_d) / "t.db")
    relay.DB_PATH = os.environ["DB_PATH"]
    os.environ["CANDIDATE_CONFIG"] = str(HERE.parent / "seed" / "candidate.toml")
    os.environ.pop("COMMUTE_ORIGIN", None)
    import candidate as _C
    _C._cache.clear()
    relay.init_db()
    ORIGIN = (_C.load().get("commute") or {}).get("origin")

    zones = ["Eastern or Central Timezone", "United States (Any Time Zone)",
             "Central and Eastern USA"]
    places = ["Mountain View, CA", "Central Islip, NY", "Eastern Shore, MD"]
    rows = ([(f"z{i}", "greenhouse|acme", loc) for i, loc in enumerate(zones)]
            + [(f"p{i}", "greenhouse|acme", loc) for i, loc in enumerate(places)]
            + [("rem", "greenhouse|acme", "Remote (EST timezone)"),
               # The same city from an ATS-named board and from an employer's own board.
               ("fan", "fantastic|greenhouse", "New York, NY"),
               ("own", "greenhouse|acme", "New York, NY")])
    with relay.db() as con:
        for rid, board, loc in rows:
            con.execute("INSERT INTO scan_candidate (at,req_id,board,title,location,score,"
                        "triaged) VALUES (?,?,?,?,?,?,1)",
                        (relay.now(), rid, board, "Implementation Manager", loc, 95))

    measured, looked_up = [], []

    def _fake_measure(origin, dests, mode, when):
        measured.extend(dests)
        return [40 for _ in dests]

    def _fake_resolve(company, location):
        looked_up.append((company, location))
        return {"status": "no_match", "query": f"{company} office {location}"}

    relay.GOOGLE_MAPS_KEY = "test-key"
    relay._measure = _fake_measure
    relay.resolve_office = _fake_resolve
    out = relay.job_place()

    with relay.db() as con:
        pl = {(r["board"], r["location"]): dict(r)
              for r in con.execute("SELECT * FROM place").fetchall()}

    print("\nthe place job never measures a time zone:")
    for z in zones:
        r = pl.get(("", z)) or {}
        check(f"{z!r} was not sent to the router", z in measured, False)
        check(f"...it is ruled review", r.get("verdict"), "review")
        check(f"...by rule, not measurement", r.get("verdict_from"), "rule")
        check(f"...and carries no minutes", r.get("best_min"), None)
    check("remote text still wins over the time zone",
          (pl.get(("", "Remote (EST timezone)")) or {}).get("verdict"), "remote")
    for p in places:
        check(f"{p!r} is still measured", p in measured, True)
        check(f"...and has a measured verdict",
              (pl.get(("", p)) or {}).get("verdict_from"), "measurement")
    check("the summary counts the zone rule", "zone 3" in out, True)

    print("\nan ATS-named board reads the city row and never looks up an office:")
    check("New York, NY has a city row", ("", "New York, NY") in pl, True)
    check("no fantastic| row is written",
          [k for k in pl if k[0].startswith("fantastic|")], [])
    check("the address lookup never ran for the ATS name",
          [c for c in looked_up if c[0] == "greenhouse" or "fantastic" in c[0]], [])
    check("an employer's own board still gets its office lookup",
          ("acme", "New York, NY") in looked_up, True)
    check("...and its own office row", ("greenhouse|acme", "New York, NY") in pl, True)
    check("no time zone reached the office lookup either",
          [c for c in looked_up if c[1] in zones], [])

    # The gate's reader. A too_far row under an ATS-named board must not reject anything:
    # only the city row speaks for a city.
    with relay.db() as con:
        con.execute("INSERT INTO place (origin,board,location,verdict,verdict_from) "
                    "VALUES (?, 'fantastic|greenhouse', 'Jersey City, NJ', 'too_far', "
                    "'measurement')", (ORIGIN,))
        con.execute("INSERT INTO place (origin,board,location,verdict,verdict_from) "
                    "VALUES (?, '', 'Jersey City, NJ', 'commutable', 'measurement')",
                    (ORIGIN,))
    relay._COMMUTE_FAR.update(mtime=None, set=set(), db_at=0.0, origin=None)
    check("the gate never reads a fantastic| row",
          "Jersey City, NJ" in relay._commute_too_far(), False)

    # ── the one-time retire step ──────────────────────────────────────────────────
    print("\nthe retire step hides ATS-named rows, keeps human rows, and runs once:")
    with relay.db() as con:
        con.execute("DELETE FROM place")
        for board, loc, verdict, frm, note in (
                ("fantastic|greenhouse", "New York, NY", "too_far", "measurement", None),
                ("fantastic|breezy", "Queens, NY", None, None, "Breezy Point"),
                ("fantastic|linkedin", "Boston, MA", "commutable", "human", "his call"),
                ("greenhouse|acme", "New York, NY", "commutable", "measurement", None),
                ("", "New York, NY", "commutable", "measurement", None)):
            con.execute("INSERT INTO place (origin,board,location,verdict,verdict_from,note) "
                        "VALUES (?,?,?,?,?,?)", (ORIGIN, board, loc, verdict, frm, note))
    check("it is part of MIGRATIONS, so every start applies it",
          relay.RETIRE_ATS_BOARD_PLACES in relay.MIGRATIONS, True)
    check("...and runs after the column it needs is added",
          relay.MIGRATIONS.index(relay.RETIRE_ATS_BOARD_PLACES)
          > relay.MIGRATIONS.index("ALTER TABLE place ADD COLUMN retired_at TEXT"), True)
    relay.init_db()
    with relay.db() as con:
        got = {r["board"]: dict(r) for r in con.execute("SELECT * FROM place").fetchall()}
    g = got["fantastic|greenhouse"]
    check("a measured fantastic| row is retired", bool(g["retired_at"]), True)
    check("...not deleted", len(got), 5)
    check("...it keeps the origin it was measured from", g["retired_origin"], ORIGIN)
    check("...and says why", g["note"], "retired: the board names the ATS, not the employer")
    b = got["fantastic|breezy"]
    check("a failed-lookup fantastic| row is retired", bool(b["retired_at"]), True)
    check("...and its old note is kept",
          b["note"], "Breezy Point | retired: the board names the ATS, not the employer")
    h = got["fantastic|linkedin"]
    check("a human row is never touched", (h["retired_at"], h["note"]), (None, "his call"))
    check("an employer's own office row is untouched", got["greenhouse|acme"]["retired_at"], None)
    check("the city row is untouched", got[""]["retired_at"], None)

    stamp = g["retired_at"]
    c2 = sqlite3.connect(relay.DB_PATH)
    n2 = c2.execute(relay.RETIRE_ATS_BOARD_PLACES).rowcount
    c2.commit(); c2.close()
    relay.init_db()
    with relay.db() as con:
        again = dict(con.execute("SELECT retired_at, note FROM place "
                                 "WHERE board='fantastic|greenhouse'").fetchone())
    check("a second run changes nothing", n2, 0)
    check("...the stamp and the note stay as they were",
          (again["retired_at"], again["note"]), (stamp, g["note"]))
finally:
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

print()
if fails:
    print(f"{len(fails)} FAILED:")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
print("all checks passed")
