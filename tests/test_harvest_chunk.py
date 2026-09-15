#!/usr/bin/env python3
"""The harvester returns EMPTY FORMS under concurrency, and calls it a finding.

🚨 MEASURED 2026-09-15 against the live service, the same four Ashby URLs each time:
       batch of 1   25 fields                 ✅
       batch of 2   25 fields, 0              1 of 2
       batch of 3   0, 0, 0                   0 of 3
       batch of 4   0, 0, 0, 8                1 of 4
Ashby renders its form in JavaScript and harvest.js waits a fixed settle period. Several
pages sharing one small Cloud Run instance do not finish painting inside it, so the snapshot
is of an empty document.

⚠️ WHY IT WENT UNNOTICED FOR WEEKS. A zero-field read is flagged "TOO FEW FIELDS: this is
probably a careers-page wrap" — a plausible, WRONG diagnosis that reads like a result. And
`harvest` is one row per URL, so an empty read MARKS THE URL AS HARVESTED and nothing ever
retries it. Lever and Greenhouse are server-rendered and survive the same batch, which made
the failure look platform-specific rather than structural.

Run:  python3 tests/test_harvest_chunk.py
"""
import importlib.util
import json
import pathlib
import sys
import types

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_posting_age as TPA                                # noqa: E402

app = TPA.load_app()
fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label:56} {got!r}")
    if not ok:
        fails.append(label)


sent = []


class _Resp:
    def __init__(self, payload): self._p = json.dumps(payload).encode()
    def read(self): return self._p
    def __enter__(self): return self
    def __exit__(self, *a): return False


def fake_urlopen(req, timeout=0):
    body = json.loads(req.data.decode())
    sent.append(body["urls"])
    return _Resp({"results": [{"url": u, "text": [{"label": "x"}]} for u in body["urls"]],
                  "elapsed_ms": 7000})


import urllib.request                                          # noqa: E402
real = urllib.request.urlopen
urllib.request.urlopen = fake_urlopen
try:
    app.HARVESTER_URL = "https://h.example"
    app.HARVEST_TOKEN = "t"

    sent.clear()
    app.HARVEST_CHUNK = 1
    out = app._harvest_call([f"u{i}" for i in range(5)])
    check("🚨 five URLs become FIVE separate requests", len(sent), 5)
    check("...each carrying exactly one URL", all(len(c) == 1 for c in sent), True)
    check("...and every result still comes back", len(out["results"]), 5)
    check("...in order", [r["url"] for r in out["results"]], ["u0", "u1", "u2", "u3", "u4"])
    # ⚠️ A timing that reads as instant hides the cost this change deliberately accepted.
    check("elapsed_ms is SUMMED across chunks, not dropped", out.get("elapsed_ms"), 35000)

    sent.clear()
    app.HARVEST_CHUNK = 2
    app._harvest_call([f"u{i}" for i in range(5)])
    check("the chunk size is configurable", [len(c) for c in sent], [2, 2, 1])

    # 🚨 One bad chunk must not discard the ones that already succeeded. The old code
    # returned a bare error for the whole batch, throwing away real work.
    calls = {"n": 0}

    def flaky(req, timeout=0):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("connection reset")
        return fake_urlopen(req, timeout)

    urllib.request.urlopen = flaky
    sent.clear()
    app.HARVEST_CHUNK = 1
    out = app._harvest_call([f"u{i}" for i in range(4)])
    check("a failed chunk does not discard the successful ones", len(out["results"]), 3)
    check("...and the failure is REPORTED, not swallowed",
          "connection reset" in out.get("partial_error", ""), True)

    def always_fail(req, timeout=0):
        raise OSError("down")

    urllib.request.urlopen = always_fail
    out = app._harvest_call(["u0", "u1"])
    check("total failure still returns an error, not empty success",
          "down" in out.get("error", ""), True)
    check("...and no results key pretending success", out.get("results"), None)
finally:
    urllib.request.urlopen = real

print("\nthe default is the only size measured safe:")
SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
check('HARVEST_CHUNK defaults to 1', 'os.environ.get("HARVEST_CHUNK", "1")' in SRC, True)

print()
if fails:
    for f in fails:
        print("  " + f)
    raise SystemExit(f"{len(fails)} failure(s)")
print("all passed")
