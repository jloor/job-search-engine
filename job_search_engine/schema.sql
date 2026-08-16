-- relay schema. Minimal on purpose: this service owns MAIL, not the whole platform.
-- The claims ledger and JD archives stay as files in the vault (SPEC O2).

PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS message (
  id             INTEGER PRIMARY KEY,
  received_at    TEXT    NOT NULL,              -- ISO8601 UTC
  to_alias       TEXT    NOT NULL,              -- ashby-pse@jobs.example.com
  from_addr      TEXT,
  from_name      TEXT,
  subject        TEXT,
  body_text      TEXT,                          -- the full body, always. This is evidence.
  body_reply     TEXT,                          -- just the new text, quoted history removed.
                                                -- Classification runs on THIS, never on body_text:
                                                -- an old "not moving forward" quoted under a fresh
                                                -- scheduling reply would otherwise read as a rejection.
  body_html      TEXT,
  message_id     TEXT,                          -- RFC822 Message-ID, for threading
  in_reply_to    TEXT,
  references_hdr TEXT,
  raw_payload    TEXT    NOT NULL,              -- stored BEFORE any parsing
  classification TEXT,                          -- confirmation|rejection|interview_invite|
                                                -- otp|recruiter_outreach|scheduling|noise
  otp_code       TEXT,
  application_ref TEXT,                         -- resolved company/role slug
  needs_human    INTEGER NOT NULL DEFAULT 1,
  handled_at     TEXT,
  -- Result of the ORIGINAL email's own authentication, as reported by the receiving
  -- MTA and forwarded to us in the webhook headers. Recorded, never trusted blindly.
  -- A recruiter mail failing DMARC is the phishing case these columns exist to surface.
  auth_spf       TEXT,
  auth_dkim      TEXT,
  auth_dmarc     TEXT,
  auth_warn      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_message_alias   ON message(to_alias);
CREATE INDEX IF NOT EXISTS idx_message_recv    ON message(received_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_message_mid ON message(message_id) WHERE message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS draft (
  id              INTEGER PRIMARY KEY,
  created_at      TEXT NOT NULL,
  in_reply_to_id  INTEGER REFERENCES message(id),
  from_alias      TEXT NOT NULL,                -- reply from the address they wrote to
  to_addr         TEXT NOT NULL,
  subject         TEXT NOT NULL,
  body_text       TEXT NOT NULL,
  intent          TEXT,                         -- schedule|accept|decline|info_request|thank_you|close_out
  status          TEXT NOT NULL DEFAULT 'proposed',  -- proposed|approved|sent|failed|discarded
  approved_by     TEXT,
  sent_at         TEXT,
  smtp_message_id TEXT,
  error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_draft_status ON draft(status);

-- append-only audit of anything that leaves or arrives, INCLUDING every auth failure
CREATE TABLE IF NOT EXISTS event (
  id         INTEGER PRIMARY KEY,
  at         TEXT NOT NULL,
  kind       TEXT NOT NULL,
  detail     TEXT,
  source_ip  TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_kind ON event(kind, at DESC);

-- Single-use approval nonces for /send. The PRIMARY KEY is the replay defence:
-- a second attempt with the same nonce hits a uniqueness violation, not a check
-- we might forget to write.
CREATE TABLE IF NOT EXISTS approval_nonce (
  nonce      TEXT PRIMARY KEY,
  used_at    TEXT NOT NULL,
  draft_id   INTEGER,
  fingerprint TEXT NOT NULL                     -- sha256 over (from,to,subject,body)
);

-- A model's reading of a message. Deliberately NOT columns on message: the regex verdict
-- in message.classification is the one the pipeline acts on, and a model that is confident
-- and wrong must not be able to overwrite it. This table only ever adds a second opinion.
--
-- ⚠️ Every row here is derived from text an outsider wrote. Treat it as a claim about the
-- message, never as an instruction. Nothing downstream may send mail, change an
-- application's status, or clear needs_human on the strength of a row in this table.
CREATE TABLE IF NOT EXISTS ai_reading (
  id             INTEGER PRIMARY KEY,
  message_id     INTEGER NOT NULL REFERENCES message(id),
  created_at     TEXT NOT NULL,
  model          TEXT NOT NULL,                 -- exact model id, so a verdict is attributable
  classification TEXT,                          -- same label set as message.classification
  confidence     TEXT,                          -- low|medium|high, not a number: a decimal
                                                -- here would read as measurement rather
                                                -- than as the model's own guess
  reasoning      TEXT,
  -- The extraction, which is the part a regex cannot do at all.
  employer       TEXT,                          -- who is actually hiring, not who sent it
  interview_at   TEXT,                          -- as stated, not normalised
  comp_mentioned TEXT,                          -- verbatim, same rule as the archived JD
  deadline       TEXT,
  next_action    TEXT,                          -- what the operator has to do, if anything
  raw_json       TEXT NOT NULL,                 -- the model's whole reply, kept as evidence
  input_tokens   INTEGER,
  output_tokens  INTEGER,
  -- Prompt-cache counters, recorded because an inert breakpoint is indistinguishable
  -- from a working one until the invoice arrives. cache_write is billed at 1.25x and
  -- cache_read at 0.1x, so these two columns are what make the saving auditable.
  cache_write_tokens INTEGER,
  cache_read_tokens  INTEGER,
  -- What the rule list said about the SAME text, recorded at read time so the two
  -- readers can be compared later without re-running either. Two independent readers
  -- that agree is real signal; where they differ, a human looks. Neither is trusted to
  -- overrule the other automatically.
  rules_classification TEXT,
  -- Fingerprint of the exact text this reading was made from. A reading is only valid
  -- for the words it saw: if body_reply is later corrected, the stored hash stops
  -- matching and the message is read again instead of keeping a stale verdict.
  body_sha256    TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_reading_msg ON ai_reading(message_id, created_at DESC);

-- A newly-appeared posting that cleared the hard gates, held with its description so a
-- model can judge fit without re-fetching the board.
--
-- ⭐ Only NEW and GATED postings land here. Storing every swept posting's description
-- would be ~16KB across tens of thousands of rows a night; this is the small tail that
-- is actually worth reading, and each row is read exactly once (triaged flips to 1).
CREATE TABLE IF NOT EXISTS scan_candidate (
  id           INTEGER PRIMARY KEY,
  at           TEXT NOT NULL,
  req_id       TEXT NOT NULL,              -- "<platform>|<token>:<id>", same key as scan_observation
  board        TEXT,
  title        TEXT,
  location     TEXT,                       -- free text; NOT gated on, see gate_posting()
  comp         TEXT,                       -- verbatim as the board stated it
  is_remote    INTEGER,
  url          TEXT,
  description  TEXT,
  triaged      INTEGER NOT NULL DEFAULT 0, -- 1 once a model has judged it
  verdict      TEXT,                       -- the model's fit call
  score        TEXT,
  reasoning    TEXT,
  -- ⚠️ WITHOUT THESE, TRIAGE COST IS UNMEASURABLE. ai_triage_posting returned usage and
  -- job_triage threw it away, so every cost figure quoted for this system ($0.00345 per
  -- posting, $20.87/month) was arithmetic on list prices, never an observation. The mail
  -- reader has recorded its usage since caching landed; triage never did.
  --
  -- ⭐ cache_read matters most. 93% of a triage call is the Career Inventory re-sent in
  -- full (20,469 tokens against ~1,500 for the posting). OpenAI-compatible endpoints cache
  -- prompts over ~1024 tokens automatically, so this column answers whether that redundancy
  -- is already nearly free or is being paid for on every single posting. Nobody can answer
  -- that from the code: only the bill knows, and this is how the bill gets read.
  model             TEXT,
  input_tokens      INTEGER,
  output_tokens     INTEGER,
  cache_read_tokens INTEGER,
  cache_write_tokens INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scan_candidate_triage ON scan_candidate(triaged, at DESC);

-- One row per unmet requirement on a posting that scored inside the band.
--
-- ⭐ This table exists to be COUNTED. The Project Backlog records which gap blocked which
-- application, filled in by hand from single postings, and the Career Inventory calls FHIR
-- "a growing blocker" on the evidence of one requisition. FHIR appears in 0 of the 24
-- archived job descriptions, because he only archives postings he chose to pursue: the
-- application set is selection-filtered and cannot say what the market asks for. A count
-- over the board sweep can.
--
-- ⚠️ `slug` is drawn from a CLOSED vocabulary (vault/Gap Vocabulary.md). Free text does not
-- aggregate: FHIR, HL7 FHIR and SMART on FHIR are three strings and one gap. Anything the
-- model could not place is stored as slug='other' with its proposal in proposed_label, and
-- the recurring ones get promoted into the vocabulary by hand.
--
-- ⚠️ Band only. A role he matches at 40% produces gaps meaning "he is not that person",
-- and counting those would swamp the signal. score is denormalised onto the row so a
-- count can be re-cut by band without joining back.
CREATE TABLE IF NOT EXISTS scan_gap (
  id             INTEGER PRIMARY KEY,
  at             TEXT NOT NULL,
  candidate_id   INTEGER NOT NULL REFERENCES scan_candidate(id),
  slug           TEXT NOT NULL,             -- from the closed vocabulary, or 'other'
  proposed_label TEXT,                      -- only meaningful when slug = 'other'
  severity       TEXT NOT NULL,             -- 'required' | 'preferred'; a wish is not a blocker
  evidence       TEXT,                      -- what the posting asked for, in its words
  score          INTEGER,                   -- the posting's fit score, denormalised
  title          TEXT,
  board          TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_gap_slug ON scan_gap(slug, severity);

-- ⚠️ scan_observation WROTE A FULL SNAPSHOT PER SWEEP: one row per requisition per board,
-- every night. Five sweeps of 16 boards produced 6,752 rows to record that almost nothing
-- had changed. Projected to the 2,060 sweepable boards that is ~174,000 rows per sweep,
-- 5.2M rows and 693MB per month, against 117 rows of actual pipeline data. The nightly
-- encrypted backup dumps the whole database, so that cost lands on the backup too.
--
-- ⭐ These two tables replace it with state plus a change log. board_state holds one row
-- per LIVE requisition and is updated in place, so it is bounded by the size of the market
-- rather than growing with time. scan_change is written ONLY when a requisition appears or
-- disappears, so a quiet night writes nothing at all.
--
-- 📌 It is also cheaper per sweep in statements, which matters over an HTTP SQL API: three
-- statements per board (read the set, insert what appeared, delete what vanished) instead
-- of one insert per requisition.
CREATE TABLE IF NOT EXISTS board_state (
  board      TEXT NOT NULL,               -- "<platform>|<token>"
  req_id     TEXT NOT NULL,               -- board-local id
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  title      TEXT,
  PRIMARY KEY (board, req_id)
);

-- The audit trail. A vanished requisition is an event worth keeping forever; a requisition
-- sitting open for a year is not worth 365 rows saying so.
CREATE TABLE IF NOT EXISTS scan_change (
  id     INTEGER PRIMARY KEY,
  at     TEXT NOT NULL,
  board  TEXT NOT NULL,
  req_id TEXT NOT NULL,
  change TEXT NOT NULL,                   -- 'appeared' | 'vanished'
  title  TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_change_at ON scan_change(at DESC, change);

-- The sweep registry.
--
-- 🚨 THIS IS DELIBERATELY NOT THE `company` TABLE. `company` is the PIPELINE registry: it
-- joins to posting and application, it is rendered into the tracker, and every row in it
-- means "he has a relationship with these people". Putting 2,060 companies he is merely
-- watching into it would mix watching with applying in the one table whose meaning the
-- whole tracker depends on, and there is no column that could later tell them apart.
--
-- ⭐ `enabled` exists so the expansion can be staged. The triage bill scales with how many
-- NEW requisitions appear per night, and the gate pass rate is unmeasured: at the churn
-- measured on 2026-08-14 (4 new across 16 boards in 7.2h, so ~1,717/day at 2,060 boards)
-- the monthly cost lands anywhere between $9 and $178 depending on it. Turning boards on in
-- tranches measures that rate before committing to it.
--
-- 📌 A company can be in both tables. job_scan sweeps the union: every enabled scan_board
-- row plus every company row that already carries an api_url, so applying to somewhere does
-- not remove it from the watch and adding it to the watch does not touch the pipeline.
CREATE TABLE IF NOT EXISTS scan_board (
  id       INTEGER PRIMARY KEY,
  platform TEXT NOT NULL,
  token    TEXT NOT NULL,
  api_url  TEXT NOT NULL,
  source   TEXT,                          -- where the token came from, for auditing
  added_at TEXT NOT NULL,
  enabled  INTEGER NOT NULL DEFAULT 0,    -- ⚠️ off by default. Staging is the point.
  note     TEXT,
  UNIQUE (platform, token)
);
CREATE INDEX IF NOT EXISTS idx_scan_board_enabled ON scan_board(enabled);

-- 🚨 The flood guard. A board with no state yet is INDISTINGUISHABLE from a board where
-- every requisition appeared at once, and "appeared" is what feeds triage. Without this,
-- adding the 2,060-board registry would present ~174,000 postings as new discoveries and
-- hand every one of them to a paid model on the first night.
--
-- So a board's first sweep SEEDS it: state is recorded, no change rows are written, no
-- candidates are produced. Real discoveries start from its second sweep.
--
-- ⚠️ It cannot be inferred from board_state being empty, because that is also what a board
-- with genuinely zero open requisitions looks like. Absence is not a verdict; this table is
-- the evidence that the question was asked before.
CREATE TABLE IF NOT EXISTS board_seeded (
  board TEXT PRIMARY KEY,
  at    TEXT NOT NULL
);

-- One row per sweep. Without it there is no record that a sweep happened on a night when
-- nothing changed, and "no changes" would be indistinguishable from "the scanner did not
-- run", which is exactly the ambiguity the vanish check must never inherit.
CREATE TABLE IF NOT EXISTS scan_run (
  id        INTEGER PRIMARY KEY,
  at        TEXT NOT NULL,
  boards    INTEGER NOT NULL,
  failed    INTEGER NOT NULL,
  appeared  INTEGER NOT NULL,
  vanished  INTEGER NOT NULL,
  note      TEXT,
  -- ⚠️ WRITTEN AT START, STAMPED AT FINISH. The row used to be inserted only when a sweep
  -- RETURNED, which distinguished "nothing changed" from "never ran" but left the third
  -- case invisible: a sweep that STARTED, wrote change rows, and died. Three of the first
  -- six change batches were exactly that (two killed by deploys, one by the pre-lock
  -- collision), and reading scan_change alone made a partial run indistinguishable from a
  -- complete one. That mistake was made, on 2026-08-14, by comparing an aborted 58-board
  -- run against a complete 2,862-board one and calling the difference phantom churn.
  --
  -- 📌 A row still 'running' after the process restarts is stale by definition, and startup
  -- marks it 'interrupted'. Absence of news is not success.
  status      TEXT NOT NULL DEFAULT 'running',   -- running | ok | interrupted
  finished_at TEXT
);
