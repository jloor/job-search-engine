# relay

Mail ingress and egress for the job-search platform. Inbound arrives from ImprovMX as
webhooks, gets archived and classified; outbound goes back out through SMTP, but only
after a human signs the exact bytes.

```
ImprovMX  ──webhook──▶  relay (Magic Container)  ──SQL over HTTPS──▶  Bunny Database
*@jobs.example.com        │                                       (libSQL)
                               └──SMTP 587──▶ smtp.improvmx.com ──▶ recruiter
                                              ▲
                                     approve.py signs first
```

Security model, threat by threat: **[SECURITY.md](SECURITY.md)**. Read it before changing
anything in the auth path.

## Files

| File | What |
|---|---|
| `app.py` | The service. FastAPI, one file. |
| `schema.sql` | Tables. Runs unchanged on local SQLite and Bunny Database. |
| `approve.py` | Operator CLI. Signs one outgoing message. Runs on his laptop, never in the container. |
| `bunny.py` | Provisions the database, mints its token, applies the schema. |
| `deploy.sh` | Builds `linux/amd64`, smoke-tests the image, pushes to GHCR. |
| `Dockerfile` | Non-root (uid 10001), no `--proxy-headers` (see SECURITY.md). |

## Storage is swappable

`BUNNY_DATABASE_URL` set routes every query to Bunny Database over its documented
HTTP SQL API (libSQL Hrana v2 pipeline). Unset falls back to a local SQLite file at
`DB_PATH`. Same `schema.sql`, same queries, no translation layer, because libSQL is a
SQLite fork.

The pipeline protocol is spoken directly with `urllib` rather than through a client
library. It is about forty lines, it keeps a dependency out of the image, and it pins
the service to the documented wire format instead of a package's release cadence.

📌 **With the managed database attached, the container needs no persistent volume at
all.** That also sidesteps volume ownership: the process runs as uid 10001, so a
bind-mounted directory owned by anyone else fails to open with
`sqlite3.OperationalError: unable to open database file`.

## Deploy

### 1. Database

```bash
export BUNNY_API_KEY=$(op read "op://Private/bunny.net/API Key" --account my.1password.com)

python3 bunny.py db-create --name job-search-relay --region NY
python3 bunny.py db-token  --name job-search-relay      # prints the two env vars
```

Then apply the schema and prove it worked:

```bash
export BUNNY_DATABASE_URL=...        # from db-token
export BUNNY_DATABASE_AUTH_TOKEN=...
python3 bunny.py db-schema
python3 bunny.py db-verify           # lists tables and row counts
```

`bunny.py` has **no delete path**, deliberately. Dropping a database that holds recruiter
correspondence should be a considered act in the dashboard, not a flag on a script.

### 2. Image

```bash
gh auth refresh -h github.com -s write:packages
gh auth token | podman login ghcr.io -u <owner> --password-stdin
./deploy.sh
```

`deploy.sh` pins `--platform linux/amd64` (Magic Containers runs nothing else), builds
with `--format docker` so podman keeps the `HEALTHCHECK`, and **starts the image and
calls `/health` before it pushes**. An image that cannot boot never reaches the registry.

### 3. Magic Containers app

1. The GHCR package is private, so connect the registry once: type GitHub, username
   `<owner>`, and a PAT with `read:packages`.

   🚨 **It must be a *classic* PAT (`ghp_…`), not a fine-grained one (`github_pat_…`).**
   GitHub's docs are explicit: *"GitHub Packages only supports authentication using a
   personal access token (classic)."* A fine-grained token authenticates fine against
   `api.github.com` and even succeeds at `podman login ghcr.io`, then fails at pull with
   a bare `denied`. Verified the hard way on 2026-08-12. Create it at
   **github.com/settings/tokens/new** (not `/settings/personal-access-tokens/new`).

   ⚠️ **Set the expiry deliberately and write the date down.** Classic PATs default to 30
   days. The first token minted for this expired unnoticed, and the failure mode months
   later is an app that cannot restart for reasons nobody remembers.
2. Image `ghcr.io/<owner>/job-search-relay:latest`, port `8080`.
3. Database > Access > **Generate Tokens** > **Add Secrets to Magic Container App**.
   That injects `BUNNY_DATABASE_URL` and `BUNNY_DATABASE_AUTH_TOKEN` under exactly those
   names, which `app.py` reads with no further configuration.
4. Add the rest as **secrets**, not plain variables:

```bash
python3 -c "import secrets;[print(n+'='+secrets.token_urlsafe(32)) for n in ('API_TOKEN','APPROVAL_SECRET','INBOUND_TOKEN')]"
```

   plus `SMTP_USER`, `SMTP_PASS`, and `MAIL_DOMAIN=jobs.example.com`.

   `ANTHROPIC_API_KEY` too, if the second reading is wanted (below). Leave it unset and
   that job skips itself and says so; nothing else changes.

🚨 **`APPROVAL_SECRET` is the human gate.** It never goes in the repo, never in a shell
history, and never into an agent's environment. Agents get `API_TOKEN` only.

### 4. Verify the proxy depth before trusting the allowlist

This is the setting that silently turns the inbound IP allowlist into decoration.

```bash
curl -s -H "Authorization: Bearer $API_TOKEN" https://<app-host>/diag/ip | python3 -m json.tool
```

`resolved` must equal your real public IP (`curl -s ifconfig.me`). If it shows a proxy
address, `TRUSTED_PROXY_HOPS` is too high. If you can change it by sending your own
`X-Forwarded-For`, it is too low. Fix it before pointing ImprovMX at the endpoint.

### 5. Point ImprovMX at it

Webhook URL: `https://<app-host>/inbound/<INBOUND_TOKEN>`

ImprovMX posts from **`15.237.103.194`** and does not sign payloads, which is why the
allowlist is the primary control and the token is the second factor. It retries **twice**
on any 4xx or 5xx, so rejections happen before any write, and parse failures answer 200
on purpose (a poison payload must not be redelivered forever; the raw row is already saved).

### Rotating the webhook token without losing mail

🚨 **The token IS the URL path**, so rotating it means changing two systems that cannot move
at the same instant. Whichever moves first, deliveries in between hit a path the other side
rejects, ImprovMX retries twice, and the message is **gone silently**.

`INBOUND_TOKEN` is therefore read as a **comma-separated list** and every entry is accepted.
That turns the race into a sequence:

1. Set `INBOUND_TOKEN=<old>,<new>` on the app. Confirm it landed **before** touching ImprovMX:
   ```bash
   curl -s -H "Authorization: Bearer $ADMIN_TOKEN" https://<host>/diag/ip \
     | python3 -c "import json,sys;print(json.load(sys.stdin)['inbound_tokens_configured'])"
   # must print 2
   ```
2. Point the ImprovMX webhook at `https://<host>/inbound/<new>`.
3. Wait for real mail, then confirm it arrived on the new path. `token_slot` is the index into
   the list, so `token_slot=1` means the new token:
   ```sql
   SELECT at, detail FROM event WHERE kind='inbound_raw' ORDER BY id DESC LIMIT 5;
   ```
4. Only once nothing has arrived on `token_slot=0` for a full mail cycle, set
   `INBOUND_TOKEN=<new>` alone. `inbound_tokens_configured` returns to 1.

⚠️ **Do not skip step 3.** Removing the old token while ImprovMX still points at it is the
same outage the list exists to prevent, just later and with less warning.

🚨 **Empty entries are dropped, and that is load-bearing rather than tidy.** An empty token
compares equal to an empty path segment, so a trailing comma would open the webhook to
anybody. Measured: with the filter removed, an unconfigured service **accepts** `/inbound/`.
The suite asserts both cases.

## Deployed

| | |
|---|---|
| App | `job-search-relay`, id `EAtkS3wXFyk5v8B`, region **ASB** (matches the database's `us-east-1`) |
| Endpoint | `mc-eiupu4t7ia.bunny.run` → `138.199.40.58` |
| Database | `db_01KZTWQQ3D6FJXASQ6Y548TR3X`, schema applied |
| Registry | id `9997`, ghcr.io as `<owner>`, classic PAT |
| `TRUSTED_PROXY_HOPS` | **1, verified** via `/diag/ip`: `resolved` matched the real client IP, and a forged `X-Forwarded-For` was correctly ignored |

⚠️ **Local DNS may lie about the endpoint.** On his home network `mc-eiupu4t7ia.bunny.run`
resolves to `167.206.37.145`, an ISP NXDOMAIN-hijack address, and a randomly generated
hostname returns the same IP. The real address is only visible over DoH. To test from
home, bypass the resolver:

```bash
curl --resolve mc-eiupu4t7ia.bunny.run:443:138.199.40.58 https://mc-eiupu4t7ia.bunny.run/health
```

📌 **The CDN edge cuts requests off at about 60 seconds**, so a slow diagnostic returns
504 even when it completed. `/diag/smtp` writes its result to the `event` table before
returning, so read the row instead of re-running the request.

### Which version is running, and is the scheduler alive

Two questions `/health` could not answer until v0.8.0. Both have the same failure shape:
the service looks fine and is doing nothing.

```bash
# which code is deployed. Anonymous callers get liveness only; the version needs a token.
curl -s -H "Authorization: Bearer $API_TOKEN" https://<host>/health | python3 -m json.tool

# when each scheduled job last ran, and whether that is too long ago
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" https://<host>/diag/jobs | python3 -m json.tool
```

🚨 **`/health` returning `{"ok":true}` was identical from v0.4.0 and v0.7.0.** A deploy that
silently did not take could not be told apart from one that did, and the number lived in
the package with no route serving it. It is now in the authenticated response, and it is
read from `__init__.py` rather than written a second time, because two copies drift.

🚨 **`/diag/jobs` is the only thing that watches the scheduler.** Every other check triggers
a job by hand through `/admin/run`, which proves the job works and proves nothing about the
loop meant to call it. If `_scheduler()` dies, all eight jobs stop, `/health` stays green,
and the silence looks exactly like a quiet night.

- **Read `ok` first.** It is false when any job has missed `STALE_FACTOR` (default 3)
  intervals. Every job stale at once means the loop, not the job.
- ⚠️ **`stale` and `last_error` answer different questions.** A job that runs exactly on
  schedule and fails every time is **not stale**. Read both, or a permanently broken job
  reports as healthy.
- The verdict comes from the `event` table, not an in-process counter. A counter resets on
  deploy and would call a container that has run nothing for a week perfectly healthy.
- A freshly booted container does not alarm on jobs that were never due. That is why
  `uptime_s` is in the response.

## Sending: two paths, and when to use each

| | ImprovMX SMTP | Resend (HTTPS API) |
|---|---|---|
| From address | **only** `outgoing@jobs.example.com` | **any** `<alias>@jobs.example.com` |
| Transport | SMTP 587 from the container | HTTPS, so no egress dependency |
| Used by | `/send` today | per-alias replies |

⭐ **Resend verified on `jobs.example.com` 2026-08-12 and proven end to end.** A probe
was sent through Resend, looped back through ImprovMX, and the relay recorded the receiving
MTA's own verdict rather than anyone reading a dashboard:

```
{"spf": "grey", "dkim": "pass", "dmarc": "pass"}    auth_warn 0
```

📌 **`spf` is not `pass`, and that is correct.** Resend sends via SES, and the SPF record
for `jobs.example.com` lists only ImprovMX. Alignment rides entirely on DKIM, which is
exactly the design: `_dmarc.jobs` sets `adkim=r`, DMARC passes if **either** mechanism
aligns, and this is why neither the apex nor the `jobs` SPF record had to be touched.

⚠️ **Do not "fix" the SPF by adding amazonses to `jobs.example.com`.** It is not
broken. Editing it risks the ImprovMX inbound path for no gain.

**DNS added (all new names, nothing existing modified):**

```
resend._domainkey.jobs   TXT   p=MIGfMA0GCSqGSIb3DQEBAQ…QIDAQAB
send.jobs                TXT   v=spf1 include:amazonses.com ~all
send.jobs                MX    10 feedback-smtp.us-east-1.amazonses.com
```

`jobs.example.com` MX still points at ImprovMX for inbound; the apex still points at
Fastmail. Resend's "Enable Receiving" is deliberately **off**.

## ✅ Outbound SMTP also works as of 2026-08-12 20:45 UTC (was blocked; the Bunny case fixed it)

Port **587 is now open** from the container to Gmail, Fastmail and ImprovMX. The full
handshake succeeds: EHLO, STARTTLS, AUTH. **A real message was delivered end to end.**

⚠️ **25 and 465 are still blocked** (`Network is unreachable`), which is the sensible
policy: authenticated submission permitted, direct-to-MX and legacy implicit TLS not.
Do not 'fix' `SMTP_PORT`; 587 is the only one that works and the only one needed.

🚨 **ImprovMX requires the From address to MATCH the authenticated SMTP user.**
Authenticated as `outgoing@jobs.example.com`, sending as
`acme@jobs.example.com` is refused with `550 5.1.9 Relay not permitted`. So the
per-application alias works for RECEIVING but not for sending. Replies currently go out
as the single `outgoing@` address. If per-alias sending matters, it needs one SMTP
credential per alias, which is a decision to make deliberately rather than discover
mid-reply.

### The original diagnosis, kept because it was right


Measured from inside the deployed container on 2026-08-12:

| Target | Result |
|---|---|
| `1.1.1.1:443`, `140.82.121.6:443` (GitHub), `8.8.8.8:53` | open |
| Bunny Database | open |
| `smtp.improvmx.com` on 587, 465, 2525, 25, **and 443** | every one times out |

DNS resolves correctly (`13.36.13.170`, `13.36.216.200`, `13.37.12.179`, AWS Paris).
General egress works. **The destination itself is unreachable from Bunny's network.**

⚠️ **Do not file this as "please open port 587."** That was the original assumption and the
control group disproves it. Mail ports are not filtered and the container is not sandboxed.
Something between Bunny and ImprovMX's AWS range drops the traffic, and the same host is
reachable from his home connection, which is how it was distinguished.

✅ **Not region-specific either. Tested 2026-08-12.** The app was moved to **AMS**
(Amsterdam, one hop from ImprovMX's Paris range, entirely different transit) and the result
was byte-identical: every port to `smtp.improvmx.com` timed out while all four control
hosts stayed reachable. Two continents, same answer. That rules out a routing or peering
fault and points at **ImprovMX dropping Bunny's address space wholesale**, which is ordinary
practice for mail providers against hosting-provider ranges. The app was moved back to ASB.

📌 **So this is at most ONE ticket, to ImprovMX, not two.** A Bunny ticket would be answered
by the control group in this very output. Expect ImprovMX to say they do not accept
submission from hosting providers, which is a policy answer, not a bug. Weigh that against
option 1 before spending the time.

**Options, in order of how much they cost:**

1. **Send over HTTPS instead of SMTP.** Outbound 443 demonstrably works. A provider with an
   HTTP send API (Resend, Postmark, SES) would work today with no platform negotiation.
   ⚠️ It changes the sending identity: that provider must be authorised for the domain,
   which means new DNS and a second DKIM selector. It does not disturb inbound.
2. **Ask both sides** whether the route can be fixed. Two tickets, slow, may go nowhere.
3. **Run only `/send` elsewhere.** Inbound is finished and working; only the outbound leg
   is affected.

## Original SMTP ticket wording (superseded, kept for the record)

Sending from a residential address returns `551 5.7.1 ... blacklisted by Spamhaus`.
Residential ranges are listed by policy, not by behaviour, which is the whole reason
outbound moved into a container.

Whether Bunny permits egress on 587 is unverified. Generate the evidence from inside the
running container rather than describing the problem:

```bash
curl -s -H "Authorization: Bearer $API_TOKEN" https://<app-host>/diag/smtp | python3 -m json.tool
```

It attempts the real connection and reports exactly where it fails (connect, EHLO,
STARTTLS, or AUTH), and writes the result to the `event` table. Paste that output into
the support ticket:

> Subject: Outbound SMTP (TCP 587) from a Magic Containers application
>
> I run a Magic Containers app that relays a small volume of personal email through my
> mail provider's authenticated submission server, `smtp.improvmx.com:587`, using
> STARTTLS and SMTP AUTH. This is authenticated submission to my own provider for my own
> domain, not direct-to-MX delivery, and the volume is a handful of messages per day.
>
> Connections from inside the container fail as follows:
>
> ```
> <paste /diag/smtp output>
> ```
>
> Is outbound TCP 587 permitted for Magic Containers applications? If it is blocked by
> default, is there a way to enable it for this app? If it cannot be enabled, please say
> so plainly and I will move the outbound leg elsewhere.

⚠️ If the answer is no, the inbound half still works and only `/send` needs rehoming. Do
not rebuild the whole service for it.

## Local development

```bash
podman build --format docker -t relay:dev .
podman run --rm -p 8099:8080 \
  -e API_TOKEN=dev -e INBOUND_TOKEN=dev -e APPROVAL_SECRET=dev \
  -e TRUSTED_PROXY_HOPS=0 -e ALLOW_INBOUND_IPS= -e DB_PATH=/tmp/dev.db relay:dev
```

`TRUSTED_PROXY_HOPS=0` and an empty `ALLOW_INBOUND_IPS` disable the two inbound controls
so you can post to the webhook by hand. **Never deploy with those values.**

## /data working copy ✅ verified 2026-08-12

The volume holds a git clone of the private repo. Git stays the source of truth; the
volume is a cache. That is what makes Bunny's volume properties survivable: per-instance,
blank on a fresh pod, no backups. A blank volume is a cache miss, so it clones.

| Check | Result |
|---|---|
| Blank volume clones on `?sync=true` | 443 files, 24 archived JDs |
| Survives a pod replacement | ✅ pod `T75pW2t…` replaced by `23ywKmR…`, clone intact, no re-sync needed |
| Second sync is idempotent | ✅ |
| Change under `applications/` or `platform/state/` | committed and pushed |
| Change under `vault/` | 🚫 refused **and reverted** |

```bash
curl -H "Authorization: Bearer $API_TOKEN" https://<host>/diag/repo            # state
curl -H "Authorization: Bearer $API_TOKEN" "https://<host>/diag/repo?sync=true" # clone/pull
```

🚨 **Two writers now share this repo.** The relay pushes from the container and the operator
pushes from his laptop. **Pull before working locally.** The relay always fetches and
hard-resets before it writes, and it can only touch `applications/` and `platform/state/`,
so `vault/` is safe from it. That fence is enforced in `gitsync.py` and tested.

⚠️ **The container has no 1Password SSH signer**, so `gitsync` sets `commit.gpgsign=false`
in the working copy. Without it every commit fails with `failed to write commit object`.

🚨 **One instance only.** Volumes are per-instance, so a second pod means a second working
copy pushing to the same repo. `rollout.py volume` refuses to attach while the app runs
more than one, and that guard has already fired once for real.

## Second reading: a model labels what the rules could not — 2026-08-13

`classify()` matches wordings somebody thought to write down. It is right about most mail
and wrong in exactly one direction: it answers `unknown` for a phrasing that is not in the
list. On 2026-08-13 a Zafran Security rejection reading *"decided to move forward with
other applicants"* came back `unknown`, because the rules held `not moving forward` and
`other candidates` and neither is what Zafran wrote.

Two things came out of that. The wording is now in `RULES` with a regression test, and a
scheduled job runs a model over whatever is still `unknown`.

**The extraction is the bigger half.** A regex can guess a label. It cannot tell you that
mail from an agency recruiter is about a job at a different company. From a probe:

| Field | From a recruiter's mail |
|---|---|
| `employer` | Northwind Health — **not** Halcyon Search, who sent it |
| `comp_mentioned` | `$135,000-$155,000 base`, verbatim |
| `interview_at` | `Thursday at 11am ET`, as written, not resolved to a date |
| `deadline` | `Friday` |
| `next_action` | reply by Friday about the Thursday slot |

### How it runs

| Setting | Default | Does |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | No key, no job. It reports `skipped`, it does not fail. |
| `AI_READ_ENABLED` | `1` | `0` stops it whatever else is set. |
| `AI_READ_EVERY_MIN` | `15` | How often the scheduler wakes it. |
| `AI_READ_BATCH` | `10` | Messages per run. |
| `AI_PROVIDER` | `anthropic` | `anthropic` or `openai_compat`. |
| `AI_BASE_URL` | `https://api.openai.com/v1` | `openai_compat` only. OpenRouter is `https://openrouter.ai/api/v1`. |
| `AI_API_KEY` | unset | `openai_compat` only. Falls back to `OPENAI_API_KEY`, then `OPENROUTER_API_KEY`. |
| `AI_MODEL` | `claude-sonnet-5` | See the model comparison below. |
| `AI_EFFORT` | `low` | Labelling is not a reasoning problem. **Empty for Haiku 4.5**, which rejects the parameter with a 400. |
| `AI_MAX_BODY_CHARS` | `6000` | A rejection says what it says in the first paragraph. |

### Prompt caching, switched on by batch size

The stable prefix is the system prompt **plus the output schema**, and the schema is the
larger half: 469 tokens of prompt against ~955 of schema, caching as **1,426 tokens**.

⚠️ **Neither piece would cache alone.** Sonnet 5 needs a 1,024-token prefix and the
prompt is 469. This only works because the two cache together.

The cost is asymmetric: a cache write is billed at **1.25x** and a read at **0.1x**, so
one message alone pays for a write it never reads back. Measured per scheduler run:

| messages in the run | vs no caching |
|---|---|
| 1 | **+15%** |
| 2 | −19% |
| 3 | −30% |
| 10 | −46% |

So `job_ai_read` sets the breakpoint only when `len(rows) >= 2`. Break-even is exactly
two, which is where the condition sits.

📌 **The 5-minute TTL is why this is per-run.** Runs are 15 minutes apart, so a cache
written by one run is always cold by the next; only messages landing in the *same* run
share a prefix. Raising `AI_READ_EVERY_MIN` batches more per run and caches better, at
the cost of a later label.

⚠️ **`cache_write_tokens` and `cache_read_tokens` are recorded per reading**, because a
breakpoint that silently fails to engage looks exactly like one that works until the
invoice arrives. The job's log line reports what the cache actually did:

```
read 3 of 3; cache 0 written / 4278 read
```

```bash
# what caching is actually saving
sqlite3 relay.db "SELECT date(created_at) d, count(*) n, sum(input_tokens) fresh,
                         sum(cache_write_tokens) w, sum(cache_read_tokens) r
                    FROM ai_reading GROUP BY d ORDER BY d DESC LIMIT 14;"
```

Verdicts land in `ai_reading`, one row per message, keyed by `message_id`. The job reads
`body_reply` — the same stripped text `classify()` reads — so when the two disagree they
disagree about the same words.

🚨 **It writes to `ai_reading` and to nothing else.** It cannot change
`message.classification`, cannot clear `needs_human`, and cannot cause mail to be sent.
Read `SECURITY.md` before changing that: mail content now leaves the box, and the section
there records what goes, what does not, and why the model has no capability worth
capturing by a hostile sender.

### Why the scheduler and not the webhook

ImprovMX retries a delivery that the webhook does not answer quickly. A model call on the
inbound path buys duplicate messages in exchange for a label that is fifteen minutes
fresher, which is the wrong trade for mail nobody is watching in real time.

```bash
# what the model made of everything the rules could not label
sqlite3 relay.db "SELECT m.subject, m.classification, a.classification, a.confidence,
                         a.employer, a.next_action
                    FROM ai_reading a JOIN message m ON m.id = a.message_id
                   ORDER BY a.created_at DESC LIMIT 20;"
```

### Which model, measured rather than assumed

Six cases through each model, then five trials each on the two that actually discriminate:
a requisition put on hold (which is **not** a rejection, and marking it one would close a
live application) and a proposed time buried in a recruiter's paragraph.

| Model | "req is paused" labelled right | Proposed time captured | Per message | Per 100 |
|---|---|---|---|---|
| `claude-opus-5` | 5/5 | 5/5 | $0.0115 | $1.15 |
| **`claude-sonnet-5`** ← default | **5/5** | **5/5** | **$0.0073** | **$0.73** |
| `claude-haiku-4-5` | **1/5** | **4/5** | $0.0018 | $0.18 |

Sonnet matched Opus on every case for about a third less, so Opus is paying for nothing
here. Haiku is six times cheaper again and is the only model that got anything wrong: it
called a paused requisition `noise` in four trials of five, and dropped `Thursday at 11am
ET` entirely in one of five.

⭐ **The cheapest model is the wrong choice, and not because of the label.** A wrong label
is survivable, because every one of these messages is `needs_human` anyway and a person
reads it. A silently dropped meeting time is not: the field just reads `null`, which is
indistinguishable from a message that proposed no time at all. **An extraction that fails
by omission cannot be noticed.**

⚠️ **One trial is not a measurement.** Sonnet got the paused-requisition case wrong on the
first single-sample run and right 5/5 on repeat. That first result was sampling noise, and
acting on it would have bought the more expensive model for no reason. Re-run trials
before changing this row.

📌 **Cost is not the deciding factor at this volume.** The gap between the most and least
expensive option is under a dollar per hundred messages. Choose on whether the extraction
is right.

### Two providers, because the model choice rests on a small sample

`AI_PROVIDER` selects the path. The prompt, the schema, the batch logic, the proposal
table and the human gate are identical either way; only the transport differs.

| | `anthropic` | `openai_compat` |
|---|---|---|
| Transport | official SDK | raw HTTP to `{AI_BASE_URL}/chat/completions` |
| Nullable fields in the schema | `anyOf` | `["string","null"]` |
| Effort parameter | `AI_EFFORT` | not sent |
| Prompt caching | explicit breakpoint, batch ≥ 2 | automatic, and see below |
| Dependency | `anthropic` | none, `urllib` |

⚠️ **The schema dialect is not cosmetic.** Anthropic's validator takes `anyOf` for a
nullable field and OpenAI's strict mode wants a type list. Send the wrong one and you get
a 400 that reads like the model failing. `schema_for()` derives both from one definition,
and the test asserts each dialect in both directions.

**To run Luna via OpenAI direct:**

```
AI_PROVIDER=openai_compat
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=sk-...
AI_MODEL=gpt-5.6-luna
```

**To revert:** `AI_PROVIDER=anthropic`, `AI_MODEL=claude-sonnet-5`. Nothing else changes,
and no redeploy is needed — both paths ship in every image.

📌 **Prompt caching does not engage on the OpenAI path, and it does not matter.** OpenAI
caches automatically above ~1024 prompt tokens; ours measured **697**, and three identical
requests returned `cached_tokens: 0` every time. At Luna's $0.10/M input the entire input
cost is $0.00007 a message. Padding the prompt to reach the threshold would mean paying
for padding to earn a discount on padding. The Anthropic breakpoint stays live on the
revert path, where it is worth 30–46%.

⚠️ **`openai_compat` via OpenRouter puts mail with two parties**, OpenRouter and the
upstream provider, each with its own retention terms. Prefer OpenAI direct for anything
that runs on real mail. OpenRouter is for benchmarking.
