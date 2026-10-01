# Scrubbr

A local, self-hosted data-broker removal assistant — a subscription-free
reimplementation of [Incogni](https://incogni.com/)'s core workflow that keeps
your personal data on your own machine.

Incogni is a paid service that acts as your *authorized agent* to get your data
deleted from ~400+ data brokers under CCPA/GDPR. This tool does the same job
locally. Because **you** are the data subject (not a third-party agent), your
requests carry full legal weight with no authorization paperwork, and you control which identifiers are included. Profiles are stored locally;
broker searches and removal requests disclose identifiers to their recipients.

## What it does (v1)

- **Broker directory** — 130 curated high-priority US brokers (people-search,
  marketing, risk, recruitment) with opt-out URLs/emails, contact method, legal
  basis, and difficulty. Seeded from `data/brokers.json`; easy to extend.
- **Local profile** — your identifiers (name, aliases, emails, phones,
  addresses, DOB), stored in SQLite, used only to fill request templates.
- **Request generation** — per-broker legal deletion + opt-out requests from
  Jinja2 templates, chosen by jurisdiction (CCPA / GDPR / generic multi-state).
- **Sending** — each broker gets an action page: for email brokers, a `mailto:`
  link and copyable text; for form brokers, the opt-out URL plus step-by-step
  instructions and your details to paste. Email-capable brokers can also be sent
  automatically in bulk from the **Send** page (opt-in, see below); form brokers
  always stay manual.
- **Status tracking** — per-broker pipeline (`not started → sent → confirmed /
  rejected / needs verification`) with history, plus a dashboard with counters
  and a "due for follow-up" list.
- **IMAP reply monitoring** — point it at a mailbox/label; it correlates broker
  replies (via a `[PIR-<id>]` subject tag), classifies them, and auto-advances
  statuses. Ambiguous mail goes to a **review queue**; it never sends, replies,
  or deletes.
- **Recurrence** — sent requests get a follow-up date (60 days people-search,
  90 otherwise) surfaced on the dashboard when due.
- **Exposure scanning** — a local Playwright browser session checks a
  broker's public search page for your profile and scores any listing
  against it (name, age, location, alias, phone), never on a bare
  name-appears-on-page match. Four outcomes: **found** / **not found** /
  **possible match** (low-confidence, you confirm or dismiss) / **couldn't
  check** (blocked/timeout, falls back to a manual search link). Go to the
  **Scan** page and click **Scan** (single broker) or **Scan all**; each
  scan launches a real browser and is rate-limited, so expect ~10-25s per
  broker, more for a bulk run.
  **Only 5 of the 130 brokers are currently wired up for this** — Whitepages,
  Radaris, FastPeopleSearch, TruePeopleSearch, That'sThem — because each one
  needs real CSS selectors hand-verified against its live results page
  (`scan` key in `data/brokers.json`). Every other broker, even ones that do
  have a public search in reality (e.g. CheckPeople), shows up under "Not
  publicly searchable" until someone adds a `scan` config for it — that's
  manual coverage growth, not something scanning unlocks automatically.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/playwright install chromium         # one-time, for exposure scanning
.venv/bin/python -m scripts.seed_brokers      # load broker registry
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 3000 --no-proxy-headers --no-access-log    # http://127.0.0.1:3000
```

Then open the dashboard. Add a **Profile** only when you are ready to store
identifying information locally and share selected details with brokers.

### Local security and privacy

Run one server process, bound to `127.0.0.1`. Only `127.0.0.1` and `localhost`
Host headers are accepted. POST forms require a signed browser CSRF cookie and
matching hidden token; explicit foreign origins/referers are rejected. Cookies
are host-only, HttpOnly and SameSite=Strict. Reload forms after restarting the
server: the signing key changes on restart. Direct scripts posting forms must
first GET a page and retain its cookie/token. Forms are limited to 1 MiB.

IMAP, SMTP STARTTLS and implicit SMTP TLS validate server certificates and
hostnames using the system trust configuration. There is no insecure fallback.
Email remains disabled unless explicitly enabled in `config.toml`.

Profiles, listings and email metadata in SQLite are **not encrypted**. Email
passwords in `config.toml` are **plaintext**; Keychain storage is not implemented.
Git exclusions help prevent accidental commits but do not protect backups or
other local users. Browser request protections are not login authentication.

Scanning sends first/last name and any city/state URL fields to broker websites;
their scripts and trackers can receive browser metadata and query details.
Removal email templates include the profile identifiers that you supply,
including DOB when present. Review requests before sending. IMAP reads recent
messages in the selected folder; use a dedicated mailbox/folder if enabled.
API documentation pages are disabled to avoid external CDN assets, and native
FastAPI telemetry is disabled. Static fonts/CSS remain local.

Reinstall dependencies with `pip install -r requirements.txt`; the tested resolved
Python environment is pinned in `requirements.lock.txt`. After changing Playwright,
rerun `playwright install chromium` with the same `PLAYWRIGHT_BROWSERS_PATH`.

### Manual removal history

Use **Removal history** to record work already done on any website, including
sites outside the broker directory. No personal profile is required. Add a site,
optional listing/evidence URLs, request date and method, outcome, notes, last
checked date, and follow-up/recheck dates. A site can have multiple records for
separate removal attempts.

The page shows due follow-ups and rechecks (including today), with status/date
filters. After completing a task, edit its date to move or clear it. These dates
are displayed in the tracker; there is no background scheduler or notification
service. Saving a record does not contact a site or send email. External links
are opened only when you click them.

Records live in the unencrypted `removal_records` table in `scrubbr.db`. Links
and notes may identify you. Avoid passwords or verification codes. "Removal
confirmed" means the site acknowledged it; "Removal independently verified"
means you checked the listing. Existing broker request/status tracking remains
separate. Editing replaces a record's fields; this first version does not keep
an audit log of edits, so use another record for a separate removal attempt.

### Optional: inbox monitoring

Copy `config.example.toml` to `config.toml`, set `[imap] enabled = true`, and
fill in host/username/app-password. Use a **dedicated mailbox or Gmail label**
and an **app-specific password**. Send your removal emails from that address so
replies land where the poller can see them, and keep the `[PIR-N]` subject tag
intact. Click **Check inbox** on the dashboard to poll.

### Optional: automatic sending

Set `[smtp] enabled = true` in `config.toml` with the **same mailbox** as
`[imap]` — broker replies must land in the mailbox being polled, so auto-sent
requests use no `Reply-To` and rely on the From address being that mailbox.
On the **Send** page, **Preview** renders and stages every eligible
not-yet-sent email/both broker without sending anything; **Send for real**
opens one SMTP connection and works through the (editable) selection with a
jittered pause between messages. Only brokers still `not_started` and not
verdicted `not_found` are eligible; follow-up re-sends and form-only brokers
always stay manual. A full run of the ~75 email-capable brokers takes several
minutes and is well under Gmail's ~500 recipients/day limit.

## Tests

```sh
.venv/bin/python -m pytest
```

Covers template rendering, status transitions / follow-up dates, reply
classification, and the scan pipeline (match scoring, HTML extraction, rate
limiting, outcome persistence) — all against saved HTML fixtures, no live
network calls.

## Project layout

```
app/       main.py (routes) · db.py · models.py · templater.py · inbox.py · sender.py
           scanner.py · fetcher.py · extract.py · matcher.py · ratelimit.py · scan_service.py
           send_service.py
           templates/ (HTML) · static/style.css
data/      brokers.json · request_templates/ (ccpa/gdpr/generic + _identity)
scripts/   seed_brokers.py
tests/
```

## Caveats

- Opt-out URLs and privacy emails change often. Verify a broker's current
  process before relying on it; update `data/brokers.json` and re-seed.
- Some brokers require phone/ID verification or re-list data quickly (flagged by
  the `difficulty` field and notes) — those need manual follow-up.
- **Address format matters for scanning.** `scanner.search_context()` extracts the
  city from the *first line* of `profile.addresses` by splitting on the last comma
  and assumes `"street, city state zip"` (one comma before the city). An address
  written `"street, city, state zip"` (two commas, e.g. `"10 Beacon St, Boston,
  MA 02108"`) yields an empty city and breaks the search URL. Known bug,
  not yet fixed — format addresses as one comma before city/state/zip to avoid it.
- This is a personal tool, not legal advice.

## v2 roadmap

Automatic email sending shipped (see above). Remaining seams:

1. **Web-form automation.** For `contact_method = form` brokers, drive the
   opt-out flow with Playwright behind a shared `deliver()` call, dispatched by
   `broker.contact_method`. Expect friction from CAPTCHAs and phone/email
   verification — keep the manual fallback.
2. **Scheduled follow-ups.** A background scheduler that re-sends due requests on
   their cadence instead of surfacing them for a manual click.
3. **Broker list expansion.** Grow toward the full ~400+ using the public
   [Big Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List)
   and the [California DROP](https://cppa.ca.gov/data_brokers/) registry.
```
