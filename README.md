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
separate removal attempts. Select a known broker from the directory or enter a
custom site name. Directory selection uses its canonical name; it never generates
or sends a request. Unknown dates stay blank. Completed cases can be entered
directly as confirmed or independently verified, without fabricated prior steps.

The page shows due follow-ups and rechecks (including today), with status/date
filters. After completing a task, edit its date to move or clear it. These dates
are displayed in the tracker; there is no background scheduler or notification
service. Saving a record does not contact a site or send email. External links
are opened only when you click them.

Records live in the unencrypted `removal_records` table in `scrubbr.db`. Links
and notes may identify you. Avoid passwords or verification codes. "Removal
confirmed" means the site acknowledged it; "Removal independently verified"
means you checked the listing. A present or inconclusive manual check cannot be
saved as verified. Existing profile-based broker request/status tracking remains
separate. Each saved manual edit retains a snapshot in **Manual history** on the
edit page, including original request/effective date and entry timestamp. Existing
records receive a labeled baseline; no earlier history is invented. Use a new
record for a separate attempt. Deleting a record deletes its manual history too.

The history page's **Due this week** queue covers the next seven local calendar
dates, including today (`today <= date < today + 7 days`), with overdue actions
shown separately first. It includes scheduled rechecks for confirmed/verified
removals. Each follow-up or recheck is one action row linking to its record and
manual notes; records without dates or beyond the window remain in the list.
After acting, edit or clear the date. Viewing the queue never contacts websites
or changes status. `[app].timezone` accepts an IANA timezone; empty uses the Mac's
local timezone. Set it explicitly when running on a computer in another zone.

### Encrypted local backup and restore

Use the Terminal CLI below. Passphrases are prompted with hidden input, confirmed
on creation, and never put in command arguments, configuration, or backup files.
Use a long, unique passphrase and keep it safely yourself: losing it prevents
recovery. Run these commands from the repository root. There is no cloud upload.

```sh
mkdir -p backups
chmod 700 backups
.venv/bin/python -m scripts.backup create --output backups/removals-2026-10-01.scrubbr-backup
.venv/bin/python -m scripts.backup restore --input backups/removals-2026-10-01.scrubbr-backup --destination backups/restored-copy.db
```

Use fresh filenames every time. Restore authenticates and validates first, shows
date/version/counts/destination (no notes or profile fields), and asks for
`RESTORE` before creating an isolated database. It never merges records.

Backups contain the **entire SQLite database**, including profiles and email
metadata if present; the CLI discloses profile presence. Manual tracker records,
broker relationships, and edit history need no external assets. `config.toml`,
credentials, environment files, browser sessions, scan artifacts, and other files
are excluded. A restored copy does not configure email; use manual-only mode
when inspecting it on a machine with an existing email configuration.

The SQLite online backup API captures a consistent snapshot, including committed
WAL writes. Plaintext snapshot/encryption work stays in memory. AES-256-GCM
encrypts the database and versioned manifest and authenticates the envelope;
Argon2id derives a 32-byte key using a fresh 16-byte salt, 64 MiB of memory,
3 iterations and 4 lanes. Each backup has a fresh 12-byte nonce and a full
128-bit authentication tag. Parameters are fixed and validated before key
derivation. These choices follow the APIs and guidance bundled with
`cryptography` 50.0.2 (AESGCM and Argon2id documentation).

Only recognized schema versions 0/1 are supported: version 0 is the current
multi-profile hardening/tracker shape and migrates additively in isolated staging.
Older singleton-profile or unknown/custom/newer schemas are rejected. Validation
checks schema structure, SQLite integrity, foreign keys, tracker values, history,
and manifest consistency. Database size is limited to 64 MiB. There is no archive
extraction. Wrong passphrases and tampering share a non-sensitive error.

Files are published atomically with mode `0600`; existing backup files are never
overwritten. Backup filenames must end in `.scrubbr-backup`, and restored databases
in `.db`, `.sqlite`, or `.sqlite3`, all ignored by Git. Restore staging files are
plaintext with restrictive permissions, removed on handled success/failure;
cleanup is not secure erasure and cannot be guaranteed after a forced kill or
power loss. Memory/passphrase zeroization is not guaranteed by Python.
Backup encryption does **not** encrypt the active database or protect an unlocked
computer. History retains corrected notes, so avoid putting secrets in any entry.

#### Safe synthetic rehearsal

Do this before entering real records. The script refuses to reuse an existing
directory and never opens your normal database or loads email configuration.

```sh
.venv/bin/python -m scripts.backup_rehearsal --directory restore-staging/demo
.venv/bin/python -m scripts.backup create --database restore-staging/demo/original.db --output restore-staging/demo/manual.scrubbr-backup
.venv/bin/python -m scripts.backup restore --input restore-staging/demo/manual.scrubbr-backup --destination restore-staging/demo/manual-restored.db
.venv/bin/python -m scripts.backup_rehearsal --compare restore-staging/demo/original.db restore-staging/demo/manual-restored.db
SCRUBBR_DB_PATH="$PWD/restore-staging/demo/manual-restored.db" SCRUBBR_MANUAL_ONLY=1 .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 3001 --no-proxy-headers --no-access-log
```

Choose a disposable test passphrase at the creation prompts, enter it at restore,
review the counts, and type `RESTORE`. Comparison must report that every logical
table and relationship matches. Open `http://127.0.0.1:3001/history`, inspect
Example records and history, edit a date, and confirm the queue updates. Stop
with Ctrl+C. Try another fresh destination with the wrong passphrase; no database
should be created. The automated suite tests tampering, corruption, unsupported
schemas, replacement protections and rollback on disposable databases.

The rehearsal's initial automatic backup uses a random disposable passphrase in
memory and discards it after comparison; use `manual.scrubbr-backup` to practice
the interactive workflow. Synthetic databases are unencrypted and Git-ignored.

#### Replacing a database and recovering

Prefer an isolated restore. To deliberately replace an existing database, first
stop **all** Scrubbr processes and other SQLite tools using it. New Scrubbr servers
hold a cooperative lock throughout their lifetime; connections also take it.
Other programs and old running versions may not honor that lock, so explicitly
stopping them is required. Do not bypass locks or delete lock files.

```sh
.venv/bin/python -m scripts.backup restore --input backups/removals-2026-10-01.scrubbr-backup --destination scrubbr.db --replace-existing --recovery-backup backups/before-replacement.scrubbr-backup
```

Review the preview, type `REPLACE`, and choose/confirm a passphrase for the recovery
snapshot. The current database must first be snapshotted, encrypted, published
to a fresh filename, and successfully decrypted/validated. Any failure aborts
replacement. The flow checks SQLite locks, checkpoints WAL, closes connections,
handles sidecars, and atomically replaces from a restrictive staged file. On a
handled replacement failure it attempts rollback from the in-memory snapshot.
Retain the encrypted recovery artifact until you have inspected the result.

After an interruption or failed rollback, keep the app stopped. Restore the
recovery artifact to a fresh `.db` path using its recovery passphrase, inspect it
with `SCRUBBR_DB_PATH` and `SCRUBBR_MANUAL_ONLY=1` as above, then deliberately
replace the original using the same guarded restore flow. A force kill/power loss
cannot run Python cleanup; the encrypted recovery snapshot is the recovery path.
No live replacement is performed during development validation.

#### Begin recording your completed removals

After rehearsal, stop the port-3001 test server. Stop/restart your usual app with
the current code; do not set `SCRUBBR_DB_PATH` for normal use. For a manual-only
session that blocks scan/send/inbox routes while leaving configuration untouched:

```sh
SCRUBBR_MANUAL_ONLY=1 .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 3000 --no-proxy-headers --no-access-log
```

Open `http://127.0.0.1:3000/history` → **Add removal record**. Choose a broker or
enter a custom site, enter the original request date if known, select the actual
status, and optionally record brief notes/evidence and follow-up/recheck dates.
Leave unknown dates blank. Choose confirmed only for a broker acknowledgement,
and independently verified only after your own check. Save; no profile or email
credentials are required. Add a separate record for another attempt. Back up to
a new encrypted filename after meaningful updates.

### Manual opt-out guidance from BADBOOL

**Opt-out guide** (`/guidance`) uses a reviewed, local, commit-pinned copy of
[Yael Grauer's Big Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List).
The initial eight guides cover BeenVerified, CheckPeople, Cyber Background Checks,
EveryJoe, FamilyTreeNow, Intelius, Spokeo and White Pages. They include source
priorities, manual instructions, links and phone/identity/cost symbols. A review
means the published source was inspected; broker procedures were not tested live.

Expand a guide and choose **Record activity**. Existing directory matches reuse
their broker ID; EveryJoe starts a custom-site record without adding a broker to
the registry. No request is sent/generated, no dates/evidence are invented, and
the initial status is **Not requested** until you choose the actual status.
Guidance also appears on matching record forms, including edits and legacy
custom records matched by name. Otherwise use the guide link before selecting a
site. Instructions remain guidance for the current source revision; they are not
automatically copied into your notes or retained as per-record procedure history.

The source and full license are bundled together with hashes in
`data/sources/badbool/catalog.json`. Imported/adapted data is **CC BY-NC-SA 4.0**,
separately from Scrubbr's MIT code; preserve attribution and the noncommercial /
share-alike terms when redistributing. See [third-party notices](THIRD_PARTY_NOTICES.md).
The comparison/update command never modifies the broker registry or SQLite.
Source-reported changes to Radaris, Rehold and Advanced Background Checks appear
as review flags, preserving all brokers and historical records. Absence from a
curated list is not evidence that a broker has closed.

From the repository root, inspect the bundled snapshot offline:

```sh
.venv/bin/python -m scripts.broker_guidance
```

To review another version, use the full commit SHA from the upstream repository:

```sh
.venv/bin/python -m scripts.broker_guidance --revision FULL_40_CHARACTER_COMMIT_SHA
```

Only this explicit option downloads the two pinned source files from GitHub;
redirects are refused. There are no startup/background downloads or broker calls.
The command prints the existing directory comparison, source additions/changes/
removals and the complete proposed guide contents. To inspect a newly suggested
site, add `--select 'Exact source site name'`. No new guides are selected merely
because they appear upstream. If an imported guide is removed/renamed, applying
fails until you deliberately `--deselect 'Old name'` and optionally select the new
name. Retained review flags keep their original source revision.

After reviewing the proposed text, repeat with `--apply` and type
`APPLY FULL_40_CHARACTER_COMMIT_SHA` when prompted. Offline selection changes also
support `--select ... --apply`; the confirmation uses the bundled revision.
The catalog is validated and atomically replaced; review the Git diff before
committing. Dates/statuses, personal profiles, credentials, scan configuration,
and the original `data/brokers.json` are unaffected. Keep the application source
and its pinned catalog together; encrypted database backups contain records,
not this public guidance dataset. No new dependency or schema migration is used.

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
