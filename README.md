# Journald-Sniffer

Linux auth event ingestion and threat detection pipeline. Reads systemd journal (facility 10 — `authpriv`), parses sudo/su/sshd sessions, classifies outcomes via keyword matching with Groq LLM fallback for ambiguous cases, and alerts on suspicious patterns. Exposed via FastAPI and containerized with Docker.

---

## How it works

```
systemd journal
      │
      ▼
  ingestor.py       → raw_logs (PostgreSQL)
      │
      ▼
  parser.py         → auth_logs (PostgreSQL)
  + llm.py          → Groq LLM for ambiguous sessions
      │
      ▼
  watchdogv2.py     → alerts printed to stdout
      │
      ▼
  app.py            → FastAPI endpoints
```

### Pipeline stages

**Stage 1 — Ingestor (`ingestor.py`)**
Reads journal entries filtered to `sudo`, `su`, and `sshd-session`. Stores each entry as a raw JSON blob in `raw_logs`. Uses the systemd journal cursor as a bookmark to resume from where it left off on subsequent runs.

**Stage 2 — Parser (`parser.py`)**
Reads `raw_logs` and groups entries by `(program, pid)` into 60-second session windows (`AuthBuffer`). Classifies each message as `success`, `failure`, or `neutral` using keyword matching. For sessions that are ambiguous (`unknown` or `suspicious` with failures present), escalates to an LLM call. Flushes each session as one row into `auth_logs`.

**Stage 3 — LLM (`llm.py`)**
Called by the parser for ambiguous sessions only. Sends all raw messages from the session to Groq (`llama-3.1-8b-instant`) and returns a classification: `success`, `failure`, `suspicious`, or `unknown`.

**Stage 4 — Watchdog (`watchdogv2.py`)**
Queries `auth_logs` for threat patterns over a 10-minute window:
- `[BRUTE_FORCE]` — same src_ip with 5+ total failures
- `[SCAN]` — same src_ip with 12+ neutral events and 0 successes
- `[SUCCESS_AFTER_FAILURE]` — same src_ip/user with both failures and a success

**Stage 5 — API (`app.py`)**
FastAPI wrapper with six REST endpoints:
- `GET /health` — service health check
- `POST /ingest` — trigger journal ingestion (Linux host only)
- `POST /parse` — parse raw logs into auth sessions
- `POST /alerts` — run watchdog and return alerts as JSON
- `GET /sessions` — query auth_logs with optional filters (src_ip, outcome, limit)
- `GET /raw` — query raw_logs with optional program filter

---

## Database schema

Three tables in PostgreSQL:

**`raw_logs`** — one row per journal entry
| Column | Type | Description |
|---|---|---|
| id | bigserial | primary key |
| program | text | e.g. `sudo`, `sshd-session` |
| hostname | text | source hostname |
| ingestion_time | timestamp | when we ingested it |
| event_time | timestamp | when it actually happened |
| pid | integer | process ID |
| raw_msg | jsonb | full journal entry as JSON |
| log_source | text | always `journald` |
| journal_cursor | text | systemd journal bookmark |

**`auth_logs`** — one row per auth session (grouped from raw_logs)
| Column | Type | Description |
|---|---|---|
| id | bigserial | primary key |
| event_time | timestamp | session start time |
| program | text | sudo / su / sshd-session |
| pid | bigint | process ID |
| action | text | always `auth_session` |
| outcome | text | success / failure / suspicious / unknown |
| username | text | target username |
| uid | text | user ID |
| src_ip | text | source IP (IPv4 or IPv6) |
| hostname | text | source hostname |
| start_time | timestamp | first event in session |
| end_time | timestamp | last event in session |
| failure_count | integer | number of failure events |
| success_count | integer | number of success events |
| neutral_count | integer | number of neutral events |
| derived_from_raw_id | bigint[] | raw_log IDs that make up this session |
| jcursor | text[] | journal cursors for this session |

**`ingest_state`** — single row bookmark for the parser
| Column | Type | Description |
|---|---|---|
| id | boolean | always `true` (enforces single row) |
| last_jcursor | text | last journal cursor processed by parser |

---

## Setup

### Prerequisites
- Linux with systemd
- PostgreSQL
- Python 3 with `python-systemd` installed via pacman (not pip)
- Groq API key (free tier at https://console.groq.com)

### Install dependencies
```bash
sudo pacman -S python-psycopg2 python-dotenv
yay -S python-groq --mflags "--nocheck"
```

### PostgreSQL setup
```bash
sudo systemctl enable --now postgresql
sudo -u postgres psql
```
```sql
CREATE USER youruser WITH PASSWORD 'yourpassword';
CREATE DATABASE watchdog OWNER youruser;
\q
```

Apply the schema:
```bash
psql -U youruser -d watchdog -f db/schema.sql
```

Insert the ingest_state row:
```sql
INSERT INTO ingest_state (id, last_jcursor) VALUES (TRUE, NULL);
```

### Environment
Create `fac10sniffer/.env`:
```
DB_HOST=localhost
DB_NAME=watchdog
DB_USER=youruser
DB_PASS=yourpassword
GROQ_API_KEY=your_groq_key
```

---

## Running

All scripts must be run from inside `fac10sniffer/` since `python-systemd` cannot run in a venv:

```bash
cd fac10sniffer

# Stage 1: ingest journal entries into raw_logs
python main.py

# Stage 2: parse raw_logs into auth_logs
python parser.py

# Stage 3: check auth_logs for threats
python watchdogv2.py
```

Or run the full pipeline:
```bash
python main.py && python parser.py && python watchdogv2.py
```

---

## Docker

Build and run with docker-compose:
```bash
docker-compose up --build
```

The API will be available at `http://localhost:8080`.

**Note:** `/ingest` requires a real Linux host with systemd journal. In Docker it will return 501 unless the container is privileged and shares `/run/systemd/journal` with the host. Uncomment the volume and privileged lines in `docker-compose.yml` if you need this.

---

## API usage

```bash
# Health check
curl http://localhost:8080/health

# Ingest journal entries
curl -X POST http://localhost:8080/ingest

# Parse raw logs
curl -X POST http://localhost:8080/parse

# Get alerts
curl -X POST http://localhost:8080/alerts

# Query sessions
curl "http://localhost:8080/sessions?outcome=failure&limit=10"

# Query raw logs
curl "http://localhost:8080/raw?program=sshd-session&limit=10"
```

---

## Notes

- `python-systemd` must be installed via pacman, not pip — it is a distro package and does not work inside a venv.
- The LLM is only called for sessions with `failure_count > 0` that the rule engine cannot confidently classify. Clean sudo/su sessions never hit the API.
- Groq free tier is used (`llama-3.1-8b-instant`). The pipeline is designed to minimize API calls.
- The watchdog only detects patterns involving a `src_ip`. Local sudo/su activity without a source IP will not trigger alerts.
