# Daily Checks

A small Python CLI that pulls your team's workload from ServiceNow and
alerts from Armis into a single morning report — console output plus a
saved markdown file. Microsoft Sentinel/Defender is also available but
opt-in by default (see below). No agents, no persistent service required;
just a Python process you run yourself or schedule with cron / Task
Scheduler.

Each integration is independent and optional. Anything you haven't
configured shows up as "skipped" in the report instead of failing the run,
so you can start with one service and add the others later.

## Setup

```bash
cd scripts/daily_checks
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env with your credentials
```

### ServiceNow

Uses the Table API with basic auth. Create (or reuse) a service account with
read access to the `incident`, `sc_req_item`, and `sc_task` tables, and set
`SNOW_INSTANCE_URL`, `SNOW_USERNAME`, `SNOW_PASSWORD`. Set
`SNOW_ASSIGNMENT_GROUP` to your team's group name to filter workload to just
your team; leave it blank to see everything open across those tables (can be
slow/noisy on a large instance).

The daily report covers incidents (INC), requested items (RITM), and catalog
tasks (SCTASK) — not just incidents — since those are what tend to come up
when someone asks "are you aware of this". For a one-off check against a
specific number, skip the full report:

```bash
python main.py --lookup RITM0012345
```

This works for INC/RITM/SCTASK/REQ/PRB/CHG numbers and prints just that
ticket's state, assignee, and last-updated time.

### Microsoft Sentinel / Defender (opt-in)

Not included in the default `--services` list — MSP-managed tickets tend to
live here rather than needing daily attention from you. Configure it the
same way as the others (it's still skipped gracefully if unconfigured), and
pull it into a run explicitly:

```bash
python main.py --services servicenow armis sentinel standup
```

Queries `SecurityIncident` in the same Log Analytics workspace the workbooks
in this repo already use, via the Azure Monitor Query SDK. Register an Azure
AD app, grant it **Log Analytics Reader** (or **Microsoft Sentinel Reader**)
on the workspace, and set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
`AZURE_CLIENT_SECRET`, `LOG_ANALYTICS_WORKSPACE_ID`.

### Armis

Uses an Armis secret key to obtain a short-lived access token, then queries
unhandled alerts via the Armis Query Language (AQL) search endpoint. Set
`ARMIS_BASE_URL` and `ARMIS_SECRET_KEY`.

### Standup prep

Always included, needs no configuration. Your team's standup is verbal with
no system of record, so this isn't pulled data — it's just the three
categories you track (interesting work, blockers, help needed) printed as
prompts so they're in front of you before the call. Drop `standup` from
`--services` if you don't want it in the report.

## Running it

```bash
python main.py                       # default: servicenow, armis, standup
python main.py --services servicenow # just one
python main.py --no-file             # console only, don't save a report
```

Reports are written to `DAILY_CHECKS_OUTPUT_DIR` (default
`./daily_checks_reports`) as `daily-checks-YYYYMMDD-HHMMSS.md`.

The process exits non-zero if any configured service errored, so you can
alert on run failures without parsing the report.

## Scheduling

**cron** (weekdays at 7:30am):

```
30 7 * * 1-5 cd /path/to/scripts/daily_checks && /path/to/.venv/bin/python main.py >> daily_checks.log 2>&1
```

**Windows Task Scheduler**: create a daily trigger that runs
`C:\path\to\.venv\Scripts\python.exe C:\path\to\scripts\daily_checks\main.py`
with "Start in" set to the `daily_checks` folder so `.env` is picked up.

## Extending

Each service lives in its own module (`servicenow.py`, `sentinel.py`,
`armis.py`) and returns a single `report.Section`. To add a fourth
integration, write a module with a `check_*(cfg, ...) -> Section` function
and wire it into `build_sections()` in `main.py`.
