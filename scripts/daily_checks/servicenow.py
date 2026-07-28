"""ServiceNow Table API client for team workload checks and ad-hoc ticket lookups."""
import requests

try:
    from .config import ServiceNowConfig
    from .report import Section, Status
except ImportError:
    from config import ServiceNowConfig
    from report import Section, Status

PRIORITY_LABELS = {
    "1": "1 - Critical",
    "2": "2 - High",
    "3": "3 - Moderate",
    "4": "4 - Low",
    "5": "5 - Planning",
}

# Tables pulled into the daily workload view. Incidents alone miss the
# RITM/SCTASK traffic that shows up in ad-hoc "are you aware of this" asks,
# so catalog requests and their tasks are included too.
WORKLOAD_TABLES = [
    ("incident", "Incident"),
    ("sc_req_item", "RITM"),
    ("sc_task", "SCTASK"),
]

# Number prefix -> table, for --lookup. Checked longest-prefix-first so
# "SCTASK" doesn't get shadowed by a hypothetical shorter match.
LOOKUP_TABLES = {
    "SCTASK": "sc_task",
    "RITM": "sc_req_item",
    "INC": "incident",
    "PRB": "problem",
    "CHG": "change_request",
    "REQ": "sc_request",
    "TASK": "sc_task",
}


def _get(cfg: ServiceNowConfig, table: str, params: dict) -> list:
    resp = requests.get(
        f"{cfg.instance_url}/api/now/table/{table}",
        params=params,
        auth=(cfg.username, cfg.password),
        headers={"Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("result", [])


def _fetch_open(cfg: ServiceNowConfig, table: str) -> list:
    query_parts = ["active=true"]
    if cfg.assignment_group:
        query_parts.append(f"assignment_group.name={cfg.assignment_group}")
    query_parts.append("ORDERBYpriority")
    params = {
        "sysparm_query": "^".join(query_parts),
        "sysparm_fields": "number,short_description,priority,state,assigned_to,opened_at",
        "sysparm_limit": "200",
        "sysparm_display_value": "true",
    }
    return _get(cfg, table, params)


def check_workload(cfg: ServiceNowConfig) -> Section:
    try:
        tickets = []
        for table, label in WORKLOAD_TABLES:
            for t in _fetch_open(cfg, table):
                t["_type"] = label
                tickets.append(t)
    except requests.RequestException as exc:
        return Section("ServiceNow — Team Workload", Status.ERROR, f"Could not reach ServiceNow: {exc}")

    unassigned = [t for t in tickets if not t.get("assigned_to")]
    critical_high = [t for t in tickets if t.get("priority") in ("1", "2")]

    by_priority = {}
    for t in tickets:
        label = PRIORITY_LABELS.get(t.get("priority"), t.get("priority") or "Unknown")
        by_priority[label] = by_priority.get(label, 0) + 1

    status = Status.ATTENTION if (critical_high or unassigned) else Status.OK
    summary = f"{len(tickets)} open tickets (INC/RITM/SCTASK), {len(critical_high)} P1/P2, {len(unassigned)} unassigned"

    rows = [
        [t.get("number"), t.get("_type"), (t.get("short_description") or "")[:45], t.get("priority"),
         t.get("state"), t.get("assigned_to") or "— unassigned —"]
        for t in sorted(critical_high, key=lambda x: x.get("priority", "9"))[:15]
    ]

    return Section(
        title="ServiceNow — Team Workload",
        status=status,
        summary=summary,
        row_headers=["Number", "Type", "Description", "Priority", "State", "Assigned To"],
        rows=rows,
        notes=[f"By priority: " + ", ".join(f"{k}={v}" for k, v in sorted(by_priority.items()))] if by_priority else [],
    )


def lookup(cfg: ServiceNowConfig, number: str) -> Section:
    """Ad-hoc lookup for a single ticket number, e.g. when a manager asks
    "are you aware of RITM0012345" and you just need the current state."""
    number = number.strip().upper()
    table = next((t for p, t in LOOKUP_TABLES.items() if number.startswith(p)), None)
    if not table:
        return Section(f"ServiceNow — Lookup {number}", Status.ERROR,
                        "Unrecognized ticket prefix (expected INC/RITM/SCTASK/REQ/PRB/CHG)")

    params = {
        "sysparm_query": f"number={number}",
        "sysparm_fields": "number,short_description,priority,state,assigned_to,assignment_group,opened_at,sys_updated_on",
        "sysparm_limit": "1",
        "sysparm_display_value": "true",
    }
    try:
        results = _get(cfg, table, params)
    except requests.RequestException as exc:
        return Section(f"ServiceNow — Lookup {number}", Status.ERROR, f"Could not reach ServiceNow: {exc}")

    if not results:
        return Section(f"ServiceNow — Lookup {number}", Status.ATTENTION, "Not found")

    t = results[0]
    return Section(
        title=f"ServiceNow — Lookup {number}",
        status=Status.OK,
        summary=(t.get("short_description") or "")[:80],
        row_headers=["Field", "Value"],
        rows=[
            ["State", t.get("state")],
            ["Priority", t.get("priority")],
            ["Assigned to", t.get("assigned_to") or "— unassigned —"],
            ["Assignment group", t.get("assignment_group")],
            ["Opened", t.get("opened_at")],
            ["Last updated", t.get("sys_updated_on")],
        ],
    )
