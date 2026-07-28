"""ServiceNow Table API client for team workload checks."""
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


def check_workload(cfg: ServiceNowConfig) -> Section:
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
    url = f"{cfg.instance_url}/api/now/table/incident"

    try:
        resp = requests.get(
            url,
            params=params,
            auth=(cfg.username, cfg.password),
            headers={"Accept": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return Section("ServiceNow — Team Workload", Status.ERROR, f"Could not reach ServiceNow: {exc}")

    incidents = resp.json().get("result", [])
    unassigned = [i for i in incidents if not i.get("assigned_to")]
    critical_high = [i for i in incidents if i.get("priority") in ("1", "2")]

    by_priority = {}
    for i in incidents:
        label = PRIORITY_LABELS.get(i.get("priority"), i.get("priority") or "Unknown")
        by_priority[label] = by_priority.get(label, 0) + 1

    status = Status.ATTENTION if (critical_high or unassigned) else Status.OK
    summary = f"{len(incidents)} open incidents, {len(critical_high)} P1/P2, {len(unassigned)} unassigned"

    rows = [
        [i.get("number"), (i.get("short_description") or "")[:60], i.get("priority"),
         i.get("state"), i.get("assigned_to") or "— unassigned —"]
        for i in sorted(critical_high, key=lambda x: x.get("priority", "9"))[:15]
    ]

    return Section(
        title="ServiceNow — Team Workload",
        status=status,
        summary=summary,
        row_headers=["Number", "Description", "Priority", "State", "Assigned To"],
        rows=rows,
        notes=[f"By priority: " + ", ".join(f"{k}={v}" for k, v in sorted(by_priority.items()))] if by_priority else [],
    )
