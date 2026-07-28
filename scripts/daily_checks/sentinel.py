"""Microsoft Sentinel / Defender checks via KQL against the Log Analytics workspace.

Queries the same workspace the Azure Monitor workbooks in this repo already
target (SecurityIncident), so it stays consistent with what's already being
tracked there rather than introducing a second data source for the same alerts.
"""
from datetime import timedelta

try:
    from .config import SentinelConfig
    from .report import Section, Status
except ImportError:
    from config import SentinelConfig
    from report import Section, Status

INCIDENT_QUERY = """
SecurityIncident
| where TimeGenerated > ago({lookback}h)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status != "Closed"
| project IncidentNumber, Title, Severity, Status, Owner = tostring(Owner.assignedTo), CreatedTime
| order by Severity asc, CreatedTime desc
"""

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}


def check_incidents(cfg: SentinelConfig, lookback_hours: int) -> Section:
    try:
        from azure.identity import ClientSecretCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus
    except ImportError:
        return Section(
            "Microsoft Sentinel — Incidents", Status.ERROR,
            "Missing dependencies: pip install azure-identity azure-monitor-query",
        )

    try:
        credential = ClientSecretCredential(cfg.tenant_id, cfg.client_id, cfg.client_secret)
        client = LogsQueryClient(credential)
        response = client.query_workspace(
            workspace_id=cfg.workspace_id,
            query=INCIDENT_QUERY.format(lookback=lookback_hours),
            timespan=timedelta(hours=lookback_hours),
        )
    except Exception as exc:
        return Section("Microsoft Sentinel — Incidents", Status.ERROR, f"Could not query Log Analytics: {exc}")

    if response.status != LogsQueryStatus.SUCCESS or not response.tables:
        return Section("Microsoft Sentinel — Incidents", Status.ERROR, "Query returned no data or partial failure")

    table = response.tables[0]
    rows = [dict(zip(table.columns, r)) for r in table.rows]
    rows.sort(key=lambda r: SEVERITY_ORDER.get(r.get("Severity"), 9))

    high = [r for r in rows if r.get("Severity") == "High"]
    status = Status.ATTENTION if high else Status.OK

    return Section(
        title="Microsoft Sentinel — Incidents",
        status=status,
        summary=f"{len(rows)} open incidents ({len(high)} High severity) in the last {lookback_hours}h",
        row_headers=["Incident #", "Title", "Severity", "Status", "Owner"],
        rows=[
            [r.get("IncidentNumber"), (r.get("Title") or "")[:60], r.get("Severity"),
             r.get("Status"), r.get("Owner") or "unassigned"]
            for r in rows[:15]
        ],
    )
