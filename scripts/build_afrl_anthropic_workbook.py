#!/usr/bin/env python3
"""Builds AFRL-Anthropic-Compliance.json — a standalone Sentinel workbook for
AFRL-funded project personnel monitoring (Anthropic access compliance control).

Companion artifacts:
  analytics-rules/afrl-anthropic-access-detection.json — the alert rule this
    workbook's Detection Investigations tab reports on.
  watchlists/DoD-Anthropic-Monitoring.csv — watchlist schema/import template.
"""
import json

OUTPUT = "/home/user/Workbooks/AFRL-Anthropic-Compliance.json"

WORKSPACE_RESOURCE_ID = (
    "/subscriptions/19f0e8be-c471-41e7-8ec0-69998a50a129/resourcegroups/"
    "rg-sentinel-ae/providers/microsoft.operationalinsights/workspaces/"
    "uon-la-sentinel-staff"
)

RULE_TITLE = "AFRL Anthropic Compliance"

ANTHROPIC_DOMAINS = (
    '"claude.ai",\n'
    '    "anthropic.com",\n'
    '    "api.anthropic.com",\n'
    '    "console.anthropic.com",\n'
    '    "docs.anthropic.com",\n'
    '    "support.anthropic.com"'
)

PROJECT_USERS_ACTIVE = (
    "let ProjectUsers =\n"
    "    _GetWatchlist('DoD-Anthropic-Monitoring')\n"
    "    | project\n"
    "        UserUPN = tolower(trim(' ', column_ifexists('UserUPN', SearchKey))),\n"
    "        Name    = column_ifexists('Name', ''),\n"
    "        Project = column_ifexists('Project', ''),\n"
    "        Status  = column_ifexists('Status', 'Active')\n"
    "    | where isnotempty(UserUPN) and Status =~ \"Active\";\n"
)

PROJECT_USERS_ALL = (
    "let ProjectUsers =\n"
    "    _GetWatchlist('DoD-Anthropic-Monitoring')\n"
    "    | project\n"
    "        UserUPN     = tolower(trim(' ', column_ifexists('UserUPN', SearchKey))),\n"
    "        Name        = column_ifexists('Name', ''),\n"
    "        Project     = column_ifexists('Project', ''),\n"
    "        LastUpdated = column_ifexists('LastUpdatedTimeUTC', column_ifexists('TimeGenerated', datetime(null)))\n"
    "    | where isnotempty(UserUPN);\n"
)

NETWORK_UNION = (
    "union isfuzzy=true\n"
    "    DeviceNetworkEvents,\n"
    "    (datatable(Timestamp:datetime, RemoteUrl:string, InitiatingProcessAccountUpn:string,\n"
    "               DeviceName:string) [])\n"
)

AI_PLATFORMS_LET = (
    "let AIPlatforms = datatable(Domain:string, Platform:string) [\n"
    '    "chatgpt.com",             "OpenAI / ChatGPT",\n'
    '    "chat.openai.com",         "OpenAI / ChatGPT",\n'
    '    "openai.com",              "OpenAI / ChatGPT",\n'
    '    "copilot.microsoft.com",   "Microsoft Copilot",\n'
    '    "copilot.cloud.microsoft", "Microsoft Copilot",\n'
    '    "gemini.google.com",       "Google Gemini",\n'
    '    "bard.google.com",         "Google Gemini",\n'
    '    "perplexity.ai",           "Perplexity",\n'
    '    "mistral.ai",              "Mistral",\n'
    '    "chat.mistral.ai",         "Mistral",\n'
    '    "poe.com",                 "Poe",\n'
    '    "huggingface.co",          "Hugging Face"\n'
    "];\n"
    "let PlatformDomains = AIPlatforms | project Domain;\n"
)

AI_PLATFORM_MATCH = (
    "| extend CleanHost = tolower(trim_start(@\"www.\", tostring(parse_url(RemoteUrl).Host)))\n"
    "| where isnotempty(CleanHost)\n"
    "| extend UserUPN = tolower(InitiatingProcessAccountUpn)\n"
    "| where isnotempty(UserUPN)\n"
    "| join kind=inner ProjectUsers on UserUPN\n"
    "| extend Domain2 = extract(@\"([a-zA-Z0-9-]+\\.[a-zA-Z]{2,})$\", 1, CleanHost)\n"
    "| extend Domain3 = extract(@\"([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.[a-zA-Z]{2,})$\", 1, CleanHost)\n"
    "| where Domain2 in (PlatformDomains) or Domain3 in (PlatformDomains)\n"
    "| extend MatchDomain = iff(Domain3 in (PlatformDomains), Domain3, Domain2)\n"
    "| join kind=inner AIPlatforms on $left.MatchDomain == $right.Domain\n"
)

DEVICEINFO_UNION = (
    "union isfuzzy=true\n"
    "    DeviceInfo,\n"
    "    (datatable(TimeGenerated:datetime, DeviceName:string, OnboardingStatus:string) [])\n"
)

SIGNINLOGS_UNION = (
    "union isfuzzy=true\n"
    "    SigninLogs,\n"
    "    (datatable(TimeGenerated:datetime, UserPrincipalName:string, DeviceDetail:dynamic,\n"
    "               AppDisplayName:string) [])\n"
)


def vis(tab_value):
    return {"parameterName": "selectedTab", "comparison": "isEqualTo", "value": tab_value}


def kql_item(name, title, query, viz, size=0, custom_width=None,
             tile_col=None, tile_palette="blue", tab="executive",
             grid_formatters=None):
    item = {
        "type": 3,
        "content": {
            "version": "KqlItem/1.0",
            "query": query,
            "size": size,
            "title": title,
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "visualization": viz,
        },
        "conditionalVisibility": vis(tab),
        "name": name,
    }
    if viz == "tiles" and tile_col:
        item["content"]["tileSettings"] = {
            "titleContent": {
                "columnMatch": tile_col,
                "formatter": 12,
                "formatOptions": {"palette": tile_palette},
            },
            "showBorder": True,
        }
    if grid_formatters:
        item["content"]["gridSettings"] = {"formatters": grid_formatters}
    if custom_width:
        item["customWidth"] = str(custom_width)
    return item


def md_item(name, text, tab):
    return {"type": 1, "content": {"json": text}, "conditionalVisibility": vis(tab), "name": name}


THRESH_MANAGED = [
    {
        "columnMatch": "ManagedStatus",
        "formatter": 18,
        "formatOptions": {
            "thresholdsOptions": "colors",
            "thresholdsGrid": [
                {"operator": "==", "thresholdValue": "Onboarded", "representation": "green", "text": "Managed (MDE)"},
                {"operator": "==", "thresholdValue": "Unknown", "representation": "redBright", "text": "Unmanaged / Unknown"},
                {"operator": "Default", "representation": "orange", "text": "{0}"},
            ],
        },
    }
]

items = []

# ── Header ────────────────────────────────────────────────────────────────
items.append({
    "type": 1,
    "content": {
        "json": (
            "# AFRL / DoD Personnel — Anthropic Access Compliance Monitoring\n"
            "**Classification: TLP:AMBER — Internal use only**\n\n"
            "> DTS continuously monitors personnel on AFRL-funded projects for access to "
            "Anthropic-hosted AI services, using Microsoft Sentinel and Microsoft Defender "
            "telemetry, as an auditable compliance control. This workbook is the reporting and "
            "investigation view for that control — start on **Executive Summary** for the current "
            "compliance posture, or jump to a specific tab above.\n>\n"
            "> First time here? See the **Setup & Validation** tab for data source requirements "
            "and how monitored personnel are maintained."
        )
    },
    "name": "header-text",
})

# ── Parameters ────────────────────────────────────────────────────────────
tabs = [
    {"value": "executive", "label": "📋 Executive Summary"},
    {"value": "anthropic", "label": "🎯 Anthropic Access"},
    {"value": "aiusage", "label": "🤖 AI Usage Context"},
    {"value": "coverage", "label": "👥 Monitored User Coverage"},
    {"value": "investigations", "label": "🔍 Detection Investigations"},
    {"value": "devices", "label": "💻 Known Devices"},
    {"value": "risk", "label": "⚠️ Unmanaged Device Risk"},
    {"value": "setup", "label": "⚙️ Setup & Validation"},
]

items.append({
    "type": 9,
    "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
            {
                "id": "param-timerange",
                "version": "KqlParameterItem/1.0",
                "name": "TimeRange",
                "label": "Time Range",
                "type": 4,
                "isRequired": True,
                "value": {"durationMs": 2592000000},
                "typeSettings": {
                    "selectableValues": [
                        {"durationMs": 604800000},
                        {"durationMs": 2592000000},
                        {"durationMs": 7776000000},
                        {"durationMs": 31536000000},
                    ]
                },
            },
            {
                "id": "param-tab",
                "version": "KqlParameterItem/1.0",
                "name": "selectedTab",
                "label": "View",
                "type": 2,
                "isRequired": True,
                "value": "executive",
                "typeSettings": {"additionalResourceOptions": [], "showDefault": False},
                "jsonData": json.dumps(tabs),
            },
        ],
        "style": "pills",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
    },
    "name": "parameters",
})

items.append({
    "type": 11,
    "content": {
        "version": "LinkItem/1.0",
        "style": "tabs",
        "links": [
            {
                "id": f"tab-link-{t['value']}",
                "cellValue": "selectedTab",
                "linkTarget": "parameter",
                "linkLabel": t["label"],
                "subTarget": t["value"],
                "style": "link",
            }
            for t in tabs
        ],
    },
    "name": "tab-navigation",
})

# ── EXECUTIVE SUMMARY (Monthly Compliance Dashboard) ────────────────────────
items.append(md_item(
    "exec-heading",
    "## Monthly Compliance Dashboard\n"
    "> Personnel and detection counts below use a fixed **current calendar month** window, "
    "independent of the time range selector, so this tile row matches whatever month you're "
    "reporting on. Detail tabs use the selector above.",
    "executive",
))

items.append(kql_item(
    "exec-tile-personnel",
    "Monitored Personnel",
    PROJECT_USERS_ACTIVE + "ProjectUsers\n| summarize ['Monitored Personnel'] = dcount(UserUPN)",
    "tiles", size=4, tile_col="Monitored Personnel", tile_palette="blue",
    tab="executive", custom_width=25,
))

items.append(kql_item(
    "exec-tile-detections",
    "Anthropic Detections (This Month)",
    PROJECT_USERS_ACTIVE +
    "let ThisMonth = startofmonth(now());\n" +
    NETWORK_UNION +
    "| where Timestamp >= ThisMonth\n"
    f"| where RemoteUrl has_any (\n    {ANTHROPIC_DOMAINS})\n"
    "| extend UserUPN = tolower(InitiatingProcessAccountUpn)\n"
    "| where isnotempty(UserUPN)\n"
    "| join kind=inner ProjectUsers on UserUPN\n"
    "| summarize ['Anthropic Detections'] = count()",
    "tiles", size=4, tile_col="Anthropic Detections", tile_palette="redBright",
    tab="executive", custom_width=25,
))

items.append(kql_item(
    "exec-tile-open-investigations",
    "Open Investigations",
    "union isfuzzy=true SecurityIncident\n"
    f'| where Title == "{RULE_TITLE}"\n'
    "| summarize arg_max(LastModifiedTime, *) by IncidentNumber\n"
    '| where Status !in ("Closed", "Resolved")\n'
    "| summarize ['Open Investigations'] = dcount(IncidentNumber)",
    "tiles", size=4, tile_col="Open Investigations", tile_palette="orange",
    tab="executive", custom_width=25,
))

items.append(kql_item(
    "exec-tile-status",
    "Compliance Status",
    PROJECT_USERS_ACTIVE +
    "let ThisMonth = startofmonth(now());\n" +
    "let AnthropicHits =\n"
    "    " + NETWORK_UNION.replace("\n", "\n    ").rstrip() + "\n"
    "    | where Timestamp >= ThisMonth\n"
    f"    | where RemoteUrl has_any (\n        {ANTHROPIC_DOMAINS})\n"
    "    | extend UserUPN = tolower(InitiatingProcessAccountUpn)\n"
    "    | where isnotempty(UserUPN)\n"
    "    | join kind=inner ProjectUsers on UserUPN;\n"
    "let Detections = toscalar(AnthropicHits | summarize coalesce(count(), 0));\n"
    "let OpenInvestigations = toscalar(\n"
    "    union isfuzzy=true SecurityIncident\n"
    f'    | where Title == "{RULE_TITLE}"\n'
    "    | summarize arg_max(LastModifiedTime, *) by IncidentNumber\n"
    '    | where Status !in ("Closed", "Resolved")\n'
    "    | summarize coalesce(dcount(IncidentNumber), 0));\n"
    "print ['Compliance Status'] = case(\n"
    "    Detections == 0, \"🟢 Green\",\n"
    "    OpenInvestigations > 0, \"🟠 Amber — Investigating\",\n"
    "    \"🔴 Red — Unresolved Detection\")",
    "tiles", size=4, tile_col="Compliance Status", tile_palette="green",
    tab="executive", custom_width=25,
))

items.append(md_item(
    "exec-narrative",
    "### Monthly Report Narrative (template)\n"
    "> Copy-paste starting point — fill in the bracketed values from the tiles above "
    "(Monitored Personnel, Anthropic Detections, Compliance Status) and today's date. Not "
    "auto-generated, so it can't render oddly or drift from what KQL happens to compute; it's a "
    "template, not a substitute for analyst review.\n\n"
    "> DTS continuously monitors **[Monitored Personnel]** personnel associated with AFRL-funded "
    "projects for access to Anthropic-hosted services using Microsoft Sentinel and Microsoft "
    "Defender telemetry. **[No access to Anthropic services was detected / N access event(s) were "
    "detected and are under review]** during **[Month Year]**. Monitoring coverage was reviewed "
    "and remains current as of **[today's date]**. The primary residual risk remains potential use "
    "of unmanaged personal devices or third-party platforms outside University visibility.",
    "executive",
))

items.append(md_item(
    "exec-coverage-heading",
    "### Monitoring Coverage Snapshot",
    "executive",
))

items.append(kql_item(
    "exec-coverage-tile-staff",
    "Staff Covered",
    PROJECT_USERS_ALL +
    "ProjectUsers\n"
    "| summarize ['Staff Covered'] = dcount(UserUPN)",
    "tiles", size=4, tile_col="Staff Covered", tile_palette="blue",
    tab="executive", custom_width=33,
))

items.append(kql_item(
    "exec-coverage-tile-devices",
    "Devices Seen (30d)",
    PROJECT_USERS_ALL +
    NETWORK_UNION +
    "| where Timestamp > ago(30d)\n"
    "| extend UserUPN = tolower(InitiatingProcessAccountUpn)\n"
    "| where isnotempty(UserUPN)\n"
    "| join kind=inner ProjectUsers on UserUPN\n"
    "| summarize ['Devices Seen (30d)'] = dcount(DeviceName)",
    "tiles", size=4, tile_col="Devices Seen (30d)", tile_palette="blue",
    tab="executive", custom_width=33,
))

items.append(kql_item(
    "exec-coverage-tile-lastreview",
    "Last Watchlist Review",
    PROJECT_USERS_ALL +
    "ProjectUsers\n"
    "| summarize ['Last Watchlist Review'] = max(LastUpdated)",
    "tiles", size=4, tile_col="Last Watchlist Review", tile_palette="blue",
    tab="executive", custom_width=33,
))

items.append(md_item(
    "exec-residual-heading",
    "### Residual Risks\n"
    "- **Unmanaged personal devices** — activity from BYOD cannot be fully monitored; see the "
    "**Unmanaged Device Risk** tab for the current unmanaged-activity percentage.\n"
    "- **Non-University networks** — off-network access (personal ISP, mobile data) bypasses "
    "on-prem network telemetry entirely; only endpoint-based signals (MDE) still see it.\n"
    "- **Embedded Anthropic services within third-party products** — a third-party product that "
    "calls the Anthropic API server-side (not from the monitored user's device) will not appear "
    "in this monitoring and is a known blind spot.",
    "executive",
))

items.append(kql_item(
    "exec-timeline",
    "Anthropic Activity Timeline",
    PROJECT_USERS_ACTIVE +
    NETWORK_UNION +
    "| where Timestamp {TimeRange}\n"
    f"| where RemoteUrl has_any (\n    {ANTHROPIC_DOMAINS})\n"
    "| extend UserUPN = tolower(InitiatingProcessAccountUpn)\n"
    "| where isnotempty(UserUPN)\n"
    "| join kind=inner ProjectUsers on UserUPN\n"
    "| summarize Detections = count() by bin(Timestamp, 1d)\n"
    "| sort by Timestamp asc",
    "timechart", tab="executive",
))

# ── ANTHROPIC ACCESS (Primary Control) ──────────────────────────────────────
items.append(md_item(
    "anthropic-heading",
    "## Anthropic Access (Primary Control)\n"
    "> Monitored domains: `claude.ai`, `anthropic.com`, `api.anthropic.com`, "
    "`console.anthropic.com`, `docs.anthropic.com`, `support.anthropic.com`. This list is "
    "intentionally hardcoded (not watchlist-driven) so the compliance control's scope can't "
    "drift from an unrelated, more loosely-curated domain list.\n>\n"
    "> **Outcome this answers:** were any monitored individuals observed accessing Anthropic "
    "services in the selected period?",
    "anthropic",
))

ANTHROPIC_DETAIL_QUERY = (
    PROJECT_USERS_ACTIVE +
    NETWORK_UNION +
    "| where Timestamp {TimeRange}\n"
    f"| where RemoteUrl has_any (\n    {ANTHROPIC_DOMAINS})\n"
    "| extend UserUPN = tolower(InitiatingProcessAccountUpn)\n"
    "| where isnotempty(UserUPN)\n"
    "| join kind=inner ProjectUsers on UserUPN\n"
    "| project Timestamp, UserUPN, Name, Project, DeviceName, RemoteUrl\n"
    "| order by Timestamp desc"
)

items.append(kql_item(
    "anthropic-tile-detections",
    "Detections (Selected Period)",
    ANTHROPIC_DETAIL_QUERY + "\n| summarize ['Detections'] = count()",
    "tiles", size=4, tile_col="Detections", tile_palette="redBright",
    tab="anthropic", custom_width=25,
))

items.append(kql_item(
    "anthropic-tile-users",
    "Users Detected",
    ANTHROPIC_DETAIL_QUERY + "\n| summarize ['Users Detected'] = dcount(UserUPN)",
    "tiles", size=4, tile_col="Users Detected", tile_palette="orange",
    tab="anthropic", custom_width=25,
))

items.append(kql_item(
    "anthropic-tile-firstseen",
    "First Seen",
    ANTHROPIC_DETAIL_QUERY + "\n| summarize ['First Seen'] = min(Timestamp)",
    "tiles", size=4, tile_col="First Seen", tile_palette="blue",
    tab="anthropic", custom_width=25,
))

items.append(kql_item(
    "anthropic-tile-lastseen",
    "Last Seen",
    ANTHROPIC_DETAIL_QUERY + "\n| summarize ['Last Seen'] = max(Timestamp)",
    "tiles", size=4, tile_col="Last Seen", tile_palette="blue",
    tab="anthropic", custom_width=25,
))

items.append(kql_item(
    "anthropic-detail-grid",
    "Anthropic Access — Detail",
    ANTHROPIC_DETAIL_QUERY,
    "table", tab="anthropic",
))

# ── AI USAGE CONTEXT ─────────────────────────────────────────────────────────
items.append(md_item(
    "aiusage-heading",
    "## AI Usage Context\n"
    "> If a monitored individual states they used Claude, this tab shows what they actually "
    "accessed — covering OpenAI/ChatGPT, Microsoft Copilot, Google Gemini, Perplexity, Mistral, "
    "Poe and Hugging Face. The platform list is extensible on request.",
    "aiusage",
))

AIUSAGE_BASE = (
    PROJECT_USERS_ACTIVE +
    AI_PLATFORMS_LET +
    NETWORK_UNION +
    "| where Timestamp {TimeRange}\n" +
    AI_PLATFORM_MATCH
)

items.append(kql_item(
    "aiusage-top-platforms",
    "Top AI Platforms Used",
    AIUSAGE_BASE +
    "| summarize Events = count(), Users = dcount(UserUPN), LastSeen = max(Timestamp) by Platform\n"
    "| sort by Events desc",
    "table", tab="aiusage", custom_width=50,
))

items.append(kql_item(
    "aiusage-trend",
    "AI Platform Usage — Trend",
    AIUSAGE_BASE +
    "| summarize Events = count() by bin(Timestamp, 1d), Platform\n"
    "| sort by Timestamp asc",
    "timechart", tab="aiusage", custom_width=50,
))

items.append(kql_item(
    "aiusage-by-user",
    "Users by Platform",
    AIUSAGE_BASE +
    "| summarize Events = count(), Devices = dcount(DeviceName), LastSeen = max(Timestamp)\n"
    "    by UserUPN, Name, Project, Platform\n"
    "| sort by LastSeen desc",
    "table", tab="aiusage",
))

# ── MONITORED USER COVERAGE ──────────────────────────────────────────────────
items.append(md_item(
    "coverage-heading",
    "## Monitored User Coverage\n"
    "> **Outcome this answers:** can DTS demonstrate that all project personnel were included in "
    "monitoring? Sourced entirely from the `DoD-Anthropic-Monitoring` watchlist (`UserUPN`, "
    "`Name`, `Project`). This deployment's watchlist doesn't track a `Status`/`DateAdded`/"
    "`DateRemoved` history, so this tab shows current headcount and roster only — it can't show "
    "who was added or removed and when. Add those columns to the watchlist later if you want that "
    "history back; the workbook doesn't require it.",
    "coverage",
))

items.append(kql_item(
    "coverage-tile-active",
    "Staff Under Monitoring",
    PROJECT_USERS_ALL +
    "ProjectUsers\n"
    "| summarize ['Staff Under Monitoring'] = dcount(UserUPN)",
    "tiles", size=4, tile_col="Staff Under Monitoring", tile_palette="blue",
    tab="coverage", custom_width=50,
))

items.append(kql_item(
    "coverage-tile-lastupdate",
    "Last Watchlist Update",
    PROJECT_USERS_ALL +
    "ProjectUsers\n"
    "| summarize ['Last Watchlist Update'] = max(LastUpdated)",
    "tiles", size=4, tile_col="Last Watchlist Update", tile_palette="blue",
    tab="coverage", custom_width=50,
))

items.append(kql_item(
    "coverage-roster",
    "Monitored Personnel Roster",
    PROJECT_USERS_ALL +
    "ProjectUsers\n"
    "| project UserUPN, Name, Project, LastUpdated\n"
    "| sort by Name asc",
    "table", tab="coverage",
))

# ── DETECTION INVESTIGATIONS ─────────────────────────────────────────────────
items.append(md_item(
    "investigations-heading",
    "## Detection Investigations\n"
    "> **Outcome this answers:** what happened when activity was detected? Sourced from "
    "`SecurityIncident` for incidents raised by the "
    f"**{RULE_TITLE}** analytics rule. To record a reviewed-and-accepted detection as a "
    "compliance exception, add the incident label `ComplianceException` when closing it in Sentinel.",
    "investigations",
))

INCIDENTS_BASE = (
    "union isfuzzy=true SecurityIncident\n"
    f'| where Title == "{RULE_TITLE}"\n'
    "| summarize arg_max(LastModifiedTime, *) by IncidentNumber\n"
)

items.append(kql_item(
    "investigations-tile-opened",
    "Investigations Opened (Selected Period)",
    INCIDENTS_BASE +
    "| where CreatedTime {TimeRange}\n"
    "| summarize ['Investigations Opened'] = dcount(IncidentNumber)",
    "tiles", size=4, tile_col="Investigations Opened", tile_palette="orange",
    tab="investigations", custom_width=25,
))

items.append(kql_item(
    "investigations-tile-closed",
    "Investigations Closed (Selected Period)",
    INCIDENTS_BASE +
    '| where Status in ("Closed", "Resolved") and ClosedTime {TimeRange}\n'
    "| summarize ['Investigations Closed'] = dcount(IncidentNumber)",
    "tiles", size=4, tile_col="Investigations Closed", tile_palette="green",
    tab="investigations", custom_width=25,
))

items.append(kql_item(
    "investigations-tile-open-now",
    "Currently Open",
    INCIDENTS_BASE +
    '| where Status !in ("Closed", "Resolved")\n'
    "| summarize ['Currently Open'] = dcount(IncidentNumber)",
    "tiles", size=4, tile_col="Currently Open", tile_palette="redBright",
    tab="investigations", custom_width=25,
))

items.append(kql_item(
    "investigations-tile-exceptions",
    "Compliance Exceptions",
    INCIDENTS_BASE +
    "| mv-expand Labels\n"
    '| where tostring(Labels.labelName) =~ "ComplianceException"\n'
    "| summarize ['Compliance Exceptions'] = dcount(IncidentNumber)",
    "tiles", size=4, tile_col="Compliance Exceptions", tile_palette="blue",
    tab="investigations", custom_width=25,
))

items.append(kql_item(
    "investigations-detail",
    "Investigation Detail",
    INCIDENTS_BASE +
    "| where CreatedTime {TimeRange}\n"
    "| project IncidentNumber, Title, Severity, Status, Classification,\n"
    "    Owner = tostring(Owner.assignedTo), CreatedTime, ClosedTime\n"
    "| sort by CreatedTime desc",
    "table", tab="investigations",
))

# ── KNOWN DEVICES ─────────────────────────────────────────────────────────────
items.append(md_item(
    "devices-heading",
    "## Known Devices\n"
    "> **Outcome this answers:** are researchers using University-managed devices? "
    "`ManagedStatus` reflects whether the last-seen device is onboarded to Microsoft Defender "
    "for Endpoint — presence there is a floor for \"managed\", not a guarantee of full Intune "
    "compliance (see **Unmanaged Device Risk** for the Entra sign-in compliance signal).",
    "devices",
))

items.append(kql_item(
    "devices-table",
    "Devices by Monitored User",
    PROJECT_USERS_ACTIVE +
    "let Activity =\n    " + NETWORK_UNION.replace("\n", "\n    ").rstrip() + "\n"
    "    | where Timestamp {TimeRange}\n"
    "    | extend UserUPN = tolower(InitiatingProcessAccountUpn)\n"
    "    | where isnotempty(UserUPN)\n"
    "    | join kind=inner ProjectUsers on UserUPN;\n"
    "let LastDevice = Activity\n"
    "    | summarize (LastSeen, LastSeenDevice) = arg_max(Timestamp, DeviceName) by UserUPN;\n"
    "let DeviceCounts = Activity\n"
    "    | summarize DeviceCount = dcount(DeviceName) by UserUPN;\n"
    "let ManagedStatus =\n    " + DEVICEINFO_UNION.replace("\n", "\n    ").rstrip() + "\n"
    "    | summarize arg_max(TimeGenerated, OnboardingStatus) by DeviceName;\n"
    "ProjectUsers\n"
    "| join kind=inner DeviceCounts on UserUPN\n"
    "| join kind=inner LastDevice on UserUPN\n"
    "| join kind=leftouter ManagedStatus on $left.LastSeenDevice == $right.DeviceName\n"
    "| project UserUPN, Name, Project, DeviceCount, LastSeenDevice, LastSeen,\n"
    "    ManagedStatus = iff(isempty(OnboardingStatus), \"Unknown\", OnboardingStatus)\n"
    "| sort by LastSeen desc",
    "table", tab="devices",
    grid_formatters=THRESH_MANAGED,
))

# ── UNMANAGED DEVICE RISK ─────────────────────────────────────────────────────
items.append(md_item(
    "risk-heading",
    "## Unmanaged Device Risk\n"
    "> **Outcome this answers:** activity from unmanaged devices cannot be fully monitored and "
    "remains a residual risk — this tab quantifies how much of monitored activity that is. "
    "`SigninLogs` requires Entra ID P1/P2; if absent, the Entra panels below will be empty and "
    "the MDE-based tile is the fallback signal.\n>\n"
    "> **Why device *name* and `TrustType`, not `isManaged`/`isCompliant`:** those two fields "
    "only populate when a device-based Conditional Access policy is actively enforcing them — "
    "without that, every sign-in reads `false`/empty regardless of the device's real status, "
    "which silently understates risk rather than overstates it. `TrustType` (Azure AD joined / "
    "Hybrid Azure AD joined / registered / blank) is populated far more reliably and is what the "
    "table below and the second tile use instead.",
    "risk",
))

items.append(kql_item(
    "risk-tile-unmanaged-pct",
    "Unmanaged Network Activity % (MDE-based)",
    PROJECT_USERS_ACTIVE +
    "let Activity =\n    " + NETWORK_UNION.replace("\n", "\n    ").rstrip() + "\n"
    "    | where Timestamp {TimeRange}\n"
    "    | extend UserUPN = tolower(InitiatingProcessAccountUpn)\n"
    "    | where isnotempty(UserUPN)\n"
    "    | join kind=inner ProjectUsers on UserUPN\n"
    "    | summarize Total = count() by DeviceName;\n"
    "let ManagedStatus =\n    " + DEVICEINFO_UNION.replace("\n", "\n    ").rstrip() + "\n"
    "    | summarize arg_max(TimeGenerated, OnboardingStatus) by DeviceName;\n"
    "Activity\n"
    "| join kind=leftouter ManagedStatus on DeviceName\n"
    "| extend Managed = OnboardingStatus == \"Onboarded\"\n"
    "| summarize TotalEvents = sum(Total), ManagedEvents = sumif(Total, Managed == true)\n"
    "| extend ['Unmanaged Activity %'] = round(100.0 * (TotalEvents - ManagedEvents) / iff(TotalEvents == 0, 1, TotalEvents), 1)\n"
    "| project ['Unmanaged Activity %']",
    "tiles", size=4, tile_col="Unmanaged Activity %", tile_palette="redBright",
    tab="risk", custom_width=50,
))

items.append(kql_item(
    "risk-tile-unregistered-pct",
    "Unregistered/Unknown Device Sign-in % (Entra-based)",
    PROJECT_USERS_ACTIVE +
    SIGNINLOGS_UNION +
    "| where TimeGenerated {TimeRange}\n"
    "| extend UserUPN = tolower(UserPrincipalName)\n"
    "| join kind=inner ProjectUsers on UserUPN\n"
    "| extend TrustType = tostring(DeviceDetail.trustType)\n"
    "| summarize\n"
    "    Total   = count(),\n"
    "    Managed = countif(TrustType in (\"Azure AD joined\", \"Hybrid Azure AD joined\", \"ServerAD joined\"))\n"
    "| extend ['Unregistered/Unknown Sign-in %'] = round(100.0 * (Total - Managed) / iff(Total == 0, 1, Total), 1)\n"
    "| project ['Unregistered/Unknown Sign-in %']",
    "tiles", size=4, tile_col="Unregistered/Unknown Sign-in %", tile_palette="redBright",
    tab="risk", custom_width=50,
))

items.append(kql_item(
    "risk-signin-table",
    "Entra Sign-ins by Device (Monitored Users)",
    PROJECT_USERS_ACTIVE +
    SIGNINLOGS_UNION +
    "| where TimeGenerated {TimeRange}\n"
    "| extend UserUPN = tolower(UserPrincipalName)\n"
    "| join kind=inner ProjectUsers on UserUPN\n"
    "| extend\n"
    "    DeviceNameRaw = tostring(DeviceDetail.displayName),\n"
    "    DeviceIdRaw   = tostring(DeviceDetail.deviceId),\n"
    "    TrustType     = tostring(DeviceDetail.trustType)\n"
    "| extend Device = case(\n"
    "    isnotempty(DeviceNameRaw), DeviceNameRaw,\n"
    "    isnotempty(DeviceIdRaw), DeviceIdRaw,\n"
    "    \"(no device info returned)\")\n"
    "| extend Trust = iff(isempty(TrustType), \"Unregistered / Unknown\", TrustType)\n"
    "| summarize\n"
    "    SignIns  = count(),\n"
    "    LastSeen = max(TimeGenerated)\n"
    "  by UserUPN, Name, Project, Device, Trust\n"
    "| sort by LastSeen desc",
    "table", tab="risk",
    grid_formatters=[
        {
            "columnMatch": "Trust",
            "formatter": 18,
            "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                    {"operator": "==", "thresholdValue": "Azure AD joined", "representation": "green", "text": "{0}"},
                    {"operator": "==", "thresholdValue": "Hybrid Azure AD joined", "representation": "green", "text": "{0}"},
                    {"operator": "==", "thresholdValue": "Unregistered / Unknown", "representation": "redBright", "text": "{0}"},
                    {"operator": "Default", "representation": "orange", "text": "{0}"},
                ],
            },
        }
    ],
))

items.append(md_item(
    "risk-callout",
    "> **Residual risk statement:** activity from personal (unmanaged) devices, non-University "
    "networks, or Anthropic services embedded server-side within third-party products falls "
    "outside what this monitoring can see. Report the tiles above as supporting evidence for "
    "that statement, not as proof of full coverage.",
    "risk",
))

# ── SETUP & VALIDATION ────────────────────────────────────────────────────────
items.append(md_item(
    "setup-heading",
    "## Setup & Validation\n"
    "### Step 1: Create the watchlist\n"
    "Sentinel → Watchlists → **+ New** → name it exactly `DoD-Anthropic-Monitoring`. Minimum "
    "columns: `UserUPN, Name, Project` (see `watchlists/DoD-Anthropic-Monitoring.csv`). SearchKey "
    "can be set to whatever you like — the workbook always resolves the real `UserUPN` column "
    "directly and only falls back to SearchKey if that column is missing.\n\n"
    "> Optional: add `Status`, `DateAdded`, `DateRemoved` columns if you want the "
    "**Monitored User Coverage** tab to track *when* staff were added/removed, not just who's "
    "currently monitored. The workbook shipped here doesn't require them — this deployment's "
    "watchlist doesn't have them.\n\n"
    "### Step 2: Analytics rule\n"
    "The Detection Investigations tab and the Compliance Status/Investigations tiles filter "
    f"`SecurityIncident` on `Title == \"{RULE_TITLE}\"`. If your Sentinel analytics rule's "
    "display name (or `alertDisplayNameFormat` override, if it has one) is anything other than "
    f"exactly `{RULE_TITLE}`, update `RULE_TITLE` in "
    "`scripts/build_afrl_anthropic_workbook.py` and regenerate — otherwise those panels will "
    "silently show zero regardless of actual activity. `analytics-rules/"
    "afrl-anthropic-access-detection.json` is kept in the repo as a reference/backup ARM "
    "template (same title, same entity mappings) — not required if you already have a rule "
    "deployed.\n\n"
    "### Step 3: Validate data sources below",
    "setup",
))

items.append(kql_item(
    "setup-watchlist-status",
    "Step 3a: DoD-Anthropic-Monitoring Watchlist Status",
    PROJECT_USERS_ALL +
    "ProjectUsers\n"
    "| summarize TotalEntries = count(), LatestUpdate = max(LastUpdated)",
    "table", tab="setup", custom_width=50,
))

items.append(kql_item(
    "setup-networkevents-status",
    "Step 3b: DeviceNetworkEvents Status",
    NETWORK_UNION +
    "| where Timestamp > ago(3d)\n"
    "| summarize RowCount = count(), DistinctUsers = dcount(InitiatingProcessAccountUpn),\n"
    "    LatestRecord = max(Timestamp)",
    "table", tab="setup", custom_width=50,
))

items.append(kql_item(
    "setup-incident-status",
    "Step 3c: SecurityIncident — Rule Match Check",
    "union isfuzzy=true SecurityIncident\n"
    f'| where Title == "{RULE_TITLE}"\n'
    "| summarize TotalIncidents = dcount(IncidentNumber), LatestRecord = max(TimeGenerated)",
    "table", tab="setup", custom_width=50,
))

items.append(kql_item(
    "setup-deviceinfo-status",
    "Step 3d: DeviceInfo Status (Known Devices tab)",
    DEVICEINFO_UNION +
    "| where TimeGenerated > ago(3d)\n"
    "| summarize RowCount = count(), Onboarded = countif(OnboardingStatus == \"Onboarded\"),\n"
    "    LatestRecord = max(TimeGenerated)",
    "table", tab="setup", custom_width=50,
))

items.append(kql_item(
    "setup-signinlogs-status",
    "Step 3e: SigninLogs Status (Unmanaged Device Risk tab — requires Entra ID P1/P2)",
    SIGNINLOGS_UNION +
    "| where TimeGenerated > ago(3d)\n"
    "| summarize RowCount = count(), LatestRecord = max(TimeGenerated)",
    "table", tab="setup", custom_width=50,
))

items.append(md_item(
    "setup-notes",
    "---\n### Notes\n\n"
    "**Why the Anthropic domain list is hardcoded, not watchlist-driven:** this is the primary "
    "compliance control. A shared, general-purpose domain watchlist (like `AI-App-Domains` used "
    "elsewhere in this repo) can be edited for unrelated reasons by someone unaware of the "
    "compliance implication. The Anthropic domain list here is fixed in both the workbook and "
    "the analytics rule so the two can never drift out of sync with each other.\n\n"
    "**Join case-sensitivity:** all UPN joins normalize both sides with `tolower()` before "
    "joining — KQL `join` is case-sensitive by default, and Defender/watchlist UPN casing isn't "
    "guaranteed to match.\n\n"
    "**`DeviceNetworkEvents` uses `Timestamp`**, not `TimeGenerated`, in this tenant's schema "
    "(Defender Advanced Hunting naming) — confirmed against a working hunting query before this "
    "workbook was built.\n\n"
    "**Compliance exceptions** are tracked as a Sentinel incident label (`ComplianceException`) "
    "rather than a separate table — apply it when closing an incident that was reviewed and "
    "accepted as expected/approved activity.",
    "setup",
))

workbook = {
    "version": "Notebook/1.0",
    "items": items,
    "fallbackResourceIds": [WORKSPACE_RESOURCE_ID],
    "fromTemplateId": "sentinel-UserWorkbook",
    "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json",
}

with open(OUTPUT, "w") as f:
    json.dump(workbook, f, indent=2, ensure_ascii=False)

print(f"Written {len(items)} items to {OUTPUT}")
print(f"File size: {len(json.dumps(workbook)):,} bytes")
