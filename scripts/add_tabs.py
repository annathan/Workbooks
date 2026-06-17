#!/usr/bin/env python3
"""Adds Executive Summary and Essential Eight tabs to native.json workbook."""
import json, copy, sys

INPUT  = "/home/user/Workbooks/native.json"
OUTPUT = "/home/user/Workbooks/native-v2.json"

with open(INPUT) as f:
    wb = json.load(f)

items = wb["items"]

# ── 1. Update param-tab jsonData ──────────────────────────────────────────────
for item in items:
    if item.get("name") == "parameters":
        for p in item["content"]["parameters"]:
            if p.get("name") == "selectedTab":
                existing = json.loads(p["jsonData"])
                new_tabs = [
                    {"value": "executive", "label": "📋 Executive Summary"},
                    {"value": "e8",        "label": "🛡️ Essential Eight"},
                ]
                p["jsonData"] = json.dumps(new_tabs + existing)
        break

# ── 2. Add tab-navigation links ───────────────────────────────────────────────
for item in items:
    if item.get("name") == "tab-navigation":
        new_links = [
            {"id": "tab-link-executive", "cellValue": "selectedTab",
             "linkTarget": "parameter", "linkLabel": "📋 Executive Summary",
             "subTarget": "executive", "style": "link"},
            {"id": "tab-link-e8", "cellValue": "selectedTab",
             "linkTarget": "parameter", "linkLabel": "🛡️ Essential Eight",
             "subTarget": "e8", "style": "link"},
        ]
        item["content"]["links"] = new_links + item["content"]["links"]
        break

# ── 3. Update vulns-heading to note Plan 1 limitation ────────────────────────
for item in items:
    if item.get("name") == "vulns-heading":
        item["content"]["json"] = (
            "## Vulnerabilities & CISA KEV Coverage\n"
            "> **⚠️ MDE Plan 1 environment:** `DeviceTvmSoftwareVulnerabilities` requires "
            "MDE Plan 2. TVM panels below will populate once Plan 2 is licensed or ARMIS is "
            "connected. See **Setup → Step 1b** to confirm.\n>\n"
            "> **What works now:** The **Active Exploit Detections** section at the bottom "
            "of this tab extracts CVE IDs directly from `SecurityAlert` — these are "
            "vulnerabilities being actively exploited against estate devices, which is more "
            "operationally urgent than a passive inventory.\n>\n"
            "> **VIB Q1 2026 priority CVEs** (Section 3.1 — check the first grid below for these specifically):\n"
            "> Cisco Firewall CVE-2026-20131 (CVSS 10.0, Interlock ransomware) · "
            "BeyondTrust CVE-2026-1731 (9.9) · Ivanti EPMM CVE-2026-1281/1340 (9.8, MDM) · "
            "Fortinet CVE-2026-24858 (9.4) · n8n CVE-2026-21858 (10.0) · "
            "Oracle EBS CVE-2025-61882 (Cl0p/FIN11 campaign) · "
            "MongoDB CVE-2025-14847 (active AU exploitation)\n>\n"
            "> CVE data sourced from MDE Threat & Vulnerability Management "
            "(`DeviceTvmSoftwareVulnerabilities`) in **Log Analytics**. Panels use the "
            "latest record per device+CVE (90-day lookback), not only rows in the workbook "
            "time range.\n>\n"
            "> **MDE portal vs Sentinel:** If **all** TVM panels including Total Open CVEs "
            "are 0, TVM may not be in this Log Analytics workspace — run **Setup → Step 1b**."
        )
        break

# ── helper ────────────────────────────────────────────────────────────────────
def vis(tab_value):
    return {"parameterName": "selectedTab",
            "comparison": "isEqualTo",
            "value": tab_value}

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
                "formatOptions": {"palette": tile_palette}
            },
            "showBorder": True
        }
    if grid_formatters:
        item["content"]["gridSettings"] = {"formatters": grid_formatters}
    if custom_width:
        item["customWidth"] = str(custom_width)
    return item

def md_item(name, text, tab):
    return {
        "type": 1,
        "content": {"json": text},
        "conditionalVisibility": vis(tab),
        "name": name,
    }

# ── 4. New items ──────────────────────────────────────────────────────────────
new_items = []

# ── VULNS TAB: active exploit detection ──────────────────────────────────────
new_items.append(md_item(
    "vulns-exploit-subheading",
    "### Active Exploit Detections (Plan 1 Compatible)\n"
    "> **Source:** `SecurityAlert` from Microsoft Defender ATP. CVE IDs are extracted from "
    "alert descriptions using regex — no TVM or Plan 2 licence required.\n>\n"
    "> Rows here represent CVEs **being actively exploited** against estate devices right now. "
    "This is more operationally urgent than a passive vulnerability inventory. "
    "Empty = no CVE-tagged alerts in the selected time range (good).",
    "vulns"
))

new_items.append(kql_item(
    name="grid-exploit-cve-alerts",
    title="Active Exploit Detections — CVEs in MDE Alerts",
    query=(
        "// Extract CVE IDs from MDE alert descriptions — Plan 1 compatible\n"
        "union isfuzzy=true SecurityAlert\n"
        "| where TimeGenerated {TimeRange}\n"
        "| where ProviderName =~ \"Microsoft Defender Advanced Threat Protection\"\n"
        "| extend CVEs = extract_all(@\"(CVE-\\d{4}-\\d{4,})\", Description)\n"
        "| where array_length(CVEs) > 0\n"
        "| mv-expand CVE = CVEs\n"
        "| summarize\n"
        "    AlertCount      = count(),\n"
        "    AffectedDevices = dcount(CompromisedEntity),\n"
        "    LastSeen        = max(TimeGenerated),\n"
        "    Severity        = any(AlertSeverity),\n"
        "    SampleAlert     = any(AlertName)\n"
        "  by tostring(CVE)\n"
        "| extend SevOrder = case(Severity==\"Critical\",4,Severity==\"High\",3,Severity==\"Medium\",2,1)\n"
        "| sort by SevOrder desc, AlertCount desc\n"
        "| project-away SevOrder\n"
        "| take 30"
    ),
    viz="table",
    tab="vulns",
    grid_formatters=[
        {
            "columnMatch": "Severity",
            "formatter": 18,
            "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                    {"operator": "==", "thresholdValue": "Critical", "representation": "redBright", "text": "Critical"},
                    {"operator": "==", "thresholdValue": "High",     "representation": "orange",   "text": "High"},
                    {"operator": "Default",                           "representation": "yellow",   "text": "{0}"},
                ]
            }
        },
        {
            "columnMatch": "AffectedDevices",
            "formatter": 4,
            "formatOptions": {"palette": "redBright", "min": 0}
        }
    ]
))

# ── EXECUTIVE SUMMARY TAB ─────────────────────────────────────────────────────
new_items.append(md_item(
    "exec-heading",
    "## Executive Security Summary\n"
    "**University of Newcastle — Quarterly Cybersecurity Report**\n\n"
    "> All trend charts on this tab use a **fixed 90-day window** regardless of the time "
    "range selector above, so the charts remain consistent when shared.\n>\n"
    "> The quarter-over-quarter table compares the current calendar quarter against the "
    "previous one automatically — no date adjustment needed.\n>\n"
    "> **Sharing tip:** Screenshot this tab or use browser print (80% zoom, no headers) "
    "for a clean one-page quarterly summary.",
    "executive"
))

new_items.append(kql_item(
    name="exec-qoq-table",
    title="Quarter-over-Quarter Security KPIs",
    query=(
        "// Quarter-over-quarter KPI comparison — auto-calculates current vs previous quarter\n"
        "let TQ  = startofquarter(now());\n"
        "let LQ  = startofquarter(ago(91d));\n"
        "// Alerts\n"
        "let a1 = toscalar(union isfuzzy=true SecurityAlert\n"
        "    | where TimeGenerated >= TQ\n"
        "    | where AlertSeverity in (\"Critical\",\"High\")\n"
        "    | summarize coalesce(count(), 0));\n"
        "let a2 = toscalar(union isfuzzy=true SecurityAlert\n"
        "    | where TimeGenerated >= LQ and TimeGenerated < TQ\n"
        "    | where AlertSeverity in (\"Critical\",\"High\")\n"
        "    | summarize coalesce(count(), 0));\n"
        "// P1/P2 Incidents\n"
        "let i1 = toscalar(union isfuzzy=true SecurityIncident\n"
        "    | where CreatedTime >= TQ\n"
        "    | summarize arg_max(LastModifiedTime,*) by IncidentNumber\n"
        "    | where Severity in (\"Critical\",\"High\")\n"
        "    | summarize coalesce(count(), 0));\n"
        "let i2 = toscalar(union isfuzzy=true SecurityIncident\n"
        "    | where CreatedTime >= LQ and CreatedTime < TQ\n"
        "    | summarize arg_max(LastModifiedTime,*) by IncidentNumber\n"
        "    | where Severity in (\"Critical\",\"High\")\n"
        "    | summarize coalesce(count(), 0));\n"
        "// MTTR\n"
        "let m1 = toscalar(union isfuzzy=true SecurityIncident\n"
        "    | where ClosedTime >= TQ\n"
        "    | where Status in (\"Closed\",\"Resolved\")\n"
        "    | extend H = datetime_diff('minute', ClosedTime, CreatedTime) / 60.0\n"
        "    | summarize coalesce(round(avg(H), 1), 0.0));\n"
        "let m2 = toscalar(union isfuzzy=true SecurityIncident\n"
        "    | where ClosedTime >= LQ and ClosedTime < TQ\n"
        "    | where Status in (\"Closed\",\"Resolved\")\n"
        "    | extend H = datetime_diff('minute', ClosedTime, CreatedTime) / 60.0\n"
        "    | summarize coalesce(round(avg(H), 1), 0.0));\n"
        "// Risky sign-ins\n"
        "let r1 = toscalar(union isfuzzy=true SigninLogs\n"
        "    | where TimeGenerated >= TQ\n"
        "    | where RiskLevelDuringSignIn in (\"high\",\"medium\")\n"
        "    | summarize coalesce(count(), 0));\n"
        "let r2 = toscalar(union isfuzzy=true SigninLogs\n"
        "    | where TimeGenerated >= LQ and TimeGenerated < TQ\n"
        "    | where RiskLevelDuringSignIn in (\"high\",\"medium\")\n"
        "    | summarize coalesce(count(), 0));\n"
        "// Blocked email (all Mimecast sources + Defender)\n"
        "let e1 = toscalar(union isfuzzy=true\n"
        "    (EmailEvents | where TimeGenerated >= TQ | where DeliveryAction in (\"Blocked\",\"Replaced\")),\n"
        "    (CommonSecurityLog | where TimeGenerated >= TQ | where DeviceVendor =~ \"Mimecast\"\n"
        "     | where tolower(tostring(DeviceAction)) has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\")),\n"
        "    (MimecastSEGEvent_CL | where TimeGenerated >= TQ\n"
        "     | where tolower(tostring(column_ifexists('action_s',column_ifexists('Action','')))) has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\"))\n"
        "    | summarize coalesce(count(), 0));\n"
        "let e2 = toscalar(union isfuzzy=true\n"
        "    (EmailEvents | where TimeGenerated >= LQ and TimeGenerated < TQ | where DeliveryAction in (\"Blocked\",\"Replaced\")),\n"
        "    (CommonSecurityLog | where TimeGenerated >= LQ and TimeGenerated < TQ | where DeviceVendor =~ \"Mimecast\"\n"
        "     | where tolower(tostring(DeviceAction)) has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\")),\n"
        "    (MimecastSEGEvent_CL | where TimeGenerated >= LQ and TimeGenerated < TQ\n"
        "     | where tolower(tostring(column_ifexists('action_s',column_ifexists('Action','')))) has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\"))\n"
        "    | summarize coalesce(count(), 0));\n"
        "// Device onboarding %\n"
        "let d1 = toscalar(union isfuzzy=true DeviceInfo\n"
        "    | where TimeGenerated >= TQ\n"
        "    | summarize arg_max(TimeGenerated,*) by DeviceId\n"
        "    | summarize coalesce(round(100.0 * countif(OnboardingStatus==\"Onboarded\") / count(), 1), 0.0));\n"
        "let d2 = toscalar(union isfuzzy=true DeviceInfo\n"
        "    | where TimeGenerated >= LQ and TimeGenerated < TQ\n"
        "    | summarize arg_max(TimeGenerated,*) by DeviceId\n"
        "    | summarize coalesce(round(100.0 * countif(OnboardingStatus==\"Onboarded\") / count(), 1), 0.0));\n"
        "datatable(Metric:string, Unit:string, GoodDir:string, ThisQ:real, LastQ:real) [\n"
        "    \"Critical / High Alerts\",  \"\",    \"Down\", coalesce(todouble(a1),0.0), coalesce(todouble(a2),0.0),\n"
        "    \"P1 / P2 Incidents\",        \"\",    \"Down\", coalesce(todouble(i1),0.0), coalesce(todouble(i2),0.0),\n"
        "    \"Avg MTTR\",                 \"hrs\", \"Down\", coalesce(todouble(m1),0.0), coalesce(todouble(m2),0.0),\n"
        "    \"Risky Sign-ins\",           \"\",    \"Down\", coalesce(todouble(r1),0.0), coalesce(todouble(r2),0.0),\n"
        "    \"Blocked Email Threats\",    \"\",    \"Down\", coalesce(todouble(e1),0.0), coalesce(todouble(e2),0.0),\n"
        "    \"Device Onboarding\",        \"%\",   \"Up\",   coalesce(todouble(d1),0.0), coalesce(todouble(d2),0.0)\n"
        "]\n"
        "| extend Delta = ThisQ - LastQ\n"
        "| extend Trend = case(\n"
        "    GoodDir == \"Down\" and Delta < 0, \"✅ Improving\",\n"
        "    GoodDir == \"Down\" and Delta > 0, \"🔴 Worsening\",\n"
        "    GoodDir == \"Up\"   and Delta > 0, \"✅ Improving\",\n"
        "    GoodDir == \"Up\"   and Delta < 0, \"🔴 Worsening\",\n"
        "    \"➡️ No change\")\n"
        "| extend ['This Quarter'] = iff(Unit == \"\", tostring(toint(ThisQ)), strcat(tostring(ThisQ), \" \", Unit))\n"
        "| extend ['Last Quarter'] = iff(Unit == \"\", tostring(toint(LastQ)), strcat(tostring(LastQ), \" \", Unit))\n"
        "| extend ['Change'] = iff(Delta >= 0, strcat(\"+\", tostring(round(Delta,1))), tostring(round(Delta,1)))\n"
        "| project Metric, ['This Quarter'], ['Last Quarter'], ['Change'], Trend"
    ),
    viz="table",
    tab="executive",
    grid_formatters=[
        {
            "columnMatch": "Trend",
            "formatter": 1
        },
        {
            "columnMatch": "Change",
            "formatter": 1
        }
    ]
))

new_items.append(md_item(
    "exec-efficiency-heading",
    "## Operational Efficiency\n"
    "> Fixed 90-day window. MTTD = mean time from first activity to incident creation. "
    "Closure Rate = % of incidents created in the period that are now closed. "
    "Alerts per Incident = alert noise ratio (lower = better tuning).",
    "executive"
))

new_items.append(kql_item(
    name="exec-mttd-tile",
    title="Avg MTTD — hrs (90d)",
    query=(
        "// Mean time to detect — first activity to incident creation\n"
        "union isfuzzy=true SecurityIncident\n"
        "| where CreatedTime > ago(90d)\n"
        "| where isnotempty(FirstActivityTime)\n"
        "| extend MTTDHours = datetime_diff('minute', CreatedTime, FirstActivityTime) / 60.0\n"
        "| where MTTDHours >= 0 and MTTDHours <= 720\n"
        "| summarize ['Avg MTTD (hrs)'] = round(avg(MTTDHours), 1)"
    ),
    viz="tiles",
    size=4,
    tile_col="Avg MTTD (hrs)",
    tile_palette="blue",
    tab="executive",
    custom_width=25
))

new_items.append(kql_item(
    name="exec-closure-tile",
    title="Incident Closure Rate (90d)",
    query=(
        "// % of incidents created in last 90d that are now closed\n"
        "union isfuzzy=true SecurityIncident\n"
        "| where CreatedTime > ago(90d)\n"
        "| summarize arg_max(LastModifiedTime,*) by IncidentNumber\n"
        "| summarize\n"
        "    Created = count(),\n"
        "    Closed  = countif(Status in (\"Closed\",\"Resolved\"))\n"
        "| extend ['Closure Rate %'] = round(100.0 * Closed / iff(Created==0,1,Created), 1)\n"
        "| project ['Closure Rate %']"
    ),
    viz="tiles",
    size=4,
    tile_col="Closure Rate %",
    tile_palette="green",
    tab="executive",
    custom_width=25
))

new_items.append(kql_item(
    name="exec-ratio-tile",
    title="Alerts per Incident (90d)",
    query=(
        "// Alert-to-incident ratio — measures alert noise\n"
        "let Alerts    = toscalar(union isfuzzy=true SecurityAlert | where TimeGenerated > ago(90d) | summarize coalesce(count(),0));\n"
        "let Incidents = toscalar(union isfuzzy=true SecurityIncident | where CreatedTime > ago(90d)\n"
        "    | summarize arg_max(LastModifiedTime,*) by IncidentNumber | summarize coalesce(count(),0));\n"
        "print ['Alerts per Incident'] = round(todouble(Alerts) / iff(Incidents==0, 1, todouble(Incidents)), 1)"
    ),
    viz="tiles",
    size=4,
    tile_col="Alerts per Incident",
    tile_palette="blue",
    tab="executive",
    custom_width=25
))

new_items.append(kql_item(
    name="exec-mfa-tile",
    title="MFA Coverage Rate (90d)",
    query=(
        "// % of successful sign-ins that used MFA\n"
        "union isfuzzy=true SigninLogs\n"
        "| where TimeGenerated > ago(90d)\n"
        "| where ResultType == \"0\"\n"
        "| summarize\n"
        "    Total   = count(),\n"
        "    WithMFA = countif(AuthenticationRequirement == \"multiFactorAuthentication\")\n"
        "| extend ['MFA Coverage %'] = round(100.0 * WithMFA / iff(Total==0,1,Total), 1)\n"
        "| project ['MFA Coverage %']"
    ),
    viz="tiles",
    size=4,
    tile_col="MFA Coverage %",
    tile_palette="green",
    tab="executive",
    custom_width=25
))

new_items.append(md_item(
    "exec-trends-heading",
    "## 90-Day Security Trends\n"
    "> All charts below use a fixed 90-day window — independent of the time range selector. "
    "Use these charts directly in quarterly reports.",
    "executive"
))

new_items.append(kql_item(
    name="exec-90d-alerts-chart",
    title="90-Day Weekly Alert Volume by Severity",
    query=(
        "// Fixed 90d — weekly alert trend by severity\n"
        "union isfuzzy=true SecurityAlert\n"
        "| where TimeGenerated > ago(90d)\n"
        "| where AlertSeverity in (\"Critical\",\"High\",\"Medium\")\n"
        "| summarize Count=count() by bin(TimeGenerated, 7d), AlertSeverity\n"
        "| sort by TimeGenerated asc"
    ),
    viz="timechart",
    tab="executive",
    custom_width=50
))

new_items.append(kql_item(
    name="exec-90d-incidents-chart",
    title="90-Day Weekly Incidents Created vs Closed",
    query=(
        "// Fixed 90d — P1/P2 incidents created and closed each week\n"
        "union isfuzzy=true SecurityIncident\n"
        "| summarize arg_max(LastModifiedTime,*) by IncidentNumber\n"
        "| where Severity in (\"Critical\",\"High\")\n"
        "| extend WeekCreated = bin(CreatedTime, 7d)\n"
        "| extend WeekClosed  = iff(Status in (\"Closed\",\"Resolved\") and ClosedTime > ago(90d), bin(ClosedTime,7d), datetime(null))\n"
        "| where CreatedTime > ago(90d) or isnotempty(WeekClosed)\n"
        "| summarize\n"
        "    ['Incidents Created'] = dcountif(IncidentNumber, CreatedTime > ago(90d)),\n"
        "    ['Incidents Closed']  = dcountif(IncidentNumber, isnotempty(WeekClosed))\n"
        "    by Week = WeekCreated\n"
        "| where isnotempty(Week)\n"
        "| sort by Week asc"
    ),
    viz="timechart",
    tab="executive",
    custom_width=50
))

new_items.append(kql_item(
    name="exec-90d-identity-chart",
    title="90-Day Weekly Risky Sign-ins",
    query=(
        "// Fixed 90d — risky sign-ins by risk level\n"
        "union isfuzzy=true SigninLogs\n"
        "| where TimeGenerated > ago(90d)\n"
        "| where RiskLevelDuringSignIn in (\"high\",\"medium\")\n"
        "| summarize Count=count() by bin(TimeGenerated, 7d), RiskLevelDuringSignIn\n"
        "| sort by TimeGenerated asc"
    ),
    viz="timechart",
    tab="executive",
    custom_width=50
))

new_items.append(kql_item(
    name="exec-90d-email-chart",
    title="90-Day Weekly Blocked Email Threats",
    query=(
        "// Fixed 90d — blocked email volume (all Mimecast sources + Defender)\n"
        "union isfuzzy=true\n"
        "    (CommonSecurityLog\n"
        "     | where TimeGenerated > ago(90d)\n"
        "     | where DeviceVendor =~ \"Mimecast\"\n"
        "     | extend _act = tolower(tostring(DeviceAction))\n"
        "     | where _act has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\")\n"
        "     | extend Source = \"Mimecast\"),\n"
        "    (MimecastSEGEvent_CL\n"
        "     | where TimeGenerated > ago(90d)\n"
        "     | extend _act = tolower(tostring(column_ifexists('action_s',column_ifexists('Action',''))))\n"
        "     | where _act has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\")\n"
        "     | extend Source = \"Mimecast SEG\"),\n"
        "    (EmailEvents\n"
        "     | where TimeGenerated > ago(90d)\n"
        "     | where DeliveryAction in (\"Blocked\",\"Replaced\")\n"
        "     | extend Source = \"Defender for O365\")\n"
        "| summarize Count=count() by bin(TimeGenerated, 7d), Source\n"
        "| sort by TimeGenerated asc"
    ),
    viz="timechart",
    tab="executive",
    custom_width=50
))

new_items.append(kql_item(
    name="exec-90d-mttr-chart",
    title="90-Day Weekly Avg MTTR (hours)",
    query=(
        "// Fixed 90d — MTTR trend\n"
        "union isfuzzy=true SecurityIncident\n"
        "| where ClosedTime > ago(90d)\n"
        "| where Status in (\"Closed\",\"Resolved\")\n"
        "| extend MTTR = datetime_diff('minute', ClosedTime, CreatedTime) / 60.0\n"
        "| summarize ['Avg MTTR (hrs)'] = round(avg(MTTR), 1) by bin(ClosedTime, 7d)\n"
        "| sort by ClosedTime asc"
    ),
    viz="timechart",
    tab="executive",
    custom_width=50
))

new_items.append(md_item(
    "exec-exploit-heading",
    "## Active CVE Exploit Detections (90-day)\n"
    "> CVEs being actively exploited against estate devices, extracted from MDE alerts. "
    "Works with Plan 1 — no TVM required.",
    "executive"
))

new_items.append(kql_item(
    name="exec-exploit-cve-summary",
    title="CVEs Actively Exploited — Last 90 Days",
    query=(
        "union isfuzzy=true SecurityAlert\n"
        "| where TimeGenerated > ago(90d)\n"
        "| where ProviderName =~ \"Microsoft Defender Advanced Threat Protection\"\n"
        "| extend CVEs = extract_all(@\"(CVE-\\d{4}-\\d{4,})\", Description)\n"
        "| where array_length(CVEs) > 0\n"
        "| mv-expand CVE = CVEs\n"
        "| summarize\n"
        "    AlertCount      = count(),\n"
        "    AffectedDevices = dcount(CompromisedEntity),\n"
        "    LastSeen        = max(TimeGenerated),\n"
        "    Severity        = any(AlertSeverity)\n"
        "  by tostring(CVE)\n"
        "| extend SevOrder = case(Severity==\"Critical\",4,Severity==\"High\",3,Severity==\"Medium\",2,1)\n"
        "| sort by SevOrder desc, AffectedDevices desc\n"
        "| project-away SevOrder"
    ),
    viz="table",
    tab="executive",
    grid_formatters=[
        {
            "columnMatch": "Severity",
            "formatter": 18,
            "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                    {"operator": "==", "thresholdValue": "Critical", "representation": "redBright", "text": "Critical"},
                    {"operator": "==", "thresholdValue": "High",     "representation": "orange",   "text": "High"},
                    {"operator": "Default",                           "representation": "yellow",   "text": "{0}"},
                ]
            }
        },
        {
            "columnMatch": "AffectedDevices",
            "formatter": 4,
            "formatOptions": {"palette": "redBright", "min": 0}
        }
    ]
))

# ── ESSENTIAL EIGHT TAB ───────────────────────────────────────────────────────
e8_heading = (
    "## ASD Essential Eight Alignment\n"
    "> Indicators mapped to the [ASD Essential Eight Maturity Model](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) "
    "for Australian university compliance reporting.\n>\n"
    "> **Coverage with current connectors (MDE Plan 1 + Entra ID):**\n>\n"
    "> | Control | Coverage | Source |\n"
    "> |---|---|---|\n"
    "> | Patch Operating Systems | ✅ OS version inventory | `DeviceInfo` |\n"
    "> | Multi-Factor Authentication | ✅ MFA rate + failures | `SigninLogs` |\n"
    "> | Restrict Administrative Privileges | ✅ Role/admin changes | `AuditLogs` |\n"
    "> | User Application Hardening | ⚠️ Script/macro alerts only | `SecurityAlert` |\n"
    "> | Patch Applications | ❌ Requires MDE Plan 2 (TVM) | — |\n"
    "> | Application Control | ❌ Requires Defender App Control data | — |\n"
    "> | Regular Backups | ❌ Not available via Sentinel | — |\n"
    "> | Office Macro Settings | ⚠️ Alert-based proxy only | `SecurityAlert` |\n"
    ">\n"
    "> Controls marked ❌ are not automatable from current data sources. Document them as "
    "process controls in your quarterly report."
)

new_items.append(md_item("e8-heading", e8_heading, "e8"))

new_items.append(kql_item(
    name="e8-mfa-rate-tile",
    title="MFA Coverage Rate (sign-ins)",
    query=(
        "union isfuzzy=true SigninLogs\n"
        "| where TimeGenerated {TimeRange}\n"
        "| where ResultType == \"0\"\n"
        "| summarize Total=count(), WithMFA=countif(AuthenticationRequirement == \"multiFactorAuthentication\")\n"
        "| extend ['MFA Coverage %'] = round(100.0 * WithMFA / iff(Total==0,1,Total), 1)\n"
        "| project ['MFA Coverage %']"
    ),
    viz="tiles",
    size=4,
    tile_col="MFA Coverage %",
    tile_palette="green",
    tab="e8",
    custom_width=25
))

new_items.append(kql_item(
    name="e8-nomfa-tile",
    title="Sign-ins Without MFA",
    query=(
        "union isfuzzy=true SigninLogs\n"
        "| where TimeGenerated {TimeRange}\n"
        "| where ResultType == \"0\"\n"
        "| where AuthenticationRequirement == \"singleFactorAuthentication\"\n"
        "| summarize ['Sign-ins Without MFA'] = count()"
    ),
    viz="tiles",
    size=4,
    tile_col="Sign-ins Without MFA",
    tile_palette="redBright",
    tab="e8",
    custom_width=25
))

new_items.append(kql_item(
    name="e8-admin-tile",
    title="Privileged Role Changes",
    query=(
        "union isfuzzy=true AuditLogs\n"
        "| where TimeGenerated {TimeRange}\n"
        "| where OperationName has_any (\"Add member to role\",\"Remove member from role\",\n"
        "    \"Add user\",\"Delete user\",\"Reset password\",\"Assign license\",\n"
        "    \"Update user\",\"Create user\")\n"
        "| summarize ['Privileged Changes'] = count()"
    ),
    viz="tiles",
    size=4,
    tile_col="Privileged Changes",
    tile_palette="orange",
    tab="e8",
    custom_width=25
))

new_items.append(kql_item(
    name="e8-eol-tile",
    title="Potentially EOL Devices",
    query=(
        "// Devices running Windows 7/8 or macOS < 12 (Monterey)\n"
        "union isfuzzy=true DeviceInfo\n"
        "| where TimeGenerated {TimeRange}\n"
        "| summarize arg_max(TimeGenerated,*) by DeviceId\n"
        "| where OnboardingStatus == \"Onboarded\"\n"
        "| extend IsEOL = case(\n"
        "    OSPlatform == \"Windows\" and OSVersion startswith \"Windows 7\", true,\n"
        "    OSPlatform == \"Windows\" and OSVersion startswith \"Windows 8\", true,\n"
        "    OSPlatform == \"macOS\" and toint(extract(@\"(\\d+)\", 1, OSVersion)) < 12, true,\n"
        "    false)\n"
        "| where IsEOL == true\n"
        "| summarize ['Potentially EOL Devices'] = dcount(DeviceId)"
    ),
    viz="tiles",
    size=4,
    tile_col="Potentially EOL Devices",
    tile_palette="redBright",
    tab="e8",
    custom_width=25
))

new_items.append(kql_item(
    name="e8-mfa-trend",
    title="MFA Coverage Rate — 90-Day Trend",
    query=(
        "// Fixed 90d — weekly MFA adoption rate\n"
        "union isfuzzy=true SigninLogs\n"
        "| where TimeGenerated > ago(90d)\n"
        "| where ResultType == \"0\"\n"
        "| summarize\n"
        "    Total   = count(),\n"
        "    WithMFA = countif(AuthenticationRequirement == \"multiFactorAuthentication\")\n"
        "    by bin(TimeGenerated, 7d)\n"
        "| extend ['MFA Coverage %'] = round(100.0 * WithMFA / iff(Total==0,1,Total), 1)\n"
        "| project TimeGenerated, ['MFA Coverage %']\n"
        "| sort by TimeGenerated asc"
    ),
    viz="timechart",
    tab="e8",
    custom_width=50
))

new_items.append(kql_item(
    name="e8-os-dist",
    title="OS Version Inventory (Patch OS — E8 Control 5)",
    query=(
        "// Current OS version distribution across onboarded devices\n"
        "union isfuzzy=true DeviceInfo\n"
        "| where TimeGenerated {TimeRange}\n"
        "| summarize arg_max(TimeGenerated,*) by DeviceId\n"
        "| where OnboardingStatus == \"Onboarded\"\n"
        "| summarize DeviceCount=count() by OSPlatform, OSVersion\n"
        "| sort by OSPlatform asc, DeviceCount desc\n"
        "| take 30"
    ),
    viz="table",
    tab="e8",
    custom_width=50
))

new_items.append(kql_item(
    name="e8-admin-detail",
    title="Privileged Role Changes Detail (Restrict Admin — E8 Control 6)",
    query=(
        "// Admin/privileged account changes from Entra ID AuditLogs\n"
        "union isfuzzy=true AuditLogs\n"
        "| where TimeGenerated {TimeRange}\n"
        "| where OperationName has_any (\n"
        "    \"Add member to role\",\"Remove member from role\",\n"
        "    \"Add user\",\"Delete user\",\"Reset password (by admin)\",\n"
        "    \"Assign license\",\"Update user\",\"Create user\",\n"
        "    \"Add owner to application\",\"Add app role assignment\")\n"
        "| extend Actor  = tostring(InitiatedBy.user.userPrincipalName)\n"
        "| extend Target = tostring(TargetResources[0].userPrincipalName)\n"
        "| extend Role   = tostring(TargetResources[0].displayName)\n"
        "| project TimeGenerated, OperationName, Actor, Target, Role, Result\n"
        "| sort by TimeGenerated desc\n"
        "| take 50"
    ),
    viz="table",
    tab="e8",
    custom_width=50
))

new_items.append(kql_item(
    name="e8-macro-alerts",
    title="Script / Macro / Exploit Alerts (User App Hardening — E8 Control 3)",
    query=(
        "// MDE alerts indicating macro, script, or application exploit activity\n"
        "union isfuzzy=true SecurityAlert\n"
        "| where TimeGenerated {TimeRange}\n"
        "| where ProviderName =~ \"Microsoft Defender Advanced Threat Protection\"\n"
        "| where AlertName has_any (\"macro\",\"script\",\"powershell\",\"wscript\",\"cscript\",\n"
        "    \"exploit\",\"shellcode\",\"injection\",\"reflective\",\"obfuscat\")\n"
        "    or Description has_any (\"macro\",\"script engine\",\"exploit kit\")\n"
        "| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Description\n"
        "| sort by AlertSeverity asc, TimeGenerated desc\n"
        "| take 50"
    ),
    viz="table",
    tab="e8",
    custom_width=50,
    grid_formatters=[
        {
            "columnMatch": "AlertSeverity",
            "formatter": 18,
            "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                    {"operator": "==", "thresholdValue": "Critical", "representation": "redBright", "text": "Critical"},
                    {"operator": "==", "thresholdValue": "High",     "representation": "orange",   "text": "High"},
                    {"operator": "Default",                           "representation": "yellow",   "text": "{0}"},
                ]
            }
        }
    ]
))

new_items.append(kql_item(
    name="e8-nomfa-users",
    title="Users Signing In Without MFA (MFA — E8 Control 8)",
    query=(
        "// Users with successful sign-ins that bypassed MFA\n"
        "union isfuzzy=true SigninLogs\n"
        "| where TimeGenerated {TimeRange}\n"
        "| where ResultType == \"0\"\n"
        "| where AuthenticationRequirement == \"singleFactorAuthentication\"\n"
        "| summarize\n"
        "    Count    = count(),\n"
        "    LastSeen = max(TimeGenerated),\n"
        "    Apps     = make_set(AppDisplayName, 5)\n"
        "  by UserPrincipalName\n"
        "| sort by Count desc\n"
        "| take 25"
    ),
    viz="table",
    tab="e8",
    custom_width=50
))

# ── Append all new items ──────────────────────────────────────────────────────
items.extend(new_items)
wb["items"] = items

with open(OUTPUT, "w") as f:
    json.dump(wb, f, indent=2, ensure_ascii=False)

print(f"Written {len(wb['items'])} items to {OUTPUT}")
print(f"File size: {len(json.dumps(wb)):,} bytes")
