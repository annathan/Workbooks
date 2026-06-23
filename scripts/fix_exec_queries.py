#!/usr/bin/env python3
"""Fix two KQL errors in native-v2.json executive summary queries."""
import json

PATH = "/home/user/Workbooks/native-v2.json"

QOQ_QUERY = (
    "// Quarter-over-quarter KPI comparison — auto-calculates current vs previous quarter\n"
    "let TQ  = startofquarter(now());\n"
    "let LQ  = startofquarter(ago(91d));\n"
    "// Alerts\n"
    "let a1 = toscalar(union isfuzzy=true SecurityAlert\n"
    "    | where TimeGenerated >= TQ\n"
    "    | where AlertSeverity in (\"Critical\",\"High\")\n"
    "    | count);\n"
    "let a2 = toscalar(union isfuzzy=true SecurityAlert\n"
    "    | where TimeGenerated >= LQ and TimeGenerated < TQ\n"
    "    | where AlertSeverity in (\"Critical\",\"High\")\n"
    "    | count);\n"
    "// P1/P2 Incidents\n"
    "let i1 = toscalar(union isfuzzy=true SecurityIncident\n"
    "    | where CreatedTime >= TQ\n"
    "    | summarize arg_max(LastModifiedTime,*) by IncidentNumber\n"
    "    | where Severity in (\"Critical\",\"High\")\n"
    "    | count);\n"
    "let i2 = toscalar(union isfuzzy=true SecurityIncident\n"
    "    | where CreatedTime >= LQ and CreatedTime < TQ\n"
    "    | summarize arg_max(LastModifiedTime,*) by IncidentNumber\n"
    "    | where Severity in (\"Critical\",\"High\")\n"
    "    | count);\n"
    "// MTTR — avg returns NaN on empty input, handle with isnull/isnan\n"
    "let m1 = toscalar(union isfuzzy=true SecurityIncident\n"
    "    | where ClosedTime >= TQ\n"
    "    | where Status in (\"Closed\",\"Resolved\")\n"
    "    | extend H = datetime_diff('minute', ClosedTime, CreatedTime) / 60.0\n"
    "    | summarize AvgH = avg(H)\n"
    "    | project iif(isnan(AvgH) or isnull(AvgH), 0.0, round(AvgH, 1)));\n"
    "let m2 = toscalar(union isfuzzy=true SecurityIncident\n"
    "    | where ClosedTime >= LQ and ClosedTime < TQ\n"
    "    | where Status in (\"Closed\",\"Resolved\")\n"
    "    | extend H = datetime_diff('minute', ClosedTime, CreatedTime) / 60.0\n"
    "    | summarize AvgH = avg(H)\n"
    "    | project iif(isnan(AvgH) or isnull(AvgH), 0.0, round(AvgH, 1)));\n"
    "// Risky sign-ins\n"
    "let r1 = toscalar(union isfuzzy=true SigninLogs\n"
    "    | where TimeGenerated >= TQ\n"
    "    | where RiskLevelDuringSignIn in (\"high\",\"medium\")\n"
    "    | count);\n"
    "let r2 = toscalar(union isfuzzy=true SigninLogs\n"
    "    | where TimeGenerated >= LQ and TimeGenerated < TQ\n"
    "    | where RiskLevelDuringSignIn in (\"high\",\"medium\")\n"
    "    | count);\n"
    "// Blocked email (all Mimecast sources + Defender)\n"
    "let e1 = toscalar(union isfuzzy=true\n"
    "    (EmailEvents | where TimeGenerated >= TQ | where DeliveryAction in (\"Blocked\",\"Replaced\")),\n"
    "    (CommonSecurityLog | where TimeGenerated >= TQ | where DeviceVendor =~ \"Mimecast\"\n"
    "     | where tolower(tostring(DeviceAction)) has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\")),\n"
    "    (MimecastSEGEvent_CL | where TimeGenerated >= TQ\n"
    "     | where tolower(tostring(column_ifexists('action_s',column_ifexists('Action','')))) has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\"))\n"
    "    | count);\n"
    "let e2 = toscalar(union isfuzzy=true\n"
    "    (EmailEvents | where TimeGenerated >= LQ and TimeGenerated < TQ | where DeliveryAction in (\"Blocked\",\"Replaced\")),\n"
    "    (CommonSecurityLog | where TimeGenerated >= LQ and TimeGenerated < TQ | where DeviceVendor =~ \"Mimecast\"\n"
    "     | where tolower(tostring(DeviceAction)) has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\")),\n"
    "    (MimecastSEGEvent_CL | where TimeGenerated >= LQ and TimeGenerated < TQ\n"
    "     | where tolower(tostring(column_ifexists('action_s',column_ifexists('Action','')))) has_any (\"block\",\"reject\",\"hold\",\"held\",\"prevent\",\"quarantine\",\"bounce\"))\n"
    "    | count);\n"
    "// Device onboarding %\n"
    "let d1 = toscalar(union isfuzzy=true DeviceInfo\n"
    "    | where TimeGenerated >= TQ\n"
    "    | summarize arg_max(TimeGenerated,*) by DeviceId\n"
    "    | summarize Total=count(), Onboarded=countif(OnboardingStatus==\"Onboarded\")\n"
    "    | project iif(Total==0, 0.0, round(100.0 * Onboarded / Total, 1)));\n"
    "let d2 = toscalar(union isfuzzy=true DeviceInfo\n"
    "    | where TimeGenerated >= LQ and TimeGenerated < TQ\n"
    "    | summarize arg_max(TimeGenerated,*) by DeviceId\n"
    "    | summarize Total=count(), Onboarded=countif(OnboardingStatus==\"Onboarded\")\n"
    "    | project iif(Total==0, 0.0, round(100.0 * Onboarded / Total, 1)));\n"
    "union\n"
    "  (print Metric=\"Critical / High Alerts\",  Unit=\"\",    GoodDir=\"Down\", ThisQ=coalesce(todouble(a1),0.0), LastQ=coalesce(todouble(a2),0.0)),\n"
    "  (print Metric=\"P1 / P2 Incidents\",        Unit=\"\",    GoodDir=\"Down\", ThisQ=coalesce(todouble(i1),0.0), LastQ=coalesce(todouble(i2),0.0)),\n"
    "  (print Metric=\"Avg MTTR\",                 Unit=\"hrs\", GoodDir=\"Down\", ThisQ=coalesce(todouble(m1),0.0), LastQ=coalesce(todouble(m2),0.0)),\n"
    "  (print Metric=\"Risky Sign-ins\",           Unit=\"\",    GoodDir=\"Down\", ThisQ=coalesce(todouble(r1),0.0), LastQ=coalesce(todouble(r2),0.0)),\n"
    "  (print Metric=\"Blocked Email Threats\",    Unit=\"\",    GoodDir=\"Down\", ThisQ=coalesce(todouble(e1),0.0), LastQ=coalesce(todouble(e2),0.0)),\n"
    "  (print Metric=\"Device Onboarding\",        Unit=\"%\",   GoodDir=\"Up\",   ThisQ=coalesce(todouble(d1),0.0), LastQ=coalesce(todouble(d2),0.0))\n"
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
)

RATIO_QUERY = (
    "// Alert-to-incident ratio — measures alert noise (lower = better tuning)\n"
    "let Alerts    = toscalar(union isfuzzy=true SecurityAlert | where TimeGenerated > ago(90d) | count);\n"
    "let Incidents = toscalar(union isfuzzy=true SecurityIncident | where CreatedTime > ago(90d)\n"
    "    | summarize arg_max(LastModifiedTime,*) by IncidentNumber | count);\n"
    "print ['Alerts per Incident'] = round(iff(Incidents == 0, 0.0, todouble(Alerts) / todouble(Incidents)), 1)"
)

with open(PATH) as f:
    wb = json.load(f)

fixed = 0
for item in wb["items"]:
    if item.get("name") == "exec-qoq-table":
        item["content"]["query"] = QOQ_QUERY
        fixed += 1
        print("Fixed: exec-qoq-table")
    elif item.get("name") == "exec-ratio-tile":
        item["content"]["query"] = RATIO_QUERY
        fixed += 1
        print("Fixed: exec-ratio-tile")

if fixed != 2:
    print(f"WARNING: expected 2 fixes, applied {fixed}")
    raise SystemExit(1)

with open(PATH, "w") as f:
    json.dump(wb, f, indent=2, ensure_ascii=False)

print(f"Done — {PATH} updated")
