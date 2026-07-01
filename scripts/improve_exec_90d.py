#!/usr/bin/env python3
"""Improve exec tab 90-day charts with better queries from workspace usage workbook."""
import json, sys

PATH = "/home/user/Workbooks/native-v2.json"

# ----- Updated queries -----

SOC_SUMMARY_QUERY = (
    "// SOC Incident Performance — 90-day rolling, P50/P90 median (not avg)\n"
    "let Lookback = 90d;\n"
    "SecurityIncident\n"
    "| where isnotempty(IncidentNumber) and isnotempty(CreatedTime)\n"
    "| where CreatedTime >= ago(Lookback)\n"
    "| summarize arg_max(LastModifiedTime, *) by IncidentNumber\n"
    "| extend\n"
    "    TTT_hours = iff(isnotnull(CreatedTime) and isnotnull(FirstModifiedTime),\n"
    "                    datetime_diff('minute', FirstModifiedTime, CreatedTime) / 60.0, real(null)),\n"
    "    TTC_hours = iff(isnotnull(CreatedTime) and isnotnull(ClosedTime),\n"
    "                    datetime_diff('minute', ClosedTime, CreatedTime) / 60.0, real(null)),\n"
    "    TTD_hours = iff(isnotnull(FirstActivityTime) and isnotnull(CreatedTime),\n"
    "                    datetime_diff('minute', CreatedTime, FirstActivityTime) / 60.0, real(null))\n"
    "| summarize\n"
    "    TotalIncidents        = dcount(IncidentNumber),\n"
    "    ['High 🔴']           = countif(Severity == 'High'),\n"
    "    ['Medium 🟡']         = countif(Severity == 'Medium'),\n"
    "    ['Low 🟢']            = countif(Severity == 'Low'),\n"
    "    Informational         = countif(Severity == 'Informational'),\n"
    "    ['MTTT/H (P50 hrs)']  = round(percentile(TTT_hours, 50), 1),\n"
    "    ['MTTC (P50 hrs)']    = round(percentile(TTC_hours, 50), 1),\n"
    "    ['MTTD (P50 hrs)']    = round(percentile(TTD_hours, 50), 1),\n"
    "    ['MTTC worst 10%']    = round(percentile(TTC_hours, 90), 1)"
)

MTTR_CHART_QUERY = (
    "// MTTT / MTTC / MTTD weekly medians — 90-day fixed window\n"
    "let Lookback = 90d;\n"
    "SecurityIncident\n"
    "| where TimeGenerated >= ago(Lookback)\n"
    "| summarize arg_max(LastModifiedTime, *) by IncidentNumber\n"
    "| extend\n"
    "    TTT_hours = iff(isnotnull(CreatedTime) and isnotnull(FirstModifiedTime),\n"
    "                    datetime_diff('minute', FirstModifiedTime, CreatedTime) / 60.0, real(null)),\n"
    "    TTC_hours = iff(isnotnull(CreatedTime) and isnotnull(ClosedTime),\n"
    "                    datetime_diff('minute', ClosedTime, CreatedTime) / 60.0, real(null)),\n"
    "    TTD_hours = iff(isnotnull(FirstActivityTime) and isnotnull(CreatedTime),\n"
    "                    datetime_diff('minute', CreatedTime, FirstActivityTime) / 60.0, real(null))\n"
    "| summarize\n"
    "    ['MTTT/H (P50 hrs)'] = round(percentile(TTT_hours, 50), 1),\n"
    "    ['MTTC (P50 hrs)']   = round(percentile(TTC_hours, 50), 1),\n"
    "    ['MTTD (P50 hrs)']   = round(percentile(TTD_hours, 50), 1),\n"
    "    ['MTTC P90 (hrs)']   = round(percentile(TTC_hours, 90), 1)\n"
    "  by TimeBucket = bin(TimeGenerated, 7d)\n"
    "| sort by TimeBucket asc\n"
    "| render timechart"
)

INCIDENT_FORECAST_QUERY = (
    "// Daily incident volume — 90-day history + 30-day forecast\n"
    "let LookbackDays = 90d;\n"
    "let ForecastDays = 30;\n"
    "let EndDate   = now();\n"
    "let StartDate = EndDate - LookbackDays;\n"
    "let ProjectTo = EndDate + (ForecastDays * 1d);\n"
    "SecurityIncident\n"
    "| make-series IncidentCount = dcount(IncidentNumber) default=0\n"
    "    on TimeGenerated from StartDate to ProjectTo step 1d\n"
    "| extend Forecast = series_decompose_forecast(IncidentCount, ForecastDays)\n"
    "| mv-expand TimeGenerated to typeof(datetime), IncidentCount to typeof(long), Forecast to typeof(real)\n"
    "| project TimeGenerated,\n"
    "    ['Actual Incidents'] = todouble(IncidentCount),\n"
    "    ['30-day Forecast']  = Forecast\n"
    "| render timechart"
)

MTTD_TILE_QUERY = (
    "// Median MTTD (P50) — detection latency, 90-day fixed\n"
    "SecurityIncident\n"
    "| where isnotnull(FirstActivityTime) and isnotnull(CreatedTime)\n"
    "| where CreatedTime >= ago(90d)\n"
    "| summarize arg_max(LastModifiedTime, *) by IncidentNumber\n"
    "| extend TTD_hours = datetime_diff('minute', CreatedTime, FirstActivityTime) / 60.0\n"
    "| where TTD_hours >= 0\n"
    "| summarize ['Median MTTD (hrs)'] = round(percentile(TTD_hours, 50), 1)"
)

MFA_TILE_QUERY = (
    "// MFA coverage — overall + privileged accounts, 90-day fixed\n"
    "let PrivUsers = IdentityInfo\n"
    "    | mv-expand AssignedRoles\n"
    "    | where AssignedRoles contains 'Admin'\n"
    "    | distinct AccountUPN;\n"
    "SigninLogs\n"
    "| where TimeGenerated >= ago(90d)\n"
    "| where ResultType == 0\n"
    "| extend IsPriv = iff(UserPrincipalName in (PrivUsers), 1, 0)\n"
    "| summarize\n"
    "    Total        = count(),\n"
    "    MFALogins    = countif(AuthenticationRequirement == 'multiFactorAuthentication'),\n"
    "    PrivTotal    = countif(IsPriv == 1),\n"
    "    PrivMFA      = countif(IsPriv == 1 and AuthenticationRequirement == 'multiFactorAuthentication')\n"
    "| extend\n"
    "    ['Overall MFA %']     = round(toreal(MFALogins) / Total * 100.0, 1),\n"
    "    ['Privileged MFA %']  = iff(PrivTotal == 0, real(null), round(toreal(PrivMFA) / PrivTotal * 100.0, 1))\n"
    "| project ['Overall MFA %'], ['Privileged MFA %']"
)

with open(PATH) as f:
    wb = json.load(f)

# New SOC summary table item to insert after exec-efficiency-heading
SOC_SUMMARY_ITEM = {
    "type": 3,
    "content": {
        "version": "KqlItem/1.0",
        "query": SOC_SUMMARY_QUERY,
        "size": 4,
        "title": "SOC Incident Performance — Last 90 Days (P50 Median)",
        "timeContext": {"durationMs": 0},
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "table",
        "gridSettings": {
            "formatters": [
                {"columnMatch": "TotalIncidents", "formatter": 4, "formatOptions": {"palette": "blue"}},
                {"columnMatch": "High", "formatter": 18, "formatOptions": {"thresholdsOptions": "icons", "thresholdsGrid": [
                    {"operator": ">", "thresholdValue": "0", "representation": "2", "text": "{0}{1}"},
                    {"operator": "Default", "thresholdValue": None, "representation": "success", "text": "{0}{1}"}
                ]}},
                {"columnMatch": "MTTC (P50 hrs)", "formatter": 4, "formatOptions": {"palette": "redGreen", "min": 0, "max": 48}},
            ]
        }
    },
    "name": "exec-soc-summary-table",
    "conditionalVisibility": {
        "parameterName": "selectedTab",
        "comparison": "isEqualTo",
        "value": "executive"
    }
}

patched = {
    "exec-90d-mttr-chart": MTTR_CHART_QUERY,
    "exec-90d-incidents-chart": INCIDENT_FORECAST_QUERY,
    "exec-mttd-tile": MTTD_TILE_QUERY,
    "exec-mfa-tile": MFA_TILE_QUERY,
}

patched_count = 0
already_present = any(item.get("name") == "exec-soc-summary-table" for item in wb["items"])
inserted = already_present
new_items = []

for item in wb["items"]:
    new_items.append(item)
    name = item.get("name", "")

    # Insert SOC summary table after exec-efficiency-heading (only if not already present)
    if name == "exec-efficiency-heading" and not inserted:
        new_items.append(SOC_SUMMARY_ITEM)
        inserted = True
        print("Inserted: exec-soc-summary-table")
    elif name == "exec-efficiency-heading" and already_present:
        print("Skipped: exec-soc-summary-table already present")

    if name in patched:
        item["content"]["query"] = patched[name]
        # Update titles for clarity
        if name == "exec-90d-mttr-chart":
            item["content"]["title"] = "MTTT / MTTC / MTTD — Weekly Medians (P50), 90-Day Fixed"
        elif name == "exec-90d-incidents-chart":
            item["content"]["title"] = "Daily Incidents — 90-Day History + 30-Day Forecast"
        elif name == "exec-mttd-tile":
            item["content"]["title"] = "Median MTTD (P50, hrs)"
        elif name == "exec-mfa-tile":
            item["content"]["title"] = "MFA Coverage — Overall & Privileged"
        patched_count += 1
        print(f"Updated: {name}")

wb["items"] = new_items

if not inserted:
    print("WARNING: exec-efficiency-heading not found, SOC summary not inserted")
    sys.exit(1)
if patched_count != len(patched):
    print(f"WARNING: expected {len(patched)} patches, applied {patched_count}")
    sys.exit(1)

with open(PATH, "w") as f:
    json.dump(wb, f, indent=2, ensure_ascii=False)

print(f"Done — {PATH} updated ({patched_count} queries replaced, 1 item inserted)")
