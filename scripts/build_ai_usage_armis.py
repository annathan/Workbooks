#!/usr/bin/env python3
"""
Builds a standalone Sentinel workbook: "AI Usage Summary (Armis-style)"

Data sources (all real, no invented fields):
  - DeviceNetworkEvents (MDE network telemetry)
  - AI-App-Domains watchlist (Domain, AppName, RiskScore, Risk[, Category])

Honesty note: DeviceNetworkEvents has NO UserAgent or HTTP Method column.
"Method"/"UserAgent" in section D are derived from InitiatingProcessFileName
(the real process making the connection) — an explicit, labeled proxy signal,
not fabricated data. If a web proxy source (CommonSecurityLog) is later
connected, swap in real HTTP fields per the comment in BASE_QUERY.
"""
import json

OUTPUT = "/home/user/Workbooks/ai-usage-armis-style.json"

# ── Shared base query, duplicated per item (workbook items don't share `let` scope) ──
BASE_QUERY = (
    "let AIApps = union isfuzzy=true (_GetWatchlist('AI-App-Domains')\n"
    "    | project\n"
    "        Domain    = column_ifexists('Domain', SearchKey),\n"
    "        AppName   = column_ifexists('AppName', ''),\n"
    "        RiskScore = toint(column_ifexists('RiskScore', '6')),\n"
    "        Risk      = column_ifexists('Risk', 'Medium'),\n"
    "        Category  = column_ifexists('Category', '')  // optional watchlist column; '' if not present\n"
    "    | where isnotempty(Domain));\n"
    "let AppDomains = AIApps | project Domain;\n"
    "let Events =\n"
    "    union isfuzzy=true\n"
    "        DeviceNetworkEvents,\n"
    "        (datatable(TimeGenerated:datetime, RemoteUrl:string, ActionType:string,\n"
    "                   InitiatingProcessAccountUpn:string, InitiatingProcessAccountDomain:string,\n"
    "                   InitiatingProcessAccountName:string, InitiatingProcessFileName:string,\n"
    "                   DeviceName:string) [])\n"
    "    | where TimeGenerated > ago(90d)\n"
    "    | where ActionType != \"InboundInternetScanInspected\"\n"
    "    | extend CleanHost = tolower(trim_start(@\"www.\", tostring(parse_url(RemoteUrl).Host)))\n"
    "    | where isnotempty(CleanHost)\n"
    "    | extend Domain2 = extract(@\"([a-zA-Z0-9-]+\\.[a-zA-Z]{2,})$\", 1, CleanHost)\n"
    "    | extend Domain3 = extract(@\"([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.[a-zA-Z]{2,})$\", 1, CleanHost)\n"
    "    | where Domain2 in (AppDomains) or Domain3 in (AppDomains)\n"
    "    | extend MatchDomain = iff(Domain3 in (AppDomains), Domain3, Domain2)\n"
    "    | join kind=inner AIApps on $left.MatchDomain == $right.Domain\n"
    "    // Canonical service name — normalisation (e.g. chatgpt.com + openai.com -> \"OpenAI/ChatGPT\")\n"
    "    // happens at the watchlist level: give both domains the same AppName when you populate it.\n"
    "    | extend Service = AppName\n"
    "    | extend UserName = coalesce(\n"
    "        InitiatingProcessAccountUpn,\n"
    "        iff(isnotempty(InitiatingProcessAccountDomain),\n"
    "            strcat(InitiatingProcessAccountName, \"@\", InitiatingProcessAccountDomain),\n"
    "            InitiatingProcessAccountName))\n"
    "    | where isnotempty(UserName)\n"
    "        and UserName !contains \"SYSTEM\" and UserName !endswith \"$\" and UserName !startswith \"NT AUTHORITY\"\n"
    "    // AccessType: DeviceNetworkEvents has no HTTP method/User-Agent column.\n"
    "    // InitiatingProcessFileName is the closest REAL signal available for API/script vs browser.\n"
    "    // If you connect a web proxy (Zscaler/Palo Alto) via CommonSecurityLog, prefer its real\n"
    "    // HTTP method/UA fields instead — union them in here with column_ifexists() guards.\n"
    "    | extend AccessType = case(\n"
    "        InitiatingProcessFileName has_any (\"chrome.exe\",\"msedge.exe\",\"firefox.exe\",\"opera.exe\",\"brave.exe\",\"safari\"), \"Browser\",\n"
    "        InitiatingProcessFileName has_any (\"python.exe\",\"python3.exe\",\"curl.exe\",\"node.exe\",\"powershell.exe\",\"pwsh.exe\",\"java.exe\",\"php.exe\",\"go.exe\",\"ruby.exe\"), \"API/Script\",\n"
    "        InitiatingProcessFileName has_any (\"Cursor.exe\",\"Code.exe\",\"code.exe\",\"git.exe\",\"docker.exe\"), \"Developer Tool\",\n"
    "        isempty(InitiatingProcessFileName), \"Unknown\",\n"
    "        \"Other Process\")\n"
    "    // Category: use watchlist Category column if populated, else infer from Service/Risk keywords\n"
    "    | extend Category = case(\n"
    "        isnotempty(Category), Category,\n"
    "        Service has_any (\"Copilot\",\"M365 Copilot\",\"Azure OpenAI\"), \"Enterprise\",\n"
    "        Service has_any (\"Cursor\",\"GitHub Copilot\",\"Hugging Face\",\"HuggingFace\",\"Replit\",\"Codeium\",\"Tabnine\"), \"Developer Tool\",\n"
    "        Risk in (\"Critical\",\"High\"), \"High-Risk\",\n"
    "        \"Consumer\");\n"
    "Events\n"
)

# ── A. AI Service Usage Summary ──────────────────────────────────────────────
QUERY_A = BASE_QUERY + (
    "| summarize DomainCount=count() by Service, MatchDomain\n"
    "| sort by Service asc, DomainCount desc\n"
    "| summarize ['Total Activities']=sum(DomainCount), TopDomains=make_list(MatchDomain) by Service\n"
    "| extend ['Key Domains'] = strcat_array(array_slice(TopDomains, 0, 2), \", \")\n"
    "| project Service, ['Total Activities'], ['Key Domains']\n"
    "| sort by ['Total Activities'] desc"
)

# ── B. Notable Observations (dynamically computed, not hardcoded) ──────────
QUERY_B = BASE_QUERY.replace("Events\n", "") + (
    "let Total = toscalar(Events | count);\n"
    "let TopSvcRow    = Events | summarize Count=count() by Service | top 1 by Count desc;\n"
    "let TopSvc       = toscalar(TopSvcRow | project Service);\n"
    "let TopSvcCount  = toscalar(TopSvcRow | project Count);\n"
    "let TopSvcPct    = iff(Total == 0, 0.0, round(100.0 * TopSvcCount / Total, 1));\n"
    "let ApiCount     = toscalar(Events | where AccessType == \"API/Script\" | count);\n"
    "let ApiPct       = iff(Total == 0, 0.0, round(100.0 * ApiCount / Total, 1));\n"
    "let BrowserCount = toscalar(Events | where AccessType == \"Browser\" | count);\n"
    "let BrowserPct   = iff(Total == 0, 0.0, round(100.0 * BrowserCount / Total, 1));\n"
    "let TopUserRow   = Events | summarize Count=count() by UserName | top 1 by Count desc;\n"
    "let TopUser      = toscalar(TopUserRow | project UserName);\n"
    "let TopUserPct   = iff(Total == 0, 0.0, round(100.0 * toscalar(TopUserRow | project Count) / Total, 1));\n"
    "let TopDeviceRow = Events | summarize Count=count() by DeviceName | top 1 by Count desc;\n"
    "let TopDevice    = toscalar(TopDeviceRow | project DeviceName);\n"
    "let TopDevicePct = iff(Total == 0, 0.0, round(100.0 * toscalar(TopDeviceRow | project Count) / Total, 1));\n"
    "let HighRiskCount = toscalar(Events | where Risk in (\"Critical\",\"High\") | count);\n"
    "let HighRiskUsers = toscalar(Events | where Risk in (\"Critical\",\"High\") | summarize dcount(UserName));\n"
    "let DevToolCount  = toscalar(Events | where AccessType == \"Developer Tool\" | count);\n"
    "print Observations = pack_array(\n"
    "    strcat(TopSvc, \" is the dominant AI service, accounting for \", TopSvcPct, \"% of all observed activity (\", TopSvcCount, \" of \", Total, \" events).\"),\n"
    "    strcat(\"Access pattern: \", ApiPct, \"% API/script-based vs \", BrowserPct, \"% browser-based — \",\n"
    "        iff(ApiPct > BrowserPct, \"automation/API usage dominates over manual browsing\", \"usage is predominantly manual/interactive\"), \".\"),\n"
    "    strcat(\"Activity is concentrated by user: \", TopUser, \" accounts for \", TopUserPct, \"% of all AI-related traffic.\"),\n"
    "    strcat(\"Activity is concentrated by device: \", TopDevice, \" accounts for \", TopDevicePct, \"% of all AI-related traffic.\"),\n"
    "    iff(HighRiskCount > 0,\n"
    "        strcat(HighRiskCount, \" events across \", HighRiskUsers, \" user(s) touched Critical/High-risk AI services — see Risky & Shadow AI table.\"),\n"
    "        \"No Critical/High-risk AI services were observed with active usage this period.\"),\n"
    "    iff(DevToolCount > 0,\n"
    "        strcat(DevToolCount, \" events indicate developer-tool AI usage — review for proprietary source code exposure.\"),\n"
    "        \"No developer-tool AI usage detected this period.\")\n"
    ")\n"
    "| mv-expand Observation = Observations to typeof(string)\n"
    "| project Observation"
)

# ── C. Risky & Shadow AI Usage ───────────────────────────────────────────────
QUERY_C = BASE_QUERY + (
    "| where Risk in (\"Critical\",\"High\",\"Medium\")\n"
    "| extend Reason = case(\n"
    "    Service has_any (\"DeepSeek\",\"Qwen\",\"Kimi\",\"Baidu\",\"ERNIE\",\"Zhipu\",\"Moonshot\"),\n"
    "        \"PRC-hosted service — data residency & export-control exposure, no enterprise agreement\",\n"
    "    Category == \"High-Risk\", \"Flagged high-risk by watchlist — unclear data handling/retention practices\",\n"
    "    Category == \"Consumer\" and Risk == \"Medium\", \"Consumer-grade AI tool — limited enterprise controls, possible data leakage via free-tier terms\",\n"
    "    Category == \"Developer Tool\", \"Developer AI tool — may transmit source code or credentials externally\",\n"
    "    Risk == \"High\", \"High risk per watchlist scoring — review data handling\",\n"
    "    \"Elevated risk — monitor for policy compliance\")\n"
    "| summarize Activities=count(), Users=dcount(UserName) by Risk, Service, Reason\n"
    "| extend RiskOrder = case(Risk == \"Critical\", 1, Risk == \"High\", 2, Risk == \"Medium\", 3, Risk == \"Low\", 4, 5)\n"
    "| sort by RiskOrder asc, Activities desc\n"
    "| project ['Risk Level']=Risk, Service, Activities, Users, Reason"
)

# ── D. High-Risk Findings ────────────────────────────────────────────────────
QUERY_D = BASE_QUERY + (
    "| where Risk in (\"Critical\",\"High\")\n"
    "| where AccessType in (\"API/Script\",\"Developer Tool\")\n"
    "| extend Method = case(\n"
    "    AccessType == \"API/Script\", \"API (script/CLI process)\",\n"
    "    AccessType == \"Developer Tool\", \"API (dev-tool integration)\",\n"
    "    \"Interactive\")\n"
    "// No native UserAgent field in DeviceNetworkEvents — process name is the closest real signal available\n"
    "| extend UserAgent = strcat(InitiatingProcessFileName, \" (process-based proxy — no HTTP UA in DeviceNetworkEvents)\")\n"
    "| summarize Activities=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)\n"
    "    by DeviceName, MatchDomain, Method, UserAgent, RiskScore, Risk\n"
    "| sort by RiskScore asc, Activities desc\n"
    "| project Device=DeviceName, Domain=MatchDomain, Method, UserAgent, RiskScore, Risk, Activities, FirstSeen, LastSeen\n"
    "| take 25"
)

# ── Workbook item builders ───────────────────────────────────────────────────
def kql_table_item(name, title, query):
    return {
        "type": 3,
        "content": {
            "version": "KqlItem/1.0",
            "query": query,
            "size": 0,
            "title": title,
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "visualization": "table",
        },
        "name": name,
    }

def md_item(name, text):
    return {"type": 1, "content": {"json": text}, "name": name}

def param_item():
    return {
        "type": 9,
        "content": {
            "version": "KqlParameterItem/1.0",
            "parameters": [
                {
                    "id": "param-workspace",
                    "version": "KqlParameterItem/1.0",
                    "name": "Workspace",
                    "type": 5,
                    "isRequired": True,
                    "value": {
                        "resourceIds": []
                    }
                }
            ],
            "style": "pills",
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
        },
        "name": "parameters",
    }

items = []

items.append(param_item())

items.append(md_item(
    "armis-heading",
    "# AI Usage Summary (Armis-style)\n"
    "> **Data sources:** `DeviceNetworkEvents` (MDE network telemetry) joined against the Sentinel "
    "watchlist **`AI-App-Domains`** (Domain, AppName, RiskScore, Risk[, Category]).\n>\n"
    "> **Window:** fixed 90-day lookback in every query below (`ago(90d)`), independent of any "
    "time-range picker.\n>\n"
    "> **Honesty note:** `DeviceNetworkEvents` does not include an HTTP method or User-Agent field. "
    "\"Method\" and \"UserAgent\" columns in Section D are derived from `InitiatingProcessFileName` "
    "(the real process making the connection) as an explicit, labeled proxy — not fabricated data. "
    "If you connect a web proxy (Zscaler, Palo Alto, etc.) that logs real HTTP telemetry via "
    "`CommonSecurityLog`, swap that in per the comment in the base query.\n>\n"
    "> **Normalisation:** domain-to-service consolidation (e.g. `chatgpt.com` + `openai.com` → "
    "\"OpenAI/ChatGPT\") happens by giving both watchlist rows the same `AppName`. Category "
    "(Enterprise / Consumer / Developer Tool / High-Risk) uses the watchlist's optional `Category` "
    "column if populated, otherwise falls back to keyword/risk-based inference — see Setup below."
))

items.append(md_item(
    "armis-section-a-heading",
    "## A. AI Service Usage Summary — Last 90 Days"
))
items.append(kql_table_item("armis-service-summary", "AI Service Usage Summary", QUERY_A))

items.append(md_item(
    "armis-section-b-heading",
    "## B. Notable Observations"
))
items.append(kql_table_item("armis-observations", "Notable Observations", QUERY_B))

items.append(md_item(
    "armis-section-c-heading",
    "## C. Risky & Shadow AI Usage — Summary by Risk Category"
))
items.append(kql_table_item("armis-risk-summary", "Risky & Shadow AI Usage", QUERY_C))

items.append(md_item(
    "armis-section-d-heading",
    "## D. High-Risk Findings — API/Automated Access to Critical/High-Risk Services"
))
items.append(kql_table_item("armis-high-risk-findings", "High-Risk Findings", QUERY_D))

items.append(md_item(
    "armis-setup-heading",
    "## Setup Notes\n"
    "**Recommended: add a `Category` column to the `AI-App-Domains` watchlist** "
    "(`Domain, AppName, RiskScore, Risk, Category`) with values `Enterprise`, `Consumer`, "
    "`Developer Tool`, or `High-Risk`, so Section C reasons and categorisation are explicit "
    "rather than inferred. If the column is absent, every query above falls back to a "
    "keyword/risk-score heuristic (visible in the `case()` logic) — functional, but less "
    "precise than an analyst-curated category per service.\n\n"
    "**To consolidate domain variants under one service name** (e.g. `chatgpt.com` and "
    "`openai.com` both reporting as \"OpenAI/ChatGPT\"), give both watchlist rows the same "
    "`AppName` value — the queries group by that field directly, no extra mapping table needed."
))

workbook = {
    "version": "Notebook/1.0",
    "items": items,
    "styleSettings": {},
    "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}

with open(OUTPUT, "w") as f:
    json.dump(workbook, f, indent=2, ensure_ascii=False)

print(f"Written {len(items)} items to {OUTPUT}")
