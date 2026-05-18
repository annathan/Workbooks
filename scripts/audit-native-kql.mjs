import fs from "fs";

const path = "c:/Users/nate/OneDrive/Documents/GitHub/Workbooks/native.json";
const wb = JSON.parse(fs.readFileSync(path, "utf8"));
const queries = [];

function walk(items) {
  for (const it of items || []) {
    if (it.content?.version === "KqlItem/1.0" && it.content.query) {
      queries.push({ name: it.name || "(unnamed)", query: it.content.query });
    }
    if (it.content?.parameters) {
      for (const p of it.content.parameters) {
        if (p.query) queries.push({ name: "param:" + p.name, query: p.query });
      }
    }
  }
}
walk(wb.items);

function balance(s, open, close) {
  let d = 0;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) {
        esc = false;
        continue;
      }
      if (c === "\\") {
        esc = true;
        continue;
      }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      continue;
    }
    if (c === open) d++;
    if (c === close) d--;
    if (d < 0) return { delta: d, ok: false };
  }
  return { delta: d, ok: d === 0 && !inStr };
}

const required = [
  "chart-overview-cve-trend",
  "chart-overview-kev-trend",
  "chart-overview-email-trend",
  "chart-overview-p1p2-trend",
  "chart-vuln-weekly-total",
  "chart-vuln-weekly-severity",
  "chart-vuln-weekly-kev",
  "chart-device-onboard-pct",
  "chart-device-sensor-impaired",
  "chart-device-exposure-high",
  "chart-email-source-weekly",
  "chart-email-threattype-weekly",
  "chart-trends-vuln-weekly-total",
  "chart-trends-vuln-weekly-severity",
  "chart-trends-vuln-weekly-kev",
];

const names = new Set(queries.map((q) => q.name));
const missing = required.filter((n) => !names.has(n));

const issues = [];
for (const { name, query } of queries) {
  for (const [o, c, label] of [
    ["(", ")", "paren"],
    ["[", "]", "bracket"],
    ["{", "}", "brace"],
  ]) {
    const r = balance(query, o, c);
    if (!r.ok) issues.push({ name, kind: label, delta: r.delta });
  }
  if (/\bCvssScore\b/.test(query)) issues.push({ name, kind: "CvssScore" });
  if (/\bIsExploitAvailable\b/.test(query) && !/column_ifexists\(\s*["']IsExploitAvailable/.test(query)) {
    issues.push({ name, kind: "bare IsExploitAvailable" });
  }
  if (/\btrim\s*\(\s*[^"']/.test(query)) issues.push({ name, kind: "bad trim" });
}

console.log("JSON_OK", true);
console.log("KQL_COUNT", queries.length);
console.log("MISSING_PANELS", missing.length ? missing.join(", ") : "none");
console.log("ISSUES", issues.length);
for (const i of issues) console.log(JSON.stringify(i));
process.exit(issues.length || missing.length ? 1 : 0);
