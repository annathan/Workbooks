## Workbooks
Workbooks provided here are samples of what is possible to address specific scenarios.

To use any of the workbooks found here, create a new workbook in Azure Monitor, and copy the code from this sample into the code area for the workbook, replacing the sample code in this workbook:

![workbook code](workbook-code.png)

## Daily checks automation

`scripts/daily_checks/` is a standalone Python CLI that pulls team workload
from ServiceNow and security posture from Microsoft Sentinel/Defender and
Armis into a single morning report. See
[scripts/daily_checks/README.md](scripts/daily_checks/README.md) for setup.

## HECVAT coverage gap

`scripts/hecvat_gap/` cross-references HECVAT security assessments (from
ServiceNow tickets) against software actually in use (from Armis) and
CMDB, to flag software that's never been assessed or whose assessment has
gone stale. Works off manual CSV/xlsx exports, no API access required. See
[scripts/hecvat_gap/README.md](scripts/hecvat_gap/README.md) for setup.

## AFRL / DoD Anthropic access compliance monitoring

Monitors a defined set of personnel on AFRL-funded projects for access to
Anthropic-hosted services (`claude.ai`, `anthropic.com` and subdomains),
using Microsoft Sentinel and Defender telemetry, and produces an
audit-ready monthly compliance record. Three parts:

- **`watchlists/DoD-Anthropic-Monitoring.csv`**: the watchlist schema/import
  template. Import into Sentinel as a watchlist named exactly
  `DoD-Anthropic-Monitoring`; minimum columns are `UserUPN, Name, Project`
  (SearchKey can be set to whatever you like; the workbook always resolves
  the real `UserUPN` column and only falls back to SearchKey if it's
  missing). Optionally add `Status`/`DateAdded`/`DateRemoved` columns if you
  want the Monitored User Coverage tab to track *when* staff were added or
  removed rather than just who's currently monitored; the shipped workbook
  doesn't require them.
- **`analytics-rules/afrl-anthropic-access-detection.json`**: reference/
  backup ARM template for the Scheduled analytics rule (not required if you
  already have one deployed, e.g. an "AFRL Anthropic Compliance" rule
  created via the portal). Keeps the entity mappings, grouping and detection
  logic on record in case you ever need to redeploy or compare.
- **`AFRL-Anthropic-Compliance.json`**: the standalone workbook (built by
  `scripts/build_afrl_anthropic_workbook.py`) with tabs for the Monthly
  Compliance Dashboard, Anthropic Access, AI Usage Context (what was
  actually used if not Claude), Monitored User Coverage, Detection
  Investigations, Known Devices, and Unmanaged Device Risk. Use it the same
  way as the other workbooks above: copy the code into a new Azure Monitor
  workbook. Run the **Setup & Validation** tab first to confirm the
  watchlist and required tables are populated.
  **Detection Investigations and the Compliance Status/Investigations
  tiles filter `SecurityIncident` on an exact `Title` match** (currently
  `"AFRL Anthropic Compliance"`, set as `RULE_TITLE` in the generator
  script). If your analytics rule's display name or `alertDisplayNameFormat`
  differs, update `RULE_TITLE` and regenerate, otherwise those panels will
  silently show zero regardless of actual activity.

To change the workbook, edit `scripts/build_afrl_anthropic_workbook.py` and
re-run it; don't hand-edit `AFRL-Anthropic-Compliance.json` directly, since
the next regeneration will overwrite it.