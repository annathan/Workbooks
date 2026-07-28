# HECVAT Coverage Gap

Prototype that answers "which software actually in use has been HECVAT-assessed,
and how stale are the assessments we do have?" — without needing API access to
ServiceNow or Armis. It works entirely off files you export yourself through
each system's UI (view/manage access is enough).

This is the manual-export version of the pipeline described in the access
request doc; if/when API access is granted, `servicenow.py`/`armis.py` in
`../daily_checks/` show the pattern to switch this over to live pulls instead
of CSV files.

## What you need to collect

1. **HECVAT xlsx attachments.** In ServiceNow, find your HECVAT-tagged
   tickets and download each attached xlsx into one folder, e.g.
   `data/hecvat_attachments/`. Including the ticket number in the filename
   (ServiceNow's default download name usually does) lets the tool tag
   each record with its ticket — not required, just nice to have.
2. **CMDB export.** Open the CI list (Software/Application CIs) in
   ServiceNow, and use the list view's built-in Export > CSV. Any column
   with the CI name works (`name`, `short_description`, etc. are all
   auto-detected).
3. **Armis application inventory export.** Open the full Applications /
   Software Inventory list (not just the dashboard's top-N chart) and
   export to CSV. Needs a column with the application name; a device-count
   column is used if present but not required.

Start with a small sample (5-10 HECVAT tickets) to sanity-check the output
before exporting everything.

## Setup

```bash
cd scripts/hecvat_gap
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Try it on synthetic data first

```bash
python sample_data/make_sample_data.py
python main.py \
  --hecvat-dir sample_data/hecvat_attachments \
  --cmdb-csv sample_data/cmdb_export.csv \
  --armis-csv sample_data/armis_export.csv \
  --output sample_data/register.xlsx
```

This generates a handful of fake HECVATs/exports and produces
`sample_data/register.xlsx` so you can see the shape of the output before
pointing it at real data.

## Run it on real exports

```bash
python main.py \
  --hecvat-dir data/hecvat_attachments \
  --cmdb-csv data/cmdb_export.csv \
  --armis-csv data/armis_export.csv \
  --stale-years 2 \
  --output register.xlsx
```

`register.xlsx` has three sheets:

- **Register** — one row per software title (union of CMDB + Armis),
  flagging `IN USE — NOT ASSESSED`, `STALE (N.Ny)`, `CURRENT`, or
  `NOT ASSESSED (not confirmed in use)`.
- **Unmatched HECVATs** — parsed HECVATs whose vendor/product name didn't
  confidently match anything in CMDB or Armis. Check these manually —
  usually a naming mismatch, occasionally software that's been retired.
- **Parse Issues** — xlsx files where a vendor name or date couldn't be
  found at all, meaning that HECVAT's layout doesn't match the label
  patterns in `hecvat_parser.py` and needs a look.

## Known limitations of this prototype

- **Name matching is fuzzy, not certain.** `--stale-years` and the match
  threshold in `matcher.py` (`DEFAULT_THRESHOLD = 82`) are starting points;
  tune them against your real data and spot-check the borderline matches.
- **HECVAT parsing is label-based**, scanning for cells like "Vendor Legal
  Name" / "Product or Service Name" / "Date Completed" rather than fixed
  cell references, since HECVAT versions and vendor customizations vary.
  If your real files use different wording, extend `LABEL_PATTERNS` in
  `hecvat_parser.py`.
- **No CMDB/Armis dedup beyond exact-string.** If your Armis export lists
  "Google Chrome" and "Chrome" as separate rows, they'll show up as two
  register entries; a normalization pass could merge these but wasn't
  built into this prototype.
