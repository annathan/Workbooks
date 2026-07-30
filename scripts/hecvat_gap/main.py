"""Build a HECVAT coverage register from manually exported CSVs and HECVAT attachments.

This is the no-API-access version of the pipeline: instead of pulling data
live from ServiceNow/Armis/CMDB, it reads files you exported yourself
through each system's UI. See README.md for where to get each export.

Usage:
    python main.py \
        --hecvat-dir sample_data/hecvat_attachments \
        --cmdb-csv sample_data/cmdb_export.csv \
        --armis-csv sample_data/armis_export.csv \
        --output register.xlsx
"""
import argparse
from datetime import datetime
from pathlib import Path

import pandas as pd

from hecvat_parser import parse_directory
from matcher import best_match

CMDB_NAME_CANDIDATES = ["name", "ci_name", "display_name", "application_name", "short_description", "u_application"]
ARMIS_NAME_CANDIDATES = ["application name", "application", "name", "app_name", "software"]
ARMIS_COUNT_CANDIDATES = ["device count", "devices", "asset count", "count"]


def pick_column(df: pd.DataFrame, candidates: list[str], required: bool = True) -> str | None:
    lowered = {c.lower().strip(): c for c in df.columns}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    for candidate in candidates:
        for col_lower, original in lowered.items():
            if candidate in col_lower:
                return original
    if required:
        raise SystemExit(
            f"Could not find a column matching any of {candidates} in columns {list(df.columns)}. "
            "Rename the relevant column in your export, or add its name to the candidate list in main.py."
        )
    return None


def load_names(csv_path: Path, name_candidates: list[str], count_candidates: list[str] | None = None) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    name_col = pick_column(df, name_candidates)
    out = pd.DataFrame({"name": df[name_col].astype(str).str.strip()})
    out = out[out["name"] != ""].drop_duplicates(subset="name")
    if count_candidates:
        count_col = pick_column(df, count_candidates, required=False)
        out["device_count"] = df.loc[out.index, count_col] if count_col else None
    return out.reset_index(drop=True)


def build_register(cmdb_names: pd.DataFrame, armis_names: pd.DataFrame, hecvat_records, stale_years: float):
    canonical = {}
    for name in cmdb_names["name"]:
        canonical.setdefault(name, {"in_cmdb": False, "in_armis": False, "device_count": None})
        canonical[name]["in_cmdb"] = True
    for _, row in armis_names.iterrows():
        name = row["name"]
        canonical.setdefault(name, {"in_cmdb": False, "in_armis": False, "device_count": None})
        canonical[name]["in_armis"] = True
        canonical[name]["device_count"] = row.get("device_count")

    canonical_names = list(canonical.keys())

    hecvat_best = {}  # canonical name -> (date, source_file, ticket_number, vendor_source)
    unmatched_hecvats = []
    parse_issues = []

    for rec in hecvat_records:
        if rec.issues:
            parse_issues.append(rec)
        # CMDB/Armis track product names, but a HECVAT's most reliable field
        # is the vendor's legal name, which is often a company, not the
        # product ("Adobe Inc." vs. "Adobe Acrobat") -- try both and keep
        # whichever scores higher against the canonical software list.
        candidates = [q for q in (rec.product, rec.vendor) if q]
        if not candidates:
            continue
        result = max((best_match(q, canonical_names) for q in candidates), key=lambda r: r.score)
        if not result.match:
            unmatched_hecvats.append((rec, result.score))
            continue
        existing = hecvat_best.get(result.match)
        if rec.assessment_date and (existing is None or existing[0] is None or rec.assessment_date > existing[0]):
            hecvat_best[result.match] = (rec.assessment_date, rec.source_file, rec.ticket_number, rec.vendor_source)
        elif existing is None:
            hecvat_best[result.match] = (rec.assessment_date, rec.source_file, rec.ticket_number, rec.vendor_source)

    today = datetime.now()
    rows = []
    for name, info in sorted(canonical.items()):
        hecvat = hecvat_best.get(name)
        last_date, source_file, ticket_number, vendor_source = hecvat if hecvat else (None, None, None, None)
        years_since = (today - last_date).days / 365.25 if last_date else None

        if info["in_armis"] and not hecvat:
            status = "IN USE — NOT ASSESSED"
        elif hecvat and years_since is not None and years_since > stale_years:
            status = f"STALE ({years_since:.1f}y)"
        elif hecvat:
            status = "CURRENT"
        elif info["in_cmdb"] and not info["in_armis"]:
            status = "NOT ASSESSED (not confirmed in use)"
        else:
            status = "NOT ASSESSED"

        rows.append(
            {
                "Software": name,
                "In CMDB": info["in_cmdb"],
                "In Armis (active use)": info["in_armis"],
                "Armis Device Count": info["device_count"],
                "Last HECVAT Date": last_date.date() if last_date else None,
                "Years Since Last HECVAT": round(years_since, 1) if years_since is not None else None,
                "HECVAT Ticket": ticket_number,
                "Status": status,
                "Vendor Match Confidence": {"cell": "high", "filename": "LOW — verify", None: None}[vendor_source],
            }
        )

    register_df = pd.DataFrame(rows).sort_values(by=["Status", "Software"])

    unmatched_df = pd.DataFrame(
        [
            {
                "Source File": rec.source_file,
                "Ticket": rec.ticket_number,
                "Parsed Vendor": rec.vendor,
                "Parsed Product": rec.product,
                "Best Score": round(score, 1),
            }
            for rec, score in unmatched_hecvats
        ]
    )

    issues_df = pd.DataFrame(
        [
            {"Source File": rec.source_file, "Ticket": rec.ticket_number, "Issues": "; ".join(rec.issues)}
            for rec in parse_issues
        ]
    )

    return register_df, unmatched_df, issues_df


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hecvat-dir", required=True, type=Path, help="Folder of downloaded HECVAT xlsx attachments")
    parser.add_argument("--cmdb-csv", required=True, type=Path, help="CMDB CI export (CSV)")
    parser.add_argument("--armis-csv", required=True, type=Path, help="Armis application inventory export (CSV)")
    parser.add_argument("--stale-years", type=float, default=2.0, help="Flag HECVATs older than this many years (default: 2)")
    parser.add_argument("--output", type=Path, default=Path("register.xlsx"))
    args = parser.parse_args()

    cmdb_names = load_names(args.cmdb_csv, CMDB_NAME_CANDIDATES)
    armis_names = load_names(args.armis_csv, ARMIS_NAME_CANDIDATES, ARMIS_COUNT_CANDIDATES)
    hecvat_records = parse_directory(args.hecvat_dir)

    register_df, unmatched_df, issues_df = build_register(cmdb_names, armis_names, hecvat_records, args.stale_years)

    with pd.ExcelWriter(args.output, engine="openpyxl") as writer:
        register_df.to_excel(writer, sheet_name="Register", index=False)
        unmatched_df.to_excel(writer, sheet_name="Unmatched HECVATs", index=False)
        issues_df.to_excel(writer, sheet_name="Parse Issues", index=False)

    flagged = (register_df["Status"] == "IN USE — NOT ASSESSED").sum()
    stale = register_df["Status"].str.startswith("STALE", na=False).sum()
    print(f"Parsed {len(hecvat_records)} HECVAT file(s), {len(unmatched_df)} unmatched, {len(issues_df)} with parse issues.")
    print(f"Register: {len(register_df)} software titles — {flagged} in use with no assessment, {stale} stale.")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
