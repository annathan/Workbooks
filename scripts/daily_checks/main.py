#!/usr/bin/env python3
"""Daily checks: pulls team workload from ServiceNow and security posture from
Microsoft Sentinel/Defender (Log Analytics) and Armis into a single report.

Configure via environment variables — copy .env.example to .env and fill in
whichever services you use; unconfigured services are skipped, not errors.

Run manually:
    python main.py
    python main.py --lookup RITM0012345   # ad-hoc single-ticket check

Or schedule it (cron example, run every weekday morning at 7:30):
    30 7 * * 1-5 cd /path/to/scripts/daily_checks && /usr/bin/python3 main.py >> daily_checks.log 2>&1
"""
import argparse
import sys

try:
    from . import armis, config, report, sentinel, servicenow, standup
except ImportError:
    import armis
    import config
    import report
    import sentinel
    import servicenow
    import standup


def build_sections(services, lookback_hours):
    sections = []

    if "standup" in services:
        sections.append(standup.prep_section())

    if "servicenow" in services:
        cfg = config.load_servicenow_config()
        if cfg:
            sections.append(servicenow.check_workload(cfg))
        else:
            sections.append(report.Section(
                "ServiceNow — Team Workload", report.Status.SKIPPED,
                "Not configured (set SNOW_INSTANCE_URL, SNOW_USERNAME, SNOW_PASSWORD)"))

    if "sentinel" in services:
        cfg = config.load_sentinel_config()
        if cfg:
            sections.append(sentinel.check_incidents(cfg, lookback_hours))
        else:
            sections.append(report.Section(
                "Microsoft Sentinel — Incidents", report.Status.SKIPPED,
                "Not configured (set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, LOG_ANALYTICS_WORKSPACE_ID)"))

    if "armis" in services:
        cfg = config.load_armis_config()
        if cfg:
            sections.append(armis.check_alerts(cfg, lookback_hours))
        else:
            sections.append(report.Section(
                "Armis — Unhandled Alerts", report.Status.SKIPPED,
                "Not configured (set ARMIS_BASE_URL, ARMIS_SECRET_KEY)"))

    return sections


def main():
    parser = argparse.ArgumentParser(description="Run daily team/security checks.")
    parser.add_argument(
        "--services", nargs="+", choices=["servicenow", "sentinel", "armis", "standup"],
        default=["servicenow", "sentinel", "armis", "standup"],
        help="Limit to specific services (default: all).",
    )
    parser.add_argument(
        "--no-file", action="store_true",
        help="Print to console only, skip writing the markdown report.",
    )
    parser.add_argument(
        "--lookup", metavar="NUMBER",
        help="Look up a single ServiceNow ticket (INC/RITM/SCTASK/REQ/PRB/CHG) instead of running the full report.",
    )
    args = parser.parse_args()

    if args.lookup:
        cfg = config.load_servicenow_config()
        if not cfg:
            print("ServiceNow not configured (set SNOW_INSTANCE_URL, SNOW_USERNAME, SNOW_PASSWORD)")
            sys.exit(1)
        section = servicenow.lookup(cfg, args.lookup)
        print(report.render_console([section]))
        sys.exit(1 if section.status == report.Status.ERROR else 0)

    report_cfg = config.load_report_config()
    sections = build_sections(args.services, report_cfg.lookback_hours)

    print(report.render_console(sections))

    if not args.no_file:
        path = report.write_report(sections, report_cfg.output_dir)
        print(f"\nSaved report to {path}")

    if any(s.status == report.Status.ERROR for s in sections):
        sys.exit(1)


if __name__ == "__main__":
    main()
