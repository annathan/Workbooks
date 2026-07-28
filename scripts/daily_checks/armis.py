"""Armis alert checks via the Armis REST API."""
import requests

try:
    from .config import ArmisConfig
    from .report import Section, Status
except ImportError:
    from config import ArmisConfig
    from report import Section, Status

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _get_access_token(cfg: ArmisConfig) -> str:
    resp = requests.post(
        f"{cfg.base_url}/api/v1/access_token/",
        data={"secret_key": cfg.secret_key},
        headers={"Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["data"]["access_token"]


def check_alerts(cfg: ArmisConfig, lookback_hours: int) -> Section:
    try:
        token = _get_access_token(cfg)
        resp = requests.get(
            f"{cfg.base_url}/api/v1/search/",
            params={
                "aql": f'in:alerts status:("Unhandled") timeFrame:"{lookback_hours} Hours"',
                "length": 50,
            },
            headers={"Authorization": token, "Accept": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return Section("Armis — Unhandled Alerts", Status.ERROR, f"Could not reach Armis: {exc}")

    alerts = resp.json().get("data", {}).get("results", [])
    alerts.sort(key=lambda a: SEVERITY_ORDER.get((a.get("severity") or "").lower(), 9))
    high_severity = [a for a in alerts if (a.get("severity") or "").lower() in ("high", "critical")]
    status = Status.ATTENTION if high_severity else Status.OK

    return Section(
        title="Armis — Unhandled Alerts",
        status=status,
        summary=f"{len(alerts)} unhandled alerts in the last {lookback_hours}h, {len(high_severity)} high/critical",
        row_headers=["Alert ID", "Type", "Severity", "Status"],
        rows=[
            [a.get("alertId"), (a.get("type") or "")[:40], a.get("severity"), a.get("status")]
            for a in alerts[:15]
        ],
    )
