"""Configuration for the daily checks automation, loaded from environment variables.

Copy .env.example to .env and fill in the values for whichever services you
want to check. Any service left unconfigured is skipped (not treated as an
error) so you can start with just one integration and add the others later.
"""
import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _env(name, default=None):
    val = os.environ.get(name, default)
    return val.strip() if isinstance(val, str) else val


def _env_int(name, default):
    val = os.environ.get(name)
    return int(val) if val else default


@dataclass
class ServiceNowConfig:
    instance_url: str
    username: str
    password: str
    assignment_group: str


@dataclass
class SentinelConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    workspace_id: str


@dataclass
class ArmisConfig:
    base_url: str
    secret_key: str


@dataclass
class ReportConfig:
    output_dir: Path
    lookback_hours: int


def load_servicenow_config():
    instance_url = _env("SNOW_INSTANCE_URL")
    username = _env("SNOW_USERNAME")
    password = _env("SNOW_PASSWORD")
    if not all([instance_url, username, password]):
        return None
    return ServiceNowConfig(
        instance_url=instance_url.rstrip("/"),
        username=username,
        password=password,
        assignment_group=_env("SNOW_ASSIGNMENT_GROUP"),
    )


def load_sentinel_config():
    tenant_id = _env("AZURE_TENANT_ID")
    client_id = _env("AZURE_CLIENT_ID")
    client_secret = _env("AZURE_CLIENT_SECRET")
    workspace_id = _env("LOG_ANALYTICS_WORKSPACE_ID")
    if not all([tenant_id, client_id, client_secret, workspace_id]):
        return None
    return SentinelConfig(tenant_id, client_id, client_secret, workspace_id)


def load_armis_config():
    base_url = _env("ARMIS_BASE_URL")
    secret_key = _env("ARMIS_SECRET_KEY")
    if not all([base_url, secret_key]):
        return None
    return ArmisConfig(base_url.rstrip("/"), secret_key)


def load_report_config():
    return ReportConfig(
        output_dir=Path(_env("DAILY_CHECKS_OUTPUT_DIR", "./daily_checks_reports")),
        lookback_hours=_env_int("DAILY_CHECKS_LOOKBACK_HOURS", 24),
    )
