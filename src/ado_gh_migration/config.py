"""Env vars, multi-group token resolution, region hosts, defaults."""
from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

load_dotenv()

REGION_HOSTS: Final[dict[str, str]] = {
    "us": "https://api.snyk.io",
    "eu": "https://api.eu.snyk.io",
    "au": "https://api.au.snyk.io",
}


def normalize_group_id(group_id: str) -> str:
    return group_id.upper().replace("-", "_")


def resolve_token(group_id: str) -> str:
    var = f"SNYK_TOKEN_GROUP_{normalize_group_id(group_id)}"
    token = os.environ.get(var) or os.environ.get("SNYK_TOKEN")
    if not token:
        raise RuntimeError(
            f"No Snyk token found. Set {var} or SNYK_TOKEN in env or .env"
        )
    return token


def base_url(region: str) -> str:
    if region not in REGION_HOSTS:
        raise ValueError(
            f"Invalid region {region!r}; choose one of {list(REGION_HOSTS)}"
        )
    return f"{REGION_HOSTS[region]}/rest"


def default_api_version() -> str:
    return os.environ.get("SNYK_REST_API_VERSION") or date.today().isoformat()


def state_dir() -> Path:
    return Path(os.environ.get("STATE_DIR", "./state")).resolve()


def is_dry_run() -> bool:
    return os.environ.get("DRY_RUN", "True").lower() not in ("false", "0", "no")
