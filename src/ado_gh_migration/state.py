"""On-disk state under STATE_DIR/<group_id>/<org_id>/...

Stages own different files inside this layout. Capture writes raw API
responses; later stages add their own derived files alongside.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    def __init__(self, root: Path, group_id: str, org_id: str):
        self.root = Path(root)
        self.group_id = group_id
        self.org_id = org_id
        self.dir = self.root / group_id / org_id
        self.dir.mkdir(parents=True, exist_ok=True)

    def write(self, name: str, payload: Any) -> Path:
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str))
        return path

    def read(self, name: str) -> Any | None:
        path = self.dir / name
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def exists(self, name: str) -> bool:
        return (self.dir / name).exists()
