"""Mapping config: parses mapping.yaml and runs the URL resolver.

Two-layer resolver applied in order:
  1. Explicit overrides — `{source_url → destination_url}`.
  2. URL derivation rule — placeholder-based pattern transform for the bulk of repos.

(A content-fingerprint fallback is deferred — see project memory.)

Source and destination are assumed to be in the same Snyk org for this tool.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class MappingConfig:
    url_derivation_from: str | None
    url_derivation_to: str | None
    url_derivation_vars: dict[str, str]
    overrides: list[dict[str, Any]]

    @classmethod
    def load(cls, path: Path) -> "MappingConfig":
        data = yaml.safe_load(Path(path).read_text()) or {}
        deriv = data.get("url_derivation") or {}
        return cls(
            url_derivation_from=deriv.get("from"),
            url_derivation_to=deriv.get("to"),
            url_derivation_vars=deriv.get("vars") or {},
            overrides=data.get("overrides") or [],
        )

    def derive_url(self, source_url: str) -> str | None:
        """Apply the placeholder-based derivation rule. Returns None if no match."""
        if not (self.url_derivation_from and self.url_derivation_to and source_url):
            return None
        pattern = re.escape(self.url_derivation_from)
        pattern = re.sub(r"\\\{(\w+)\\\}", r"(?P<\1>[^/]+)", pattern)
        m = re.fullmatch(pattern, source_url)
        if not m:
            return None
        groups: dict[str, str] = dict(self.url_derivation_vars)
        groups.update(m.groupdict())
        try:
            return self.url_derivation_to.format(**groups)
        except KeyError:
            return None

    def find_override(self, source_url: str) -> dict | None:
        for entry in self.overrides:
            if entry.get("source_url") == source_url:
                return entry
        return None

    def resolve(self, source_url: str) -> dict[str, Any]:
        """Resolve a source URL to a destination URL.

        Returns a dict: {destination_url, resolved_via}
        where resolved_via is 'override' | 'derivation' | 'unmapped'.
        """
        override = self.find_override(source_url)
        if override:
            return {
                "destination_url": override.get("destination_url"),
                "resolved_via": "override",
            }
        derived = self.derive_url(source_url)
        if derived:
            return {"destination_url": derived, "resolved_via": "derivation"}
        return {"destination_url": None, "resolved_via": "unmapped"}
