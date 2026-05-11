from pathlib import Path

import pytest

from ado_gh_migration.mapping import MappingConfig


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "mapping.yaml"
    p.write_text(content)
    return p


def test_derivation_simple(tmp_path: Path):
    cfg = MappingConfig.load(_write(
        tmp_path,
        """
url_derivation:
  from: "https://dev.azure.com/{account}/{project}/_git/{repo}"
  to:   "https://github.com/{gh_org}/{repo}"
  vars:  { gh_org: my-gh-org }
""",
    ))
    out = cfg.derive_url("https://dev.azure.com/acme/proj/_git/foo")
    assert out == "https://github.com/my-gh-org/foo"


def test_derivation_returns_none_on_mismatch(tmp_path: Path):
    cfg = MappingConfig.load(_write(
        tmp_path,
        """
url_derivation:
  from: "https://dev.azure.com/{account}/_git/{repo}"
  to:   "https://github.com/x/{repo}"
""",
    ))
    assert cfg.derive_url("https://github.com/x/y") is None


def test_override_wins_over_derivation(tmp_path: Path):
    cfg = MappingConfig.load(_write(
        tmp_path,
        """
url_derivation:
  from: "https://dev.azure.com/{account}/{project}/_git/{repo}"
  to:   "https://github.com/x/{repo}"
overrides:
  - source_url:      "https://dev.azure.com/a/b/_git/oldname"
    destination_url: "https://github.com/x/newname"
""",
    ))
    res = cfg.resolve("https://dev.azure.com/a/b/_git/oldname")
    assert res["resolved_via"] == "override"
    assert res["destination_url"] == "https://github.com/x/newname"


def test_unmapped_when_no_match(tmp_path: Path):
    cfg = MappingConfig.load(_write(
        tmp_path,
        """
url_derivation:
  from: "https://dev.azure.com/{a}/{b}/_git/{c}"
  to:   "https://github.com/x/{c}"
""",
    ))
    res = cfg.resolve("https://gitlab.com/foo/bar")
    assert res["resolved_via"] == "unmapped"
    assert res["destination_url"] is None


def test_derivation_falls_back_when_var_missing(tmp_path: Path):
    cfg = MappingConfig.load(_write(
        tmp_path,
        """
url_derivation:
  from: "https://dev.azure.com/{a}/_git/{repo}"
  to:   "https://github.com/{gh_org}/{repo}"
""",
    ))
    # gh_org not in vars and not extractable from from-pattern → no match
    assert cfg.derive_url("https://dev.azure.com/x/_git/y") is None


@pytest.mark.parametrize(
    "src, expected",
    [
        ("https://dev.azure.com/acme/proj/_git/foo", "https://github.com/gh/foo"),
        ("https://dev.azure.com/A/B/_git/Bar", "https://github.com/gh/Bar"),
    ],
)
def test_derivation_preserves_repo_segment(tmp_path: Path, src: str, expected: str):
    cfg = MappingConfig.load(_write(
        tmp_path,
        """
url_derivation:
  from: "https://dev.azure.com/{account}/{project}/_git/{repo}"
  to:   "https://github.com/gh/{repo}"
""",
    ))
    assert cfg.derive_url(src) == expected
