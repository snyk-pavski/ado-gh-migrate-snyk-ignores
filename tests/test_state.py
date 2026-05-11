from pathlib import Path

from ado_gh_migration.state import StateStore


def test_write_and_read_roundtrip(tmp_path: Path):
    s = StateStore(tmp_path, "g1", "o1")
    s.write("foo.json", {"hello": "world"})
    assert s.read("foo.json") == {"hello": "world"}
    assert s.exists("foo.json")
    assert (tmp_path / "g1" / "o1" / "foo.json").exists()


def test_read_missing_returns_none(tmp_path: Path):
    s = StateStore(tmp_path, "g1", "o1")
    assert s.read("missing.json") is None
    assert not s.exists("missing.json")


def test_write_creates_subdirs(tmp_path: Path):
    s = StateStore(tmp_path, "g1", "o1")
    s.write("issues/proj1.json", {"k": 1})
    assert (tmp_path / "g1" / "o1" / "issues" / "proj1.json").exists()


def test_state_dir_isolated_per_org(tmp_path: Path):
    a = StateStore(tmp_path, "g1", "o1")
    b = StateStore(tmp_path, "g1", "o2")
    a.write("x.json", {"a": 1})
    b.write("x.json", {"b": 2})
    assert a.read("x.json") == {"a": 1}
    assert b.read("x.json") == {"b": 2}
