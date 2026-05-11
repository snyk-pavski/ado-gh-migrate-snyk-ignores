from ado_gh_migration.signature import issue_signature


def _make_issue(title="X", file="a.py", sl=1, sc=1, el=1, ec=2):
    return {
        "attributes": {
            "title": title,
            "coordinates": [
                {
                    "representations": [
                        {
                            "sourceLocation": {
                                "file": file,
                                "region": {
                                    "start": {"line": sl, "column": sc},
                                    "end": {"line": el, "column": ec},
                                },
                            }
                        }
                    ]
                }
            ],
        }
    }


def test_signature_extracts_position():
    issue = _make_issue("NoSQL Injection", "routes/index.js", 39, 10, 39, 14)
    assert issue_signature(issue) == ("NoSQL Injection", "routes/index.js", 39, 10, 39, 14)


def test_signature_disambiguates_same_line_by_column():
    a = _make_issue(file="x.py", sl=10, sc=4, el=10, ec=8)
    b = _make_issue(file="x.py", sl=10, sc=20, el=10, ec=24)
    assert issue_signature(a) != issue_signature(b)


def test_signature_handles_missing_coordinates():
    assert issue_signature({"attributes": {"title": "T"}}) == ("T", None, None, None, None, None)


def test_signature_handles_empty_input():
    assert issue_signature({}) == (None, None, None, None, None, None)
