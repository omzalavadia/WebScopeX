from pathlib import Path
import json

from webscopex import Scanner, Finding


def test_normalize_domain():
    assert Scanner.normalize_domain("https://Example.COM/path") == "example.com"


def test_scope_match(tmp_path):
    s = Scanner("api.example.com", tmp_path, lambda x: None, lambda x: None, lambda x: None, lambda x: None, {}, scope_root="example.com")
    assert s.in_scope_host("www.example.com")
    assert not s.in_scope_host("example.net")


def test_delta(tmp_path):
    old = {"findings": [{"module":"DNS","item":"A","details":"192.0.2.1","severity":"info"}]}
    p = tmp_path / "old.json"
    p.write_text(json.dumps(old), encoding="utf-8")
    current = [Finding("DNS","A","192.0.2.2","info")]
    d = Scanner.compare_reports(str(p), current)
    assert d["previous_available"] is True
    assert len(d["added"]) == 1
    assert len(d["removed"]) == 1
