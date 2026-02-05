"""Tests for hybrid query engine: RRF, co-occurrence, platform, CWE."""

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.query.engine import (
    HybridQueryEngine, EnrichedTechnique, PLATFORM_PATTERNS,
    CVE_PATTERN, CWE_PATTERN,
)
from src.query.semantic import SemanticResult


@dataclass
class FakeKeywordResult:
    attack_id: str
    name: str
    score: float
    tactics: list[str]
    platforms: list[str]


def _sem(*items):
    """Create list of SemanticResult."""
    return [
        SemanticResult(
            attack_id=i[0], name=i[1], similarity=i[2],
            tactics=i[3] if len(i) > 3 else [],
            platforms=i[4] if len(i) > 4 else [],
        )
        for i in items
    ]


def _kw(*items):
    """Create list of FakeKeywordResult."""
    return [
        FakeKeywordResult(
            attack_id=i[0], name=i[1], score=i[2],
            tactics=i[3] if len(i) > 3 else [],
            platforms=i[4] if len(i) > 4 else [],
        )
        for i in items
    ]


class TestRRFFusion:
    def test_combines_semantic_and_keyword(self):
        graph = MagicMock()
        semantic = MagicMock()
        engine = HybridQueryEngine(graph, semantic, enable_bm25=False)
        sem = _sem(
            ("T1110", "Brute Force", 0.9),
            ("T1078", "Valid Accounts", 0.8),
        )
        kw = _kw(
            ("T1078", "Valid Accounts", 5.0),
            ("T1059", "Command Interpreter", 3.0),
        )
        result = engine._rrf(sem, kw)
        ids = [r["attack_id"] for r in result]
        # T1078 appears in both, should rank highest
        assert ids[0] == "T1078"
        # All three should be present
        assert set(ids) == {"T1110", "T1078", "T1059"}

    def test_rrf_scores_are_positive(self):
        graph = MagicMock()
        semantic = MagicMock()
        engine = HybridQueryEngine(graph, semantic, enable_bm25=False)
        sem = _sem(("T1110", "Brute Force", 0.9))
        kw = _kw(("T1110", "Brute Force", 5.0))
        result = engine._rrf(sem, kw)
        assert all(r["rrf_score"] > 0 for r in result)


class TestPlatformDetection:
    def test_detects_windows(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        assert "Windows" in engine._detect_platforms("PowerShell attack on Windows server")
        assert "Windows" in engine._detect_platforms("registry modification found")
        assert "Windows" in engine._detect_platforms("mimikatz credential dump")

    def test_detects_linux(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        assert "Linux" in engine._detect_platforms("Ubuntu server compromise via /etc/passwd")
        assert "Linux" in engine._detect_platforms("cron job persistence")
        assert "Linux" in engine._detect_platforms("sudo privilege escalation")

    def test_detects_macos(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        assert "macOS" in engine._detect_platforms("macOS launchd persistence")

    def test_detects_cloud(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        assert "AWS" in engine._detect_platforms("AWS S3 bucket misconfiguration")
        assert "Azure AD" in engine._detect_platforms("Azure AD conditional access bypass")
        assert "GCP" in engine._detect_platforms("Google Cloud GCP IAM")

    def test_no_platform(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        assert engine._detect_platforms("generic security finding") == []

    def test_multiple_platforms(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        result = engine._detect_platforms("Windows and Linux servers with AWS accounts")
        assert "Windows" in result
        assert "Linux" in result
        assert "AWS" in result


class TestPlatformBoosting:
    def test_boosts_matching_platform(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [
            {"attack_id": "T1", "platforms": ["Windows"], "rrf_score": 1.0},
            {"attack_id": "T2", "platforms": ["Linux"], "rrf_score": 1.0},
        ]
        result = engine._boost_platforms(combined, ["Windows"])
        win = [r for r in result if r["attack_id"] == "T1"][0]
        lin = [r for r in result if r["attack_id"] == "T2"][0]
        assert win["rrf_score"] > lin["rrf_score"]

    def test_no_boost_without_match(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [
            {"attack_id": "T1", "platforms": ["macOS"], "rrf_score": 1.0},
        ]
        result = engine._boost_platforms(combined, ["Windows"])
        assert result[0]["rrf_score"] == 1.0


class TestCWEDetection:
    def test_cwe_pattern(self):
        assert CWE_PATTERN.findall("CWE-79 XSS vulnerability") == ["CWE-79"]
        assert CWE_PATTERN.findall("CWE-89 SQL injection and CWE-79") == ["CWE-89", "CWE-79"]
        assert CWE_PATTERN.findall("No weakness here") == []

    def test_cve_pattern(self):
        assert CVE_PATTERN.findall("CVE-2024-1234 exploit") == ["CVE-2024-1234"]
        assert CVE_PATTERN.findall("Multiple: CVE-2024-1234 CVE-2023-99999") == [
            "CVE-2024-1234", "CVE-2023-99999"
        ]

    def test_extract_cwe_techniques(self):
        graph = MagicMock()
        graph.get_techniques_for_cwe.return_value = [
            {"attack_id": "T1059.007", "name": "JavaScript"}
        ]
        engine = HybridQueryEngine(graph, MagicMock())
        techs = engine._extract_cwe_techniques("Found CWE-79 vulnerability")
        assert len(techs) == 1
        assert techs[0]["attack_id"] == "T1059.007"
        graph.get_techniques_for_cwe.assert_called_once_with("CWE-79")

    def test_no_cwe_returns_empty(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        assert engine._extract_cwe_techniques("No weakness") == []


class TestCWEInjection:
    def test_injects_new_technique(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [
            {"attack_id": "T1110", "rrf_score": 0.5, "platforms": [], "tactics": []},
        ]
        cwe_techs = [{"attack_id": "T1059.007", "name": "JavaScript"}]
        result = engine._inject_cwe_techniques(combined, cwe_techs)
        ids = {r["attack_id"] for r in result}
        assert "T1059.007" in ids
        new = [r for r in result if r["attack_id"] == "T1059.007"][0]
        assert new["cwe_boost"] is True

    def test_boosts_existing_technique(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [
            {"attack_id": "T1059.007", "rrf_score": 0.5, "platforms": [], "tactics": []},
        ]
        cwe_techs = [{"attack_id": "T1059.007", "name": "JavaScript"}]
        result = engine._inject_cwe_techniques(combined, cwe_techs)
        boosted = result[0]
        assert boosted["rrf_score"] > 0.5
        assert boosted["cwe_boost"] is True


class TestCooccurrenceBoosting:
    def test_boost_capped_at_max(self):
        graph = MagicMock()
        graph.get_cooccurring_techniques.return_value = [
            {"attack_id": "T1078", "name": "Valid Accounts",
             "campaign_count": 100, "group_count": 100,
             "latest_campaign": "2024-01-01T00:00:00Z"},
        ]
        engine = HybridQueryEngine(graph, MagicMock())
        combined = [
            {"attack_id": "T1110", "rrf_score": 1.0, "platforms": [], "tactics": []},
            {"attack_id": "T1078", "rrf_score": 0.5, "platforms": [], "tactics": []},
        ]
        result = engine._boost_cooccurrence(combined, top_k=5, max_boost=1.3)
        boosted = [r for r in result if r["attack_id"] == "T1078"][0]
        assert boosted.get("cooccurrence_boost", 1.0) <= 1.3

    def test_empty_combined(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        assert engine._boost_cooccurrence([], top_k=5) == []


class TestQueryIntegration:
    def test_semantic_only_mode(self):
        graph = MagicMock()
        graph.get_technique.return_value = {
            "name": "Brute Force", "description": "...", "tactics": [], "platforms": [],
            "data_sources": [],
        }
        graph.get_mitigations_with_inheritance.return_value = []
        graph.get_software_for_technique.return_value = []
        graph.get_groups_for_technique.return_value = []
        graph.get_detection_strategies.return_value = []
        graph.get_data_sources.return_value = []
        graph.get_campaigns_for_technique.return_value = []
        graph.get_d3fend_for_technique.return_value = []
        graph.get_techniques_for_cwe.return_value = []

        semantic = MagicMock()
        semantic.search.return_value = _sem(("T1110", "Brute Force", 0.9))

        engine = HybridQueryEngine(graph, semantic, enable_bm25=False)
        result = engine.query("brute force", top_k=5, enrich=True, use_bm25=False)
        assert len(result.techniques) >= 1
        assert result.techniques[0].attack_id == "T1110"
        assert "semantic" in result.metadata["mode"]
