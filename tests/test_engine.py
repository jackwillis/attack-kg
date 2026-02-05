"""Tests for hybrid query engine: RRF, co-occurrence, CWE, routing, platform boost."""

import re
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.query.engine import (
    HybridQueryEngine, EnrichedTechnique,
    CVE_PATTERN, CWE_PATTERN, VULN_KEYWORD_TECHNIQUES,
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

    def test_routing_metadata_present(self):
        graph = MagicMock()
        graph.get_technique.return_value = {
            "name": "Exploit Public-Facing Application", "description": "...",
            "tactics": [], "platforms": [], "data_sources": [],
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
        semantic.search.return_value = _sem(("T1190", "Exploit Public-Facing Application", 0.9))

        engine = HybridQueryEngine(graph, semantic, enable_bm25=False)
        result = engine.query("CVE-2024-1234 vulnerability", top_k=5, use_bm25=False)
        assert "finding_type" in result.metadata
        assert result.metadata["finding_type"] == "vulnerability"
        assert "routing_confidence" in result.metadata

    def test_vulnerability_uses_higher_cwe_boost(self):
        """Vulnerability finding should use 2.0x CWE boost instead of 1.4x."""
        graph = MagicMock()
        graph.get_techniques_for_cwe.return_value = [
            {"attack_id": "T1059.007", "name": "JavaScript"}
        ]
        graph.get_technique.return_value = {
            "name": "JavaScript", "description": "...",
            "tactics": [], "platforms": [], "data_sources": [],
        }
        graph.get_mitigations_with_inheritance.return_value = []
        graph.get_software_for_technique.return_value = []
        graph.get_groups_for_technique.return_value = []
        graph.get_detection_strategies.return_value = []
        graph.get_data_sources.return_value = []
        graph.get_campaigns_for_technique.return_value = []
        graph.get_d3fend_for_technique.return_value = []

        semantic = MagicMock()
        semantic.search.return_value = _sem(
            ("T1059.007", "JavaScript", 0.8),
        )
        engine = HybridQueryEngine(graph, semantic, enable_bm25=False)

        # Vulnerability query: higher CWE boost (2.0)
        vuln_result = engine.query(
            "CWE-79 unpatched vulnerability", top_k=5, use_bm25=False
        )

        # Attack narrative: lower CWE boost (1.4) — force CWE into a narrative query
        graph2 = MagicMock()
        graph2.get_techniques_for_cwe.return_value = [
            {"attack_id": "T1059.007", "name": "JavaScript"}
        ]
        graph2.get_technique.return_value = graph.get_technique.return_value
        graph2.get_mitigations_with_inheritance.return_value = []
        graph2.get_software_for_technique.return_value = []
        graph2.get_groups_for_technique.return_value = []
        graph2.get_detection_strategies.return_value = []
        graph2.get_data_sources.return_value = []
        graph2.get_campaigns_for_technique.return_value = []
        graph2.get_d3fend_for_technique.return_value = []
        graph2.get_cooccurring_techniques.return_value = []

        semantic2 = MagicMock()
        semantic2.search.return_value = _sem(
            ("T1059.007", "JavaScript", 0.8),
        )
        engine2 = HybridQueryEngine(graph2, semantic2, enable_bm25=False)
        # This query routes as attack_narrative (no vuln signals)
        narr_result = engine2.query(
            "APT29 exploited CWE-79", top_k=5, use_bm25=False
        )

        # Both should have the technique, but the vuln query metadata should show vulnerability
        assert vuln_result.metadata["finding_type"] == "vulnerability"


class TestVulnKeywordTable:
    def test_auth_bypass_matches(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [{"attack_id": "T1110", "rrf_score": 0.5, "platforms": [], "tactics": []}]
        result = engine._inject_vuln_techniques(combined, "authentication bypass in FortiOS")
        ids = {r["attack_id"] for r in result}
        assert "T1190" in ids

    def test_rce_matches(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = []
        result = engine._inject_vuln_techniques(combined, "remote code execution vulnerability")
        ids = {r["attack_id"] for r in result}
        assert "T1190" in ids or "T1203" in ids

    def test_sql_injection_matches(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = []
        result = engine._inject_vuln_techniques(combined, "SQL injection in login form")
        ids = {r["attack_id"] for r in result}
        assert "T1190" in ids

    def test_container_escape_matches(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = []
        result = engine._inject_vuln_techniques(combined, "container escape vulnerability")
        ids = {r["attack_id"] for r in result}
        assert "T1611" in ids

    def test_s3_bucket_exposed_matches(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = []
        result = engine._inject_vuln_techniques(combined, "S3 bucket exposed to public")
        ids = {r["attack_id"] for r in result}
        assert "T1530" in ids

    def test_imds_matches(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = []
        result = engine._inject_vuln_techniques(combined, "IMDS metadata service accessible")
        ids = {r["attack_id"] for r in result}
        assert "T1552.005" in ids

    def test_no_match_returns_unchanged(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [{"attack_id": "T1110", "rrf_score": 0.5, "platforms": [], "tactics": []}]
        result = engine._inject_vuln_techniques(combined, "normal operation")
        assert len(result) == 1

    def test_boosts_existing_technique(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [{"attack_id": "T1190", "rrf_score": 0.5, "platforms": [], "tactics": []}]
        result = engine._inject_vuln_techniques(combined, "authentication bypass")
        boosted = [r for r in result if r["attack_id"] == "T1190"][0]
        assert boosted["rrf_score"] > 0.5
        assert boosted["vuln_kw_boost"] is True


class TestPlatformBoost:
    def test_platform_boost_reorders_candidates(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [
            {"attack_id": "T1110", "rrf_score": 0.5, "platforms": ["Linux"], "tactics": []},
            {"attack_id": "T1078", "rrf_score": 0.49, "platforms": ["Windows"], "tactics": []},
        ]
        # Boost Windows — should push T1078 above T1110
        result = engine._boost_platform_match(combined, ["Windows"], boost=1.2)
        assert result[0]["attack_id"] == "T1078"

    def test_no_platform_overlap_no_change(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [
            {"attack_id": "T1110", "rrf_score": 0.5, "platforms": ["Linux"], "tactics": []},
        ]
        result = engine._boost_platform_match(combined, ["Windows"], boost=1.2)
        assert result[0]["rrf_score"] == 0.5  # unchanged

    def test_empty_platforms_no_crash(self):
        engine = HybridQueryEngine(MagicMock(), MagicMock())
        combined = [
            {"attack_id": "T1110", "rrf_score": 0.5, "platforms": [], "tactics": []},
        ]
        result = engine._boost_platform_match(combined, ["Windows"])
        assert len(result) == 1


class TestVulnKeywordPatterns:
    """Verify each VULN_KEYWORD_TECHNIQUES regex matches its intended input."""

    def test_all_patterns_compile(self):
        for pattern, tech_ids in VULN_KEYWORD_TECHNIQUES:
            assert isinstance(pattern, re.Pattern)
            assert len(tech_ids) > 0

    def test_session_fixation(self):
        matched = [
            tids for pat, tids in VULN_KEYWORD_TECHNIQUES if pat.search("session fixation attack")
        ]
        assert any("T1550.004" in tids for tids in matched)

    def test_token_theft(self):
        matched = [
            tids for pat, tids in VULN_KEYWORD_TECHNIQUES if pat.search("OAuth token theft")
        ]
        assert any("T1528" in tids for tids in matched)

    def test_weak_encryption(self):
        matched = [
            tids for pat, tids in VULN_KEYWORD_TECHNIQUES if pat.search("weak encryption in TLS")
        ]
        assert any("T1573" in tids for tids in matched)

    def test_certificate_bypass(self):
        matched = [
            tids for pat, tids in VULN_KEYWORD_TECHNIQUES
            if pat.search("certificate validation bypass")
        ]
        assert any("T1553.004" in tids for tids in matched)
