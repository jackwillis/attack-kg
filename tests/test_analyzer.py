"""Tests for single-stage LLM analyzer with hallucination filtering."""

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

from src.reasoning.analyzer import AttackAnalyzer, AnalysisResult, TechniqueMatch, Remediation
from src.query.engine import EnrichedTechnique, QueryResult


def _mock_engine(techniques=None):
    """Create a mock HybridQueryEngine."""
    if techniques is None:
        techniques = [
            EnrichedTechnique(
                attack_id="T1110.003", name="Password Spraying",
                description="Adversaries may spray passwords.",
                similarity=0.87, tactics=["Credential Access"],
                platforms=["Windows", "Azure AD"],
                mitigations=[
                    {"attack_id": "M1032", "name": "Multi-factor Authentication",
                     "inherited": False},
                ],
                software=[], groups=[], detection_strategies=[],
                data_sources=["Logon Session"], campaigns=[],
                d3fend=[
                    {"d3fend_id": "D3-MFA", "name": "Multi-factor Authentication",
                     "definition": "Require multiple factors.",
                     "via_mitigation": "M1032"},
                ],
            ),
        ]
    engine = MagicMock()
    engine.query.return_value = QueryResult(
        query="test", techniques=techniques, metadata={"top_k": 5, "mode": "test"},
    )
    return engine


def _mock_llm(response: dict):
    """Create a mock LLM backend that returns a fixed response."""
    llm = MagicMock()
    llm.generate_json.return_value = response
    return llm


class TestAnalyzer:
    def test_valid_analysis(self):
        engine = _mock_engine()
        llm = _mock_llm({
            "techniques": [
                {"attack_id": "T1110.003", "name": "Password Spraying",
                 "confidence": "high", "evidence": "password spray detected",
                 "tactics": ["Credential Access"]},
            ],
            "finding_type": "attack_narrative",
            "kill_chain_analysis": "Attacker sprayed passwords.",
            "remediations": [
                {"mitigation_id": "M1032", "name": "MFA", "priority": "HIGH",
                 "confidence": "high", "addresses": ["T1110.003"],
                 "implementation": "Enable MFA."},
            ],
            "defend_recommendations": [
                {"d3fend_id": "D3-MFA", "name": "MFA", "priority": "HIGH",
                 "confidence": "medium", "addresses": ["T1110.003"],
                 "implementation": "Deploy TOTP.", "via_mitigations": ["M1032"]},
            ],
            "detection_recommendations": [
                {"data_source": "Logon Session", "rationale": "Detect failures",
                 "techniques_covered": ["T1110.003"]},
            ],
        })
        analyzer = AttackAnalyzer(engine, llm)
        result = analyzer.analyze("password spraying against Azure AD")
        assert len(result.techniques) == 1
        assert result.techniques[0].attack_id == "T1110.003"
        assert result.techniques[0].confidence == "high"
        assert len(result.remediations) == 1
        assert result.remediations[0].mitigation_id == "M1032"
        assert len(result.remediations[0].d3fend) == 1
        assert result.finding_type == "attack_narrative"
        assert result.kill_chain != ""

    def test_filters_hallucinated_technique(self):
        engine = _mock_engine()
        llm = _mock_llm({
            "techniques": [
                {"attack_id": "T1110.003", "name": "Password Spraying",
                 "confidence": "high", "evidence": "evidence"},
                {"attack_id": "T9999", "name": "Hallucinated",
                 "confidence": "high", "evidence": "fake"},
            ],
            "finding_type": "attack_narrative",
            "remediations": [],
            "detection_recommendations": [],
        })
        analyzer = AttackAnalyzer(engine, llm)
        result = analyzer.analyze("test")
        assert len(result.techniques) == 1
        assert result.techniques[0].attack_id == "T1110.003"
        assert "T9999" in result.filtered_ids["techniques"]

    def test_filters_hallucinated_mitigation(self):
        engine = _mock_engine()
        llm = _mock_llm({
            "techniques": [
                {"attack_id": "T1110.003", "name": "Password Spraying",
                 "confidence": "high", "evidence": "ev"},
            ],
            "finding_type": "attack_narrative",
            "remediations": [
                {"mitigation_id": "M9999", "name": "Fake", "priority": "HIGH",
                 "confidence": "high", "addresses": ["T1110.003"],
                 "implementation": "Fake."},
            ],
            "detection_recommendations": [],
        })
        analyzer = AttackAnalyzer(engine, llm)
        result = analyzer.analyze("test")
        assert len(result.remediations) == 0
        assert "M9999" in result.filtered_ids["mitigations"]

    def test_remediation_requires_identified_technique(self):
        """Remediation addresses must reference techniques the LLM identified."""
        engine = _mock_engine()
        llm = _mock_llm({
            "techniques": [],  # LLM didn't identify any techniques
            "finding_type": "vulnerability",
            "remediations": [
                {"mitigation_id": "M1032", "name": "MFA", "priority": "HIGH",
                 "confidence": "high", "addresses": ["T1110.003"],
                 "implementation": "Enable MFA."},
            ],
            "detection_recommendations": [],
        })
        analyzer = AttackAnalyzer(engine, llm)
        result = analyzer.analyze("test")
        assert len(result.remediations) == 0

    def test_llm_error_returns_error_result(self):
        engine = _mock_engine()
        llm = _mock_llm({"error": "JSON parse failure", "raw": "garbage"})
        analyzer = AttackAnalyzer(engine, llm)
        result = analyzer.analyze("test")
        assert result.finding_type == "error"
        assert len(result.techniques) == 0

    def test_to_dict(self):
        result = AnalysisResult(
            finding="test finding",
            finding_type="attack_narrative",
            techniques=[
                TechniqueMatch("T1110.003", "Password Spraying", "high", "evidence",
                               ["Credential Access"]),
            ],
            remediations=[
                Remediation("M1032", "MFA", "HIGH", "high", ["T1110.003"], "Enable MFA.",
                            [{"d3fend_id": "D3-MFA", "name": "MFA", "implementation": "TOTP"}]),
            ],
            detections=[],
            kill_chain="Password spraying led to access.",
        )
        d = result.to_dict()
        assert d["finding"] == "test finding"
        assert d["finding_type"] == "attack_narrative"
        assert len(d["techniques"]) == 1
        assert d["techniques"][0]["attack_id"] == "T1110.003"
        assert len(d["remediations"]) == 1
        assert d["remediations"][0]["d3fend"][0]["d3fend_id"] == "D3-MFA"

    def test_context_format_passed_through(self):
        engine = _mock_engine()
        llm = _mock_llm({
            "techniques": [], "finding_type": "vulnerability",
            "remediations": [], "detection_recommendations": [],
        })
        analyzer = AttackAnalyzer(engine, llm, context_format="json")
        analyzer.analyze("test")
        # Check that generate_json was called with valid content
        prompt = llm.generate_json.call_args[0][0]
        assert "test" in prompt  # finding text is in prompt
