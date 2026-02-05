"""Tests for context encoding (XML, TOON, JSON)."""

import json
from dataclasses import dataclass, field
from typing import Any

from src.reasoning.encoder import encode_xml, encode_json, encode_context, _xml_attr


@dataclass
class FakeTechnique:
    attack_id: str
    name: str
    description: str
    similarity: float
    tactics: list[str]
    platforms: list[str]
    software: list[dict[str, str]] = field(default_factory=list)
    detection_strategies: list[dict[str, str]] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)


def _make_techniques():
    return [
        FakeTechnique(
            attack_id="T1110.003", name="Password Spraying",
            description="Adversaries may use a single password against many accounts.",
            similarity=0.87, tactics=["Credential Access"],
            platforms=["Windows", "Linux", "Azure AD"],
            software=[{"attack_id": "S0154", "name": "Cobalt Strike", "type": "Tool"}],
            detection_strategies=[{"name": "Auth Failure Monitoring", "attack_id": "DS001"}],
            data_sources=["Logon Session", "User Account"],
        ),
        FakeTechnique(
            attack_id="T1078", name="Valid Accounts",
            description="Adversaries may obtain credentials.",
            similarity=0.72, tactics=["Defense Evasion", "Persistence"],
            platforms=["Windows", "Linux"],
            software=[], detection_strategies=[], data_sources=["Logon Session"],
        ),
    ]


def _make_mitigations():
    return [
        {"attack_id": "M1032", "name": "Multi-factor Authentication",
         "addresses": ["T1110.003", "T1078"], "inherited": False},
        {"attack_id": "M1036", "name": "Account Use Policies",
         "addresses": ["T1110.003"], "inherited": True},
    ]


def _make_d3fend():
    return [
        {"d3fend_id": "D3-MFA", "name": "Multi-factor Authentication",
         "via_mitigation": "M1032", "addresses": ["T1110.003"],
         "definition": "Require multiple authentication factors."},
    ]


class TestXmlAttr:
    def test_simple(self):
        assert _xml_attr("id", "T1110") == 'id="T1110"'

    def test_escapes_quotes(self):
        assert '&quot;' in _xml_attr("desc", 'say "hello"')

    def test_escapes_ampersand(self):
        assert '&amp;' in _xml_attr("n", "AT&T")

    def test_escapes_lt(self):
        assert '&lt;' in _xml_attr("n", "a<b")


class TestEncodeXml:
    def test_contains_techniques(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), _make_d3fend())
        assert "<ctx>" in xml
        assert "</ctx>" in xml
        assert 'id="T1110.003"' in xml
        assert 'id="T1078"' in xml

    def test_contains_mitigations(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), _make_d3fend())
        assert "<mitigations>" in xml
        assert 'id="M1032"' in xml
        assert 'inh="true"' in xml  # M1036 is inherited

    def test_contains_d3fend(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), _make_d3fend())
        assert "<d3fend>" in xml
        assert 'id="D3-MFA"' in xml

    def test_contains_software(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), _make_d3fend())
        assert "<software>" in xml
        assert 'id="S0154"' in xml

    def test_contains_detections(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), _make_d3fend())
        assert "<detections>" in xml
        assert "Auth Failure Monitoring" in xml

    def test_contains_datasources(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), _make_d3fend())
        assert "<datasources>" in xml
        assert "Logon Session" in xml

    def test_no_d3fend_section_when_empty(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), [])
        assert "<d3fend>" not in xml

    def test_similarity_format(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), [])
        assert 'sim="0.87"' in xml
        assert 'sim="0.72"' in xml

    def test_tactics_semicolon_joined(self):
        xml = encode_xml(_make_techniques(), _make_mitigations(), [])
        assert 'tac="Defense Evasion;Persistence"' in xml

    def test_description_truncated(self):
        t = FakeTechnique(
            attack_id="T9999", name="Long", description="A" * 500,
            similarity=0.5, tactics=[], platforms=[],
        )
        xml = encode_xml([t], [], [])
        # Description should be truncated to 200 chars
        assert "A" * 200 in xml
        assert "A" * 201 not in xml


class TestEncodeJson:
    def test_valid_json(self):
        result = encode_json(_make_techniques(), _make_mitigations(), _make_d3fend())
        data = json.loads(result)
        assert "techniques" in data
        assert "mitigations" in data
        assert "d3fend" in data

    def test_technique_fields(self):
        data = json.loads(encode_json(_make_techniques(), _make_mitigations(), _make_d3fend()))
        t = data["techniques"][0]
        assert t["attack_id"] == "T1110.003"
        assert t["similarity"] == 0.87
        assert "Windows" in t["platforms"]

    def test_software_included(self):
        data = json.loads(encode_json(_make_techniques(), _make_mitigations(), []))
        assert "software" in data
        assert len(data["software"]) >= 1
        assert data["software"][0]["id"] == "S0154"

    def test_detections_included(self):
        data = json.loads(encode_json(_make_techniques(), _make_mitigations(), []))
        assert "detections" in data
        assert len(data["detections"]) >= 1

    def test_data_sources_included(self):
        data = json.loads(encode_json(_make_techniques(), _make_mitigations(), []))
        assert "data_sources" in data
        assert len(data["data_sources"]) >= 1


class TestEncodeContext:
    def test_xml_default(self):
        result = encode_context(_make_techniques(), _make_mitigations(), [], fmt="xml")
        assert "<ctx>" in result

    def test_json_format(self):
        result = encode_context(_make_techniques(), _make_mitigations(), [], fmt="json")
        data = json.loads(result)
        assert "techniques" in data

    def test_unknown_format_falls_back_to_xml(self):
        result = encode_context(_make_techniques(), _make_mitigations(), [], fmt="unknown")
        assert "<ctx>" in result
