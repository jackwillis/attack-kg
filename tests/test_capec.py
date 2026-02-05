"""Tests for CAPEC XML parsing and N-Triples generation."""

from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree

from src.ingest.capec import parse_capec, capec_to_ntriples, _nt_escape


def _write_capec_xml(tmp_path: Path, attack_patterns: list[dict]) -> Path:
    """Create a minimal CAPEC XML file for testing."""
    root = Element("{http://capec.mitre.org/capec-3}Attack_Pattern_Catalog")
    root.set("Name", "Test")
    root.set("Version", "3.9")
    aps = SubElement(root, "{http://capec.mitre.org/capec-3}Attack_Patterns")

    for ap_data in attack_patterns:
        ap = SubElement(aps, "{http://capec.mitre.org/capec-3}Attack_Pattern")
        ap.set("ID", ap_data["id"])
        ap.set("Name", ap_data["name"])
        ap.set("Status", ap_data.get("status", "Draft"))

        if "description" in ap_data:
            desc = SubElement(ap, "{http://capec.mitre.org/capec-3}Description")
            desc.text = ap_data["description"]

        if "attack_ids" in ap_data:
            tms = SubElement(ap, "{http://capec.mitre.org/capec-3}Taxonomy_Mappings")
            for tid in ap_data["attack_ids"]:
                tm = SubElement(tms, "{http://capec.mitre.org/capec-3}Taxonomy_Mapping")
                tm.set("Taxonomy_Name", "ATTACK")
                entry = SubElement(tm, "{http://capec.mitre.org/capec-3}Entry_ID")
                entry.text = tid

        if "cwe_ids" in ap_data:
            rws = SubElement(ap, "{http://capec.mitre.org/capec-3}Related_Weaknesses")
            for cwe in ap_data["cwe_ids"]:
                rw = SubElement(rws, "{http://capec.mitre.org/capec-3}Related_Weakness")
                rw.set("CWE_ID", cwe)

    xml_path = tmp_path / "capec_test.xml"
    tree = ElementTree(root)
    tree.write(str(xml_path), xml_declaration=True, encoding="unicode")
    return xml_path


class TestNtEscape:
    def test_basic(self):
        assert _nt_escape("hello") == "hello"

    def test_special_chars(self):
        assert '\\"' in _nt_escape('say "hi"')
        assert "\\n" in _nt_escape("line\n")


class TestParseCapec:
    def test_parses_attack_mapping(self, tmp_path):
        xml = _write_capec_xml(tmp_path, [
            {"id": "86", "name": "XSS via HTTP Headers",
             "description": "Cross-site scripting via headers.",
             "attack_ids": ["T1059.007"]},
        ])
        result = parse_capec(xml)
        assert "CAPEC-86" in result["capec_to_attack"]
        assert "T1059.007" in result["capec_to_attack"]["CAPEC-86"]
        assert "CAPEC-86" in result["capec_info"]
        assert result["capec_info"]["CAPEC-86"]["name"] == "XSS via HTTP Headers"

    def test_parses_cwe_mapping(self, tmp_path):
        xml = _write_capec_xml(tmp_path, [
            {"id": "86", "name": "XSS", "cwe_ids": ["79", "80"],
             "attack_ids": ["T1059.007"]},
        ])
        result = parse_capec(xml)
        assert "CWE-79" in result["cwe_to_capec"]
        assert "CAPEC-86" in result["cwe_to_capec"]["CWE-79"]
        assert "CWE-80" in result["cwe_to_capec"]

    def test_skips_deprecated(self, tmp_path):
        xml = _write_capec_xml(tmp_path, [
            {"id": "99", "name": "Old", "status": "Deprecated",
             "attack_ids": ["T1059"]},
        ])
        result = parse_capec(xml)
        assert "CAPEC-99" not in result["capec_info"]
        assert "CAPEC-99" not in result["capec_to_attack"]

    def test_multiple_patterns(self, tmp_path):
        xml = _write_capec_xml(tmp_path, [
            {"id": "86", "name": "XSS", "attack_ids": ["T1059.007"]},
            {"id": "112", "name": "Brute Force", "attack_ids": ["T1110"],
             "cwe_ids": ["307"]},
        ])
        result = parse_capec(xml)
        assert len(result["capec_info"]) == 2
        assert "CAPEC-86" in result["capec_to_attack"]
        assert "CAPEC-112" in result["capec_to_attack"]


class TestCapecToNTriples:
    def test_generates_triples(self, tmp_path):
        xml = _write_capec_xml(tmp_path, [
            {"id": "86", "name": "XSS via HTTP Headers",
             "description": "Cross-site scripting.",
             "attack_ids": ["T1059.007"],
             "cwe_ids": ["79"]},
        ])
        mappings = parse_capec(xml)
        nt = capec_to_ntriples(mappings)
        assert "capec/86" in nt
        assert "mapsToTechnique" in nt
        assert "technique/T1059.007" in nt
        assert "mapsToCAPEC" in nt
        assert "cwe/79" in nt
        assert "XSS via HTTP Headers" in nt

    def test_capec_attack_bidirectional(self, tmp_path):
        xml = _write_capec_xml(tmp_path, [
            {"id": "86", "name": "XSS", "attack_ids": ["T1059.007"]},
        ])
        mappings = parse_capec(xml)
        nt = capec_to_ntriples(mappings)
        assert "mapsToTechnique" in nt
        assert "mappedFromCAPEC" in nt

    def test_empty_mappings(self):
        mappings = {"capec_to_attack": {}, "cwe_to_capec": {}, "capec_info": {}}
        nt = capec_to_ntriples(mappings)
        assert nt == ""
