"""Tests for STIX → N-Triples conversion."""

from src.ingest.stix_to_rdf import StixToNTriples, _nt_escape, _get_attack_id


def _minimal_bundle(*objects):
    return {"type": "bundle", "id": "bundle--1", "objects": list(objects)}


def _technique(aid="T1059", name="Command and Scripting Interpreter"):
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--aaa",
        "name": name,
        "description": "Adversaries may abuse interpreters.",
        "x_mitre_platforms": ["Windows", "Linux"],
        "x_mitre_data_sources": ["Process: Process Creation"],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        "x_mitre_domains": ["enterprise-attack"],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": aid,
             "url": f"https://attack.mitre.org/techniques/{aid}"}
        ],
    }


def _group(aid="G0016", name="APT29"):
    return {
        "type": "intrusion-set",
        "id": "intrusion-set--bbb",
        "name": name,
        "aliases": ["APT29", "Cozy Bear"],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": aid}
        ],
    }


def _mitigation(aid="M1032", name="Multi-factor Authentication"):
    return {
        "type": "course-of-action",
        "id": "course-of-action--ccc",
        "name": name,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": aid}
        ],
    }


def _relationship(src_ref, tgt_ref, rel_type="uses"):
    return {
        "type": "relationship",
        "id": "relationship--rrr",
        "source_ref": src_ref,
        "target_ref": tgt_ref,
        "relationship_type": rel_type,
    }


class TestNtEscape:
    def test_basic(self):
        assert _nt_escape('hello') == 'hello'

    def test_quotes(self):
        assert _nt_escape('say "hi"') == 'say \\"hi\\"'

    def test_newlines(self):
        assert _nt_escape("line1\nline2") == "line1\\nline2"

    def test_backslash(self):
        assert _nt_escape("a\\b") == "a\\\\b"

    def test_tabs(self):
        assert _nt_escape("a\tb") == "a\\tb"


class TestGetAttackId:
    def test_extracts_id(self):
        obj = {"external_references": [
            {"source_name": "mitre-attack", "external_id": "T1110.003"}
        ]}
        assert _get_attack_id(obj) == "T1110.003"

    def test_no_refs(self):
        assert _get_attack_id({}) is None
        assert _get_attack_id({"external_references": []}) is None

    def test_wrong_source(self):
        obj = {"external_references": [
            {"source_name": "cve", "external_id": "CVE-2024-1234"}
        ]}
        assert _get_attack_id(obj) is None


class TestStixToNTriples:
    def test_technique_produces_triples(self):
        conv = StixToNTriples()
        bundle = _minimal_bundle(_technique())
        nt = conv.convert(bundle)
        assert "technique/T1059" in nt
        assert "Technique" in nt
        assert "Command and Scripting Interpreter" in nt
        assert "attackId" in nt
        assert "Windows" in nt
        assert "execution" in nt

    def test_group_produces_triples(self):
        conv = StixToNTriples()
        bundle = _minimal_bundle(_group())
        nt = conv.convert(bundle)
        assert "group/G0016" in nt
        assert "APT29" in nt
        assert "Group" in nt
        assert "alias" in nt

    def test_mitigation_produces_triples(self):
        conv = StixToNTriples()
        bundle = _minimal_bundle(_mitigation())
        nt = conv.convert(bundle)
        assert "mitigation/M1032" in nt
        assert "Multi-factor Authentication" in nt
        assert "Mitigation" in nt

    def test_relationship_uses(self):
        g = _group()
        t = _technique()
        rel = _relationship(g["id"], t["id"], "uses")
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(g, t, rel))
        nt = "".join(conv._triples)
        assert "uses" in nt
        assert "usedBy" in nt  # inverse predicate

    def test_relationship_mitigates(self):
        m = _mitigation()
        t = _technique()
        rel = _relationship(m["id"], t["id"], "mitigates")
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(m, t, rel))
        nt = "".join(conv._triples)
        assert "mitigates" in nt
        assert "mitigatedBy" in nt

    def test_subtechnique_of(self):
        parent = _technique("T1059", "Command and Scripting Interpreter")
        parent["id"] = "attack-pattern--parent"
        child = _technique("T1059.001", "PowerShell")
        child["id"] = "attack-pattern--child"
        rel = _relationship(child["id"], parent["id"], "subtechnique-of")
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(parent, child, rel))
        nt = "".join(conv._triples)
        assert "subtechniqueOf" in nt

    def test_revoked_entity_skipped(self):
        t = _technique()
        t["revoked"] = True
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(t))
        nt = "".join(conv._triples)
        assert "T1059" not in nt

    def test_deprecated_entity_skipped(self):
        t = _technique()
        t["x_mitre_deprecated"] = True
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(t))
        nt = "".join(conv._triples)
        assert "T1059" not in nt

    def test_stix_to_uri_mapping(self):
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(_technique()))
        assert "attack-pattern--aaa" in conv.stix_to_uri
        assert "technique/T1059" in conv.stix_to_uri["attack-pattern--aaa"]

    def test_campaign_with_timestamps(self):
        c = {
            "type": "campaign",
            "id": "campaign--xxx",
            "name": "C0015",
            "first_seen": "2022-01-01T00:00:00Z",
            "last_seen": "2022-12-31T00:00:00Z",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "C0015"}
            ],
        }
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(c))
        nt = "".join(conv._triples)
        assert "firstSeen" in nt
        assert "lastSeen" in nt
        assert "Campaign" in nt

    def test_software_malware(self):
        s = {
            "type": "malware",
            "id": "malware--mmm",
            "name": "Mimikatz",
            "x_mitre_platforms": ["Windows"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0002"}
            ],
        }
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(s))
        nt = "".join(conv._triples)
        assert "Malware" in nt
        assert "Software" in nt
        assert "software/S0002" in nt

    def test_software_tool(self):
        s = {
            "type": "tool",
            "id": "tool--ttt",
            "name": "Cobalt Strike",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0154"}
            ],
        }
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(s))
        nt = "".join(conv._triples)
        assert "Tool" in nt
        assert "Software" in nt

    def test_tactic(self):
        t = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--ttt",
            "name": "Execution",
            "x_mitre_shortname": "execution",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0002"}
            ],
        }
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(t))
        nt = "".join(conv._triples)
        assert "tactic/execution" in nt
        assert "Tactic" in nt
        assert "Execution" in nt

    def test_save(self, tmp_path):
        conv = StixToNTriples()
        conv.convert(_minimal_bundle(_technique()))
        out = tmp_path / "test.nt"
        conv.save(out)
        assert out.exists()
        content = out.read_text()
        assert "T1059" in content
