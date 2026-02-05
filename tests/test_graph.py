"""Tests for RDF graph store (pyoxigraph)."""

import pytest

from src.store.graph import AttackGraph

A = "https://attack.mitre.org/"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
RDFS_LABEL = "http://www.w3.org/2000/01/rdf-schema#label"


def _make_nt(*lines):
    """Join N-Triple lines."""
    return "\n".join(lines) + "\n"


def _triple(s, p, o):
    return f"<{s}> <{p}> <{o}> ."


def _lit(s, p, v):
    v = v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'<{s}> <{p}> "{v}" .'


def _graph_with_technique(tmp_path):
    """Create a graph with a single technique + mitigation + group."""
    nt = _make_nt(
        # Technique
        _triple(f"{A}technique/T1059", RDF_TYPE, f"{A}Technique"),
        _lit(f"{A}technique/T1059", f"{A}attackId", "T1059"),
        _lit(f"{A}technique/T1059", RDFS_LABEL, "Command and Scripting Interpreter"),
        _lit(f"{A}technique/T1059", f"{A}description", "Adversaries may use interpreters."),
        _triple(f"{A}technique/T1059", f"{A}tactic", f"{A}tactic/execution"),
        _lit(f"{A}technique/T1059", f"{A}platform", "Windows"),
        _lit(f"{A}technique/T1059", f"{A}platform", "Linux"),
        _lit(f"{A}technique/T1059", f"{A}dataSource", "Process: Process Creation"),
        # Subtechnique
        _triple(f"{A}technique/T1059.001", RDF_TYPE, f"{A}Technique"),
        _lit(f"{A}technique/T1059.001", f"{A}attackId", "T1059.001"),
        _lit(f"{A}technique/T1059.001", RDFS_LABEL, "PowerShell"),
        _triple(f"{A}technique/T1059.001", f"{A}subtechniqueOf", f"{A}technique/T1059"),
        _triple(f"{A}technique/T1059.001", f"{A}tactic", f"{A}tactic/execution"),
        _lit(f"{A}technique/T1059.001", f"{A}platform", "Windows"),
        # Tactic
        _triple(f"{A}tactic/execution", RDF_TYPE, f"{A}Tactic"),
        _lit(f"{A}tactic/execution", RDFS_LABEL, "Execution"),
        # Mitigation
        _triple(f"{A}mitigation/M1042", RDF_TYPE, f"{A}Mitigation"),
        _lit(f"{A}mitigation/M1042", f"{A}attackId", "M1042"),
        _lit(f"{A}mitigation/M1042", RDFS_LABEL, "Disable or Remove Feature or Program"),
        _triple(f"{A}mitigation/M1042", f"{A}mitigates", f"{A}technique/T1059"),
        # Another mitigation for subtechnique only
        _triple(f"{A}mitigation/M1045", RDF_TYPE, f"{A}Mitigation"),
        _lit(f"{A}mitigation/M1045", f"{A}attackId", "M1045"),
        _lit(f"{A}mitigation/M1045", RDFS_LABEL, "Code Signing"),
        _triple(f"{A}mitigation/M1045", f"{A}mitigates", f"{A}technique/T1059.001"),
        # Group
        _triple(f"{A}group/G0016", RDF_TYPE, f"{A}Group"),
        _lit(f"{A}group/G0016", f"{A}attackId", "G0016"),
        _lit(f"{A}group/G0016", RDFS_LABEL, "APT29"),
        _triple(f"{A}group/G0016", f"{A}uses", f"{A}technique/T1059"),
        # Software
        _triple(f"{A}software/S0154", RDF_TYPE, f"{A}Tool"),
        _lit(f"{A}software/S0154", f"{A}attackId", "S0154"),
        _lit(f"{A}software/S0154", RDFS_LABEL, "Cobalt Strike"),
        _triple(f"{A}software/S0154", f"{A}uses", f"{A}technique/T1059"),
        # Detection strategy
        _triple(f"{A}detection/DS0001", RDF_TYPE, f"{A}DetectionStrategy"),
        _lit(f"{A}detection/DS0001", f"{A}attackId", "DS0001"),
        _lit(f"{A}detection/DS0001", RDFS_LABEL, "Process Monitoring"),
        _triple(f"{A}detection/DS0001", f"{A}detects", f"{A}technique/T1059"),
        # Campaign
        _triple(f"{A}campaign/C0015", RDF_TYPE, f"{A}Campaign"),
        _lit(f"{A}campaign/C0015", f"{A}attackId", "C0015"),
        _lit(f"{A}campaign/C0015", RDFS_LABEL, "C0015"),
        _triple(f"{A}campaign/C0015", f"{A}uses", f"{A}technique/T1059"),
        _lit(f"{A}campaign/C0015", f"{A}firstSeen", "2022-01-01T00:00:00Z"),
        _lit(f"{A}campaign/C0015", f"{A}lastSeen", "2022-12-31T00:00:00Z"),
    )
    nt_file = tmp_path / "test.nt"
    nt_file.write_text(nt)
    graph = AttackGraph()
    graph.load_file(nt_file, fmt="nt")
    return graph


class TestAttackGraph:
    def test_load_and_len(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        assert len(graph) > 0

    def test_load_file_clear(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        initial = len(graph)
        nt_file = tmp_path / "test.nt"
        graph.load_file(nt_file, fmt="nt", clear=True)
        assert len(graph) == initial  # same data reloaded

    def test_load_file_additive(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        initial = len(graph)
        extra = _make_nt(
            _triple(f"{A}technique/T9999", RDF_TYPE, f"{A}Technique"),
            _lit(f"{A}technique/T9999", f"{A}attackId", "T9999"),
            _lit(f"{A}technique/T9999", RDFS_LABEL, "Test Technique"),
        )
        extra_file = tmp_path / "extra.nt"
        extra_file.write_text(extra)
        graph.load_file(extra_file, fmt="nt")
        assert len(graph) > initial

    def test_query_raw(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        rows = graph.query("SELECT ?name WHERE { ?t a attack:Technique ; rdfs:label ?name }")
        names = {r["name"] for r in rows}
        assert "Command and Scripting Interpreter" in names

    def test_get_technique(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        t = graph.get_technique("T1059")
        assert t is not None
        assert t["name"] == "Command and Scripting Interpreter"
        assert t["attack_id"] == "T1059"
        assert "Windows" in t["platforms"]
        assert "Linux" in t["platforms"]
        assert "Execution" in t["tactics"]

    def test_get_technique_not_found(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        assert graph.get_technique("T9999") is None

    def test_get_mitigations(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        mits = graph.get_mitigations_with_inheritance("T1059")
        assert len(mits) >= 1
        ids = {m["attack_id"] for m in mits}
        assert "M1042" in ids

    def test_get_mitigations_inherited(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        mits = graph.get_mitigations_with_inheritance("T1059.001")
        ids = {m["attack_id"] for m in mits}
        assert "M1045" in ids  # direct
        assert "M1042" in ids  # inherited from parent
        inherited = [m for m in mits if m["attack_id"] == "M1042"]
        assert inherited[0]["inherited"] is True

    def test_get_software(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        sw = graph.get_software_for_technique("T1059")
        assert len(sw) >= 1
        assert sw[0]["name"] == "Cobalt Strike"

    def test_get_groups(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        groups = graph.get_groups_for_technique("T1059")
        assert len(groups) >= 1
        assert groups[0]["name"] == "APT29"

    def test_get_detection_strategies(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        det = graph.get_detection_strategies("T1059")
        assert len(det) >= 1
        assert det[0]["name"] == "Process Monitoring"

    def test_get_data_sources(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        ds = graph.get_data_sources("T1059")
        assert "Process: Process Creation" in ds

    def test_get_campaigns(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        camps = graph.get_campaigns_for_technique("T1059")
        assert len(camps) >= 1
        assert camps[0]["attack_id"] == "C0015"

    def test_get_subtechniques(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        subs = graph.get_subtechniques("T1059")
        assert len(subs) == 1
        assert subs[0]["attack_id"] == "T1059.001"

    def test_get_stats(self, tmp_path):
        graph = _graph_with_technique(tmp_path)
        stats = graph.get_stats()
        assert stats["techniques"] >= 2
        assert stats["groups"] >= 1
        assert stats["mitigations"] >= 1


class TestCooccurrence:
    def test_cooccurrence_via_campaign(self, tmp_path):
        """Two techniques used by the same campaign should co-occur."""
        nt = _make_nt(
            _triple(f"{A}technique/T1059", RDF_TYPE, f"{A}Technique"),
            _lit(f"{A}technique/T1059", f"{A}attackId", "T1059"),
            _lit(f"{A}technique/T1059", RDFS_LABEL, "T1059"),
            _triple(f"{A}technique/T1078", RDF_TYPE, f"{A}Technique"),
            _lit(f"{A}technique/T1078", f"{A}attackId", "T1078"),
            _lit(f"{A}technique/T1078", RDFS_LABEL, "Valid Accounts"),
            _triple(f"{A}campaign/C0015", RDF_TYPE, f"{A}Campaign"),
            _lit(f"{A}campaign/C0015", f"{A}attackId", "C0015"),
            _lit(f"{A}campaign/C0015", RDFS_LABEL, "C0015"),
            _triple(f"{A}campaign/C0015", f"{A}uses", f"{A}technique/T1059"),
            _triple(f"{A}campaign/C0015", f"{A}uses", f"{A}technique/T1078"),
            _lit(f"{A}campaign/C0015", f"{A}lastSeen", "2023-06-01T00:00:00Z"),
        )
        nt_file = tmp_path / "cooc.nt"
        nt_file.write_text(nt)
        graph = AttackGraph()
        graph.load_file(nt_file, fmt="nt")
        cooc = graph.get_cooccurring_techniques("T1059", min_count=1)
        aids = {c["attack_id"] for c in cooc}
        assert "T1078" in aids
        match = [c for c in cooc if c["attack_id"] == "T1078"][0]
        assert match["campaign_count"] >= 1


class TestCWEMapping:
    def test_cwe_to_technique_via_capec(self, tmp_path):
        """CWE -> CAPEC -> ATT&CK chain should resolve."""
        nt = _make_nt(
            _triple(f"{A}cwe/79", RDF_TYPE, f"{A}CWE"),
            _lit(f"{A}cwe/79", f"{A}cweId", "CWE-79"),
            _triple(f"{A}cwe/79", f"{A}mapsToCAPEC", f"{A}capec/86"),
            _triple(f"{A}capec/86", RDF_TYPE, f"{A}CAPEC"),
            _lit(f"{A}capec/86", f"{A}capecId", "CAPEC-86"),
            _triple(f"{A}capec/86", f"{A}mapsToTechnique", f"{A}technique/T1059.007"),
            _triple(f"{A}technique/T1059.007", RDF_TYPE, f"{A}Technique"),
            _lit(f"{A}technique/T1059.007", f"{A}attackId", "T1059.007"),
            _lit(f"{A}technique/T1059.007", RDFS_LABEL, "JavaScript"),
        )
        nt_file = tmp_path / "cwe.nt"
        nt_file.write_text(nt)
        graph = AttackGraph()
        graph.load_file(nt_file, fmt="nt")
        techs = graph.get_techniques_for_cwe("CWE-79")
        assert len(techs) >= 1
        assert techs[0]["attack_id"] == "T1059.007"
        assert techs[0]["via_capec"] == "CAPEC-86"

    def test_capec_to_technique(self, tmp_path):
        nt = _make_nt(
            _triple(f"{A}capec/86", RDF_TYPE, f"{A}CAPEC"),
            _triple(f"{A}capec/86", f"{A}mapsToTechnique", f"{A}technique/T1059.007"),
            _triple(f"{A}technique/T1059.007", RDF_TYPE, f"{A}Technique"),
            _lit(f"{A}technique/T1059.007", f"{A}attackId", "T1059.007"),
            _lit(f"{A}technique/T1059.007", RDFS_LABEL, "JavaScript"),
        )
        nt_file = tmp_path / "capec.nt"
        nt_file.write_text(nt)
        graph = AttackGraph()
        graph.load_file(nt_file, fmt="nt")
        techs = graph.get_techniques_for_capec("CAPEC-86")
        assert len(techs) >= 1
        assert techs[0]["attack_id"] == "T1059.007"
