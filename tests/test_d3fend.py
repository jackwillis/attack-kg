"""Tests for D3FEND integration."""

import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.ingest.d3fend import download_d3fend, D3FEND_URL
from src.store.graph import AttackGraph


class TestD3FendDownload:
    """Tests for D3FEND download functionality."""

    def test_download_creates_file(self, tmp_path):
        """Test that download creates the TTL file."""
        # Mock the HTTP response
        mock_response = MagicMock()
        mock_response.text = """
        @prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

        d3f:D3-MFA a d3f:DefensiveTechnique ;
            d3f:d3fend-id "D3-MFA" ;
            rdfs:label "Multi-factor Authentication" .
        """

        with patch("httpx.Client") as mock_client:
            mock_client_instance = MagicMock()
            mock_client_instance.get.return_value = mock_response
            mock_client.return_value.__enter__.return_value = mock_client_instance

            result = download_d3fend(tmp_path, force=True)

            assert result.exists()
            assert result.name == "d3fend.ttl"
            assert "D3-MFA" in result.read_text()

    def test_download_uses_cache(self, tmp_path):
        """Test that download uses cached file if exists."""
        # Create a cached file
        cached_file = tmp_path / "d3fend.ttl"
        cached_file.write_text("# cached content")

        with patch("httpx.Client") as mock_client:
            result = download_d3fend(tmp_path, force=False)

            # Should not make HTTP request
            mock_client.assert_not_called()
            assert result == cached_file

    def test_download_force_overwrites(self, tmp_path):
        """Test that force flag re-downloads even if cached."""
        # Create a cached file
        cached_file = tmp_path / "d3fend.ttl"
        cached_file.write_text("# old content")

        mock_response = MagicMock()
        mock_response.text = "# new content"

        with patch("httpx.Client") as mock_client:
            mock_client_instance = MagicMock()
            mock_client_instance.get.return_value = mock_response
            mock_client.return_value.__enter__.return_value = mock_client_instance

            result = download_d3fend(tmp_path, force=True)

            mock_client_instance.get.assert_called_once_with(D3FEND_URL)
            assert "new content" in result.read_text()


class TestD3FendGraphIntegration:
    """Tests for D3FEND graph integration."""

    @pytest.fixture
    def sample_d3fend_ttl(self, tmp_path):
        """Create a sample D3FEND TTL file."""
        ttl_content = """
        @prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

        d3f:Multi-factorAuthentication a d3f:DefensiveTechnique ;
            d3f:d3fend-id "D3-MFA" ;
            rdfs:label "Multi-factor Authentication" ;
            d3f:definition "Requiring proof of two or more mechanisms to authenticate." .

        d3f:AccountLocking a d3f:DefensiveTechnique ;
            d3f:d3fend-id "D3-AL" ;
            rdfs:label "Account Locking" ;
            d3f:definition "The process of disabling a user account after too many failed login attempts." .

        d3f:M1032 d3f:related d3f:Multi-factorAuthentication .
        d3f:M1032 d3f:related d3f:AccountLocking .
        """
        ttl_file = tmp_path / "d3fend.ttl"
        ttl_file.write_text(ttl_content)
        return ttl_file

    @pytest.fixture
    def sample_attack_nt(self, tmp_path):
        """Create a sample ATT&CK N-Triples file."""
        nt_content = """
        <https://attack.mitre.org/technique/T1110> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://attack.mitre.org/Technique> .
        <https://attack.mitre.org/technique/T1110> <http://www.w3.org/2000/01/rdf-schema#label> "Brute Force" .
        <https://attack.mitre.org/technique/T1110> <https://attack.mitre.org/attackId> "T1110" .
        <https://attack.mitre.org/technique/T1110.003> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://attack.mitre.org/Technique> .
        <https://attack.mitre.org/technique/T1110.003> <http://www.w3.org/2000/01/rdf-schema#label> "Password Spraying" .
        <https://attack.mitre.org/technique/T1110.003> <https://attack.mitre.org/attackId> "T1110.003" .
        <https://attack.mitre.org/technique/T1110.003> <https://attack.mitre.org/subtechniqueOf> <https://attack.mitre.org/technique/T1110> .
        <https://attack.mitre.org/mitigation/M1032> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://attack.mitre.org/Mitigation> .
        <https://attack.mitre.org/mitigation/M1032> <http://www.w3.org/2000/01/rdf-schema#label> "Multi-factor Authentication" .
        <https://attack.mitre.org/mitigation/M1032> <https://attack.mitre.org/attackId> "M1032" .
        <https://attack.mitre.org/mitigation/M1032> <https://attack.mitre.org/mitigates> <https://attack.mitre.org/technique/T1110> .
        """
        nt_file = tmp_path / "attack.nt"
        nt_file.write_text(nt_content)
        return nt_file

    def test_load_d3fend(self, sample_d3fend_ttl, tmp_path):
        """Test loading D3FEND TTL into the graph."""
        graph = AttackGraph()  # In-memory store
        loaded = graph.load_d3fend(sample_d3fend_ttl)

        assert loaded > 0

        # Check D3FEND stats
        stats = graph.get_d3fend_stats()
        assert stats["d3fend_techniques"] >= 2

    def test_get_d3fend_technique(self, sample_d3fend_ttl, tmp_path):
        """Test getting a D3FEND technique by ID."""
        graph = AttackGraph()
        graph.load_d3fend(sample_d3fend_ttl)

        technique = graph.get_d3fend_technique("D3-MFA")

        assert technique is not None
        assert technique["d3fend_id"] == "D3-MFA"
        assert technique["name"] == "Multi-factor Authentication"
        assert "proof of two or more" in technique.get("definition", "")

    def test_get_d3fend_for_mitigation(self, sample_d3fend_ttl, tmp_path):
        """Test getting D3FEND techniques for a mitigation."""
        graph = AttackGraph()
        graph.load_d3fend(sample_d3fend_ttl)

        d3fend_techniques = graph.get_d3fend_for_mitigation("M1032")

        assert len(d3fend_techniques) == 2
        d3fend_ids = {t["d3fend_id"] for t in d3fend_techniques}
        assert "D3-MFA" in d3fend_ids
        assert "D3-AL" in d3fend_ids

    def test_get_d3fend_for_technique(self, sample_attack_nt, sample_d3fend_ttl, tmp_path):
        """Test getting D3FEND techniques for an ATT&CK technique."""
        graph = AttackGraph()
        graph.load_from_file(sample_attack_nt, format="nt", force=True)
        graph.load_d3fend(sample_d3fend_ttl)

        # T1110 is mitigated by M1032, which is related to D3-MFA and D3-AL
        d3fend_techniques = graph.get_d3fend_for_technique("T1110")

        assert len(d3fend_techniques) == 2
        d3fend_ids = {t["d3fend_id"] for t in d3fend_techniques}
        assert "D3-MFA" in d3fend_ids
        assert "D3-AL" in d3fend_ids

        # Check via_mitigation context
        for tech in d3fend_techniques:
            assert tech["via_mitigation"] == "M1032"
            assert tech["via_mitigation_name"] == "Multi-factor Authentication"

    def test_get_d3fend_for_subtechnique_with_inheritance(
        self, sample_attack_nt, sample_d3fend_ttl, tmp_path
    ):
        """Test that subtechniques inherit parent D3FEND mappings."""
        graph = AttackGraph()
        graph.load_from_file(sample_attack_nt, format="nt", force=True)
        graph.load_d3fend(sample_d3fend_ttl)

        # T1110.003 inherits mitigations from T1110
        d3fend_techniques = graph.get_d3fend_for_technique("T1110.003")

        assert len(d3fend_techniques) == 2
        # Check that inherited flag is set
        for tech in d3fend_techniques:
            assert tech["inherited"] is True

    def test_get_all_d3fend_techniques(self, sample_d3fend_ttl, tmp_path):
        """Test listing all D3FEND techniques."""
        graph = AttackGraph()
        graph.load_d3fend(sample_d3fend_ttl)

        techniques = graph.get_all_d3fend_techniques()

        assert len(techniques) >= 2
        names = {t["name"] for t in techniques}
        assert "Multi-factor Authentication" in names
        assert "Account Locking" in names


class TestD3FendQueryMethods:
    """Tests for D3FEND-related query methods."""

    @pytest.fixture
    def loaded_graph(self, tmp_path):
        """Create a graph with both ATT&CK and D3FEND data."""
        # Create ATT&CK data
        nt_content = """
        <https://attack.mitre.org/technique/T1110> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://attack.mitre.org/Technique> .
        <https://attack.mitre.org/technique/T1110> <http://www.w3.org/2000/01/rdf-schema#label> "Brute Force" .
        <https://attack.mitre.org/technique/T1110> <https://attack.mitre.org/attackId> "T1110" .
        <https://attack.mitre.org/mitigation/M1032> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://attack.mitre.org/Mitigation> .
        <https://attack.mitre.org/mitigation/M1032> <http://www.w3.org/2000/01/rdf-schema#label> "Multi-factor Authentication" .
        <https://attack.mitre.org/mitigation/M1032> <https://attack.mitre.org/attackId> "M1032" .
        <https://attack.mitre.org/mitigation/M1032> <https://attack.mitre.org/mitigates> <https://attack.mitre.org/technique/T1110> .
        """
        nt_file = tmp_path / "attack.nt"
        nt_file.write_text(nt_content)

        # Create D3FEND data
        ttl_content = """
        @prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

        d3f:Multi-factorAuthentication a d3f:DefensiveTechnique ;
            d3f:d3fend-id "D3-MFA" ;
            rdfs:label "Multi-factor Authentication" ;
            d3f:definition "Requiring two or more authentication factors." .

        d3f:M1032 d3f:related d3f:Multi-factorAuthentication .
        """
        ttl_file = tmp_path / "d3fend.ttl"
        ttl_file.write_text(ttl_content)

        # Load graph
        graph = AttackGraph()
        graph.load_from_file(nt_file, format="nt", force=True)
        graph.load_d3fend(ttl_file)

        return graph

    def test_d3fend_stats(self, loaded_graph):
        """Test D3FEND stats reporting."""
        stats = loaded_graph.get_d3fend_stats()

        assert "d3fend_techniques" in stats
        assert stats["d3fend_techniques"] >= 1

    def test_d3fend_not_found(self, loaded_graph):
        """Test querying non-existent D3FEND technique."""
        technique = loaded_graph.get_d3fend_technique("D3-NONEXISTENT")
        assert technique is None

    def test_empty_mitigation_d3fend(self, loaded_graph):
        """Test querying D3FEND for mitigation with no links."""
        # M9999 doesn't exist
        techniques = loaded_graph.get_d3fend_for_mitigation("M9999")
        assert techniques == []
