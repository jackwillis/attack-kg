"""Tests for data ingestion."""

import json
from pathlib import Path

import pytest
from rdflib import Namespace

from src.ingest.download import load_stix_bundle, get_objects_by_type
from src.ingest.stix_to_rdf import StixToRdfConverter

FIXTURES_DIR = Path(__file__).parent / "fixtures"
ATTACK = Namespace("https://attack.mitre.org/")


@pytest.fixture
def sample_bundle():
    """Load the sample STIX bundle."""
    return load_stix_bundle(FIXTURES_DIR / "sample_stix.json")


class TestStixLoader:
    def test_load_bundle(self, sample_bundle):
        """Test loading a STIX bundle."""
        assert sample_bundle["type"] == "bundle"
        assert "objects" in sample_bundle
        assert len(sample_bundle["objects"]) > 0

    def test_get_objects_by_type(self, sample_bundle):
        """Test grouping objects by type."""
        by_type = get_objects_by_type(sample_bundle)

        assert "attack-pattern" in by_type
        assert "intrusion-set" in by_type
        assert "relationship" in by_type
        assert len(by_type["attack-pattern"]) == 2
        assert len(by_type["intrusion-set"]) == 1


class TestStixToRdf:
    def test_convert_technique(self, sample_bundle):
        """Test converting a technique to RDF."""
        converter = StixToRdfConverter()
        graph = converter.convert(sample_bundle)

        # Check technique exists
        technique_uri = ATTACK["technique/T1110"]
        triples = list(graph.triples((technique_uri, None, None)))
        assert len(triples) > 0

        # Check label
        from rdflib.namespace import RDFS

        labels = list(graph.triples((technique_uri, RDFS.label, None)))
        assert len(labels) == 1
        assert str(labels[0][2]) == "Brute Force"

    def test_convert_group(self, sample_bundle):
        """Test converting a group to RDF."""
        converter = StixToRdfConverter()
        graph = converter.convert(sample_bundle)

        group_uri = ATTACK["group/G0016"]
        triples = list(graph.triples((group_uri, None, None)))
        assert len(triples) > 0

    def test_convert_relationship(self, sample_bundle):
        """Test converting relationships."""
        converter = StixToRdfConverter()
        graph = converter.convert(sample_bundle)

        # Check subtechnique relationship
        subtechnique_uri = ATTACK["technique/T1110.003"]
        parent_uri = ATTACK["technique/T1110"]

        subtechnique_triples = list(
            graph.triples((subtechnique_uri, ATTACK.subtechniqueOf, parent_uri))
        )
        assert len(subtechnique_triples) == 1

        # Check group uses technique
        group_uri = ATTACK["group/G0016"]
        uses_triples = list(graph.triples((group_uri, ATTACK.uses, subtechnique_uri)))
        assert len(uses_triples) == 1

        # Check mitigation mitigates technique
        mitigation_uri = ATTACK["mitigation/M1032"]
        mitigates_triples = list(
            graph.triples((mitigation_uri, ATTACK.mitigates, subtechnique_uri))
        )
        assert len(mitigates_triples) == 1

    def test_stix_to_uri_mapping(self, sample_bundle):
        """Test that STIX IDs are mapped to URIs."""
        converter = StixToRdfConverter()
        converter.convert(sample_bundle)

        # Check that mappings exist
        assert "attack-pattern--test-technique-001" in converter.stix_to_uri
        assert "intrusion-set--test-group-001" in converter.stix_to_uri

        # Check URI format
        technique_uri = converter.stix_to_uri["attack-pattern--test-technique-001"]
        assert str(technique_uri) == "https://attack.mitre.org/technique/T1110"

    def test_triple_count(self, sample_bundle):
        """Test that conversion produces expected number of triples."""
        converter = StixToRdfConverter()
        graph = converter.convert(sample_bundle)

        # Should have at least some triples
        assert len(graph) > 20
