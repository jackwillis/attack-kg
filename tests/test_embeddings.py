"""Tests for embedding model defaults."""

from src.ingest.embeddings import DEFAULT_MODEL, EmbeddingGenerator


class TestEmbeddingDefaults:
    def test_default_model_is_attack_bert(self):
        assert DEFAULT_MODEL == "basel/ATTACK-BERT"

    def test_generator_uses_default_model(self):
        gen = EmbeddingGenerator()
        assert gen.model_name == "basel/ATTACK-BERT"

    def test_nomic_revision_applied(self):
        gen = EmbeddingGenerator("nomic-ai/nomic-embed-text-v1.5")
        assert gen._revision is not None

    def test_attack_bert_no_revision(self):
        gen = EmbeddingGenerator()
        assert gen._revision is None
