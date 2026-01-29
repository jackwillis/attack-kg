"""Hybrid query engine combining SPARQL and semantic search."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console

from src.store.graph import AttackGraph
from src.query.semantic import SemanticSearchEngine, SemanticResult

console = Console()


@dataclass
class EnrichedTechnique:
    """A technique with both semantic match info and graph-derived context."""

    attack_id: str
    name: str
    description: str
    similarity: float
    tactics: list[str]
    groups: list[dict[str, str]]
    mitigations: list[dict[str, str]]
    software: list[dict[str, str]]
    subtechniques: list[dict[str, str]]
    parent_technique: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "description": self.description,
            "similarity": self.similarity,
            "tactics": self.tactics,
            "groups": self.groups,
            "mitigations": self.mitigations,
            "software": self.software,
            "subtechniques": self.subtechniques,
            "parent_technique": self.parent_technique,
        }


@dataclass
class HybridQueryResult:
    """Result of a hybrid query combining semantic and graph results."""

    query: str
    techniques: list[EnrichedTechnique]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "techniques": [t.to_dict() for t in self.techniques],
            "metadata": self.metadata,
        }


class HybridQueryEngine:
    """
    Combines semantic search with SPARQL graph queries.

    This is the core neuro-symbolic query engine that:
    1. Uses vector similarity to find relevant techniques
    2. Uses SPARQL to enrich results with relationships
    3. Provides structured context for LLM reasoning
    """

    def __init__(
        self,
        graph_path: Path | str,
        vector_path: Path | str,
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        """
        Initialize the hybrid query engine.

        Args:
            graph_path: Path to Oxigraph persistent storage
            vector_path: Path to ChromaDB persistent storage
            embedding_model: Sentence transformer model
        """
        self.graph = AttackGraph(graph_path)
        self.semantic = SemanticSearchEngine(vector_path, embedding_model)

    def query(
        self,
        question: str,
        top_k: int = 5,
        enrich: bool = True,
    ) -> HybridQueryResult:
        """
        Execute a hybrid query.

        Args:
            question: Natural language question or finding description
            top_k: Number of technique results
            enrich: Whether to enrich with graph relationships

        Returns:
            HybridQueryResult with techniques and context
        """
        # Step 1: Semantic search for relevant techniques
        semantic_results = self.semantic.search(question, top_k=top_k)

        # Step 2: Enrich each result with graph data
        enriched_techniques = []
        for result in semantic_results:
            if enrich:
                enriched = self._enrich_technique(result)
            else:
                enriched = EnrichedTechnique(
                    attack_id=result.attack_id,
                    name=result.name,
                    description="",
                    similarity=result.similarity,
                    tactics=result.tactics,
                    groups=[],
                    mitigations=[],
                    software=[],
                    subtechniques=[],
                )
            enriched_techniques.append(enriched)

        return HybridQueryResult(
            query=question,
            techniques=enriched_techniques,
            metadata={
                "top_k": top_k,
                "enriched": enrich,
                "result_count": len(enriched_techniques),
            },
        )

    def _enrich_technique(self, semantic_result: SemanticResult) -> EnrichedTechnique:
        """Enrich a semantic result with graph relationships."""
        attack_id = semantic_result.attack_id

        # Get basic technique info
        tech_info = self.graph.get_technique(attack_id) or {}

        # Get related entities
        groups = self.graph.get_groups_using_technique(attack_id)
        mitigations = self.graph.get_mitigations_for_technique(attack_id)
        software = self.graph.get_software_using_technique(attack_id)
        subtechniques = self.graph.get_subtechniques(attack_id)

        # Check if this is a sub-technique and get parent
        parent_technique = None
        if "." in attack_id:
            parent_id = attack_id.split(".")[0]
            parent_info = self.graph.get_technique(parent_id)
            if parent_info:
                parent_technique = {
                    "attack_id": parent_id,
                    "name": parent_info["name"],
                }

        return EnrichedTechnique(
            attack_id=attack_id,
            name=semantic_result.name,
            description=tech_info.get("description", ""),
            similarity=semantic_result.similarity,
            tactics=semantic_result.tactics,
            groups=groups,
            mitigations=mitigations,
            software=software,
            subtechniques=subtechniques,
            parent_technique=parent_technique,
        )

    def find_defenses_for_finding(
        self,
        finding_text: str,
        top_k: int = 3,
    ) -> dict[str, Any]:
        """
        Given a finding, suggest techniques and their mitigations.

        Primary use case: auto-tagging pentest findings with ATT&CK
        and providing defensive recommendations.

        Args:
            finding_text: Description of a security finding
            top_k: Number of techniques to consider

        Returns:
            Dictionary with techniques and consolidated mitigations
        """
        result = self.query(finding_text, top_k=top_k)

        # Consolidate unique mitigations across all matched techniques
        seen_mitigations = {}
        for tech in result.techniques:
            for mit in tech.mitigations:
                if mit["attack_id"] not in seen_mitigations:
                    seen_mitigations[mit["attack_id"]] = {
                        **mit,
                        "addresses_techniques": [tech.attack_id],
                    }
                else:
                    seen_mitigations[mit["attack_id"]]["addresses_techniques"].append(
                        tech.attack_id
                    )

        # Sort mitigations by how many techniques they address
        sorted_mitigations = sorted(
            seen_mitigations.values(),
            key=lambda m: len(m["addresses_techniques"]),
            reverse=True,
        )

        return {
            "finding": finding_text,
            "techniques": [
                {
                    "attack_id": t.attack_id,
                    "name": t.name,
                    "similarity": t.similarity,
                    "tactics": t.tactics,
                }
                for t in result.techniques
            ],
            "recommended_mitigations": sorted_mitigations,
        }

    def get_threat_context(
        self,
        technique_id: str,
    ) -> dict[str, Any]:
        """
        Get full threat context for a technique.

        Useful for understanding the threat landscape around a technique.

        Args:
            technique_id: ATT&CK technique ID

        Returns:
            Dictionary with full context including groups, software, etc.
        """
        tech_info = self.graph.get_technique(technique_id)
        if not tech_info:
            return {"error": f"Technique not found: {technique_id}"}

        groups = self.graph.get_groups_using_technique(technique_id)
        software = self.graph.get_software_using_technique(technique_id)
        mitigations = self.graph.get_mitigations_for_technique(technique_id)
        subtechniques = self.graph.get_subtechniques(technique_id)

        # Get similar techniques via semantic search
        similar = self.semantic.find_similar_techniques(technique_id, top_k=5)

        return {
            "technique": tech_info,
            "threat_actors": groups,
            "software": software,
            "mitigations": mitigations,
            "subtechniques": subtechniques,
            "similar_techniques": [s.to_dict() for s in similar],
        }

    def compare_groups(
        self,
        group1_id: str,
        group2_id: str,
    ) -> dict[str, Any]:
        """
        Compare techniques between two threat groups.

        Args:
            group1_id: First group ID (e.g., G0016)
            group2_id: Second group ID

        Returns:
            Dictionary with shared and unique techniques
        """
        techniques1 = {
            t["attack_id"]: t for t in self.graph.get_techniques_for_group(group1_id)
        }
        techniques2 = {
            t["attack_id"]: t for t in self.graph.get_techniques_for_group(group2_id)
        }

        shared_ids = set(techniques1.keys()) & set(techniques2.keys())
        only_group1 = set(techniques1.keys()) - set(techniques2.keys())
        only_group2 = set(techniques2.keys()) - set(techniques1.keys())

        return {
            "group1": group1_id,
            "group2": group2_id,
            "shared_techniques": [techniques1[tid] for tid in shared_ids],
            f"only_{group1_id}": [techniques1[tid] for tid in only_group1],
            f"only_{group2_id}": [techniques2[tid] for tid in only_group2],
            "similarity_score": len(shared_ids) / max(len(techniques1), len(techniques2), 1),
        }
