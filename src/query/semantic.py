"""Semantic search interface for ATT&CK techniques."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


@dataclass
class SemanticResult:
    """A semantic search result."""

    attack_id: str
    name: str
    similarity: float
    tactics: list[str]
    platforms: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "similarity": self.similarity,
            "tactics": self.tactics,
            "platforms": self.platforms,
        }


class SemanticSearchEngine:
    """
    Semantic search engine for ATT&CK techniques.

    Uses sentence embeddings to find techniques that are semantically
    similar to natural language queries or finding descriptions.
    """

    def __init__(
        self,
        vector_store_path: Path | str,
        model_name: str = "nomic-ai/nomic-embed-text-v1.5",
    ):
        """
        Initialize the semantic search engine.

        Args:
            vector_store_path: Path to ChromaDB persistent storage
            model_name: Sentence transformer model to use
        """
        from src.ingest.embeddings import EmbeddingGenerator, VectorStore

        self.vector_store_path = Path(vector_store_path)
        self.embedder = EmbeddingGenerator(model_name)
        self.store = VectorStore(self.vector_store_path)

    def search(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.0,
        tactic_filter: str | None = None,
        platform_filter: str | None = None,
    ) -> list[SemanticResult]:
        """
        Search for techniques semantically similar to the query.

        Args:
            query: Natural language query or finding description
            top_k: Number of results to return
            min_similarity: Minimum similarity threshold (0-1)
            tactic_filter: Optional filter by tactic name
            platform_filter: Optional filter by platform

        Returns:
            List of SemanticResult objects
        """
        from src.logging import log_semantic_search, log_semantic_result

        search_id = log_semantic_search(query, top_k)

        # Generate query embedding
        embedding = self.embedder.embed_text(query)

        # Build ChromaDB where clause
        where = None
        if tactic_filter or platform_filter:
            conditions = []
            if tactic_filter:
                conditions.append({"tactics": {"$contains": tactic_filter}})
            if platform_filter:
                conditions.append({"platforms": {"$contains": platform_filter}})

            if len(conditions) == 1:
                where = conditions[0]
            else:
                where = {"$and": conditions}

        # Query vector store
        raw_results = self.store.search(
            query=query,
            embedding=embedding,
            n_results=top_k,
            where=where,
        )

        # Convert to SemanticResult objects
        results = []
        for r in raw_results:
            similarity = r.get("similarity", 0)
            if similarity >= min_similarity:
                tactics = r.get("tactics", "").split(",") if r.get("tactics") else []
                platforms = r.get("platforms", "").split(",") if r.get("platforms") else []
                results.append(SemanticResult(
                    attack_id=r["attack_id"],
                    name=r["name"],
                    similarity=similarity,
                    tactics=[t.strip() for t in tactics if t.strip()],
                    platforms=[p.strip() for p in platforms if p.strip()],
                ))

        log_semantic_result(search_id, [r.to_dict() for r in results])
        return results

    def find_techniques_for_finding(
        self,
        finding_text: str,
        top_k: int = 3,
    ) -> list[SemanticResult]:
        """
        Map a penetration testing finding to ATT&CK techniques.

        This is the primary interface for auto-tagging findings.

        Args:
            finding_text: Description of the finding from a pentest report
            top_k: Number of technique suggestions

        Returns:
            List of candidate techniques ranked by relevance
        """
        return self.search(finding_text, top_k=top_k, min_similarity=0.3)

    def find_similar_techniques(
        self,
        technique_id: str,
        top_k: int = 5,
    ) -> list[SemanticResult]:
        """
        Find techniques similar to a known technique.

        Useful for exploring related techniques.

        Args:
            technique_id: ATT&CK technique ID (e.g., T1110.003)
            top_k: Number of similar techniques

        Returns:
            List of similar techniques (excluding the query technique)
        """
        # Get the technique's text from the store
        results = self.store.collection.get(
            ids=[technique_id],
            include=["documents"],
        )

        if not results["documents"]:
            console.print(f"[yellow]Technique not found in vector store: {technique_id}[/yellow]")
            return []

        technique_text = results["documents"][0]

        # Search for similar, requesting one extra to exclude self
        similar = self.search(technique_text, top_k=top_k + 1)

        # Filter out the query technique
        return [r for r in similar if r.attack_id != technique_id][:top_k]
