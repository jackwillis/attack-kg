"""Vector store interface for semantic search."""

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from src.ingest.embeddings import EmbeddingGenerator, VectorStore

console = Console()


class SemanticSearch:
    """
    High-level interface for semantic search over ATT&CK techniques.

    Wraps the VectorStore with convenient query methods.
    """

    def __init__(
        self,
        store_path: Path | str | None = None,
        model_name: str = "nomic-ai/nomic-embed-text-v1.5",
    ):
        """
        Initialize semantic search.

        Args:
            store_path: Path to ChromaDB persistent storage
            model_name: Embedding model to use
        """
        self.embedder = EmbeddingGenerator(model_name)
        self.store = VectorStore(store_path)

    def search(
        self,
        query: str,
        n_results: int = 5,
        tactic: str | None = None,
        platform: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search for techniques similar to the query.

        Args:
            query: Natural language query or description
            n_results: Number of results to return
            tactic: Optional filter by tactic (e.g., "credential-access")
            platform: Optional filter by platform (e.g., "Windows")

        Returns:
            List of matching techniques with similarity scores
        """
        # Generate query embedding
        embedding = self.embedder.embed_text(query)

        # Build where clause for filtering
        where = None
        if tactic or platform:
            conditions = []
            if tactic:
                conditions.append({"tactics": {"$contains": tactic}})
            if platform:
                conditions.append({"platforms": {"$contains": platform}})

            if len(conditions) == 1:
                where = conditions[0]
            else:
                where = {"$and": conditions}

        return self.store.search(
            query=query,
            embedding=embedding,
            n_results=n_results,
            where=where,
        )

    def find_similar_techniques(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """
        Find techniques semantically similar to the query.

        This is the primary interface for the neuro-symbolic system.

        Args:
            query: Natural language description or finding text
            top_k: Number of results

        Returns:
            List of techniques with attack_id, name, and similarity score
        """
        return self.search(query, n_results=top_k)

    def print_search_results(
        self,
        query: str,
        n_results: int = 5,
        tactic: str | None = None,
    ) -> None:
        """Search and print results as a formatted table."""
        results = self.search(query, n_results=n_results, tactic=tactic)

        if not results:
            console.print("[yellow]No results found[/yellow]")
            return

        table = Table(title=f"Techniques similar to: '{query}'")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Tactics")
        table.add_column("Similarity", justify="right")

        for r in results:
            similarity = f"{r['similarity']:.3f}" if r.get("similarity") else "N/A"
            table.add_row(r["attack_id"], r["name"], r.get("tactics", ""), similarity)

        console.print(table)

    def count(self) -> int:
        """Return the number of indexed techniques."""
        return self.store.count()
