"""Semantic search over ATT&CK technique embeddings."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SemanticResult:
    attack_id: str
    name: str
    similarity: float
    tactics: list[str]
    platforms: list[str]
    source: str = "attack"
    tool: str | None = None


class SemanticSearch:
    """ChromaDB-backed semantic search."""

    def __init__(self, vector_path: Path | str, model: str = "nomic-ai/nomic-embed-text-v1.5"):
        from src.ingest.embeddings import EmbeddingGenerator, VectorStore
        self.embedder = EmbeddingGenerator(model)
        self.store = VectorStore(vector_path)

    def search(self, query: str, top_k: int = 10) -> list[SemanticResult]:
        embedding = self.embedder.embed_one(query)
        raw = self.store.search(embedding, n=top_k)
        results, seen = [], set()
        for r in raw:
            meta = r["metadata"]
            aid = meta.get("attack_id", r["id"])
            source = meta.get("type", "attack")
            if source in ("lolbas", "gtfobins", "capec") and aid in seen:
                continue
            seen.add(aid)
            tactics_raw = meta.get("tactics", "")
            tactics = [t.strip() for t in tactics_raw.split(",") if t.strip()] if tactics_raw else []
            platforms_raw = meta.get("platforms", "")
            platforms = [p.strip() for p in platforms_raw.split(",") if p.strip()] if platforms_raw else []
            if source in ("lolbas", "gtfobins") and meta.get("platform"):
                platforms = [meta["platform"]]
            results.append(SemanticResult(
                attack_id=aid,
                name=meta.get("name", meta.get("tool", "")),
                similarity=r.get("similarity", 0) or 0,
                tactics=tactics, platforms=platforms,
                source=source, tool=meta.get("tool"),
            ))
        return results
