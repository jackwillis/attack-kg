"""Embedding generation and ChromaDB vector store."""

import os
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()

DEFAULT_MODEL = "basel/ATTACK-BERT"
NOMIC_REVISION = "e5cf08aadaa33385f5990def41f7a23405aec398"


class EmbeddingGenerator:
    """Sentence-transformers embedding model with offline support."""

    def __init__(self, model: str = DEFAULT_MODEL):
        self.model_name = model
        self._revision = NOMIC_REVISION if "nomic" in model else None
        self._offline = os.environ.get("ATTACK_KG_OFFLINE", "").lower() in ("1", "true")
        self._model = None

    @property
    def model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            console.print(f"[blue]Loading embedding model: {self.model_name}[/blue]")
            self._model = SentenceTransformer(
                self.model_name, trust_remote_code=True,
                revision=self._revision, local_files_only=self._offline,
            )
        return self._model

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(texts, show_progress_bar=True, batch_size=32).tolist()

    def embed_one(self, text: str) -> list[float]:
        return self.model.encode(text).tolist()


class VectorStore:
    """ChromaDB vector store."""

    def __init__(self, path: Path | str | None = None, reset: bool = False):
        import chromadb
        from chromadb.config import Settings
        if path:
            Path(path).mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(
                path=str(path), settings=Settings(anonymized_telemetry=False))
        else:
            self.client = chromadb.Client(Settings(anonymized_telemetry=False))
        if reset:
            try:
                self.client.delete_collection("techniques")
            except Exception:
                pass
        self.collection = self.client.get_or_create_collection(
            "techniques", metadata={"hnsw:space": "cosine"})

    def add(self, ids: list[str], texts: list[str], embeddings: list[list[float]],
            metadatas: list[dict[str, Any]]):
        for i in range(0, len(ids), 500):
            e = min(i + 500, len(ids))
            self.collection.add(ids=ids[i:e], documents=texts[i:e],
                                embeddings=embeddings[i:e], metadatas=metadatas[i:e])

    def search(self, embedding: list[float], n: int = 10) -> list[dict[str, Any]]:
        results = self.collection.query(
            query_embeddings=[embedding], n_results=n,
            include=["documents", "metadatas", "distances"])
        out = []
        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i]
                dist = results["distances"][0][i] if results["distances"] else None
                out.append({
                    "id": doc_id, "metadata": meta,
                    "similarity": 1 - dist if dist is not None else None,
                })
        return out

    def count(self) -> int:
        return self.collection.count()


def extract_techniques(graph) -> list[dict[str, Any]]:
    """Extract technique documents from RDF graph for embedding."""
    rows = graph.query("""
    SELECT ?attackId ?name ?description ?detection
           (GROUP_CONCAT(DISTINCT ?tactic; separator=",") AS ?tactics)
           (GROUP_CONCAT(DISTINCT ?platform; separator=",") AS ?platforms)
    WHERE {
        ?t a attack:Technique ; attack:attackId ?attackId ; rdfs:label ?name .
        OPTIONAL { ?t attack:description ?description }
        OPTIONAL { ?t attack:detection ?detection }
        OPTIONAL { ?t attack:tactic ?tu .
                   BIND(REPLACE(STR(?tu), "https://attack.mitre.org/tactic/", "") AS ?tactic) }
        OPTIONAL { ?t attack:platform ?platform }
    }
    GROUP BY ?attackId ?name ?description ?detection
    ORDER BY ?attackId
    """)
    docs = []
    for r in rows:
        aid = r["attackId"]
        name = r["name"]
        tactics = r.get("tactics", "")
        platforms = r.get("platforms", "")
        text = f"Technique: {name}\nID: {aid}"
        if tactics:
            text += f"\nTactics: {tactics}"
        if platforms:
            text += f"\nPlatforms: {platforms}"
        if r.get("description"):
            text += f"\nDescription: {r['description']}"
        if r.get("detection"):
            text += f"\nDetection: {r['detection']}"
        docs.append({
            "id": aid, "text": text,
            "metadata": {"attack_id": aid, "name": name,
                         "tactics": tactics, "platforms": platforms, "type": "attack"},
        })
    console.print(f"[green]Extracted {len(docs)} techniques[/green]")
    return docs


def build_vector_store(
    graph, persist_dir: Path | str | None = None, data_dir: Path | str = Path("data"),
    include_lolbas: bool = True, include_gtfobins: bool = True,
    include_capec: bool = True,
) -> VectorStore:
    """Build ChromaDB vector store from graph + external sources."""
    console.print("[bold]Extracting techniques...[/bold]")
    tech_docs = extract_techniques(graph)

    ext_docs: list[dict[str, Any]] = []
    if include_lolbas:
        from src.ingest.lolbas import parse_lolbas
        ext_docs.extend(parse_lolbas(Path(data_dir) / "lolbas"))
    if include_gtfobins:
        from src.ingest.gtfobins import parse_gtfobins
        ext_docs.extend(parse_gtfobins(Path(data_dir) / "gtfobins"))
    if include_capec:
        capec_xml = Path(data_dir) / "capec_latest.xml"
        if capec_xml.exists():
            from src.ingest.capec import parse_capec, parse_capec_for_embedding
            mappings = parse_capec(capec_xml)
            ext_docs.extend(parse_capec_for_embedding(mappings))

    all_docs = tech_docs + ext_docs
    console.print(f"[bold]Generating embeddings for {len(all_docs)} documents...[/bold]")
    embedder = EmbeddingGenerator()
    embeddings = embedder.embed([d["text"] for d in all_docs])

    console.print("[bold]Storing in ChromaDB...[/bold]")
    store = VectorStore(persist_dir, reset=True)
    store.add(
        ids=[d["id"] for d in all_docs],
        texts=[d["text"] for d in all_docs],
        embeddings=embeddings,
        metadatas=[d["metadata"] for d in all_docs],
    )
    console.print(f"[green bold]Vector store complete: {len(all_docs)} documents[/green bold]")
    return store
