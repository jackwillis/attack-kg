"""Generate embeddings for ATT&CK techniques and store in ChromaDB."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn

console = Console()


@dataclass
class TechniqueDocument:
    """A technique prepared for embedding."""

    attack_id: str
    name: str
    description: str
    detection: str
    tactics: list[str]
    platforms: list[str]

    def to_text(self) -> str:
        """Combine fields into a single text for embedding."""
        parts = [
            f"Technique: {self.name}",
            f"ID: {self.attack_id}",
        ]

        if self.tactics:
            parts.append(f"Tactics: {', '.join(self.tactics)}")

        if self.platforms:
            parts.append(f"Platforms: {', '.join(self.platforms)}")

        if self.description:
            parts.append(f"Description: {self.description}")

        if self.detection:
            parts.append(f"Detection: {self.detection}")

        return "\n".join(parts)

    def to_metadata(self) -> dict[str, Any]:
        """Return metadata for ChromaDB."""
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "tactics": ",".join(self.tactics),
            "platforms": ",".join(self.platforms),
        }


def extract_techniques_from_graph(graph) -> list[TechniqueDocument]:
    """
    Extract technique documents from the RDF graph.

    Args:
        graph: AttackGraph instance

    Returns:
        List of TechniqueDocument objects
    """
    sparql = """
    PREFIX attack: <https://attack.mitre.org/>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

    SELECT ?attackId ?name ?description ?detection
           (GROUP_CONCAT(DISTINCT ?tactic; separator=",") AS ?tactics)
           (GROUP_CONCAT(DISTINCT ?platform; separator=",") AS ?platforms)
    WHERE {
        ?technique a attack:Technique ;
                   attack:attackId ?attackId ;
                   rdfs:label ?name .
        OPTIONAL { ?technique attack:description ?description }
        OPTIONAL { ?technique attack:detection ?detection }
        OPTIONAL {
            ?technique attack:tactic ?tacticUri .
            BIND(REPLACE(STR(?tacticUri), "https://attack.mitre.org/tactic/", "") AS ?tactic)
        }
        OPTIONAL { ?technique attack:platform ?platform }
    }
    GROUP BY ?attackId ?name ?description ?detection
    ORDER BY ?attackId
    """

    results = graph.query_to_list(sparql)
    documents = []

    for row in results:
        tactics = row.get("tactics", "")
        tactics_list = [t.strip() for t in tactics.split(",") if t.strip()] if tactics else []

        platforms = row.get("platforms", "")
        platforms_list = [p.strip() for p in platforms.split(",") if p.strip()] if platforms else []

        doc = TechniqueDocument(
            attack_id=str(row["attackId"]),
            name=str(row["name"]),
            description=str(row.get("description", "")),
            detection=str(row.get("detection", "")),
            tactics=tactics_list,
            platforms=platforms_list,
        )
        documents.append(doc)

    console.print(f"[green]Extracted {len(documents)} techniques for embedding[/green]")
    return documents


class EmbeddingGenerator:
    """Generate embeddings using sentence-transformers."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize the embedding model.

        Args:
            model_name: Name of the sentence-transformers model to use
        """
        self.model_name = model_name
        self._model = None

    @property
    def model(self):
        """Lazy-load the embedding model."""
        if self._model is None:
            console.print(f"[blue]Loading embedding model: {self.model_name}[/blue]")
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name)
        return self._model

    def embed_text(self, text: str) -> list[float]:
        """Generate embedding for a single text."""
        return self.model.encode(text).tolist()

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts."""
        return self.model.encode(texts).tolist()

    def embed_documents(self, documents: list[TechniqueDocument]) -> list[list[float]]:
        """
        Generate embeddings for technique documents.

        Args:
            documents: List of TechniqueDocument objects

        Returns:
            List of embedding vectors
        """
        texts = [doc.to_text() for doc in documents]

        console.print(f"[blue]Generating embeddings for {len(texts)} documents...[/blue]")
        console.print(f"[dim]This may take a minute on first run (downloading model)...[/dim]")

        # Use sentence-transformers' built-in progress bar
        embeddings = self.model.encode(texts, show_progress_bar=True, batch_size=32)

        console.print(f"[green]Generated {len(embeddings)} embeddings[/green]")
        return embeddings.tolist()


class VectorStore:
    """ChromaDB vector store for technique embeddings."""

    def __init__(self, persist_dir: Path | str | None = None, collection_name: str = "techniques"):
        """
        Initialize ChromaDB store.

        Args:
            persist_dir: Directory for persistent storage. None for in-memory.
            collection_name: Name of the collection to use
        """
        import chromadb
        from chromadb.config import Settings

        self.persist_dir = Path(persist_dir) if persist_dir else None

        if self.persist_dir:
            self.persist_dir.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=Settings(anonymized_telemetry=False),
            )
            console.print(f"[green]Using ChromaDB store at:[/green] {self.persist_dir}")
        else:
            self.client = chromadb.Client(Settings(anonymized_telemetry=False))

        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},  # Use cosine similarity
        )

    def add_documents(
        self,
        documents: list[TechniqueDocument],
        embeddings: list[list[float]],
    ) -> None:
        """
        Add technique documents with their embeddings.

        Args:
            documents: List of TechniqueDocument objects
            embeddings: Corresponding embedding vectors
        """
        ids = [doc.attack_id for doc in documents]
        texts = [doc.to_text() for doc in documents]
        metadatas = [doc.to_metadata() for doc in documents]

        # ChromaDB has a batch size limit, process in chunks
        batch_size = 500
        for i in range(0, len(ids), batch_size):
            end = min(i + batch_size, len(ids))
            self.collection.add(
                ids=ids[i:end],
                documents=texts[i:end],
                embeddings=embeddings[i:end],
                metadatas=metadatas[i:end],
            )

        console.print(f"[green]Added {len(documents)} documents to vector store[/green]")

    def search(
        self,
        query: str,
        embedding: list[float] | None = None,
        n_results: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search for similar techniques.

        Args:
            query: Query text (used if embedding not provided)
            embedding: Pre-computed query embedding (optional)
            n_results: Number of results to return
            where: Optional metadata filters

        Returns:
            List of matching techniques with scores
        """
        if embedding is not None:
            results = self.collection.query(
                query_embeddings=[embedding],
                n_results=n_results,
                where=where,
                include=["documents", "metadatas", "distances"],
            )
        else:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where,
                include=["documents", "metadatas", "distances"],
            )

        # Format results
        output = []
        if results["ids"] and results["ids"][0]:
            for i, attack_id in enumerate(results["ids"][0]):
                output.append({
                    "attack_id": attack_id,
                    "name": results["metadatas"][0][i].get("name", ""),
                    "tactics": results["metadatas"][0][i].get("tactics", ""),
                    "distance": results["distances"][0][i] if results["distances"] else None,
                    "similarity": 1 - results["distances"][0][i] if results["distances"] else None,
                })

        return output

    def count(self) -> int:
        """Return the number of documents in the collection."""
        return self.collection.count()


def build_vector_store(
    graph,
    persist_dir: Path | str | None = None,
    model_name: str = "all-MiniLM-L6-v2",
) -> VectorStore:
    """
    Build vector store from RDF graph.

    Args:
        graph: AttackGraph instance
        persist_dir: Directory for persistent storage
        model_name: Embedding model to use

    Returns:
        Populated VectorStore instance
    """
    console.print("\n[bold]Step 1/3:[/bold] Extracting techniques from graph...")
    documents = extract_techniques_from_graph(graph)

    console.print("\n[bold]Step 2/3:[/bold] Generating embeddings...")
    embedder = EmbeddingGenerator(model_name)
    embeddings = embedder.embed_documents(documents)

    console.print("\n[bold]Step 3/3:[/bold] Storing in ChromaDB...")
    store = VectorStore(persist_dir)
    store.add_documents(documents, embeddings)

    console.print(f"\n[green bold]Vector store complete![/green bold] {store.count()} techniques indexed.")
    return store
