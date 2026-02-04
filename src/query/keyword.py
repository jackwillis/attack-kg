"""BM25-based keyword search for ATT&CK techniques."""

import re
from dataclasses import dataclass
from typing import Any

from rank_bm25 import BM25Okapi
from rich.console import Console

from src.store.graph import AttackGraph

console = Console()


@dataclass
class KeywordResult:
    """A keyword search result."""

    attack_id: str
    name: str
    score: float
    tactics: list[str]
    platforms: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "score": self.score,
            "tactics": self.tactics,
            "platforms": self.platforms,
        }


class KeywordSearchEngine:
    """
    BM25-based keyword search over technique corpus.

    Complements semantic search by finding exact matches for:
    - Technique IDs (T1110.003)
    - Tool names (mimikatz, certutil)
    - Technical terms (LSASS, SAM, kerberoasting)
    """

    def __init__(self, graph: AttackGraph):
        """
        Initialize the keyword search engine.

        Args:
            graph: AttackGraph instance for fetching technique data
        """
        self.graph = graph
        self.index: BM25Okapi | None = None
        self.corpus: list[dict[str, Any]] = []
        self._tokenized_corpus: list[list[str]] = []

    def _tokenize(self, text: str) -> list[str]:
        """
        Tokenize text for BM25 indexing.

        Handles:
        - Lowercase normalization
        - Splitting on whitespace and punctuation
        - Preserving technique IDs (T1110.003)
        - Preserving hyphenated terms (pass-the-hash)
        """
        if not text:
            return []

        # Lowercase
        text = text.lower()

        # Split on whitespace and most punctuation, but preserve:
        # - Technique IDs (T1110.003 -> t1110.003)
        # - Hyphenated terms (pass-the-hash)
        tokens = re.findall(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*", text)

        return tokens

    def build_index(self) -> int:
        """
        Build BM25 index from all techniques in the graph.

        Returns:
            Number of techniques indexed
        """
        console.print("[dim]Building BM25 keyword index...[/dim]")

        # Query all techniques with full metadata
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

        results = self.graph.query(sparql)

        self.corpus = []
        self._tokenized_corpus = []

        for row in results:
            attack_id = row["attackId"]
            name = row["name"]
            description = row.get("description", "")
            detection = row.get("detection", "")
            tactics_str = row.get("tactics", "")
            platforms_str = row.get("platforms", "")

            tactics = [t.strip() for t in tactics_str.split(",") if t.strip()] if tactics_str else []
            platforms = [p.strip() for p in platforms_str.split(",") if p.strip()] if platforms_str else []

            # Build document text for tokenization
            doc_text = f"{attack_id} {name} {' '.join(tactics)} {' '.join(platforms)} {description} {detection}"
            tokens = self._tokenize(doc_text)

            self.corpus.append({
                "attack_id": attack_id,
                "name": name,
                "tactics": tactics,
                "platforms": platforms,
            })
            self._tokenized_corpus.append(tokens)

        # Build BM25 index
        self.index = BM25Okapi(self._tokenized_corpus)

        console.print(f"[green]BM25 index built with {len(self.corpus)} techniques[/green]")
        return len(self.corpus)

    def is_indexed(self) -> bool:
        """Check if the index has been built."""
        return self.index is not None and len(self.corpus) > 0

    def search(self, query: str, top_k: int = 10) -> list[KeywordResult]:
        """
        Search for techniques matching the query using BM25.

        Args:
            query: Search query (keywords, technique IDs, tool names)
            top_k: Number of results to return

        Returns:
            List of KeywordResult objects sorted by BM25 score
        """
        if not self.is_indexed():
            self.build_index()

        # Tokenize query
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        # Get BM25 scores
        scores = self.index.get_scores(query_tokens)

        # Get top-k indices
        top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]

        # Build results
        results = []
        for idx in top_indices:
            if scores[idx] > 0:  # Only include non-zero scores
                doc = self.corpus[idx]
                results.append(KeywordResult(
                    attack_id=doc["attack_id"],
                    name=doc["name"],
                    score=float(scores[idx]),
                    tactics=doc["tactics"],
                    platforms=doc["platforms"],
                ))

        return results

    def search_by_id(self, attack_id: str) -> KeywordResult | None:
        """
        Find a technique by its exact attack ID.

        Args:
            attack_id: ATT&CK technique ID (e.g., T1110.003)

        Returns:
            KeywordResult if found, None otherwise
        """
        if not self.is_indexed():
            self.build_index()

        attack_id_upper = attack_id.upper()
        for doc in self.corpus:
            if doc["attack_id"].upper() == attack_id_upper:
                return KeywordResult(
                    attack_id=doc["attack_id"],
                    name=doc["name"],
                    score=1.0,  # Exact match
                    tactics=doc["tactics"],
                    platforms=doc["platforms"],
                )
        return None
