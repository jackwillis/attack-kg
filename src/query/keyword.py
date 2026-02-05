"""BM25 keyword search over ATT&CK techniques."""

import re
from dataclasses import dataclass
from typing import Any

from rank_bm25 import BM25Okapi
from rich.console import Console

console = Console()


@dataclass
class KeywordResult:
    attack_id: str
    name: str
    score: float
    tactics: list[str]
    platforms: list[str]


_CVE_CWE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|CWE-\d{1,4})\b", re.IGNORECASE)


def _tokenize(text: str) -> list[str]:
    if not text:
        return []
    # Extract CVE/CWE IDs as atomic uppercase tokens first
    ids = _CVE_CWE_RE.findall(text)
    normalized_ids = [i.upper() for i in ids]
    # Remove CVE/CWE IDs from text before general tokenization
    remainder = _CVE_CWE_RE.sub("", text)
    general = re.findall(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*", remainder.lower())
    return normalized_ids + general


class KeywordSearch:
    """BM25-based keyword search, lazy-loaded from graph."""

    def __init__(self, graph):
        self.graph = graph
        self._index: BM25Okapi | None = None
        self._corpus: list[dict[str, Any]] = []
        self._tokens: list[list[str]] = []

    def _build(self):
        rows = self.graph.query("""
        SELECT ?attackId ?name ?description ?detection
               (GROUP_CONCAT(DISTINCT ?tactic; separator=",") AS ?tactics)
               (GROUP_CONCAT(DISTINCT ?platform; separator=",") AS ?platforms)
        WHERE {
            ?t a attack:Technique ; attack:attackId ?attackId ; rdfs:label ?name .
            OPTIONAL { ?t attack:description ?description }
            OPTIONAL { ?t attack:detection ?detection }
            OPTIONAL { ?t attack:tactic ?tu . ?tu rdfs:label ?tactic }
            OPTIONAL { ?t attack:platform ?platform }
        }
        GROUP BY ?attackId ?name ?description ?detection
        """)
        self._corpus = []
        self._tokens = []
        for r in rows:
            tactics = [t for t in r.get("tactics", "").split(",") if t]
            platforms = [p for p in r.get("platforms", "").split(",") if p]
            doc_text = " ".join([
                r["attackId"], r["name"], " ".join(tactics),
                " ".join(platforms), r.get("description", ""), r.get("detection", ""),
            ])
            self._corpus.append({
                "attack_id": r["attackId"], "name": r["name"],
                "tactics": tactics, "platforms": platforms,
            })
            self._tokens.append(_tokenize(doc_text))
        self._index = BM25Okapi(self._tokens)
        console.print(f"[green]BM25 index: {len(self._corpus)} techniques[/green]")

    def search(self, query: str, top_k: int = 10) -> list[KeywordResult]:
        if self._index is None:
            self._build()
        tokens = _tokenize(query)
        if not tokens:
            return []
        scores = self._index.get_scores(tokens)
        top = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]
        return [
            KeywordResult(
                attack_id=self._corpus[i]["attack_id"],
                name=self._corpus[i]["name"],
                score=float(scores[i]),
                tactics=self._corpus[i]["tactics"],
                platforms=self._corpus[i]["platforms"],
            )
            for i in top if scores[i] > 0
        ]
