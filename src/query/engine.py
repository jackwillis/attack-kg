"""Hybrid query engine: semantic + BM25 + RRF + co-occurrence + graph enrichment."""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import exp, sqrt
from pathlib import Path
from typing import Any

from rich.console import Console

from src.store.graph import AttackGraph
from src.query.semantic import SemanticSearch, SemanticResult
from src.query.keyword import KeywordSearch

console = Console()

# CVE/CWE pattern detection
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_PATTERN = re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE)


@dataclass
class EnrichedTechnique:
    """Technique with full graph-enriched context."""
    attack_id: str
    name: str
    description: str
    similarity: float
    tactics: list[str]
    platforms: list[str] = field(default_factory=list)
    mitigations: list[dict[str, Any]] = field(default_factory=list)
    software: list[dict[str, str]] = field(default_factory=list)
    groups: list[dict[str, str]] = field(default_factory=list)
    detection_strategies: list[dict[str, str]] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    campaigns: list[dict[str, str]] = field(default_factory=list)
    d3fend: list[dict[str, Any]] = field(default_factory=list)
    cooccurrence_boost: float = 0.0


@dataclass
class QueryResult:
    query: str
    techniques: list[EnrichedTechnique]
    metadata: dict[str, Any] = field(default_factory=dict)


class HybridQueryEngine:
    """Core neuro-symbolic query engine combining vector + keyword + graph."""

    def __init__(
        self,
        graph: AttackGraph,
        semantic: SemanticSearch,
        enable_bm25: bool = True,
    ):
        self.graph = graph
        self.semantic = semantic
        self._keyword: KeywordSearch | None = None
        self._enable_bm25 = enable_bm25

    @property
    def keyword(self) -> KeywordSearch | None:
        if self._keyword is None and self._enable_bm25:
            self._keyword = KeywordSearch(self.graph)
        return self._keyword

    def query(
        self, question: str, top_k: int = 5, enrich: bool = True,
        use_bm25: bool = True, use_cooccurrence: bool = True,
    ) -> QueryResult:
        # Step 1: Semantic search (2x candidates)
        n = top_k * 2 if use_bm25 else top_k
        sem_results = self.semantic.search(question, top_k=n)

        if use_bm25 and self._enable_bm25 and self.keyword:
            # Step 2: BM25 keyword search
            kw_results = self.keyword.search(question, top_k=n)

            # Step 3: RRF fusion
            combined = self._rrf(sem_results, kw_results)

            # Step 4: Co-occurrence boosting
            if use_cooccurrence:
                combined = self._boost_cooccurrence(combined, top_k)
        else:
            combined = [
                {"attack_id": r.attack_id, "name": r.name,
                 "similarity": r.similarity, "tactics": r.tactics,
                 "platforms": r.platforms, "rrf_score": r.similarity}
                for r in sem_results
            ]

        # Step 4b: CWE/CVE-based technique injection
        cwe_techniques = self._extract_cwe_techniques(question)
        if cwe_techniques:
            combined = self._inject_cwe_techniques(combined, cwe_techniques)

        # Step 5: Take top_k and enrich
        top = combined[:top_k]
        techniques = []
        for item in top:
            if enrich:
                techniques.append(self._enrich(item))
            else:
                techniques.append(EnrichedTechnique(
                    attack_id=item["attack_id"], name=item["name"],
                    description="", similarity=item.get("similarity", item.get("rrf_score", 0)),
                    tactics=item.get("tactics", []), platforms=item.get("platforms", []),
                ))

        mode = "hybrid_rrf" if use_bm25 else "semantic"
        if use_cooccurrence:
            mode += "+cooccurrence"
        if cwe_techniques:
            mode += "+cwe"
        return QueryResult(query=question, techniques=techniques,
                           metadata={"top_k": top_k, "mode": mode, "count": len(techniques)})

    def _rrf(self, sem: list[SemanticResult], kw: list, k: int = 60) -> list[dict]:
        scores: dict[str, float] = {}
        data: dict[str, dict] = {}
        for rank, r in enumerate(sem, 1):
            scores[r.attack_id] = scores.get(r.attack_id, 0) + 1 / (k + rank)
            if r.attack_id not in data:
                data[r.attack_id] = {
                    "attack_id": r.attack_id, "name": r.name,
                    "similarity": r.similarity,
                    "tactics": r.tactics, "platforms": r.platforms,
                }
        for rank, r in enumerate(kw, 1):
            scores[r.attack_id] = scores.get(r.attack_id, 0) + 1 / (k + rank)
            if r.attack_id not in data:
                data[r.attack_id] = {
                    "attack_id": r.attack_id, "name": r.name,
                    "tactics": r.tactics, "platforms": r.platforms,
                }
        sorted_ids = sorted(scores, key=lambda x: scores[x], reverse=True)
        result = []
        for aid in sorted_ids:
            d = data[aid]
            d["rrf_score"] = scores[aid]
            result.append(d)
        return result

    def _boost_cooccurrence(
        self, combined: list[dict], top_k: int,
        max_boost: float = 1.3, seeds: int = 3,
    ) -> list[dict]:
        """Boost techniques by co-occurrence with weighted campaign/group scoring.

        Campaigns get 1.5x weight (more specific), groups get 1.0x.
        Recent campaigns get time-decay bonus: weight *= exp(-0.1 * age_years).
        """
        if not combined:
            return combined
        boosts: dict[str, float] = {}
        now = datetime.now(timezone.utc)
        for seed in combined[:seeds]:
            cooc = self.graph.get_cooccurring_techniques(seed["attack_id"], min_count=1, limit=15)
            for c in cooc:
                # Weighted count: campaigns 1.5x, groups 1.0x
                campaign_weight = c.get("campaign_count", 0) * 1.5
                group_weight = c.get("group_count", 0) * 1.0
                weighted_count = campaign_weight + group_weight
                if weighted_count < 1.5:  # Skip noise (need at least ~1 campaign or 2 groups)
                    continue
                # Time-decay for campaigns: boost recent campaigns
                time_factor = 1.0
                latest = c.get("latest_campaign", "")
                if latest and campaign_weight > 0:
                    try:
                        last_date = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                        if last_date.tzinfo is None:
                            last_date = last_date.replace(tzinfo=timezone.utc)
                        age_years = (now - last_date).days / 365.25
                        time_factor = exp(-0.1 * max(0, age_years))
                    except (ValueError, TypeError):
                        pass
                strength = min(max_boost, 1.0 + sqrt(weighted_count) * 0.1 * (0.5 + 0.5 * time_factor))
                accumulated = boosts.get(c["attack_id"], 1.0) * strength
                boosts[c["attack_id"]] = min(accumulated, max_boost)
        for item in combined:
            aid = item["attack_id"]
            if aid in boosts:
                item["rrf_score"] = item.get("rrf_score", 0) * boosts[aid]
                item["cooccurrence_boost"] = boosts[aid]
        combined.sort(key=lambda x: x.get("rrf_score", 0), reverse=True)
        return combined[:top_k * 2]

    def _extract_cwe_techniques(self, text: str) -> list[dict]:
        """Extract CWE IDs from text and map to ATT&CK techniques via CAPEC."""
        cwes = CWE_PATTERN.findall(text)
        if not cwes:
            return []
        techniques = []
        seen = set()
        for cwe_id in cwes:
            for t in self.graph.get_techniques_for_cwe(cwe_id):
                if t["attack_id"] not in seen:
                    seen.add(t["attack_id"])
                    techniques.append(t)
        if techniques:
            console.print(f"[blue]CWE mapping: {', '.join(cwes)} -> "
                          f"{len(techniques)} techniques[/blue]")
        return techniques

    def _inject_cwe_techniques(
        self, combined: list[dict], cwe_techniques: list[dict],
        boost: float = 1.4,
    ) -> list[dict]:
        """Inject CWE-mapped techniques into combined results with boost."""
        existing = {item["attack_id"] for item in combined}
        for t in cwe_techniques:
            aid = t["attack_id"]
            if aid in existing:
                # Boost existing technique
                for item in combined:
                    if item["attack_id"] == aid:
                        item["rrf_score"] = item.get("rrf_score", 0) * boost
                        item["cwe_boost"] = True
                        break
            else:
                # Inject new technique
                combined.append({
                    "attack_id": aid, "name": t.get("name", ""),
                    "tactics": [], "platforms": [],
                    "rrf_score": 0.01 * boost,  # Low base, but boosted
                    "cwe_boost": True,
                })
        combined.sort(key=lambda x: x.get("rrf_score", 0), reverse=True)
        return combined

    def _enrich(self, item: dict) -> EnrichedTechnique:
        aid = item["attack_id"]
        tech = self.graph.get_technique(aid) or {}
        return EnrichedTechnique(
            attack_id=aid,
            name=item.get("name", tech.get("name", "")),
            description=tech.get("description", ""),
            similarity=item.get("similarity", item.get("rrf_score", 0)),
            tactics=item.get("tactics", tech.get("tactics", [])),
            platforms=item.get("platforms", tech.get("platforms", [])),
            mitigations=self.graph.get_mitigations_with_inheritance(aid),
            software=self.graph.get_software_for_technique(aid),
            groups=self.graph.get_groups_for_technique(aid),
            detection_strategies=self.graph.get_detection_strategies(aid),
            data_sources=tech.get("data_sources", []) or self.graph.get_data_sources(aid),
            campaigns=self.graph.get_campaigns_for_technique(aid),
            d3fend=self.graph.get_d3fend_for_technique(aid),
            cooccurrence_boost=item.get("cooccurrence_boost", 0),
        )
