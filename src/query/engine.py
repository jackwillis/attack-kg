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

# Vulnerability keyword → ATT&CK technique mapping.
# Bridges the vocabulary gap where CAPEC has no path (only 27% of techniques
# have CAPEC mappings). Each entry maps a regex pattern (case-insensitive) to
# one or more technique IDs that should be injected as candidates.
VULN_KEYWORD_TECHNIQUES: list[tuple[re.Pattern, list[str]]] = [
    # Authentication / access control
    (re.compile(r"authenticat\w*\s+bypass|bypass\w*\s+authenticat", re.I), ["T1190", "T1078"]),
    (re.compile(r"improper\s+authenticat|missing\s+authenticat", re.I), ["T1190", "T1078"]),
    (re.compile(r"SSO\s+(bypass|vulnerab|flaw)", re.I), ["T1190", "T1550"]),
    (re.compile(r"unauthorized\s+(access|admin)", re.I), ["T1190", "T1078"]),
    (re.compile(r"privilege\s+escalat", re.I), ["T1068", "T1548"]),
    (re.compile(r"improper\s+access\s+control", re.I), ["T1190", "T1068"]),
    # Injection
    (re.compile(r"SQL\s+injection|\bSQLi\b", re.I), ["T1190", "T1059"]),
    (re.compile(r"command\s+injection|OS\s+command", re.I), ["T1190", "T1059"]),
    (re.compile(r"code\s+injection|remote\s+code\s+execut|\bRCE\b", re.I), ["T1190", "T1203"]),
    (re.compile(r"cross.site\s+script|\bXSS\b", re.I), ["T1190", "T1059.007"]),
    (re.compile(r"server.side\s+request\s+forgery|\bSSRF\b", re.I), ["T1190", "T1557"]),
    (re.compile(r"deserialization", re.I), ["T1190", "T1203"]),
    # File / path
    (re.compile(r"path\s+traversal|directory\s+traversal|\.\.\/", re.I), ["T1190", "T1083"]),
    (re.compile(r"arbitrary\s+file\s+(upload|write|read)", re.I), ["T1190", "T1105"]),
    # Memory corruption
    (re.compile(r"buffer\s+overflow|heap\s+overflow|stack\s+overflow", re.I), ["T1190", "T1203"]),
    (re.compile(r"use.after.free|double.free|memory\s+corrupt", re.I), ["T1190", "T1203"]),
    # Network appliance / public-facing
    (re.compile(r"(FortiOS|FortiGate|FortiProxy|FortiManager|FortiAnalyzer)", re.I), ["T1190"]),
    (re.compile(r"(Citrix|Pulse\s+Secure|Ivanti|PAN-OS|Palo\s+Alto|SonicWall)", re.I), ["T1190"]),
    (re.compile(r"(VPN|firewall|load\s+balancer|gateway)\s+vulnerab", re.I), ["T1190"]),
    # Credential exposure
    (re.compile(r"credential\s+(leak|expos|disclos)", re.I), ["T1552", "T1078"]),
    (re.compile(r"hardcoded\s+(password|credential|secret)", re.I), ["T1552.001", "T1078"]),
]


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

        # Step 4c: Vulnerability keyword → technique injection
        vuln_techniques = self._extract_vuln_keyword_techniques(question)
        if vuln_techniques:
            combined = self._inject_vuln_techniques(combined, vuln_techniques)

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
        if vuln_techniques:
            mode += "+vuln_kw"
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

    def _extract_vuln_keyword_techniques(self, text: str) -> list[dict]:
        """Map vulnerability keywords to ATT&CK techniques via lookup table.

        Covers the gap where CAPEC has no mappings (73% of techniques).
        """
        techniques: list[dict] = []
        seen: set[str] = set()
        matched_patterns: list[str] = []
        for pattern, tech_ids in VULN_KEYWORD_TECHNIQUES:
            if pattern.search(text):
                matched_patterns.append(pattern.pattern[:40])
                for tid in tech_ids:
                    if tid not in seen:
                        seen.add(tid)
                        techniques.append({"attack_id": tid, "name": tid})
        if techniques:
            console.print(f"[blue]Vuln keyword mapping: {len(techniques)} techniques[/blue]")
        return techniques

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
                # Inject new technique (name/tactics/platforms filled by enrichment)
                combined.append({
                    "attack_id": aid, "name": t.get("name", aid),
                    "rrf_score": 0.01 * boost,
                    "cwe_boost": True,
                })
        combined.sort(key=lambda x: x.get("rrf_score", 0), reverse=True)
        return combined

    def _inject_vuln_techniques(
        self, combined: list[dict], vuln_techniques: list[dict],
        boost: float = 1.3,
    ) -> list[dict]:
        """Inject vulnerability-keyword-matched techniques with competitive scores.

        Unlike CWE injection (speculative, low base score), keyword matches are
        high-confidence domain knowledge — give them a score that competes with
        semantic results so they survive the top_k cut.
        """
        # Use median RRF score of current candidates as the base
        rrf_scores = [item.get("rrf_score", 0) for item in combined if item.get("rrf_score", 0) > 0]
        base = sorted(rrf_scores)[len(rrf_scores) // 2] if rrf_scores else 0.5

        existing = {item["attack_id"] for item in combined}
        for t in vuln_techniques:
            aid = t["attack_id"]
            if aid in existing:
                for item in combined:
                    if item["attack_id"] == aid:
                        item["rrf_score"] = item.get("rrf_score", 0) * boost
                        item["vuln_kw_boost"] = True
                        break
            else:
                combined.append({
                    "attack_id": aid, "name": t.get("name", aid),
                    "rrf_score": base * boost,
                    "vuln_kw_boost": True,
                })
        combined.sort(key=lambda x: x.get("rrf_score", 0), reverse=True)
        return combined

    def _enrich(self, item: dict) -> EnrichedTechnique:
        aid = item["attack_id"]
        tech = self.graph.get_technique(aid) or {}
        return EnrichedTechnique(
            attack_id=aid,
            name=tech.get("name") or item.get("name", ""),
            description=tech.get("description", ""),
            similarity=item.get("similarity", item.get("rrf_score", 0)),
            tactics=tech.get("tactics") or item.get("tactics", []),
            platforms=tech.get("platforms") or item.get("platforms", []),
            mitigations=self.graph.get_mitigations_with_inheritance(aid),
            software=self.graph.get_software_for_technique(aid),
            groups=self.graph.get_groups_for_technique(aid),
            detection_strategies=self.graph.get_detection_strategies(aid),
            data_sources=tech.get("data_sources", []) or self.graph.get_data_sources(aid),
            campaigns=self.graph.get_campaigns_for_technique(aid),
            d3fend=self.graph.get_d3fend_for_technique(aid),
            cooccurrence_boost=item.get("cooccurrence_boost", 0),
        )
