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
from src.query.router import FindingType, route_finding

console = Console()

# CVE/CWE pattern detection
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_PATTERN = re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE)

# Vulnerability keyword → ATT&CK technique mapping
# (compiled regex, list of technique IDs)
VULN_KEYWORD_TECHNIQUES: list[tuple[re.Pattern, list[str]]] = [
    # Authentication / credential attacks
    (re.compile(r"\bauthentication bypass\b", re.I), ["T1190", "T1556"]),
    (re.compile(r"\bbrute.?force\b", re.I), ["T1110"]),
    (re.compile(r"\bcredential.?stuff(?:ing)?\b", re.I), ["T1110.004"]),
    (re.compile(r"\bpassword spray(?:ing)?\b", re.I), ["T1110.003"]),
    (re.compile(r"\bdefault.?(?:credential|password)\b", re.I), ["T1078.001"]),
    (re.compile(r"\bsession.?(?:fixation|hijack)\b", re.I), ["T1550.004"]),
    (re.compile(r"\btoken.?(?:theft|forgery|replay)\b", re.I), ["T1528"]),
    # Injection / code execution
    (re.compile(r"\bremote code execution|RCE\b", re.I), ["T1190", "T1203"]),
    (re.compile(r"\bSQL.?injection\b", re.I), ["T1190"]),
    (re.compile(r"\bcommand.?injection\b", re.I), ["T1059"]),
    (re.compile(r"\bcode.?injection\b", re.I), ["T1055"]),
    (re.compile(r"\bXSS|cross.?site.?script\b", re.I), ["T1059.007"]),
    (re.compile(r"\bdeserialization\b", re.I), ["T1190"]),
    (re.compile(r"\btemplate.?injection\b", re.I), ["T1221"]),
    (re.compile(r"\bSSRF|server.?side.?request\b", re.I), ["T1090"]),
    # Buffer / memory
    (re.compile(r"\bbuffer.?overflow\b", re.I), ["T1190", "T1203"]),
    (re.compile(r"\bheap.?overflow\b", re.I), ["T1203"]),
    (re.compile(r"\buse.?after.?free\b", re.I), ["T1203"]),
    # Privilege escalation
    (re.compile(r"\bprivilege.?escalation|privesc\b", re.I), ["T1068"]),
    (re.compile(r"\bSUID|setuid\b", re.I), ["T1548.001"]),
    # File / path
    (re.compile(r"\bpath.?traversal|directory.?traversal\b", re.I), ["T1083"]),
    (re.compile(r"\bfile.?(?:upload|inclusion)\b", re.I), ["T1190"]),
    (re.compile(r"\bLFI|RFI\b"), ["T1190"]),
    # Misconfiguration
    (re.compile(r"\bmisconfigur(?:ation|ed)\b", re.I), ["T1574"]),
    (re.compile(r"\bopen.?redirect\b", re.I), ["T1189"]),
    (re.compile(r"\binsecure.?(?:default|permission|config)\b", re.I), ["T1574"]),
    (re.compile(r"\bexposed.?(?:service|port|endpoint|interface|api)\b", re.I), ["T1190"]),
    (re.compile(r"\b(?:login|admin|management).?(?:page|panel|portal|console|interface).?(?:exposed|accessible|public|internet)\b", re.I), ["T1190", "T1078"]),
    (re.compile(r"\b(?:exposed|accessible|public).{0,20}(?:login|admin|management|authentication)\b", re.I), ["T1190", "T1078"]),
    (re.compile(r"\bimproper.?access.?control\b", re.I), ["T1078"]),
    # Cloud-specific
    (re.compile(r"\bIAM.?misconfigur\b", re.I), ["T1078", "T1098"]),
    (re.compile(r"\bS3.?bucket.?(?:exposed|public|open)\b", re.I), ["T1530"]),
    (re.compile(r"\b(?:metadata.?service|IMDS)\b", re.I), ["T1552.005"]),
    # Container/K8s
    (re.compile(r"\bcontainer.?escape\b", re.I), ["T1611"]),
    (re.compile(r"\bprivileged.?container\b", re.I), ["T1611"]),
    # Cryptographic
    (re.compile(r"\bweak.?(?:encryption|cipher)\b", re.I), ["T1573"]),
    (re.compile(r"\bcertificate.?(?:validation|verify|bypass)\b", re.I), ["T1553.004"]),
    # Data exposure
    (re.compile(r"\binformation.?(?:disclosure|leak(?:age)?)\b", re.I), ["T1005"]),
    (re.compile(r"\bsensitive.?data.?(?:exposed|exposure)\b", re.I), ["T1005"]),
    # Denial of service
    (re.compile(r"\bdenial.?of.?service|DoS\b", re.I), ["T1499"]),
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
        self._sw_index: dict[str, str] | None = None  # lowered name → software_id
        self._sw_pattern: re.Pattern | None = None

    @property
    def keyword(self) -> KeywordSearch | None:
        if self._keyword is None and self._enable_bm25:
            self._keyword = KeywordSearch(self.graph)
        return self._keyword

    def query(
        self, question: str, top_k: int = 5, enrich: bool = True,
        use_bm25: bool = True, use_cooccurrence: bool = True,
    ) -> QueryResult:
        # Step 0: Route finding type
        routing = route_finding(question)
        is_vuln = routing.finding_type == FindingType.VULNERABILITY

        # Adjust parameters based on finding type
        if is_vuln:
            use_cooccurrence = False
            cwe_boost = 2.0
            vuln_kw_boost = 1.8
        else:
            cwe_boost = 1.4
            vuln_kw_boost = 1.3

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
            combined = self._inject_cwe_techniques(combined, cwe_techniques, boost=cwe_boost)

        # Step 4c: Vulnerability keyword technique injection
        combined = self._inject_vuln_techniques(combined, question, boost=vuln_kw_boost)

        # Step 4d: Software/tool name technique injection
        sw_techniques = self._extract_software_techniques(question)
        if sw_techniques:
            combined = self._inject_software_techniques(combined, sw_techniques, boost=1.5)

        # Step 4e: Platform-aware boosting
        if routing.platforms:
            combined = self._boost_platform_match(combined, routing.platforms)

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
        if sw_techniques:
            mode += "+software"
        metadata = {
            "top_k": top_k, "mode": mode, "count": len(techniques),
            "finding_type": routing.finding_type.value,
            "routing_confidence": routing.confidence,
            "routing_signals": routing.signals,
        }
        return QueryResult(query=question, techniques=techniques, metadata=metadata)

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

    def _inject_vuln_techniques(
        self, combined: list[dict], text: str, boost: float = 1.3,
    ) -> list[dict]:
        """Inject techniques matched by vulnerability keyword patterns."""
        matched_ids: set[str] = set()
        for pattern, tech_ids in VULN_KEYWORD_TECHNIQUES:
            if pattern.search(text):
                matched_ids.update(tech_ids)
        if not matched_ids:
            return combined
        existing = {item["attack_id"] for item in combined}
        for aid in matched_ids:
            if aid in existing:
                for item in combined:
                    if item["attack_id"] == aid:
                        item["rrf_score"] = item.get("rrf_score", 0) * boost
                        item["vuln_kw_boost"] = True
                        break
            else:
                combined.append({
                    "attack_id": aid, "name": "",
                    "tactics": [], "platforms": [],
                    "rrf_score": 0.01 * boost,
                    "vuln_kw_boost": True,
                })
        combined.sort(key=lambda x: x.get("rrf_score", 0), reverse=True)
        return combined

    def _boost_platform_match(
        self, combined: list[dict], platforms: list[str], boost: float = 1.2,
    ) -> list[dict]:
        """Boost candidates whose platforms overlap with detected platforms."""
        platform_set = set(platforms)
        for item in combined:
            item_platforms = set(item.get("platforms", []))
            if item_platforms & platform_set:
                item["rrf_score"] = item.get("rrf_score", 0) * boost
                item["platform_boost"] = True
        combined.sort(key=lambda x: x.get("rrf_score", 0), reverse=True)
        return combined

    # Common English words that happen to be ATT&CK software names.
    # These only match with a qualifying suffix like .exe.
    _SW_COMMON_WORDS = frozenset({
        "at", "net", "cmd", "arp", "ftp", "tor", "page", "epic", "spark",
        "anchor", "gold", "iron", "carbon", "agent", "rover", "matrix",
        "ace", "get", "set", "run",
    })

    @property
    def _software_index(self) -> tuple[dict[str, str], re.Pattern | None]:
        """Lazy-init software name → ID index + compiled match pattern."""
        if self._sw_index is None:
            idx: dict[str, str] = {}
            for sw in self.graph.get_all_software_names():
                name = sw["name"]
                # Skip very short names that cause false positives
                if len(name) < 3:
                    continue
                low = name.lower()
                # Common words only match with .exe suffix (handled separately)
                if low in self._SW_COMMON_WORDS:
                    idx[low + ".exe"] = sw["attack_id"]
                    continue
                idx[low] = sw["attack_id"]
            self._sw_index = idx
            if idx:
                # Build regex alternation sorted longest-first for greedy matching
                escaped = [re.escape(n) for n in sorted(idx, key=len, reverse=True)]
                self._sw_pattern = re.compile(
                    r"\b(?:" + "|".join(escaped) + r")\b", re.IGNORECASE,
                )
            console.print(f"[dim]Software index: {len(idx)} names/aliases[/dim]")
        return self._sw_index, self._sw_pattern

    def _extract_software_techniques(self, text: str) -> list[dict]:
        """Extract mentioned software/tool names and map to techniques."""
        idx, pattern = self._software_index
        if not pattern:
            return []
        matches = pattern.findall(text)
        if not matches:
            return []
        # Deduplicate software IDs, then look up techniques
        sw_ids = {idx[m.lower()] for m in matches if m.lower() in idx}
        techniques: list[dict] = []
        seen: set[str] = set()
        for sid in sw_ids:
            for t in self.graph.get_techniques_for_software(sid):
                if t["attack_id"] not in seen:
                    seen.add(t["attack_id"])
                    techniques.append(t)
        if techniques:
            names = sorted({m for m in matches})
            console.print(f"[cyan]Software match: {', '.join(names)} -> "
                          f"{len(techniques)} techniques[/cyan]")
        return techniques

    def _inject_software_techniques(
        self, combined: list[dict], sw_techniques: list[dict],
        boost: float = 1.5,
    ) -> list[dict]:
        """Inject/boost techniques derived from software name matches."""
        existing = {item["attack_id"] for item in combined}
        for t in sw_techniques:
            aid = t["attack_id"]
            if aid in existing:
                for item in combined:
                    if item["attack_id"] == aid:
                        item["rrf_score"] = item.get("rrf_score", 0) * boost
                        item["software_boost"] = True
                        break
            else:
                combined.append({
                    "attack_id": aid, "name": t.get("name", ""),
                    "tactics": [], "platforms": [],
                    "rrf_score": 0.01 * boost,
                    "software_boost": True,
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
