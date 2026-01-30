"""Hybrid query engine combining SPARQL and semantic search."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from rich.console import Console

from src.store.graph import AttackGraph
from src.query.semantic import SemanticSearchEngine, SemanticResult

console = Console()

# Entity type literals
EntityType = Literal["technique", "group", "software", "mitigation", "campaign", "tactic", "data_source"]


@dataclass
class EnrichedTechnique:
    """A technique with both semantic match info and graph-derived context."""

    attack_id: str
    name: str
    description: str
    similarity: float
    tactics: list[str]
    groups: list[dict[str, str]]
    mitigations: list[dict[str, str]]
    software: list[dict[str, str]]
    subtechniques: list[dict[str, str]]
    parent_technique: dict[str, str] | None = None
    # New fields for comprehensive coverage
    platforms: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    detection: str = ""
    detection_strategies: list[dict[str, str]] = field(default_factory=list)
    campaigns: list[dict[str, str]] = field(default_factory=list)
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "description": self.description,
            "similarity": self.similarity,
            "tactics": self.tactics,
            "groups": self.groups,
            "mitigations": self.mitigations,
            "software": self.software,
            "subtechniques": self.subtechniques,
            "parent_technique": self.parent_technique,
            "platforms": self.platforms,
            "data_sources": self.data_sources,
            "detection": self.detection,
            "detection_strategies": self.detection_strategies,
            "campaigns": self.campaigns,
            "url": self.url,
        }


@dataclass
class HybridQueryResult:
    """Result of a hybrid query combining semantic and graph results."""

    query: str
    techniques: list[EnrichedTechnique]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "techniques": [t.to_dict() for t in self.techniques],
            "metadata": self.metadata,
        }


class HybridQueryEngine:
    """
    Combines semantic search with SPARQL graph queries.

    This is the core neuro-symbolic query engine that:
    1. Uses vector similarity to find relevant techniques
    2. Uses SPARQL to enrich results with relationships
    3. Provides structured context for LLM reasoning
    """

    def __init__(
        self,
        graph_path: Path | str | None = None,
        vector_path: Path | str | None = None,
        embedding_model: str = "nomic-ai/nomic-embed-text-v1.5",
        *,
        graph: AttackGraph | None = None,
        semantic: SemanticSearchEngine | None = None,
    ):
        """
        Initialize the hybrid query engine.

        Args:
            graph_path: Path to Oxigraph persistent storage
            vector_path: Path to ChromaDB persistent storage
            embedding_model: Sentence transformer model
            graph: Existing AttackGraph instance (avoids lock conflicts)
            semantic: Existing SemanticSearchEngine instance
        """
        self.graph = graph if graph is not None else AttackGraph(graph_path)
        self.semantic = semantic if semantic is not None else SemanticSearchEngine(vector_path, embedding_model)

    def query(
        self,
        question: str,
        top_k: int = 5,
        enrich: bool = True,
    ) -> HybridQueryResult:
        """
        Execute a hybrid query.

        Args:
            question: Natural language question or finding description
            top_k: Number of technique results
            enrich: Whether to enrich with graph relationships

        Returns:
            HybridQueryResult with techniques and context
        """
        # Step 1: Semantic search for relevant techniques
        semantic_results = self.semantic.search(question, top_k=top_k)

        # Step 2: Enrich each result with graph data
        enriched_techniques = []
        for result in semantic_results:
            if enrich:
                enriched = self._enrich_technique(result)
            else:
                enriched = EnrichedTechnique(
                    attack_id=result.attack_id,
                    name=result.name,
                    description="",
                    similarity=result.similarity,
                    tactics=result.tactics,
                    groups=[],
                    mitigations=[],
                    software=[],
                    subtechniques=[],
                )
            enriched_techniques.append(enriched)

        return HybridQueryResult(
            query=question,
            techniques=enriched_techniques,
            metadata={
                "top_k": top_k,
                "enriched": enrich,
                "result_count": len(enriched_techniques),
            },
        )

    def _enrich_technique(self, semantic_result: SemanticResult) -> EnrichedTechnique:
        """Enrich a semantic result with graph relationships."""
        attack_id = semantic_result.attack_id

        # Get full technique info with all metadata
        tech_info = self.graph.get_technique_full(attack_id) or self.graph.get_technique(attack_id) or {}

        # Get related entities
        groups = self.graph.get_groups_using_technique(attack_id)
        mitigations = self.graph.get_mitigations_with_inheritance(attack_id)
        software = self.graph.get_software_using_technique(attack_id)
        subtechniques = self.graph.get_subtechniques(attack_id)

        # Get detection-related data
        detection_strategies = self.graph.get_detection_strategies_for_technique(attack_id)
        data_sources = tech_info.get("data_sources", []) or self.graph.get_data_sources_for_technique(attack_id)

        # Get campaigns using this technique
        campaigns = self.graph.get_campaigns_using_technique(attack_id)

        # Check if this is a sub-technique and get parent
        parent_technique = None
        if "." in attack_id:
            parent_id = attack_id.split(".")[0]
            parent_info = self.graph.get_technique(parent_id)
            if parent_info:
                parent_technique = {
                    "attack_id": parent_id,
                    "name": parent_info["name"],
                }

        return EnrichedTechnique(
            attack_id=attack_id,
            name=semantic_result.name,
            description=tech_info.get("description", ""),
            similarity=semantic_result.similarity,
            tactics=semantic_result.tactics,
            groups=groups,
            mitigations=mitigations,
            software=software,
            subtechniques=subtechniques,
            parent_technique=parent_technique,
            platforms=tech_info.get("platforms", []) or semantic_result.platforms,
            data_sources=data_sources,
            detection=tech_info.get("detection", ""),
            detection_strategies=detection_strategies,
            campaigns=campaigns,
            url=tech_info.get("url", ""),
        )

    def find_defenses_for_finding(
        self,
        finding_text: str,
        top_k: int = 3,
    ) -> dict[str, Any]:
        """
        Given a finding, suggest techniques and their mitigations.

        Primary use case: auto-tagging pentest findings with ATT&CK
        and providing defensive recommendations.

        Args:
            finding_text: Description of a security finding
            top_k: Number of techniques to consider

        Returns:
            Dictionary with techniques and consolidated mitigations
        """
        result = self.query(finding_text, top_k=top_k)

        # Consolidate unique mitigations across all matched techniques
        seen_mitigations = {}
        for tech in result.techniques:
            for mit in tech.mitigations:
                if mit["attack_id"] not in seen_mitigations:
                    seen_mitigations[mit["attack_id"]] = {
                        **mit,
                        "addresses_techniques": [tech.attack_id],
                    }
                else:
                    seen_mitigations[mit["attack_id"]]["addresses_techniques"].append(
                        tech.attack_id
                    )

        # Sort mitigations by how many techniques they address
        sorted_mitigations = sorted(
            seen_mitigations.values(),
            key=lambda m: len(m["addresses_techniques"]),
            reverse=True,
        )

        return {
            "finding": finding_text,
            "techniques": [
                {
                    "attack_id": t.attack_id,
                    "name": t.name,
                    "similarity": t.similarity,
                    "tactics": t.tactics,
                }
                for t in result.techniques
            ],
            "recommended_mitigations": sorted_mitigations,
        }

    def get_threat_context(
        self,
        technique_id: str,
    ) -> dict[str, Any]:
        """
        Get full threat context for a technique.

        Useful for understanding the threat landscape around a technique.

        Args:
            technique_id: ATT&CK technique ID

        Returns:
            Dictionary with full context including groups, software, etc.
        """
        tech_info = self.graph.get_technique(technique_id)
        if not tech_info:
            return {"error": f"Technique not found: {technique_id}"}

        groups = self.graph.get_groups_using_technique(technique_id)
        software = self.graph.get_software_using_technique(technique_id)
        mitigations = self.graph.get_mitigations_with_inheritance(technique_id)
        subtechniques = self.graph.get_subtechniques(technique_id)

        # Get similar techniques via semantic search
        similar = self.semantic.find_similar_techniques(technique_id, top_k=5)

        return {
            "technique": tech_info,
            "threat_actors": groups,
            "software": software,
            "mitigations": mitigations,
            "subtechniques": subtechniques,
            "similar_techniques": [s.to_dict() for s in similar],
        }

    def compare_groups(
        self,
        group1_id: str,
        group2_id: str,
    ) -> dict[str, Any]:
        """
        Compare techniques between two threat groups.

        Args:
            group1_id: First group ID (e.g., G0016)
            group2_id: Second group ID

        Returns:
            Dictionary with shared and unique techniques
        """
        techniques1 = {
            t["attack_id"]: t for t in self.graph.get_techniques_for_group(group1_id)
        }
        techniques2 = {
            t["attack_id"]: t for t in self.graph.get_techniques_for_group(group2_id)
        }

        shared_ids = set(techniques1.keys()) & set(techniques2.keys())
        only_group1 = set(techniques1.keys()) - set(techniques2.keys())
        only_group2 = set(techniques2.keys()) - set(techniques1.keys())

        return {
            "group1": group1_id,
            "group2": group2_id,
            "shared_techniques": [techniques1[tid] for tid in shared_ids],
            f"only_{group1_id}": [techniques1[tid] for tid in only_group1],
            f"only_{group2_id}": [techniques2[tid] for tid in only_group2],
            "similarity_score": len(shared_ids) / max(len(techniques1), len(techniques2), 1),
        }

    # -------------------------------------------------------------------------
    # Campaign-based queries
    # -------------------------------------------------------------------------

    def get_campaign_context(
        self,
        campaign_id: str,
    ) -> dict[str, Any]:
        """
        Get full context for a campaign including techniques, group, and timeline.

        Args:
            campaign_id: ATT&CK campaign ID (e.g., C0027)

        Returns:
            Dictionary with full campaign context
        """
        campaign = self.graph.get_campaign(campaign_id)
        if not campaign:
            return {"error": f"Campaign not found: {campaign_id}"}

        techniques = self.graph.get_techniques_for_campaign(campaign_id)
        attributed_group = self.graph.get_group_for_campaign(campaign_id)

        # Get tactics coverage for the campaign
        tactics_used = set()
        for tech in techniques:
            tech_info = self.graph.get_technique(tech["attack_id"])
            # Get tactics for this technique via semantic search metadata
            search_results = self.semantic.search(tech["name"], top_k=1)
            if search_results:
                tactics_used.update(search_results[0].tactics)

        # Consolidate mitigations across all techniques (with inheritance)
        all_mitigations = {}
        for tech in techniques:
            for mit in self.graph.get_mitigations_with_inheritance(tech["attack_id"]):
                if mit["attack_id"] not in all_mitigations:
                    all_mitigations[mit["attack_id"]] = {
                        **mit,
                        "addresses_techniques": [tech["attack_id"]],
                    }
                else:
                    all_mitigations[mit["attack_id"]]["addresses_techniques"].append(tech["attack_id"])

        return {
            "campaign": campaign,
            "attributed_group": attributed_group,
            "techniques": techniques,
            "techniques_count": len(techniques),
            "tactics_used": list(tactics_used),
            "mitigations": sorted(
                all_mitigations.values(),
                key=lambda m: len(m["addresses_techniques"]),
                reverse=True,
            ),
        }

    def find_similar_campaigns(
        self,
        campaign_id: str,
        min_overlap: float = 0.3,
    ) -> list[dict[str, Any]]:
        """
        Find campaigns that use similar techniques.

        Args:
            campaign_id: ATT&CK campaign ID
            min_overlap: Minimum technique overlap ratio (0-1)

        Returns:
            List of similar campaigns with overlap scores
        """
        target_techniques = set(
            t["attack_id"] for t in self.graph.get_techniques_for_campaign(campaign_id)
        )

        if not target_techniques:
            return []

        similar = []
        for campaign in self.graph.get_all_campaigns():
            if campaign["attack_id"] == campaign_id:
                continue

            camp_techniques = set(
                t["attack_id"] for t in self.graph.get_techniques_for_campaign(campaign["attack_id"])
            )

            if not camp_techniques:
                continue

            overlap = len(target_techniques & camp_techniques)
            overlap_ratio = overlap / len(target_techniques | camp_techniques)

            if overlap_ratio >= min_overlap:
                similar.append({
                    **campaign,
                    "shared_techniques_count": overlap,
                    "overlap_ratio": round(overlap_ratio, 3),
                })

        return sorted(similar, key=lambda c: c["overlap_ratio"], reverse=True)

    # -------------------------------------------------------------------------
    # Detection and data source queries
    # -------------------------------------------------------------------------

    def get_detection_coverage(
        self,
        data_sources: list[str],
    ) -> dict[str, Any]:
        """
        Analyze detection coverage based on available data sources.

        Args:
            data_sources: List of data sources you have available

        Returns:
            Dictionary with detectable and undetectable techniques
        """
        all_techniques = []
        # Get a representative set of techniques via broad search
        for tactic in ["initial-access", "execution", "persistence", "privilege-escalation",
                       "defense-evasion", "credential-access", "discovery", "lateral-movement",
                       "collection", "exfiltration", "command-and-control", "impact"]:
            all_techniques.extend(self.graph.get_techniques_for_tactic(tactic))

        # Deduplicate
        seen = set()
        unique_techniques = []
        for t in all_techniques:
            if t["attack_id"] not in seen:
                seen.add(t["attack_id"])
                unique_techniques.append(t)

        detectable = []
        not_detectable = []
        partial = []

        for tech in unique_techniques:
            tech_data_sources = self.graph.get_data_sources_for_technique(tech["attack_id"])

            if not tech_data_sources:
                not_detectable.append({**tech, "reason": "No data sources defined"})
                continue

            # Check how many of the technique's data sources we have
            matching = [ds for ds in tech_data_sources
                        if any(available.lower() in ds.lower() for available in data_sources)]

            coverage = len(matching) / len(tech_data_sources) if tech_data_sources else 0

            if coverage >= 1.0:
                detectable.append({**tech, "coverage": 1.0, "data_sources": tech_data_sources})
            elif coverage > 0:
                partial.append({
                    **tech,
                    "coverage": round(coverage, 2),
                    "available": matching,
                    "missing": [ds for ds in tech_data_sources if ds not in matching],
                })
            else:
                not_detectable.append({
                    **tech,
                    "required_data_sources": tech_data_sources,
                })

        return {
            "input_data_sources": data_sources,
            "fully_detectable": detectable,
            "partially_detectable": partial,
            "not_detectable": not_detectable,
            "coverage_summary": {
                "fully_detectable_count": len(detectable),
                "partially_detectable_count": len(partial),
                "not_detectable_count": len(not_detectable),
                "total_techniques": len(unique_techniques),
                "coverage_percentage": round(
                    (len(detectable) + len(partial) * 0.5) / max(len(unique_techniques), 1) * 100, 1
                ),
            },
        }

    def find_by_data_source(
        self,
        data_source: str,
        top_k: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Find techniques detectable by a specific data source.

        Args:
            data_source: Data source name (e.g., "Process Creation", "Network Traffic")
            top_k: Maximum number of results

        Returns:
            List of techniques with their detection strategies
        """
        techniques = self.graph.get_techniques_by_data_source(data_source)[:top_k]

        results = []
        for tech in techniques:
            detection_strategies = self.graph.get_detection_strategies_for_technique(tech["attack_id"])
            tech_info = self.graph.get_technique(tech["attack_id"]) or {}

            results.append({
                **tech,
                "detection_guidance": tech_info.get("detection", ""),
                "detection_strategies_count": len(detection_strategies),
            })

        return results

    # -------------------------------------------------------------------------
    # Platform and tactic analysis
    # -------------------------------------------------------------------------

    def get_attack_surface(
        self,
        platforms: list[str],
    ) -> dict[str, Any]:
        """
        Analyze the attack surface for specific platforms.

        Args:
            platforms: List of platforms (e.g., ["Windows", "Linux"])

        Returns:
            Dictionary with techniques organized by tactic
        """
        techniques_by_tactic: dict[str, list[dict]] = {}

        for platform in platforms:
            for tech in self.graph.get_techniques_by_platform(platform):
                # Get tactics for this technique
                results = self.semantic.search(tech["name"], top_k=1)
                if results:
                    for tactic in results[0].tactics:
                        if tactic not in techniques_by_tactic:
                            techniques_by_tactic[tactic] = []
                        if not any(t["attack_id"] == tech["attack_id"] for t in techniques_by_tactic[tactic]):
                            techniques_by_tactic[tactic].append({
                                **tech,
                                "platforms": [platform],
                            })
                        else:
                            # Add platform to existing technique
                            for t in techniques_by_tactic[tactic]:
                                if t["attack_id"] == tech["attack_id"]:
                                    if platform not in t["platforms"]:
                                        t["platforms"].append(platform)

        # Order tactics by kill chain
        kill_chain_order = [
            "reconnaissance", "resource-development", "initial-access", "execution",
            "persistence", "privilege-escalation", "defense-evasion", "credential-access",
            "discovery", "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact"
        ]

        ordered_tactics = {}
        for tactic in kill_chain_order:
            if tactic in techniques_by_tactic:
                ordered_tactics[tactic] = techniques_by_tactic[tactic]

        # Add any tactics not in the standard order
        for tactic, techniques in techniques_by_tactic.items():
            if tactic not in ordered_tactics:
                ordered_tactics[tactic] = techniques

        return {
            "platforms": platforms,
            "techniques_by_tactic": ordered_tactics,
            "total_techniques": sum(len(t) for t in techniques_by_tactic.values()),
            "tactics_covered": list(ordered_tactics.keys()),
        }

    def analyze_kill_chain(
        self,
        finding_text: str,
        phases: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Analyze a finding across the kill chain to understand attack progression.

        Args:
            finding_text: Security finding or incident description
            phases: Optional specific phases to analyze (defaults to all)

        Returns:
            Dictionary with technique matches across kill chain phases
        """
        if phases is None:
            phases = [
                "initial-access", "execution", "persistence", "privilege-escalation",
                "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact"
            ]

        # Get semantic matches
        semantic_results = self.semantic.search(finding_text, top_k=15)

        # Organize by tactic
        by_phase: dict[str, list[dict]] = {phase: [] for phase in phases}

        for result in semantic_results:
            for tactic in result.tactics:
                if tactic in by_phase:
                    by_phase[tactic].append({
                        "attack_id": result.attack_id,
                        "name": result.name,
                        "similarity": round(result.similarity, 3),
                    })

        # Find the most likely attack path
        attack_path = []
        for phase in phases:
            if by_phase[phase]:
                best_match = max(by_phase[phase], key=lambda x: x["similarity"])
                attack_path.append({
                    "phase": phase,
                    **best_match,
                })

        return {
            "finding": finding_text,
            "matches_by_phase": {k: v for k, v in by_phase.items() if v},
            "likely_attack_path": attack_path,
            "phases_identified": [p for p in phases if by_phase[p]],
            "coverage": len([p for p in phases if by_phase[p]]) / len(phases),
        }

    # -------------------------------------------------------------------------
    # Group and software analysis
    # -------------------------------------------------------------------------

    def get_group_profile(
        self,
        group_id: str,
    ) -> dict[str, Any]:
        """
        Get a comprehensive profile of a threat group.

        Args:
            group_id: ATT&CK group ID (e.g., G0016, APT29)

        Returns:
            Dictionary with full group profile
        """
        # Try to find group by ID or name
        group_info = self.graph.get_group_full(group_id)

        if not group_info:
            # Try searching by name
            matches = self.graph.find_group_by_name(group_id)
            if matches:
                group_id = matches[0]["attack_id"]
                group_info = self.graph.get_group_full(group_id)

        if not group_info:
            return {"error": f"Group not found: {group_id}"}

        techniques = self.graph.get_techniques_for_group(group_id)
        campaigns = self.graph.get_campaigns_for_group(group_id)

        # Analyze tactics used
        tactics_count: dict[str, int] = {}
        for tech in techniques:
            results = self.semantic.search(tech["name"], top_k=1)
            if results:
                for tactic in results[0].tactics:
                    tactics_count[tactic] = tactics_count.get(tactic, 0) + 1

        # Get software used by this group
        software_sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?type WHERE {{
            <https://attack.mitre.org/group/{group_id}> attack:uses ?software .
            ?software a ?type ;
                      attack:attackId ?attackId ;
                      rdfs:label ?name .
            FILTER(?type IN (attack:Malware, attack:Tool))
        }}
        ORDER BY ?name
        """
        software = [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "type": "Malware" if "Malware" in r.get("type", "") else "Tool",
            }
            for r in self.graph.query(software_sparql)
        ]

        return {
            "group": group_info,
            "techniques": techniques,
            "techniques_count": len(techniques),
            "campaigns": campaigns,
            "campaigns_count": len(campaigns),
            "software": software,
            "software_count": len(software),
            "tactics_distribution": dict(sorted(tactics_count.items(), key=lambda x: -x[1])),
            "primary_tactics": [t for t, c in sorted(tactics_count.items(), key=lambda x: -x[1])[:3]],
        }

    def find_groups_by_technique_pattern(
        self,
        technique_ids: list[str],
        min_match: int = 2,
    ) -> list[dict[str, Any]]:
        """
        Find threat groups that use a specific set of techniques.

        Args:
            technique_ids: List of technique IDs to search for
            min_match: Minimum number of techniques that must match

        Returns:
            List of groups with match counts
        """
        # Get all groups
        groups_sparql = """
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {
            ?group a attack:Group ;
                   attack:attackId ?attackId ;
                   rdfs:label ?name .
        }
        """
        all_groups = self.graph.query(groups_sparql)

        results = []
        for group in all_groups:
            group_techniques = set(
                t["attack_id"] for t in self.graph.get_techniques_for_group(group["attackId"])
            )

            matching = [tid for tid in technique_ids if tid in group_techniques]

            if len(matching) >= min_match:
                results.append({
                    "attack_id": group["attackId"],
                    "name": group["name"],
                    "matching_techniques": matching,
                    "match_count": len(matching),
                    "match_ratio": round(len(matching) / len(technique_ids), 2),
                })

        return sorted(results, key=lambda x: x["match_count"], reverse=True)

    def get_software_profile(
        self,
        software_id: str,
    ) -> dict[str, Any]:
        """
        Get a comprehensive profile of malware or tool.

        Args:
            software_id: ATT&CK software ID (e.g., S0154)

        Returns:
            Dictionary with full software profile
        """
        software_info = self.graph.get_software_full(software_id)

        if not software_info:
            # Try searching by name
            matches = self.graph.find_software_by_name(software_id)
            if matches:
                software_id = matches[0]["attack_id"]
                software_info = self.graph.get_software_full(software_id)

        if not software_info:
            return {"error": f"Software not found: {software_id}"}

        # Get techniques used by this software
        software_uri = f"<https://attack.mitre.org/software/{software_id}>"
        techniques_sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            {software_uri} attack:uses ?technique .
            ?technique a attack:Technique ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
        }}
        ORDER BY ?attackId
        """
        techniques = [
            {"attack_id": r["attackId"], "name": r["name"]}
            for r in self.graph.query(techniques_sparql)
        ]

        # Get groups that use this software
        groups_sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            ?group a attack:Group ;
                   attack:uses {software_uri} ;
                   attack:attackId ?attackId ;
                   rdfs:label ?name .
        }}
        ORDER BY ?name
        """
        groups = [
            {"attack_id": r["attackId"], "name": r["name"]}
            for r in self.graph.query(groups_sparql)
        ]

        # Analyze tactics
        tactics_count: dict[str, int] = {}
        for tech in techniques:
            results = self.semantic.search(tech["name"], top_k=1)
            if results:
                for tactic in results[0].tactics:
                    tactics_count[tactic] = tactics_count.get(tactic, 0) + 1

        return {
            "software": software_info,
            "techniques": techniques,
            "techniques_count": len(techniques),
            "used_by_groups": groups,
            "groups_count": len(groups),
            "tactics_distribution": dict(sorted(tactics_count.items(), key=lambda x: -x[1])),
        }

    # -------------------------------------------------------------------------
    # Comprehensive entity search and listing
    # -------------------------------------------------------------------------

    def list_entities(
        self,
        entity_type: EntityType,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List all entities of a given type.

        Args:
            entity_type: Type of entity to list
            limit: Maximum number of results

        Returns:
            List of entities with basic info
        """
        type_map = {
            "technique": "attack:Technique",
            "group": "attack:Group",
            "software": "attack:Software",
            "mitigation": "attack:Mitigation",
            "campaign": "attack:Campaign",
            "tactic": "attack:Tactic",
            "data_source": "attack:DataSource",
        }

        rdf_type = type_map.get(entity_type)
        if not rdf_type:
            return []

        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?description WHERE {{
            ?entity a {rdf_type} ;
                    rdfs:label ?name .
            OPTIONAL {{ ?entity attack:attackId ?attackId }}
            OPTIONAL {{ ?entity attack:description ?description }}
        }}
        ORDER BY ?attackId ?name
        LIMIT {limit}
        """

        results = []
        for r in self.graph.query(sparql):
            results.append({
                "attack_id": r.get("attackId", ""),
                "name": r["name"],
                "description": r.get("description", ""),
            })

        return results

    def search_entities(
        self,
        query: str,
        entity_types: list[EntityType] | None = None,
        top_k: int = 10,
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Search across multiple entity types using semantic and text matching.

        Args:
            query: Search query (natural language or keyword)
            entity_types: Types to search (defaults to all)
            top_k: Maximum results per type

        Returns:
            Dictionary with results organized by entity type
        """
        if entity_types is None:
            entity_types = ["technique", "group", "software", "mitigation", "campaign"]

        results: dict[str, list[dict[str, Any]]] = {}

        # Techniques use semantic search
        if "technique" in entity_types:
            semantic_results = self.semantic.search(query, top_k=top_k)
            results["techniques"] = [
                {
                    "attack_id": r.attack_id,
                    "name": r.name,
                    "similarity": round(r.similarity, 3),
                    "tactics": r.tactics,
                }
                for r in semantic_results
            ]

        # Other entities use text search
        query_escaped = query.replace('"', '\\"')

        if "group" in entity_types:
            results["groups"] = self.graph.find_group_by_name(query)[:top_k]

        if "software" in entity_types:
            results["software"] = self.graph.find_software_by_name(query)[:top_k]

        if "mitigation" in entity_types:
            sparql = f"""
            PREFIX attack: <https://attack.mitre.org/>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

            SELECT ?attackId ?name WHERE {{
                ?mit a attack:Mitigation ;
                     attack:attackId ?attackId ;
                     rdfs:label ?name .
                FILTER(CONTAINS(LCASE(?name), LCASE("{query_escaped}")))
            }}
            ORDER BY ?name
            LIMIT {top_k}
            """
            results["mitigations"] = [
                {"attack_id": r["attackId"], "name": r["name"]}
                for r in self.graph.query(sparql)
            ]

        if "campaign" in entity_types:
            sparql = f"""
            PREFIX attack: <https://attack.mitre.org/>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

            SELECT ?attackId ?name ?firstSeen WHERE {{
                ?camp a attack:Campaign ;
                      attack:attackId ?attackId ;
                      rdfs:label ?name .
                OPTIONAL {{ ?camp attack:firstSeen ?firstSeen }}
                FILTER(CONTAINS(LCASE(?name), LCASE("{query_escaped}")))
            }}
            ORDER BY ?name
            LIMIT {top_k}
            """
            results["campaigns"] = [
                {
                    "attack_id": r["attackId"],
                    "name": r["name"],
                    "first_seen": r.get("firstSeen", ""),
                }
                for r in self.graph.query(sparql)
            ]

        return results

    def get_entity(
        self,
        attack_id: str,
        entity_type: EntityType | None = None,
    ) -> dict[str, Any] | None:
        """
        Get full details for any entity by ID.

        Args:
            attack_id: ATT&CK ID (e.g., T1110.003, G0016, S0154)
            entity_type: Optional type hint (auto-detected if not provided)

        Returns:
            Full entity details or None if not found
        """
        # Auto-detect type from ID prefix if not provided
        if entity_type is None:
            if attack_id.startswith("T"):
                entity_type = "technique"
            elif attack_id.startswith("G"):
                entity_type = "group"
            elif attack_id.startswith("S"):
                entity_type = "software"
            elif attack_id.startswith("M"):
                entity_type = "mitigation"
            elif attack_id.startswith("C"):
                entity_type = "campaign"
            elif attack_id.startswith("TA"):
                entity_type = "tactic"
            elif attack_id.startswith("DS"):
                entity_type = "data_source"

        if entity_type == "technique":
            return self.graph.get_technique_full(attack_id)
        elif entity_type == "group":
            return self.graph.get_group_full(attack_id)
        elif entity_type == "software":
            return self.graph.get_software_full(attack_id)
        elif entity_type == "mitigation":
            return self.graph.get_mitigation_full(attack_id)
        elif entity_type == "campaign":
            return self.graph.get_campaign(attack_id)
        elif entity_type == "tactic":
            tactics = self.graph.get_all_tactics()
            return next((t for t in tactics if t.get("attack_id") == attack_id), None)

        return None

    def get_relationships(
        self,
        attack_id: str,
        entity_type: EntityType | None = None,
    ) -> dict[str, Any]:
        """
        Get all relationships for an entity.

        Args:
            attack_id: ATT&CK ID
            entity_type: Optional type hint

        Returns:
            Dictionary with all related entities organized by relationship type
        """
        # Auto-detect type
        if entity_type is None:
            if attack_id.startswith("T"):
                entity_type = "technique"
            elif attack_id.startswith("G"):
                entity_type = "group"
            elif attack_id.startswith("S"):
                entity_type = "software"
            elif attack_id.startswith("M"):
                entity_type = "mitigation"
            elif attack_id.startswith("C"):
                entity_type = "campaign"

        relationships: dict[str, Any] = {"entity_id": attack_id, "entity_type": entity_type}

        if entity_type == "technique":
            relationships["groups"] = self.graph.get_groups_using_technique(attack_id)
            relationships["software"] = self.graph.get_software_using_technique(attack_id)
            relationships["mitigations"] = self.graph.get_mitigations_with_inheritance(attack_id)
            relationships["campaigns"] = self.graph.get_campaigns_using_technique(attack_id)
            relationships["subtechniques"] = self.graph.get_subtechniques(attack_id)
            relationships["detection_strategies"] = self.graph.get_detection_strategies_for_technique(attack_id)

            # Parent technique if sub-technique
            if "." in attack_id:
                parent_id = attack_id.split(".")[0]
                parent = self.graph.get_technique(parent_id)
                if parent:
                    relationships["parent_technique"] = {"attack_id": parent_id, "name": parent["name"]}

        elif entity_type == "group":
            relationships["techniques"] = self.graph.get_techniques_for_group(attack_id)
            relationships["campaigns"] = self.graph.get_campaigns_for_group(attack_id)

            # Software used
            software_sparql = f"""
            PREFIX attack: <https://attack.mitre.org/>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

            SELECT ?attackId ?name ?type WHERE {{
                <https://attack.mitre.org/group/{attack_id}> attack:uses ?software .
                ?software a ?type ;
                          attack:attackId ?attackId ;
                          rdfs:label ?name .
                FILTER(?type IN (attack:Malware, attack:Tool))
            }}
            """
            relationships["software"] = [
                {
                    "attack_id": r["attackId"],
                    "name": r["name"],
                    "type": "Malware" if "Malware" in r.get("type", "") else "Tool",
                }
                for r in self.graph.query(software_sparql)
            ]

        elif entity_type == "software":
            # Techniques used
            software_uri = f"<https://attack.mitre.org/software/{attack_id}>"
            techniques_sparql = f"""
            PREFIX attack: <https://attack.mitre.org/>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

            SELECT ?attackId ?name WHERE {{
                {software_uri} attack:uses ?technique .
                ?technique a attack:Technique ;
                           attack:attackId ?attackId ;
                           rdfs:label ?name .
            }}
            """
            relationships["techniques"] = [
                {"attack_id": r["attackId"], "name": r["name"]}
                for r in self.graph.query(techniques_sparql)
            ]

            # Groups using this software
            groups_sparql = f"""
            PREFIX attack: <https://attack.mitre.org/>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

            SELECT ?attackId ?name WHERE {{
                ?group a attack:Group ;
                       attack:uses {software_uri} ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
            }}
            """
            relationships["used_by_groups"] = [
                {"attack_id": r["attackId"], "name": r["name"]}
                for r in self.graph.query(groups_sparql)
            ]

        elif entity_type == "mitigation":
            # Techniques mitigated
            mit_uri = f"<https://attack.mitre.org/mitigation/{attack_id}>"
            sparql = f"""
            PREFIX attack: <https://attack.mitre.org/>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

            SELECT ?attackId ?name WHERE {{
                {mit_uri} attack:mitigates ?technique .
                ?technique a attack:Technique ;
                           attack:attackId ?attackId ;
                           rdfs:label ?name .
            }}
            """
            relationships["mitigates_techniques"] = [
                {"attack_id": r["attackId"], "name": r["name"]}
                for r in self.graph.query(sparql)
            ]

        elif entity_type == "campaign":
            relationships["techniques"] = self.graph.get_techniques_for_campaign(attack_id)
            relationships["attributed_to"] = self.graph.get_group_for_campaign(attack_id)

        return relationships

    def get_knowledge_base_summary(self) -> dict[str, Any]:
        """
        Get a comprehensive summary of the knowledge base.

        Returns:
            Dictionary with statistics and metadata about the knowledge base
        """
        stats = self.graph.get_stats()
        tactics = self.graph.get_all_tactics()
        platforms = self.graph.get_all_platforms()
        campaigns = self.graph.get_all_campaigns()

        # Get date range of campaigns
        campaign_dates = []
        for camp in campaigns:
            if camp.get("first_seen"):
                campaign_dates.append(camp["first_seen"])
            if camp.get("last_seen"):
                campaign_dates.append(camp["last_seen"])

        return {
            "statistics": stats,
            "tactics": [{"name": t["name"], "shortname": t.get("shortname", "")} for t in tactics],
            "platforms": platforms,
            "campaigns_count": len(campaigns),
            "campaign_date_range": {
                "earliest": min(campaign_dates) if campaign_dates else None,
                "latest": max(campaign_dates) if campaign_dates else None,
            },
            "vector_store_count": self.semantic.store.count() if hasattr(self.semantic, 'store') else 0,
        }

    def find_related_to_finding(
        self,
        finding_text: str,
        expand_relationships: bool = True,
    ) -> dict[str, Any]:
        """
        Find all entities related to a security finding.

        This is a comprehensive search that finds techniques, groups, software,
        campaigns, and mitigations relevant to the finding.

        Args:
            finding_text: Security finding or incident description
            expand_relationships: Whether to include related entities

        Returns:
            Comprehensive results with all related entities
        """
        # Get matching techniques
        result = self.query(finding_text, top_k=5, enrich=True)

        # Consolidate related entities across all techniques
        all_groups: dict[str, dict] = {}
        all_software: dict[str, dict] = {}
        all_mitigations: dict[str, dict] = {}
        all_campaigns: dict[str, dict] = {}

        for tech in result.techniques:
            for g in tech.groups:
                if g["attack_id"] not in all_groups:
                    all_groups[g["attack_id"]] = {**g, "related_techniques": [tech.attack_id]}
                else:
                    all_groups[g["attack_id"]]["related_techniques"].append(tech.attack_id)

            for s in tech.software:
                if s["attack_id"] not in all_software:
                    all_software[s["attack_id"]] = {**s, "related_techniques": [tech.attack_id]}
                else:
                    all_software[s["attack_id"]]["related_techniques"].append(tech.attack_id)

            for m in tech.mitigations:
                if m["attack_id"] not in all_mitigations:
                    all_mitigations[m["attack_id"]] = {**m, "related_techniques": [tech.attack_id]}
                else:
                    all_mitigations[m["attack_id"]]["related_techniques"].append(tech.attack_id)

            for c in tech.campaigns:
                if c["attack_id"] not in all_campaigns:
                    all_campaigns[c["attack_id"]] = {**c, "related_techniques": [tech.attack_id]}
                else:
                    all_campaigns[c["attack_id"]]["related_techniques"].append(tech.attack_id)

        # Sort by number of related techniques
        sorted_groups = sorted(all_groups.values(), key=lambda x: len(x["related_techniques"]), reverse=True)
        sorted_software = sorted(all_software.values(), key=lambda x: len(x["related_techniques"]), reverse=True)
        sorted_mitigations = sorted(all_mitigations.values(), key=lambda x: len(x["related_techniques"]), reverse=True)
        sorted_campaigns = sorted(all_campaigns.values(), key=lambda x: len(x["related_techniques"]), reverse=True)

        return {
            "finding": finding_text,
            "techniques": [t.to_dict() for t in result.techniques],
            "related_groups": sorted_groups,
            "related_software": sorted_software,
            "recommended_mitigations": sorted_mitigations,
            "related_campaigns": sorted_campaigns,
            "summary": {
                "techniques_found": len(result.techniques),
                "groups_involved": len(sorted_groups),
                "software_involved": len(sorted_software),
                "mitigations_available": len(sorted_mitigations),
                "campaigns_related": len(sorted_campaigns),
            },
        }
