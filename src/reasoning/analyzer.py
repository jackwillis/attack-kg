"""Attack narrative analyzer for classifying findings with MITRE ATT&CK techniques."""

import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@dataclass
class TechniqueMatch:
    """A technique identified in the attack narrative."""

    attack_id: str
    name: str
    confidence: str  # "high", "medium", "low"
    evidence: str
    tactics: list[str]
    groups: list[dict[str, str]] = field(default_factory=list)


@dataclass
class RemediationItem:
    """A prioritized remediation recommendation."""

    mitigation_id: str
    name: str
    priority: str  # "HIGH", "MEDIUM", "LOW"
    addresses: list[str]  # technique IDs
    implementation: str


@dataclass
class DetectionRecommendation:
    """A detection recommendation based on data sources."""

    data_source: str
    rationale: str
    techniques_covered: list[str]


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    finding: str
    techniques: list[TechniqueMatch]
    remediations: list[RemediationItem]
    detection_recommendations: list[DetectionRecommendation] = field(default_factory=list)
    finding_type: str = "attack_narrative"  # "attack_narrative" or "vulnerability"
    kill_chain_analysis: str = ""
    raw_llm_response: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding,
            "finding_type": self.finding_type,
            "techniques": [
                {
                    "attack_id": t.attack_id,
                    "name": t.name,
                    "confidence": t.confidence,
                    "evidence": t.evidence,
                    "tactics": t.tactics,
                    "groups": t.groups,
                }
                for t in self.techniques
            ],
            "remediations": [
                {
                    "mitigation_id": r.mitigation_id,
                    "name": r.name,
                    "priority": r.priority,
                    "addresses": r.addresses,
                    "implementation": r.implementation,
                }
                for r in self.remediations
            ],
            "detection_recommendations": [
                {
                    "data_source": d.data_source,
                    "rationale": d.rationale,
                    "techniques_covered": d.techniques_covered,
                }
                for d in self.detection_recommendations
            ],
            "kill_chain_analysis": self.kill_chain_analysis,
        }


# Prompts for classification and remediation
CLASSIFICATION_SYSTEM_PROMPT = """You are a cybersecurity analyst expert in MITRE ATT&CK framework.
Your task is to analyze security findings and identify relevant ATT&CK techniques.

You will be given:
1. A security finding - this may be an attack narrative OR a vulnerability/misconfiguration report
2. A list of candidate techniques with their descriptions from the ATT&CK knowledge base
3. Context including: platforms targeted, threat groups known to use each technique, campaigns that have used them, and data sources for detection

IMPORTANT: Handle TWO types of findings differently:

**Attack Narratives** (evidence of actual adversary activity):
- Identify techniques with clear evidence from the narrative
- Use confidence levels based on how explicitly the technique is demonstrated
- Evidence should describe what the attacker DID

**Vulnerability/Misconfiguration Findings** (security weaknesses, no attack yet):
- Identify techniques that COULD exploit this vulnerability
- Use confidence levels based on how directly the vulnerability enables the technique
- Evidence should describe HOW an attacker could leverage this weakness
- Mark these as "potential" in the evidence field (e.g., "Exposed admin login could enable...")

For each relevant technique, provide:
- Confidence level (high/medium/low)
- Specific evidence - either observed behavior OR potential exploitation path
- The technique's associated tactics

Consider the additional context:
- If the finding mentions specific platforms, prioritize techniques targeting those platforms
- If threat actors or campaigns are mentioned, check if they align with known groups using the techniques
- Note which data sources would help detect the identified techniques

Output JSON with this structure:
{
    "techniques": [
        {
            "attack_id": "T1110.003",
            "name": "Password Spraying",
            "confidence": "high",
            "evidence": "The narrative explicitly mentions password spraying",
            "tactics": ["Credential Access"],
            "relevant_groups": ["APT29", "Scattered Spider"],
            "detection_data_sources": ["Authentication logs", "Active Directory"]
        }
    ],
    "finding_type": "attack_narrative" or "vulnerability",
    "kill_chain_analysis": "Brief description of where this fits in the attack lifecycle, or potential attack path if vulnerability",
    "reasoning": "Brief explanation of the overall analysis"
}"""


REMEDIATION_SYSTEM_PROMPT = """You are a cybersecurity remediation expert.
Given identified ATT&CK techniques and their available mitigations, provide prioritized remediation recommendations.

This applies to BOTH:
- **Attack narratives**: Remediate the techniques that were used
- **Vulnerability findings**: Remediate to PREVENT the potential techniques from being exploited

Consider:
1. Mitigations that address multiple identified techniques should be higher priority
2. Mitigations with lower implementation complexity are preferable when equally effective
3. Provide specific, actionable implementation guidance tailored to the finding
4. Consider detection capabilities - recommend data sources to collect for ongoing monitoring
5. If threat groups are identified, consider their known TTPs for additional hardening
6. For vulnerability findings, focus on preventive controls that close the exposure

Output JSON with this structure:
{
    "remediations": [
        {
            "mitigation_id": "M1032",
            "name": "Multi-factor Authentication",
            "priority": "HIGH",
            "addresses": ["T1110.003", "T1078.004"],
            "implementation": "Enable MFA for all Azure AD accounts. Configure conditional access policies..."
        }
    ],
    "detection_recommendations": [
        {
            "data_source": "Authentication Logs",
            "rationale": "Monitor for multiple failed authentication attempts indicating password spraying",
            "techniques_covered": ["T1110.003"]
        }
    ],
    "summary": "Brief summary of the remediation strategy"
}"""


class AttackAnalyzer:
    """
    Analyzes attack narratives to identify ATT&CK techniques and suggest remediation.

    Uses the hybrid query engine to find candidate techniques, then leverages
    an LLM to classify and explain the mapping.
    """

    def __init__(
        self,
        hybrid_engine,
        llm_backend=None,
    ):
        """
        Initialize the analyzer.

        Args:
            hybrid_engine: HybridQueryEngine instance
            llm_backend: LLM backend to use (defaults to Ollama)
        """
        self.hybrid = hybrid_engine
        if llm_backend is None:
            from src.reasoning.llm import OllamaBackend
            llm_backend = OllamaBackend()
        self.llm = llm_backend

    def analyze(self, finding_text: str, top_k: int = 5) -> AnalysisResult:
        """
        Analyze an attack narrative or finding.

        Args:
            finding_text: The attack narrative or security finding to analyze
            top_k: Number of candidate techniques to consider

        Returns:
            AnalysisResult with techniques, remediation, and explanations
        """
        # Step 1: Use hybrid engine to find candidate techniques
        hybrid_result = self.hybrid.query(finding_text, top_k=top_k, enrich=True)

        # Step 2: Build context for LLM classification
        candidates_context = self._build_candidates_context(hybrid_result.techniques)

        # Step 3: Classify with LLM
        classification = self._classify_techniques(finding_text, candidates_context)

        # Step 4: Build mitigation context for remediation
        mitigation_context = self._build_mitigation_context(
            hybrid_result.techniques, classification
        )

        # Step 5: Get remediation and detection recommendations
        remediations, detection_recs = self._get_remediations(
            finding_text, classification, mitigation_context
        )

        # Step 6: Enrich with group information
        techniques = self._enrich_with_groups(classification, hybrid_result.techniques)

        # Extract metadata from classification
        kill_chain_analysis = classification.get("kill_chain_analysis", "")
        finding_type = classification.get("finding_type", "attack_narrative")

        return AnalysisResult(
            finding=finding_text,
            techniques=techniques,
            remediations=remediations,
            detection_recommendations=detection_recs,
            finding_type=finding_type,
            kill_chain_analysis=kill_chain_analysis,
            raw_llm_response={
                "classification": classification,
            },
        )

    def _build_candidates_context(self, techniques) -> str:
        """Build a context string describing candidate techniques with full enriched data."""
        context_parts = []
        for tech in techniques:
            desc = tech.description[:400] + "..." if len(tech.description) > 400 else tech.description

            parts = [
                f"- {tech.attack_id} ({tech.name})",
                f"  Description: {desc}",
                f"  Tactics: {', '.join(tech.tactics)}",
                f"  Similarity score: {tech.similarity:.2f}",
            ]

            # Add platforms if available
            if tech.platforms:
                parts.append(f"  Platforms: {', '.join(tech.platforms)}")

            # Add data sources for detection
            if tech.data_sources:
                ds_list = tech.data_sources[:5]  # Limit to top 5
                parts.append(f"  Detection Data Sources: {', '.join(ds_list)}")

            # Add detection guidance if available
            if tech.detection:
                det_preview = tech.detection[:200] + "..." if len(tech.detection) > 200 else tech.detection
                parts.append(f"  Detection Guidance: {det_preview}")

            # Add groups using this technique
            if tech.groups:
                group_names = [g.get("name", g.get("attack_id", "")) for g in tech.groups[:5]]
                parts.append(f"  Known Threat Groups: {', '.join(group_names)}")

            # Add campaigns using this technique
            if tech.campaigns:
                campaign_names = [c.get("name", c.get("attack_id", "")) for c in tech.campaigns[:3]]
                parts.append(f"  Used in Campaigns: {', '.join(campaign_names)}")

            # Add software using this technique
            if tech.software:
                software_names = [s.get("name", "") for s in tech.software[:5]]
                parts.append(f"  Associated Software: {', '.join(software_names)}")

            # Add parent/sub-technique relationships
            if tech.parent_technique:
                parts.append(f"  Parent Technique: {tech.parent_technique['attack_id']} ({tech.parent_technique['name']})")
            if tech.subtechniques:
                sub_names = [f"{s['attack_id']}" for s in tech.subtechniques[:3]]
                parts.append(f"  Sub-techniques: {', '.join(sub_names)}")

            context_parts.append("\n".join(parts))

        return "\n\n".join(context_parts)

    def _classify_techniques(
        self, finding_text: str, candidates_context: str
    ) -> dict[str, Any]:
        """Use LLM to classify which techniques are present."""
        prompt = f"""Attack Narrative:
{finding_text}

Candidate ATT&CK Techniques (from knowledge base search):
{candidates_context}

Analyze the narrative and identify which of these techniques (if any) are evidenced.
Only include techniques with clear supporting evidence from the narrative."""

        result = self.llm.generate_json(prompt, system=CLASSIFICATION_SYSTEM_PROMPT)
        return result

    def _build_mitigation_context(
        self, techniques, classification: dict[str, Any]
    ) -> str:
        """Build context about available mitigations and detection data sources."""
        # Get IDs of classified techniques
        classified_ids = {
            t.get("attack_id") for t in classification.get("techniques", [])
        }

        # Gather mitigations for classified techniques
        mitigations_by_id = {}
        data_sources_by_technique = {}

        for tech in techniques:
            if tech.attack_id in classified_ids:
                # Collect mitigations, tracking inheritance
                for mit in tech.mitigations:
                    if mit["attack_id"] not in mitigations_by_id:
                        mitigations_by_id[mit["attack_id"]] = {
                            **mit,
                            "addresses": [tech.attack_id],
                            "_sources": [{"tech_id": tech.attack_id, "inherited": mit.get("inherited", False)}],
                        }
                    else:
                        mitigations_by_id[mit["attack_id"]]["addresses"].append(
                            tech.attack_id
                        )
                        mitigations_by_id[mit["attack_id"]]["_sources"].append(
                            {"tech_id": tech.attack_id, "inherited": mit.get("inherited", False)}
                        )

                # Collect data sources for detection
                if tech.data_sources:
                    data_sources_by_technique[tech.attack_id] = tech.data_sources

        # Format mitigation context
        context_parts = ["AVAILABLE MITIGATIONS:"]
        for mit_id, mit in mitigations_by_id.items():
            # Check if any source is inherited (from parent technique)
            inherited_note = ""
            if any(s.get("inherited") for s in mit.get("_sources", [])):
                inherited_note = " [inherited from parent technique]"
            context_parts.append(
                f"- {mit_id} ({mit['name']}){inherited_note}\n"
                f"  Addresses: {', '.join(mit['addresses'])}"
            )

        if not mitigations_by_id:
            context_parts.append("No specific mitigations found in knowledge base.")

        # Add data sources for detection
        if data_sources_by_technique:
            context_parts.append("\nDETECTION DATA SOURCES:")
            for tech_id, sources in data_sources_by_technique.items():
                context_parts.append(f"- {tech_id}: {', '.join(sources[:5])}")

        return "\n".join(context_parts)

    def _get_remediations(
        self,
        finding_text: str,
        classification: dict[str, Any],
        mitigation_context: str,
    ) -> tuple[list[RemediationItem], list[DetectionRecommendation]]:
        """Get prioritized remediation and detection recommendations from LLM."""
        techniques_summary = "\n".join(
            f"- {t['attack_id']} ({t['name']}): {t.get('evidence', 'N/A')}"
            for t in classification.get("techniques", [])
        )

        if not techniques_summary:
            return [], []

        prompt = f"""Finding: {finding_text}

Identified Techniques:
{techniques_summary}

{mitigation_context}

Provide prioritized remediation and detection recommendations."""

        result = self.llm.generate_json(prompt, system=REMEDIATION_SYSTEM_PROMPT)

        remediations = []
        for r in result.get("remediations", []):
            remediations.append(
                RemediationItem(
                    mitigation_id=r.get("mitigation_id", ""),
                    name=r.get("name", ""),
                    priority=r.get("priority", "MEDIUM"),
                    addresses=r.get("addresses", []),
                    implementation=r.get("implementation", ""),
                )
            )

        detection_recs = []
        for d in result.get("detection_recommendations", []):
            detection_recs.append(
                DetectionRecommendation(
                    data_source=d.get("data_source", ""),
                    rationale=d.get("rationale", ""),
                    techniques_covered=d.get("techniques_covered", []),
                )
            )

        return remediations, detection_recs

    def _enrich_with_groups(
        self, classification: dict[str, Any], techniques
    ) -> list[TechniqueMatch]:
        """Enrich classified techniques with group information."""
        # Build lookup from hybrid results
        tech_lookup = {t.attack_id: t for t in techniques}

        matches = []
        for t in classification.get("techniques", []):
            attack_id = t.get("attack_id", "")
            enriched = tech_lookup.get(attack_id)

            groups = []
            if enriched and enriched.groups:
                groups = enriched.groups[:5]  # Limit to top 5 groups

            matches.append(
                TechniqueMatch(
                    attack_id=attack_id,
                    name=t.get("name", ""),
                    confidence=t.get("confidence", "medium"),
                    evidence=t.get("evidence", ""),
                    tactics=t.get("tactics", []),
                    groups=groups,
                )
            )
        return matches


def print_analysis_result(result: AnalysisResult) -> None:
    """Print analysis result with rich formatting."""
    from rich.markdown import Markdown

    # Determine finding type label
    is_vulnerability = result.finding_type == "vulnerability"
    type_label = "[yellow]Vulnerability/Misconfiguration[/yellow]" if is_vulnerability else "[cyan]Attack Narrative[/cyan]"

    # Header panel
    console.print(Panel(
        f"[bold]Finding:[/bold] {result.finding}\n\n[dim]Type:[/dim] {type_label}",
        title="[bold cyan]ATTACK ANALYSIS[/bold cyan]",
        border_style="cyan",
    ))

    # Techniques section
    if result.techniques:
        section_title = "POTENTIAL EXPLOITATION TECHNIQUES" if is_vulnerability else "TECHNIQUES IDENTIFIED"
        console.print(f"\n[bold cyan]{section_title}[/bold cyan]")
        console.print()

        for tech in result.techniques:
            # Confidence color
            conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(
                tech.confidence.lower(), "white"
            )

            console.print(
                f"[bold]{tech.attack_id}[/bold] - {tech.name} "
                f"([{conf_color}]{tech.confidence.capitalize()} confidence[/{conf_color}])"
            )
            console.print(f"  [dim]Evidence:[/dim] {tech.evidence}")
            console.print(f"  [dim]Tactic:[/dim] {', '.join(tech.tactics)}")

            if tech.groups:
                group_names = ", ".join(g.get("name", g.get("attack_id", "")) for g in tech.groups[:3])
                if len(tech.groups) > 3:
                    group_names += f" (+{len(tech.groups) - 3} more)"
                console.print(f"  [dim]Groups:[/dim] {group_names}")

            console.print()
    else:
        console.print("\n[yellow]No techniques identified with confidence.[/yellow]\n")

    # Kill chain analysis
    if result.kill_chain_analysis:
        console.print("[bold cyan]KILL CHAIN ANALYSIS[/bold cyan]")
        console.print(Markdown(result.kill_chain_analysis))
        console.print()

    # Remediation section
    if result.remediations:
        console.print("[bold cyan]RECOMMENDED REMEDIATION[/bold cyan]")
        console.print()

        for i, rem in enumerate(result.remediations, 1):
            # Priority color
            priority_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(
                rem.priority.upper(), "white"
            )

            console.print(
                f"[bold]{i}. {rem.name}[/bold] ({rem.mitigation_id}) - "
                f"[{priority_color}]{rem.priority} PRIORITY[/{priority_color}]"
            )
            console.print(f"   [dim]Addresses:[/dim] {', '.join(rem.addresses)}")
            console.print(f"   [dim]Implementation:[/dim]")
            # Indent markdown output
            for line in rem.implementation.split('\n'):
                console.print(f"   {line}")
            console.print()
    else:
        console.print("[yellow]No specific remediations generated.[/yellow]\n")

    # Detection recommendations
    if result.detection_recommendations:
        console.print("[bold cyan]DETECTION RECOMMENDATIONS[/bold cyan]")
        console.print()

        for det in result.detection_recommendations:
            console.print(f"[bold]• {det.data_source}[/bold]")
            console.print(f"   [dim]Rationale:[/dim]")
            for line in det.rationale.split('\n'):
                console.print(f"   {line}")
            if det.techniques_covered:
                console.print(f"   [dim]Covers:[/dim] {', '.join(det.techniques_covered)}")
            console.print()
