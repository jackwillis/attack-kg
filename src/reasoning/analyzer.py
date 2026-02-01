"""Attack narrative analyzer for classifying findings with MITRE ATT&CK techniques."""

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel

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
class DefendTechnique:
    """A D3FEND technique nested under a mitigation."""

    defend_id: str
    name: str
    implementation: str = ""


@dataclass
class RemediationItem:
    """A prioritized remediation recommendation."""

    mitigation_id: str
    name: str
    priority: str  # "HIGH", "MEDIUM", "LOW"
    addresses: list[str]  # technique IDs
    implementation: str
    defend_techniques: list[DefendTechnique] = field(default_factory=list)


@dataclass
class DefendRecommendation:
    """A D3FEND defensive technique recommendation."""

    defend_id: str
    name: str
    priority: str  # "HIGH", "MEDIUM", "LOW"
    addresses: list[str]  # technique IDs
    implementation: str
    via_mitigations: list[str] = field(default_factory=list)


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
    defend_recommendations: list[DefendRecommendation] = field(default_factory=list)
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
                    "defend_techniques": [
                        {"defend_id": d.defend_id, "name": d.name, "implementation": d.implementation}
                        for d in r.defend_techniques
                    ] if r.defend_techniques else [],
                }
                for r in self.remediations
            ],
            "defend_recommendations": [
                {
                    "defend_id": d.defend_id,
                    "name": d.name,
                    "priority": d.priority,
                    "addresses": d.addresses,
                    "implementation": d.implementation,
                    "via_mitigations": d.via_mitigations,
                }
                for d in self.defend_recommendations
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


# Single combined prompt for classification + remediation
ANALYSIS_SYSTEM_PROMPT = """You are a cybersecurity analyst expert in MITRE ATT&CK and D3FEND frameworks.
Your task is to analyze security findings, identify relevant ATT&CK techniques, and provide remediation guidance.

You will receive:
1. A security finding (attack narrative OR vulnerability/misconfiguration)
2. Candidate ATT&CK techniques with descriptions, threat groups, and detection data sources
3. Available ATT&CK mitigations for those techniques
4. D3FEND defensive techniques linked to those mitigations (more specific, actionable controls)

HANDLE TWO FINDING TYPES:

**Attack Narratives** (evidence of adversary activity):
- Identify techniques with clear evidence from the narrative
- Evidence should describe what the attacker DID
- Remediations prevent recurrence

**Vulnerability/Misconfiguration Findings** (no attack yet):
- Identify techniques that COULD exploit this vulnerability
- Evidence should describe HOW an attacker could leverage this weakness
- Remediations close the exposure before exploitation

PRIORITIZATION GUIDANCE:

For ATT&CK Mitigations:
- HIGH: Directly addresses the primary technique(s), broad coverage
- MEDIUM: Addresses secondary techniques or provides defense-in-depth
- LOW: Useful but not essential for this specific finding

For D3FEND Techniques:
- D3FEND provides specific, actionable defensive techniques
- Prioritize based on how directly they address the identified techniques
- Include implementation details specific to the finding context

Output JSON with this exact structure (generate in this order - techniques first, then build on that):
{
    "techniques": [
        {
            "attack_id": "T1110.003",
            "name": "Password Spraying",
            "confidence": "high",
            "evidence": "Specific evidence from the finding",
            "tactics": ["Credential Access"]
        }
    ],
    "finding_type": "attack_narrative" or "vulnerability",
    "kill_chain_analysis": "Brief description of attack lifecycle position or potential attack path",
    "remediations": [
        {
            "mitigation_id": "M1032",
            "name": "Multi-factor Authentication",
            "priority": "HIGH",
            "addresses": ["T1110.003"],
            "implementation": "Specific steps to implement this mitigation for this finding"
        }
    ],
    "defend_recommendations": [
        {
            "defend_id": "D3-MFA",
            "name": "Multi-factor Authentication",
            "priority": "HIGH",
            "addresses": ["T1110.003"],
            "implementation": "Specific D3FEND technique implementation guidance",
            "via_mitigations": ["M1032"]
        }
    ],
    "detection_recommendations": [
        {
            "data_source": "Authentication Logs",
            "rationale": "Why this data source helps detect the identified techniques",
            "techniques_covered": ["T1110.003"]
        }
    ]
}

IMPORTANT:
- Only include techniques with clear evidence or strong potential for exploitation
- Provide specific, actionable implementation guidance (not generic advice)
- D3FEND techniques are more specific than ATT&CK mitigations - leverage this for detailed guidance
- Consider the organization's likely environment based on the finding context"""


class AttackAnalyzer:
    """
    Analyzes attack narratives to identify ATT&CK techniques and suggest remediation.

    Uses the hybrid query engine to find candidate techniques, then leverages
    an LLM to classify and provide comprehensive remediation including D3FEND.
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
            AnalysisResult with techniques, remediation, D3FEND, and detection guidance
        """
        # Step 1: Use hybrid engine to find candidate techniques with full enrichment
        hybrid_result = self.hybrid.query(finding_text, top_k=top_k, enrich=True)

        # Step 2: Build complete context including D3FEND
        context = self._build_complete_context(hybrid_result.techniques)

        # Step 3: Single LLM call for classification + remediation
        prompt = f"""Security Finding:
{finding_text}

{context}

Analyze this finding and provide:
1. Which techniques are evidenced (or could be exploited if vulnerability)
2. Prioritized ATT&CK mitigations with specific implementation steps
3. D3FEND defensive techniques with actionable guidance
4. Detection recommendations based on available data sources"""

        result = self.llm.generate_json(prompt, system=ANALYSIS_SYSTEM_PROMPT)

        # Step 4: Build response with group enrichment
        techniques = self._enrich_with_groups(result, hybrid_result.techniques)

        # Build remediations and merge D3FEND into them
        remediations, defend_recommendations = self._merge_defend_into_mitigations(
            result.get("remediations", []),
            result.get("defend_recommendations", []),
        )

        detection_recs = [
            DetectionRecommendation(
                data_source=d.get("data_source", ""),
                rationale=d.get("rationale", ""),
                techniques_covered=d.get("techniques_covered", []),
            )
            for d in result.get("detection_recommendations", [])
        ]

        return AnalysisResult(
            finding=finding_text,
            techniques=techniques,
            remediations=remediations,
            defend_recommendations=defend_recommendations,
            detection_recommendations=detection_recs,
            finding_type=result.get("finding_type", "attack_narrative"),
            kill_chain_analysis=result.get("kill_chain_analysis", ""),
            raw_llm_response=result,
        )

    def _build_complete_context(self, techniques) -> str:
        """Build complete context with techniques, mitigations, and D3FEND."""
        sections = []

        # Section 1: Candidate techniques
        sections.append("CANDIDATE ATT&CK TECHNIQUES:")
        for tech in techniques:
            desc = tech.description[:400] + "..." if len(tech.description) > 400 else tech.description

            parts = [
                f"\n{tech.attack_id} ({tech.name})",
                f"  Description: {desc}",
                f"  Tactics: {', '.join(tech.tactics)}",
                f"  Similarity: {tech.similarity:.2f}",
            ]

            if tech.platforms:
                parts.append(f"  Platforms: {', '.join(tech.platforms)}")

            if tech.groups:
                group_names = [g.get("name", g.get("attack_id", "")) for g in tech.groups[:5]]
                parts.append(f"  Known Groups: {', '.join(group_names)}")

            if tech.data_sources:
                parts.append(f"  Data Sources: {', '.join(tech.data_sources[:5])}")

            if tech.detection:
                det_preview = tech.detection[:200] + "..." if len(tech.detection) > 200 else tech.detection
                parts.append(f"  Detection: {det_preview}")

            sections.append("\n".join(parts))

        # Section 2: Available mitigations
        sections.append("\n\nAVAILABLE ATT&CK MITIGATIONS:")
        mitigations_by_id = {}
        for tech in techniques:
            for mit in tech.mitigations:
                if mit["attack_id"] not in mitigations_by_id:
                    mitigations_by_id[mit["attack_id"]] = {
                        **mit,
                        "addresses": [tech.attack_id],
                    }
                else:
                    if tech.attack_id not in mitigations_by_id[mit["attack_id"]]["addresses"]:
                        mitigations_by_id[mit["attack_id"]]["addresses"].append(tech.attack_id)

        if mitigations_by_id:
            for mit_id, mit in mitigations_by_id.items():
                inherited = " [inherited]" if mit.get("inherited") else ""
                sections.append(
                    f"  {mit_id} ({mit['name']}){inherited} - addresses: {', '.join(mit['addresses'])}"
                )
        else:
            sections.append("  No specific mitigations found.")

        # Section 3: D3FEND countermeasures
        sections.append("\n\nD3FEND DEFENSIVE TECHNIQUES:")
        defend_by_id = {}
        for tech in techniques:
            defend_techniques = self.hybrid.graph.get_d3fend_for_technique(tech.attack_id)
            for d3f in defend_techniques:
                d3f_id = d3f["defend_id"]
                if d3f_id not in defend_by_id:
                    defend_by_id[d3f_id] = {
                        **dfn,
                        "addresses": [tech.attack_id],
                        "via_mitigations": [d3f["via_mitigation"]],
                    }
                else:
                    if tech.attack_id not in defend_by_id[d3f_id]["addresses"]:
                        defend_by_id[d3f_id]["addresses"].append(tech.attack_id)
                    if d3f["via_mitigation"] not in defend_by_id[d3f_id]["via_mitigations"]:
                        defend_by_id[d3f_id]["via_mitigations"].append(d3f["via_mitigation"])

        if defend_by_id:
            for d3f_id, d3f in defend_by_id.items():
                definition = d3f.get("definition", "")
                if len(definition) > 150:
                    definition = definition[:150] + "..."
                sections.append(
                    f"  {d3f_id} ({d3f['name']})\n"
                    f"    Definition: {definition}\n"
                    f"    Addresses: {', '.join(d3f['addresses'])}\n"
                    f"    Via mitigations: {', '.join(d3f['via_mitigations'])}"
                )
        else:
            sections.append("  No D3FEND techniques found (D3FEND may not be loaded).")

        return "\n".join(sections)

    def _enrich_with_groups(
        self, llm_result: dict[str, Any], techniques
    ) -> list[TechniqueMatch]:
        """Enrich classified techniques with group information."""
        tech_lookup = {t.attack_id: t for t in techniques}

        matches = []
        for t in llm_result.get("techniques", []):
            attack_id = t.get("attack_id", "")
            enriched = tech_lookup.get(attack_id)

            groups = []
            if enriched and enriched.groups:
                groups = enriched.groups[:5]

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

    def _merge_defend_into_mitigations(
        self,
        raw_remediations: list[dict[str, Any]],
        raw_defend: list[dict[str, Any]],
    ) -> tuple[list[RemediationItem], list[DefendRecommendation]]:
        """
        Merge D3FEND recommendations into their parent mitigations.

        D3FEND techniques that map to a mitigation are nested under it.
        D3FEND techniques without a mitigation mapping remain standalone.

        Returns:
            Tuple of (remediations with nested D3FEND, standalone D3FEND)
        """
        # Build mitigation lookup
        mitigation_ids = {r.get("mitigation_id", "") for r in raw_remediations}

        # Partition D3FEND: those with matching mitigations vs standalone
        defend_by_mitigation: dict[str, list[dict]] = {}
        standalone_defend: list[dict] = []

        for d in raw_defend:
            via_mitigations = d.get("via_mitigations", [])
            matched = False

            for mit_id in via_mitigations:
                if mit_id in mitigation_ids:
                    if mit_id not in defend_by_mitigation:
                        defend_by_mitigation[mit_id] = []
                    defend_by_mitigation[mit_id].append(d)
                    matched = True
                    break  # Only nest under first matching mitigation

            if not matched and via_mitigations:
                # D3FEND maps to a mitigation not in our list - still standalone
                standalone_defend.append(d)
            elif not via_mitigations:
                # No mitigation mapping - standalone
                standalone_defend.append(d)

        # Build remediations with nested D3FEND
        remediations = []
        for r in raw_remediations:
            mit_id = r.get("mitigation_id", "")
            nested_defend = [
                DefendTechnique(
                    defend_id=d.get("defend_id", ""),
                    name=d.get("name", ""),
                    implementation=d.get("implementation", ""),
                )
                for d in defend_by_mitigation.get(mit_id, [])
            ]

            remediations.append(
                RemediationItem(
                    mitigation_id=mit_id,
                    name=r.get("name", ""),
                    priority=r.get("priority", "MEDIUM"),
                    addresses=r.get("addresses", []),
                    implementation=r.get("implementation", ""),
                    defend_techniques=nested_defend,
                )
            )

        # Build standalone D3FEND recommendations
        standalone = [
            DefendRecommendation(
                defend_id=d.get("defend_id", ""),
                name=d.get("name", ""),
                priority=d.get("priority", "MEDIUM"),
                addresses=d.get("addresses", []),
                implementation=d.get("implementation", ""),
                via_mitigations=d.get("via_mitigations", []),
            )
            for d in standalone_defend
        ]

        return remediations, standalone


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

    # Remediations section (ATT&CK mitigations with nested D3FEND)
    if result.remediations:
        console.print("[bold cyan]REMEDIATIONS[/bold cyan]")
        console.print()

        for i, rem in enumerate(result.remediations, 1):
            priority_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(
                rem.priority.upper(), "white"
            )

            console.print(
                f"[bold]{i}. {rem.name}[/bold] ({rem.mitigation_id}) - "
                f"[{priority_color}]{rem.priority} PRIORITY[/{priority_color}]"
            )
            console.print(f"   [dim]Addresses:[/dim] {', '.join(rem.addresses)}")
            console.print(f"   [dim]Implementation:[/dim]")
            for line in rem.implementation.split('\n'):
                console.print(f"   {line}")

            # Show nested D3FEND techniques if present
            if rem.defend_techniques:
                d3f_ids = ", ".join(d.defend_id for d in rem.defend_techniques)
                console.print(f"   [dim]D3FEND:[/dim] {d3f_ids}")
                for d3f in rem.defend_techniques:
                    if d3f.implementation:
                        console.print(f"      [dim]{d3f.defend_id}:[/dim] {d3f.implementation}")

            console.print()

    # Standalone D3FEND recommendations (not linked to a mitigation in the output)
    if result.defend_recommendations:
        console.print("[bold cyan]ADDITIONAL D3FEND COUNTERMEASURES[/bold cyan]")
        console.print()

        for i, d3f in enumerate(result.defend_recommendations, 1):
            priority_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(
                d3f.priority.upper(), "white"
            )

            console.print(
                f"[bold]{i}. {d3f.name}[/bold] ({d3f.defend_id}) - "
                f"[{priority_color}]{d3f.priority} PRIORITY[/{priority_color}]"
            )
            console.print(f"   [dim]Addresses:[/dim] {', '.join(d3f.addresses)}")
            if d3f.via_mitigations:
                console.print(f"   [dim]Via:[/dim] {', '.join(d3f.via_mitigations)}")
            console.print(f"   [dim]Implementation:[/dim]")
            for line in d3f.implementation.split('\n'):
                console.print(f"   {line}")
            console.print()

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

    # Summary footer
    nested_defend_count = sum(len(r.defend_techniques) for r in result.remediations)
    total_defend = nested_defend_count + len(result.defend_recommendations)

    if result.remediations or result.defend_recommendations:
        summary_parts = [f"{len(result.techniques)} techniques"]
        summary_parts.append(f"{len(result.remediations)} mitigations")
        if total_defend > 0:
            summary_parts.append(f"{total_defend} D3FEND techniques")
        console.print(f"[dim]Summary: {', '.join(summary_parts)}[/dim]")
