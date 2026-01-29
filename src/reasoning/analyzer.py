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
class AnalysisResult:
    """Complete analysis result."""

    finding: str
    techniques: list[TechniqueMatch]
    remediations: list[RemediationItem]
    raw_llm_response: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding,
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
        }


# Prompts for classification and remediation
CLASSIFICATION_SYSTEM_PROMPT = """You are a cybersecurity analyst expert in MITRE ATT&CK framework.
Your task is to analyze attack narratives and identify which ATT&CK techniques are present.

You will be given:
1. An attack narrative or security finding
2. A list of candidate techniques with their descriptions from the ATT&CK knowledge base

For each relevant technique, provide:
- Confidence level (high/medium/low) based on how clearly the technique is evidenced
- Specific evidence from the narrative that maps to this technique
- The technique's associated tactics

Be conservative: only identify techniques with clear evidence. Do not speculate.

Output JSON with this structure:
{
    "techniques": [
        {
            "attack_id": "T1110.003",
            "name": "Password Spraying",
            "confidence": "high",
            "evidence": "The narrative explicitly mentions password spraying",
            "tactics": ["Credential Access"]
        }
    ],
    "reasoning": "Brief explanation of the overall analysis"
}"""


REMEDIATION_SYSTEM_PROMPT = """You are a cybersecurity remediation expert.
Given identified ATT&CK techniques and their available mitigations, provide prioritized remediation recommendations.

Consider:
1. Mitigations that address multiple identified techniques should be higher priority
2. Mitigations with lower implementation complexity are preferable when equally effective
3. Provide specific, actionable implementation guidance

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

        # Step 5: Get remediation recommendations
        remediations = self._get_remediations(
            finding_text, classification, mitigation_context
        )

        # Step 6: Enrich with group information
        techniques = self._enrich_with_groups(classification, hybrid_result.techniques)

        return AnalysisResult(
            finding=finding_text,
            techniques=techniques,
            remediations=remediations,
            raw_llm_response={
                "classification": classification,
                "remediation_response": remediations,
            },
        )

    def _build_candidates_context(self, techniques) -> str:
        """Build a context string describing candidate techniques."""
        context_parts = []
        for tech in techniques:
            desc = tech.description[:300] + "..." if len(tech.description) > 300 else tech.description
            context_parts.append(
                f"- {tech.attack_id} ({tech.name}): {desc}\n"
                f"  Tactics: {', '.join(tech.tactics)}\n"
                f"  Similarity score: {tech.similarity:.2f}"
            )
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
        """Build context about available mitigations."""
        # Get IDs of classified techniques
        classified_ids = {
            t.get("attack_id") for t in classification.get("techniques", [])
        }

        # Gather mitigations for classified techniques
        mitigations_by_id = {}
        for tech in techniques:
            if tech.attack_id in classified_ids:
                for mit in tech.mitigations:
                    if mit["attack_id"] not in mitigations_by_id:
                        mitigations_by_id[mit["attack_id"]] = {
                            **mit,
                            "addresses": [tech.attack_id],
                        }
                    else:
                        mitigations_by_id[mit["attack_id"]]["addresses"].append(
                            tech.attack_id
                        )

        # Format context
        context_parts = []
        for mit_id, mit in mitigations_by_id.items():
            context_parts.append(
                f"- {mit_id} ({mit['name']})\n"
                f"  Addresses: {', '.join(mit['addresses'])}"
            )

        return "\n".join(context_parts) if context_parts else "No specific mitigations found in knowledge base."

    def _get_remediations(
        self,
        finding_text: str,
        classification: dict[str, Any],
        mitigation_context: str,
    ) -> list[RemediationItem]:
        """Get prioritized remediation recommendations from LLM."""
        techniques_summary = "\n".join(
            f"- {t['attack_id']} ({t['name']}): {t.get('evidence', 'N/A')}"
            for t in classification.get("techniques", [])
        )

        if not techniques_summary:
            return []

        prompt = f"""Finding: {finding_text}

Identified Techniques:
{techniques_summary}

Available Mitigations from ATT&CK:
{mitigation_context}

Provide prioritized remediation recommendations."""

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
        return remediations

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
    # Header panel
    finding_display = result.finding[:80] + "..." if len(result.finding) > 80 else result.finding
    console.print(Panel(
        f"[bold]Finding:[/bold] {finding_display}",
        title="[bold cyan]ATTACK ANALYSIS[/bold cyan]",
        border_style="cyan",
    ))

    # Techniques section
    if result.techniques:
        console.print("\n[bold cyan]TECHNIQUES IDENTIFIED[/bold cyan]")
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
            console.print(f"   [dim]Implementation:[/dim] {rem.implementation}")
            console.print()
    else:
        console.print("[yellow]No specific remediations generated.[/yellow]\n")
