"""Stage 1: Node selection from candidate techniques.

This stage focuses purely on selecting which ATT&CK techniques from the
retrieved candidates actually apply to the finding. It does NOT write
remediation - that's Stage 2's job.
"""

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

console = Console()


NODE_SELECTION_PROMPT = """You are selecting relevant ATT&CK techniques from candidates.

Your ONLY job is to determine which of the provided candidate techniques apply to this security finding.

RULES:
1. You may ONLY select techniques from the provided candidates list
2. Do NOT invent or hallucinate technique IDs
3. Focus on evidence from the finding that matches technique descriptions
4. Consider the kill chain context if provided

For each selected technique, provide:
- attack_id: The technique ID (must be from candidates)
- confidence: "high", "medium", or "low"
- evidence: Brief quote or description from finding that justifies selection
- tactic: Primary tactic (from kill chain)

Output JSON with this exact structure:
{
    "finding_type": "attack_narrative" or "vulnerability",
    "selected_techniques": [
        {
            "attack_id": "T1110.003",
            "confidence": "high",
            "evidence": "password spraying against Azure AD",
            "tactic": "Credential Access"
        }
    ],
    "kill_chain_analysis": "Brief description of attack lifecycle"
}

IMPORTANT: Only output valid JSON. No markdown, no explanation outside JSON."""


@dataclass
class SelectedTechnique:
    """A technique selected by Stage 1."""

    attack_id: str
    confidence: str
    evidence: str
    tactic: str


@dataclass
class SelectionResult:
    """Result from Stage 1 node selection."""

    finding_type: str
    selected_techniques: list[SelectedTechnique]
    kill_chain_analysis: str
    raw_response: dict[str, Any] = field(default_factory=dict)

    def get_technique_ids(self) -> list[str]:
        """Get list of selected technique IDs."""
        return [t.attack_id for t in self.selected_techniques]


class NodeSelector:
    """
    Stage 1: Select relevant nodes from candidate techniques.

    This stage focuses on:
    - Identifying which candidates actually apply
    - Extracting evidence from the finding
    - Determining confidence levels
    - Classifying finding type (attack vs vulnerability)
    """

    def __init__(self, llm_backend):
        """
        Initialize the node selector.

        Args:
            llm_backend: LLM backend for generation
        """
        self.llm = llm_backend

    def select(
        self,
        finding: str,
        candidates_toon: str,
        valid_technique_ids: set[str],
    ) -> SelectionResult:
        """
        Select relevant techniques from candidates.

        Args:
            finding: The security finding text
            candidates_toon: TOON-formatted candidates context
            valid_technique_ids: Set of valid technique IDs from candidates

        Returns:
            SelectionResult with selected techniques
        """
        from src.logging import log_llm_request

        prompt = f"""Security Finding:
{finding}

{candidates_toon}

Select which techniques from the candidates apply to this finding.
Only select techniques that have clear evidence in the finding."""

        log_llm_request(prompt, system=NODE_SELECTION_PROMPT, model="stage1")

        # Generate selection
        result = self.llm.generate_json(prompt, system=NODE_SELECTION_PROMPT)

        # Validate and filter to only valid technique IDs
        selected = []
        filtered_ids = []

        for tech in result.get("selected_techniques", []):
            attack_id = tech.get("attack_id", "")
            if attack_id in valid_technique_ids:
                selected.append(SelectedTechnique(
                    attack_id=attack_id,
                    confidence=tech.get("confidence", "medium"),
                    evidence=tech.get("evidence", ""),
                    tactic=tech.get("tactic", ""),
                ))
            else:
                filtered_ids.append(attack_id)
                console.print(f"[yellow]Stage 1: Filtered hallucinated technique: {attack_id}[/yellow]")

        if filtered_ids:
            console.print(f"[dim]Stage 1 filtered {len(filtered_ids)} invalid technique IDs[/dim]")

        return SelectionResult(
            finding_type=result.get("finding_type", "attack_narrative"),
            selected_techniques=selected,
            kill_chain_analysis=result.get("kill_chain_analysis", ""),
            raw_response=result,
        )
