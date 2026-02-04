"""Stage 2: Remediation writing for selected techniques.

This stage focuses on writing detailed, product-specific remediation
guidance for the techniques selected in Stage 1.
"""

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

console = Console()


REMEDIATION_PROMPT = """You are writing remediation guidance for selected ATT&CK techniques.

You will receive:
1. The original security finding
2. Selected techniques (already validated by Stage 1)
3. Available ATT&CK mitigations for those techniques
4. D3FEND defensive techniques linked to those mitigations

═══════════════════════════════════════════════════════════════════════════════
CONTEXT EXTRACTION (DO THIS FIRST)
═══════════════════════════════════════════════════════════════════════════════

Before generating recommendations, extract technology indicators from the finding:

1. **Operating System**: Look for paths (/var/www = Linux, C:\\ = Windows), services (systemd, apache2, IIS)
2. **Products**: Specific software mentioned (ownCloud, FortiOS, Apache, nginx, etc.)
3. **Environment**: Cloud indicators (AWS, Azure, GCP) vs on-premise (file paths, local services)
4. **Authentication**: LDAP, Active Directory, SAML, local accounts, SSO providers mentioned

Use ONLY these indicators to scope your recommendations. Do NOT assume enterprise tools
(Azure AD, Okta, CrowdStrike) unless the finding explicitly mentions them.

═══════════════════════════════════════════════════════════════════════════════
IMPLEMENTATION GUIDANCE RULES (CRITICAL)
═══════════════════════════════════════════════════════════════════════════════

When writing implementation steps:

DO:
- Reference the specific product's native features
- Describe the general location of settings
- Provide conceptual steps that an admin can follow
- Use phrases like "Configure [product] to..." or "Enable [feature] in [product]"

DO NOT:
- Invent specific configuration file syntax unless 100% certain
- Fabricate command-line flags or API parameters
- Assume configuration file formats you're not certain about
- Mix guidance for different products

WHEN UNCERTAIN about exact syntax:
- State the goal clearly
- Reference official docs
- Describe the admin UI path if known
- Avoid inventing specific code/config that could be wrong

═══════════════════════════════════════════════════════════════════════════════
PRIORITIZATION
═══════════════════════════════════════════════════════════════════════════════

For ATT&CK Mitigations:
- HIGH: Directly addresses primary technique(s), broad coverage
- MEDIUM: Addresses secondary techniques or provides defense-in-depth
- LOW: Useful but not essential for this specific finding

For D3FEND Techniques:
- Nest under parent mitigation when there's a direct mapping
- Provide operational/detection-focused guidance
- Focus on monitoring, thresholds, and active defense measures

═══════════════════════════════════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════════════════════════════════

Output JSON with this exact structure:
{
    "remediations": [
        {
            "mitigation_id": "M1032",
            "name": "Multi-factor Authentication",
            "priority": "HIGH",
            "addresses": ["T1110.003"],
            "implementation": "1. Enable [product]'s built-in 2FA feature. 2. Require 2FA for admin accounts. 3. Configure via Admin > Security settings."
        }
    ],
    "defend_recommendations": [
        {
            "d3fend_id": "D3-MFA",
            "name": "Multi-factor Authentication",
            "priority": "HIGH",
            "addresses": ["T1110.003"],
            "implementation": "Deploy TOTP-based MFA using [product]'s native 2FA module.",
            "via_mitigations": ["M1032"]
        }
    ],
    "detection_recommendations": [
        {
            "data_source": "Authentication Logs",
            "rationale": "Why this helps detect the identified techniques",
            "techniques_covered": ["T1110.003"]
        }
    ]
}

CONSISTENCY RULE: The "addresses" and "techniques_covered" fields must ONLY contain
technique IDs that were selected in Stage 1. Do not reference techniques not selected.

IMPORTANT: Only output valid JSON. No markdown, no explanation outside JSON."""


@dataclass
class RemediationItem:
    """A remediation recommendation from Stage 2."""

    mitigation_id: str
    name: str
    priority: str
    addresses: list[str]
    implementation: str


@dataclass
class D3FendRecommendation:
    """A D3FEND recommendation from Stage 2."""

    d3fend_id: str
    name: str
    priority: str
    addresses: list[str]
    implementation: str
    via_mitigations: list[str]


@dataclass
class DetectionRecommendation:
    """A detection recommendation from Stage 2."""

    data_source: str
    rationale: str
    techniques_covered: list[str]


@dataclass
class RemediationResult:
    """Result from Stage 2 remediation writing."""

    remediations: list[RemediationItem]
    defend_recommendations: list[D3FendRecommendation]
    detection_recommendations: list[DetectionRecommendation]
    raw_response: dict[str, Any] = field(default_factory=dict)


class RemediationWriter:
    """
    Stage 2: Write detailed remediation for selected techniques.

    This stage focuses on:
    - Product-specific implementation guidance
    - Prioritized remediation steps
    - D3FEND defensive technique integration
    - Detection recommendations
    """

    def __init__(self, llm_backend, graph=None):
        """
        Initialize the remediation writer.

        Args:
            llm_backend: LLM backend for generation
            graph: Optional AttackGraph for additional lookups
        """
        self.llm = llm_backend
        self.graph = graph

    def write(
        self,
        finding: str,
        selected_technique_ids: list[str],
        mitigations_toon: str,
        d3fend_toon: str,
        valid_mitigation_ids: set[str],
        valid_d3fend_ids: set[str],
    ) -> RemediationResult:
        """
        Write remediation guidance for selected techniques.

        Args:
            finding: The original security finding
            selected_technique_ids: Technique IDs selected in Stage 1
            mitigations_toon: TOON-formatted mitigations for selected techniques
            d3fend_toon: TOON-formatted D3FEND techniques
            valid_mitigation_ids: Set of valid mitigation IDs from context
            valid_d3fend_ids: Set of valid D3FEND IDs from context

        Returns:
            RemediationResult with remediation guidance
        """
        from src.logging import log_llm_request

        selected_ids_str = ", ".join(selected_technique_ids)

        prompt = f"""Security Finding:
{finding}

Selected Techniques (from Stage 1): {selected_ids_str}

{mitigations_toon}

{d3fend_toon}

Write detailed, product-specific remediation guidance for the selected techniques.
Prioritize mitigations by impact and include D3FEND recommendations where applicable."""

        log_llm_request(prompt, system=REMEDIATION_PROMPT, model="stage2")

        # Generate remediation
        result = self.llm.generate_json(prompt, system=REMEDIATION_PROMPT)

        # Validate and filter responses
        selected_set = set(selected_technique_ids)

        # Process remediations
        remediations = []
        for rem in result.get("remediations", []):
            mit_id = rem.get("mitigation_id", "")
            if mit_id not in valid_mitigation_ids:
                console.print(f"[yellow]Stage 2: Filtered invalid mitigation: {mit_id}[/yellow]")
                continue

            # Filter addresses to only selected techniques
            addresses = [t for t in rem.get("addresses", []) if t in selected_set]
            if not addresses:
                continue

            remediations.append(RemediationItem(
                mitigation_id=mit_id,
                name=rem.get("name", ""),
                priority=rem.get("priority", "MEDIUM"),
                addresses=addresses,
                implementation=rem.get("implementation", ""),
            ))

        # Process D3FEND recommendations
        defend_recs = []
        for d3f in result.get("defend_recommendations", []):
            d3f_id = d3f.get("d3fend_id", "")
            if d3f_id not in valid_d3fend_ids:
                console.print(f"[yellow]Stage 2: Filtered invalid D3FEND: {d3f_id}[/yellow]")
                continue

            # Filter addresses to only selected techniques
            addresses = [t for t in d3f.get("addresses", []) if t in selected_set]
            if not addresses:
                continue

            # Filter via_mitigations to valid ones
            via_mits = [m for m in d3f.get("via_mitigations", []) if m in valid_mitigation_ids]

            defend_recs.append(D3FendRecommendation(
                d3fend_id=d3f_id,
                name=d3f.get("name", ""),
                priority=d3f.get("priority", "MEDIUM"),
                addresses=addresses,
                implementation=d3f.get("implementation", ""),
                via_mitigations=via_mits,
            ))

        # Process detection recommendations
        detection_recs = []
        for det in result.get("detection_recommendations", []):
            # Filter techniques_covered to only selected techniques
            covered = [t for t in det.get("techniques_covered", []) if t in selected_set]
            if covered:
                detection_recs.append(DetectionRecommendation(
                    data_source=det.get("data_source", ""),
                    rationale=det.get("rationale", ""),
                    techniques_covered=covered,
                ))

        return RemediationResult(
            remediations=remediations,
            defend_recommendations=defend_recs,
            detection_recommendations=detection_recs,
            raw_response=result,
        )
