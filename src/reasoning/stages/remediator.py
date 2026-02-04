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
ANTI-HALLUCINATION RULES (CRITICAL - READ CAREFULLY)
═══════════════════════════════════════════════════════════════════════════════

NEVER INVENT:
- Configuration file paths you're not 100% certain exist
- Command-line flags, options, or parameters you're uncertain about
- API endpoints, methods, or payloads
- Specific version numbers unless stated in the finding
- Product names, tools, or services not mentioned in the finding
- Registry keys, file locations, or system paths you're guessing

ALWAYS:
- Add "confidence": "high"/"medium"/"low" to each remediation item
- Use "low" confidence when providing general guidance without specific syntax
- Use "medium" confidence when you know the approach but not exact steps
- Use "high" confidence ONLY for well-documented, standard configurations

WHEN UNCERTAIN (this is PREFERRED over guessing):
- Say "Consult [product] documentation for exact configuration steps"
- Say "Enable [feature] through the [product] admin interface" (without inventing paths)
- Say "Configure rate limiting according to your [product] version's documentation"
- Provide the GOAL, not invented implementation details

EXAMPLE OF GOOD GUIDANCE:
"Enable MFA in ownCloud by configuring a TOTP app in the admin settings. Consult ownCloud documentation for your version's specific configuration steps."

EXAMPLE OF BAD GUIDANCE (DO NOT DO THIS):
"Edit /etc/owncloud/config.php and add: $CONFIG['mfa_enabled'] = true; $CONFIG['totp_secret_length'] = 32;"
^ This invents file paths and config syntax that may not exist!

═══════════════════════════════════════════════════════════════════════════════
IMPLEMENTATION GUIDANCE RULES
═══════════════════════════════════════════════════════════════════════════════

When writing implementation steps:

DO:
- Reference the specific product's native features
- Describe the general location of settings (e.g., "in the security settings panel")
- Provide conceptual steps that an admin can follow
- Use phrases like "Configure [product] to..." or "Enable [feature] in [product]"
- Include "Consult vendor documentation" for complex configurations

DO NOT:
- Invent specific configuration file syntax unless 100% certain
- Fabricate command-line flags or API parameters
- Assume configuration file formats you're not certain about
- Mix guidance for different products
- Provide code snippets unless they are standard and well-known

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

Output JSON with IDs, implementation, and CONFIDENCE level (names will be looked up):
{
    "remediations": [
        {
            "id": "M1032",
            "priority": "HIGH",
            "confidence": "high",
            "addresses": ["T1110.003"],
            "implementation": "Enable MFA in ownCloud admin settings. Consult ownCloud documentation for TOTP provider configuration."
        }
    ],
    "defend": [
        {
            "id": "D3-MFA",
            "priority": "HIGH",
            "confidence": "medium",
            "addresses": ["T1110.003"],
            "implementation": "Deploy TOTP-based MFA. Configure according to your authentication provider's documentation.",
            "via": ["M1032"]
        }
    ],
    "detection": [
        {"source": "Authentication Logs", "rationale": "Detects repeated failed logins", "covers": ["T1110.003"]}
    ]
}

CONFIDENCE LEVELS:
- "high": Well-documented, standard approach (e.g., "enable MFA" is always valid)
- "medium": Correct approach but specifics vary by product/version
- "low": General guidance only, implementation details are uncertain

CONSISTENCY RULE: "addresses" and "covers" must ONLY contain technique IDs from Stage 1.

IMPORTANT: Only output valid JSON. No markdown, no explanation outside JSON."""


@dataclass
class RemediationItem:
    """A remediation recommendation from Stage 2."""

    mitigation_id: str
    name: str
    priority: str
    addresses: list[str]
    implementation: str
    confidence: str = "medium"  # "high", "medium", "low"


@dataclass
class D3FendRecommendation:
    """A D3FEND recommendation from Stage 2."""

    d3fend_id: str
    name: str
    priority: str
    addresses: list[str]
    implementation: str
    via_mitigations: list[str]
    confidence: str = "medium"  # "high", "medium", "low"


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

    def rehydrate(self, graph) -> "RemediationResult":
        """
        Rehydrate remediation items with names from the knowledge graph.

        Args:
            graph: AttackGraph instance for lookups

        Returns:
            Self for chaining
        """
        # Rehydrate mitigation names
        for rem in self.remediations:
            if not rem.name:
                mit_data = graph.get_mitigation(rem.mitigation_id)
                if mit_data:
                    rem.name = mit_data.get("name", "")

        # Rehydrate D3FEND names
        for d3f in self.defend_recommendations:
            if not d3f.name:
                d3f_data = graph.get_d3fend_technique(d3f.d3fend_id)
                if d3f_data:
                    d3f.name = d3f_data.get("name", "")

        return self


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

        # Process remediations (support both new "id" and legacy "mitigation_id")
        remediations = []
        for rem in result.get("remediations", []):
            mit_id = rem.get("id", rem.get("mitigation_id", ""))
            if mit_id not in valid_mitigation_ids:
                console.print(f"[yellow]Stage 2: Filtered invalid mitigation: {mit_id}[/yellow]")
                continue

            # Filter addresses to only selected techniques
            addresses = [t for t in rem.get("addresses", []) if t in selected_set]
            if not addresses:
                continue

            remediations.append(RemediationItem(
                mitigation_id=mit_id,
                name=rem.get("name", ""),  # Will be rehydrated if empty
                priority=rem.get("priority", "MEDIUM"),
                addresses=addresses,
                implementation=rem.get("implementation", ""),
                confidence=rem.get("confidence", "medium"),
            ))

        # Process D3FEND recommendations (support both new "id"/"via" and legacy formats)
        defend_recs = []
        raw_defend = result.get("defend", result.get("defend_recommendations", []))
        for d3f in raw_defend:
            d3f_id = d3f.get("id", d3f.get("d3fend_id", ""))
            if d3f_id not in valid_d3fend_ids:
                console.print(f"[yellow]Stage 2: Filtered invalid D3FEND: {d3f_id}[/yellow]")
                continue

            # Filter addresses to only selected techniques
            addresses = [t for t in d3f.get("addresses", []) if t in selected_set]
            if not addresses:
                continue

            # Filter via_mitigations to valid ones (support both "via" and "via_mitigations")
            via_mits = d3f.get("via", d3f.get("via_mitigations", []))
            via_mits = [m for m in via_mits if m in valid_mitigation_ids]

            defend_recs.append(D3FendRecommendation(
                d3fend_id=d3f_id,
                name=d3f.get("name", ""),  # Will be rehydrated if empty
                priority=d3f.get("priority", "MEDIUM"),
                addresses=addresses,
                implementation=d3f.get("implementation", ""),
                via_mitigations=via_mits,
                confidence=d3f.get("confidence", "medium"),
            ))

        # Process detection recommendations (support both new and legacy formats)
        detection_recs = []
        raw_detection = result.get("detection", result.get("detection_recommendations", []))
        for det in raw_detection:
            # Support both "covers" and "techniques_covered"
            covered = det.get("covers", det.get("techniques_covered", []))
            covered = [t for t in covered if t in selected_set]
            if covered:
                detection_recs.append(DetectionRecommendation(
                    data_source=det.get("source", det.get("data_source", "")),
                    rationale=det.get("rationale", ""),
                    techniques_covered=covered,
                ))

        return RemediationResult(
            remediations=remediations,
            defend_recommendations=defend_recs,
            detection_recommendations=detection_recs,
            raw_response=result,
        )
