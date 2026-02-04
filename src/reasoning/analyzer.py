"""Attack narrative analyzer for classifying findings with MITRE ATT&CK techniques."""

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel

from src.reasoning.toon_encoder import (
    build_toon_context,
    techniques_to_toon,
    mitigations_to_toon,
    d3fend_to_toon,
)

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

    d3fend_id: str
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
    d3fend_techniques: list[DefendTechnique] = field(default_factory=list)
    confidence: str = "medium"  # "high", "medium", "low" - LLM's confidence in implementation specifics


@dataclass
class DefendRecommendation:
    """A D3FEND defensive technique recommendation."""

    d3fend_id: str
    name: str
    priority: str  # "HIGH", "MEDIUM", "LOW"
    addresses: list[str]  # technique IDs
    implementation: str
    via_mitigations: list[str] = field(default_factory=list)
    confidence: str = "medium"  # "high", "medium", "low" - LLM's confidence in implementation specifics


@dataclass
class DetectionRecommendation:
    """A detection recommendation based on data sources."""

    data_source: str
    rationale: str
    techniques_covered: list[str]


@dataclass
class ContextConstraints:
    """Valid IDs from RAG context for constraining LLM output."""

    technique_ids: set[str]
    mitigation_ids: set[str]
    d3fend_ids: set[str]


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
    filtered_ids: dict[str, list[str]] = field(default_factory=dict)  # IDs removed by validation

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
                    "confidence": r.confidence,
                    "addresses": r.addresses,
                    "implementation": r.implementation,
                    "d3fend_techniques": [
                        {"d3fend_id": d.d3fend_id, "name": d.name, "implementation": d.implementation}
                        for d in r.d3fend_techniques
                    ] if r.d3fend_techniques else [],
                }
                for r in self.remediations
            ],
            "defend_recommendations": [
                {
                    "d3fend_id": d.d3fend_id,
                    "name": d.name,
                    "priority": d.priority,
                    "confidence": d.confidence,
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
            "filtered_ids": self.filtered_ids,
        }


# Single combined prompt for classification + remediation
ANALYSIS_SYSTEM_PROMPT = """You are a cybersecurity analyst expert in MITRE ATT&CK and D3FEND frameworks.
Your task is to analyze security findings, identify relevant ATT&CK techniques, and provide remediation guidance.

You will receive:
1. A security finding (attack narrative OR vulnerability/misconfiguration)
2. Candidate ATT&CK techniques with descriptions, threat groups, and detection data sources
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

Use ONLY these indicators to scope your recommendations. Do NOT assume enterprise tools (Azure AD, Okta, CrowdStrike) unless the finding explicitly mentions them.

═══════════════════════════════════════════════════════════════════════════════
FINDING TYPES
═══════════════════════════════════════════════════════════════════════════════

**Attack Narratives** (evidence of adversary activity):
- Identify techniques with clear evidence from the narrative
- Evidence describes what the attacker DID
- Remediations prevent recurrence

**Vulnerability/Misconfiguration Findings** (no attack yet):
- Identify techniques that COULD exploit this vulnerability
- Evidence describes HOW an attacker could leverage this weakness
- Remediations close the exposure before exploitation

═══════════════════════════════════════════════════════════════════════════════
IMPLEMENTATION GUIDANCE RULES (CRITICAL)
═══════════════════════════════════════════════════════════════════════════════

When writing implementation steps:

DO:
- Reference the specific product's native features (e.g., "ownCloud's built-in 2FA module")
- Describe the general location of settings (e.g., "Settings > Security > Two-Factor Authentication")
- Provide conceptual steps that an admin can follow
- Use phrases like "Configure [product] to..." or "Enable [feature] in [product]"
- Mention CLI tools by name if commonly known (e.g., "occ command for ownCloud")

DO NOT:
- Invent specific configuration file syntax (e.g., config.php arrays) unless you are 100% certain
- Fabricate command-line flags or API parameters
- Assume configuration file formats or locations you're not certain about
- Mix guidance for different products (e.g., Azure AD for self-hosted Linux apps)

WHEN UNCERTAIN about exact syntax or configuration:
- State the goal clearly: "Configure password complexity requirements"
- Reference official docs: "Refer to [product] documentation for exact configuration syntax"
- Describe the admin UI path if known: "Navigate to Admin > Security settings"
- Avoid inventing specific code/config that could be wrong

═══════════════════════════════════════════════════════════════════════════════
ANTI-HALLUCINATION RULES (CRITICAL)
═══════════════════════════════════════════════════════════════════════════════

NEVER INVENT:
- Configuration file paths you're not 100% certain exist
- Command-line flags, options, or parameters you're uncertain about
- API endpoints, methods, or payloads
- Specific version numbers unless stated in the finding
- Product names or services not mentioned in the finding

ALWAYS:
- Add "confidence": "high"/"medium"/"low" to each remediation item
- Use "low" confidence when providing general guidance without specific syntax
- Use "medium" confidence when you know the approach but not exact steps
- Use "high" confidence ONLY for well-documented, standard configurations

EXAMPLE OF GOOD GUIDANCE:
"Enable MFA in ownCloud via the admin settings. Consult ownCloud documentation for TOTP configuration."

EXAMPLE OF BAD GUIDANCE (DO NOT DO THIS):
"Edit /etc/owncloud/config.php and add: $CONFIG['mfa_enabled'] = true;"
^ This invents file paths and config syntax that may not exist!

═══════════════════════════════════════════════════════════════════════════════
PRIORITIZATION
═══════════════════════════════════════════════════════════════════════════════

For ATT&CK Mitigations:
- HIGH: Directly addresses primary technique(s), broad coverage
- MEDIUM: Addresses secondary techniques or provides defense-in-depth
- LOW: Useful but not essential for this specific finding

For D3FEND Techniques:
- Nest under parent mitigation when there's a direct mapping
- Provide operational/detection-focused guidance (D3FEND is more specific than ATT&CK mitigations)
- Focus on monitoring, thresholds, and active defense measures

═══════════════════════════════════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════════════════════════════════

Output JSON with this exact structure:
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
    "kill_chain_analysis": "Brief attack lifecycle description",
    "remediations": [
        {
            "mitigation_id": "M1032",
            "name": "Multi-factor Authentication",
            "priority": "HIGH",
            "confidence": "high",
            "addresses": ["T1110.003"],
            "implementation": "1. Enable [product]'s built-in 2FA feature. 2. Require 2FA for admin accounts. 3. Consult [product] documentation for exact configuration."
        }
    ],
    "defend_recommendations": [
        {
            "d3fend_id": "D3-MFA",
            "name": "Multi-factor Authentication",
            "priority": "HIGH",
            "confidence": "medium",
            "addresses": ["T1110.003"],
            "implementation": "Deploy TOTP-based MFA. Consult your authentication provider's documentation for configuration.",
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

CONSISTENCY RULE: The "addresses" and "techniques_covered" fields in remediations, defend_recommendations, and detection_recommendations must ONLY contain technique IDs that appear in your "techniques" array. Do not reference techniques you did not identify.

═══════════════════════════════════════════════════════════════════════════════
FINAL CHECKLIST
═══════════════════════════════════════════════════════════════════════════════

Before outputting, verify:
- All recommendations match the detected OS/product (no Windows advice for Linux)
- No invented configuration syntax or file formats
- Implementation steps are actionable but not falsely specific
- D3FEND techniques are nested under relevant mitigations where applicable
- Techniques have clear evidence tied to the finding text
- CRITICAL: Remediations and D3FEND "addresses" fields ONLY reference technique IDs that appear in your "techniques" list. Do not reference techniques you did not identify."""


class AttackAnalyzer:
    """
    Analyzes attack narratives to identify ATT&CK techniques and suggest remediation.

    Uses the hybrid query engine to find candidate techniques, then leverages
    an LLM to classify and provide comprehensive remediation including D3FEND.

    Supports two modes:
    - Single-stage (default): One LLM call for classification + remediation
    - Two-stage: Separate LLM calls for node selection and remediation writing
    """

    def __init__(
        self,
        hybrid_engine,
        llm_backend=None,
        two_stage: bool = False,
        use_toon: bool = True,
        use_bm25: bool = True,
        use_kill_chain: bool = True,
    ):
        """
        Initialize the analyzer.

        Args:
            hybrid_engine: HybridQueryEngine instance
            llm_backend: LLM backend to use (defaults to Ollama)
            two_stage: Use two-stage LLM architecture (default False)
            use_toon: Use TOON format for context (default True)
            use_bm25: Use BM25 hybrid retrieval (default True)
            use_kill_chain: Include kill chain adjacent techniques (default True)
        """
        self.hybrid = hybrid_engine
        if llm_backend is None:
            from src.reasoning.llm import OllamaBackend
            llm_backend = OllamaBackend()
        self.llm = llm_backend
        self.two_stage = two_stage
        self.use_toon = use_toon
        self.use_bm25 = use_bm25
        self.use_kill_chain = use_kill_chain

        # Lazy-load two-stage components
        self._selector = None
        self._remediator = None

    @property
    def selector(self):
        """Lazy-load the NodeSelector for Stage 1."""
        if self._selector is None:
            from src.reasoning.stages import NodeSelector
            self._selector = NodeSelector(self.llm)
        return self._selector

    @property
    def remediator(self):
        """Lazy-load the RemediationWriter for Stage 2."""
        if self._remediator is None:
            from src.reasoning.stages import RemediationWriter
            self._remediator = RemediationWriter(self.llm, self.hybrid.graph)
        return self._remediator

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
        hybrid_result = self.hybrid.query(
            finding_text,
            top_k=top_k,
            enrich=True,
            use_bm25=self.use_bm25,
            use_kill_chain=self.use_kill_chain,
        )

        if self.two_stage:
            return self._analyze_two_stage(finding_text, hybrid_result)
        else:
            return self._analyze_single_stage(finding_text, hybrid_result)

    def _analyze_single_stage(self, finding_text: str, hybrid_result) -> AnalysisResult:
        """Single-stage analysis (original implementation)."""
        from src.logging import log_llm_request

        # Build complete context including D3FEND and get valid ID constraints
        if self.use_toon:
            context, constraints = self._build_toon_context(hybrid_result.techniques, hybrid_result)
        else:
            context, constraints = self._build_complete_context(hybrid_result.techniques)

        # Single LLM call for classification + remediation
        prompt = f"""Security Finding:
{finding_text}

{context}

Analyze this finding and provide:
1. Which techniques are evidenced (or could be exploited if vulnerability)
2. Prioritized ATT&CK mitigations with specific implementation steps
3. D3FEND defensive techniques with actionable guidance
4. Detection recommendations based on available data sources"""

        log_llm_request(prompt, system=ANALYSIS_SYSTEM_PROMPT, model="single-stage")
        raw_result = self.llm.generate_json(prompt, system=ANALYSIS_SYSTEM_PROMPT)

        # Validate and filter LLM response to only include IDs from RAG context
        result, filtered_ids = self._validate_llm_response(raw_result, constraints)

        # Build response with group enrichment
        techniques = self._enrich_with_groups(result, hybrid_result.techniques)

        # Build remediations and merge D3FEND into them
        remediations, defend_recommendations = self._merge_d3fend_into_mitigations(
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
            raw_llm_response=raw_result,
            filtered_ids=filtered_ids,
        )

    def _analyze_two_stage(self, finding_text: str, hybrid_result) -> AnalysisResult:
        """Two-stage analysis with separate selection and remediation."""
        # Build constraints from retrieved techniques
        valid_technique_ids: set[str] = set()
        valid_mitigation_ids: set[str] = set()
        valid_d3fend_ids: set[str] = set()

        mitigations_by_id: dict[str, dict] = {}
        d3fend_by_id: dict[str, dict] = {}

        for tech in hybrid_result.techniques:
            valid_technique_ids.add(tech.attack_id)

            for mit in tech.mitigations:
                mit_id = mit["attack_id"]
                valid_mitigation_ids.add(mit_id)
                if mit_id not in mitigations_by_id:
                    mitigations_by_id[mit_id] = {**mit, "addresses": [tech.attack_id]}
                else:
                    if tech.attack_id not in mitigations_by_id[mit_id]["addresses"]:
                        mitigations_by_id[mit_id]["addresses"].append(tech.attack_id)

            # Collect D3FEND techniques
            d3fend_techniques = self.hybrid.graph.get_d3fend_for_technique(tech.attack_id)
            for d3f in d3fend_techniques:
                d3f_id = d3f["d3fend_id"]
                valid_d3fend_ids.add(d3f_id)
                if d3f_id not in d3fend_by_id:
                    d3fend_by_id[d3f_id] = {
                        **d3f,
                        "addresses": [tech.attack_id],
                        "via_mitigations": [d3f.get("via_mitigation", "")],
                    }
                else:
                    if tech.attack_id not in d3fend_by_id[d3f_id]["addresses"]:
                        d3fend_by_id[d3f_id]["addresses"].append(tech.attack_id)

        # ===== STAGE 1: Node Selection =====
        console.print("[dim]Stage 1: Selecting relevant techniques...[/dim]")

        # Build TOON context for Stage 1 (techniques only, no mitigations/D3FEND yet)
        candidates_toon = techniques_to_toon(hybrid_result.techniques, include_description=True)

        # Add kill chain context if available
        if hybrid_result.kill_chain_context:
            candidates_toon += f"\n\nKILL CHAIN CONTEXT\n{hybrid_result.kill_chain_context}"

        selection = self.selector.select(finding_text, candidates_toon, valid_technique_ids)

        # Rehydrate selected techniques with authoritative data from the graph
        selection.rehydrate(self.hybrid.graph)

        if not selection.selected_techniques:
            console.print("[yellow]Stage 1: No techniques selected[/yellow]")
            return AnalysisResult(
                finding=finding_text,
                techniques=[],
                remediations=[],
                finding_type=selection.finding_type,
                kill_chain_analysis=selection.kill_chain_analysis,
            )

        selected_ids = selection.get_technique_ids()
        console.print(f"[green]Stage 1: Selected {len(selected_ids)} techniques: {', '.join(selected_ids)}[/green]")

        # ===== STAGE 2: Remediation Writing =====
        console.print("[dim]Stage 2: Writing remediation guidance...[/dim]")

        # Filter mitigations to only those relevant to selected techniques
        filtered_mitigations = []
        for mit_id, mit in mitigations_by_id.items():
            relevant_addresses = [t for t in mit["addresses"] if t in selected_ids]
            if relevant_addresses:
                filtered_mitigations.append({**mit, "addresses": relevant_addresses})

        # Filter D3FEND to only those relevant to selected techniques
        filtered_d3fend = []
        for d3f_id, d3f in d3fend_by_id.items():
            relevant_addresses = [t for t in d3f["addresses"] if t in selected_ids]
            if relevant_addresses:
                filtered_d3fend.append({**d3f, "addresses": relevant_addresses})

        # Build TOON context for Stage 2
        mitigations_toon = mitigations_to_toon(filtered_mitigations)
        d3fend_toon = d3fend_to_toon(filtered_d3fend)

        remediation_result = self.remediator.write(
            finding_text,
            selected_ids,
            mitigations_toon,
            d3fend_toon,
            valid_mitigation_ids,
            valid_d3fend_ids,
        )

        # Rehydrate remediation names from the graph
        remediation_result.rehydrate(self.hybrid.graph)

        # Build techniques list from Stage 1 selection (rehydrated with graph data)
        tech_lookup = {t.attack_id: t for t in hybrid_result.techniques}
        techniques = []
        for sel_tech in selection.selected_techniques:
            # Get groups from hybrid_result (already retrieved during search)
            enriched = tech_lookup.get(sel_tech.attack_id)
            groups = enriched.groups[:5] if enriched and enriched.groups else []

            techniques.append(TechniqueMatch(
                attack_id=sel_tech.attack_id,
                name=sel_tech.name,  # Rehydrated from graph
                confidence=sel_tech.confidence,
                evidence=sel_tech.evidence,
                tactics=[sel_tech.tactic] if sel_tech.tactic else [],  # Rehydrated from graph
                groups=groups,
            ))

        # Convert Stage 2 results to analyzer result format
        remediations = []
        for rem in remediation_result.remediations:
            remediations.append(RemediationItem(
                mitigation_id=rem.mitigation_id,
                name=rem.name,
                priority=rem.priority,
                addresses=rem.addresses,
                implementation=rem.implementation,
                d3fend_techniques=[],  # Will be populated below
                confidence=rem.confidence,
            ))

        # Merge D3FEND into mitigations
        defend_recommendations = []
        for d3f in remediation_result.defend_recommendations:
            # Check if this D3FEND maps to a mitigation in our results
            matched = False
            for rem in remediations:
                if rem.mitigation_id in d3f.via_mitigations:
                    rem.d3fend_techniques.append(DefendTechnique(
                        d3fend_id=d3f.d3fend_id,
                        name=d3f.name,
                        implementation=d3f.implementation,
                    ))
                    matched = True
                    break

            if not matched:
                defend_recommendations.append(DefendRecommendation(
                    d3fend_id=d3f.d3fend_id,
                    name=d3f.name,
                    priority=d3f.priority,
                    addresses=d3f.addresses,
                    implementation=d3f.implementation,
                    via_mitigations=d3f.via_mitigations,
                    confidence=d3f.confidence,
                ))

        detection_recs = [
            DetectionRecommendation(
                data_source=d.data_source,
                rationale=d.rationale,
                techniques_covered=d.techniques_covered,
            )
            for d in remediation_result.detection_recommendations
        ]

        return AnalysisResult(
            finding=finding_text,
            techniques=techniques,
            remediations=remediations,
            defend_recommendations=defend_recommendations,
            detection_recommendations=detection_recs,
            finding_type=selection.finding_type,
            kill_chain_analysis=selection.kill_chain_analysis,
            raw_llm_response={
                "stage1": selection.raw_response,
                "stage2": remediation_result.raw_response,
            },
        )

    def _build_toon_context(self, techniques, hybrid_result=None) -> tuple[str, ContextConstraints]:
        """Build TOON-formatted context for LLM.

        Returns:
            Tuple of (toon_context_string, ContextConstraints with valid IDs)
        """
        from src.reasoning.toon_encoder import (
            build_toon_context,
            estimate_token_savings,
        )

        # Track valid IDs for constraining LLM output
        valid_technique_ids: set[str] = set()
        valid_mitigation_ids: set[str] = set()
        valid_d3fend_ids: set[str] = set()

        # Collect mitigations
        mitigations_list = []
        mitigations_by_id: dict[str, dict] = {}
        for tech in techniques:
            valid_technique_ids.add(tech.attack_id)
            for mit in tech.mitigations:
                mit_id = mit["attack_id"]
                valid_mitigation_ids.add(mit_id)
                if mit_id not in mitigations_by_id:
                    mitigations_by_id[mit_id] = {**mit, "addresses": [tech.attack_id]}
                else:
                    if tech.attack_id not in mitigations_by_id[mit_id]["addresses"]:
                        mitigations_by_id[mit_id]["addresses"].append(tech.attack_id)

        mitigations_list = list(mitigations_by_id.values())

        # Collect D3FEND techniques
        d3fend_list = []
        d3fend_by_id: dict[str, dict] = {}
        for tech in techniques:
            d3fend_techniques = self.hybrid.graph.get_d3fend_for_technique(tech.attack_id)
            for d3f in d3fend_techniques:
                d3f_id = d3f["d3fend_id"]
                valid_d3fend_ids.add(d3f_id)
                if d3f_id not in d3fend_by_id:
                    d3fend_by_id[d3f_id] = {
                        **d3f,
                        "addresses": [tech.attack_id],
                        "via_mitigations": [d3f.get("via_mitigation", "")],
                    }
                else:
                    if tech.attack_id not in d3fend_by_id[d3f_id]["addresses"]:
                        d3fend_by_id[d3f_id]["addresses"].append(tech.attack_id)

        d3fend_list = list(d3fend_by_id.values())

        # Build TOON context
        toon_context = build_toon_context(
            techniques=techniques,
            mitigations=mitigations_list,
            d3fend_techniques=d3fend_list,
            include_description=True,
            include_data_sources=True,
        )

        constraints = ContextConstraints(
            technique_ids=valid_technique_ids,
            mitigation_ids=valid_mitigation_ids,
            d3fend_ids=valid_d3fend_ids,
        )

        return toon_context, constraints

    def _build_complete_context(self, techniques) -> tuple[str, ContextConstraints]:
        """Build complete context with techniques, mitigations, and D3FEND.

        Returns:
            Tuple of (context_string, ContextConstraints with valid IDs)
        """
        sections = []

        # Track valid IDs for constraining LLM output
        valid_technique_ids: set[str] = set()
        valid_mitigation_ids: set[str] = set()
        valid_d3fend_ids: set[str] = set()

        # Section 1: Candidate techniques
        sections.append("CANDIDATE ATT&CK TECHNIQUES:")
        for tech in techniques:
            valid_technique_ids.add(tech.attack_id)
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
                valid_mitigation_ids.add(mit_id)
                inherited = " [inherited]" if mit.get("inherited") else ""
                sections.append(
                    f"  {mit_id} ({mit['name']}){inherited} - addresses: {', '.join(mit['addresses'])}"
                )
        else:
            sections.append("  No specific mitigations found.")

        # Section 3: D3FEND countermeasures
        sections.append("\n\nD3FEND DEFENSIVE TECHNIQUES:")
        d3fend_by_id = {}
        for tech in techniques:
            d3fend_techniques = self.hybrid.graph.get_d3fend_for_technique(tech.attack_id)
            for d3f in d3fend_techniques:
                d3f_id = d3f["d3fend_id"]  # Key from graph.py
                if d3f_id not in d3fend_by_id:
                    d3fend_by_id[d3f_id] = {
                        **d3f,
                        "addresses": [tech.attack_id],
                        "via_mitigations": [d3f["via_mitigation"]],
                    }
                else:
                    if tech.attack_id not in d3fend_by_id[d3f_id]["addresses"]:
                        d3fend_by_id[d3f_id]["addresses"].append(tech.attack_id)
                    if d3f["via_mitigation"] not in d3fend_by_id[d3f_id]["via_mitigations"]:
                        d3fend_by_id[d3f_id]["via_mitigations"].append(d3f["via_mitigation"])

        if d3fend_by_id:
            for d3f_id, d3f in d3fend_by_id.items():
                valid_d3fend_ids.add(d3f_id)
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

        constraints = ContextConstraints(
            technique_ids=valid_technique_ids,
            mitigation_ids=valid_mitigation_ids,
            d3fend_ids=valid_d3fend_ids,
        )

        return "\n".join(sections), constraints

    def _validate_llm_response(
        self,
        llm_result: dict[str, Any],
        constraints: ContextConstraints,
    ) -> tuple[dict[str, Any], dict[str, list[str]]]:
        """Validate and filter LLM response to only include IDs from RAG context.

        Args:
            llm_result: Raw LLM JSON response
            constraints: Valid IDs from context

        Returns:
            Tuple of (filtered_result, filtered_ids_by_type)
        """
        filtered_ids: dict[str, list[str]] = {
            "techniques": [],
            "mitigations": [],
            "d3fend": [],
        }

        result = llm_result.copy()

        # Filter techniques to only those in context
        if "techniques" in result:
            valid_techniques = []
            for t in result["techniques"]:
                attack_id = t.get("attack_id", "")
                if attack_id in constraints.technique_ids:
                    valid_techniques.append(t)
                else:
                    filtered_ids["techniques"].append(attack_id)
                    console.print(
                        f"[yellow]Filtered hallucinated technique: {attack_id}[/yellow]"
                    )
            result["techniques"] = valid_techniques

        # Get the set of technique IDs the LLM actually identified (post-filtering)
        identified_technique_ids = {
            t.get("attack_id", "") for t in result.get("techniques", [])
        }

        # Filter remediations to only valid mitigation IDs
        if "remediations" in result:
            valid_remediations = []
            for r in result["remediations"]:
                mit_id = r.get("mitigation_id", "")
                if mit_id in constraints.mitigation_ids:
                    # Also filter the "addresses" field to only identified techniques
                    r["addresses"] = [
                        tid for tid in r.get("addresses", [])
                        if tid in identified_technique_ids
                    ]
                    if r["addresses"]:  # Only keep if it addresses at least one technique
                        valid_remediations.append(r)
                    else:
                        filtered_ids["mitigations"].append(mit_id)
                        console.print(
                            f"[yellow]Filtered mitigation with no valid addresses: {mit_id}[/yellow]"
                        )
                else:
                    filtered_ids["mitigations"].append(mit_id)
                    console.print(
                        f"[yellow]Filtered hallucinated mitigation: {mit_id}[/yellow]"
                    )
            result["remediations"] = valid_remediations

        # Filter D3FEND recommendations to only valid IDs
        if "defend_recommendations" in result:
            valid_d3fend = []
            for d in result["defend_recommendations"]:
                d3f_id = d.get("d3fend_id", "")
                if d3f_id in constraints.d3fend_ids:
                    # Filter "addresses" to only identified techniques
                    d["addresses"] = [
                        tid for tid in d.get("addresses", [])
                        if tid in identified_technique_ids
                    ]
                    # Filter "via_mitigations" to only valid mitigations
                    d["via_mitigations"] = [
                        mid for mid in d.get("via_mitigations", [])
                        if mid in constraints.mitigation_ids
                    ]
                    if d["addresses"]:  # Only keep if it addresses at least one technique
                        valid_d3fend.append(d)
                    else:
                        filtered_ids["d3fend"].append(d3f_id)
                        console.print(
                            f"[yellow]Filtered D3FEND with no valid addresses: {d3f_id}[/yellow]"
                        )
                else:
                    filtered_ids["d3fend"].append(d3f_id)
                    console.print(
                        f"[yellow]Filtered hallucinated D3FEND: {d3f_id}[/yellow]"
                    )
            result["defend_recommendations"] = valid_d3fend

        # Filter detection recommendations' technique references
        if "detection_recommendations" in result:
            for det in result["detection_recommendations"]:
                det["techniques_covered"] = [
                    tid for tid in det.get("techniques_covered", [])
                    if tid in identified_technique_ids
                ]

        return result, filtered_ids

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

    def _merge_d3fend_into_mitigations(
        self,
        raw_remediations: list[dict[str, Any]],
        raw_d3fend: list[dict[str, Any]],
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
        d3fend_by_mitigation: dict[str, list[dict]] = {}
        standalone_d3fend: list[dict] = []

        for d in raw_d3fend:
            via_mitigations = d.get("via_mitigations", [])
            matched = False

            for mit_id in via_mitigations:
                if mit_id in mitigation_ids:
                    if mit_id not in d3fend_by_mitigation:
                        d3fend_by_mitigation[mit_id] = []
                    d3fend_by_mitigation[mit_id].append(d)
                    matched = True
                    break  # Only nest under first matching mitigation

            if not matched and via_mitigations:
                # D3FEND maps to a mitigation not in our list - still standalone
                standalone_d3fend.append(d)
            elif not via_mitigations:
                # No mitigation mapping - standalone
                standalone_d3fend.append(d)

        # Build remediations with nested D3FEND
        remediations = []
        for r in raw_remediations:
            mit_id = r.get("mitigation_id", "")
            nested_d3fend = [
                DefendTechnique(
                    d3fend_id=d.get("d3fend_id", ""),
                    name=d.get("name", ""),
                    implementation=d.get("implementation", ""),
                )
                for d in d3fend_by_mitigation.get(mit_id, [])
            ]

            remediations.append(
                RemediationItem(
                    mitigation_id=mit_id,
                    name=r.get("name", ""),
                    priority=r.get("priority", "MEDIUM"),
                    addresses=r.get("addresses", []),
                    implementation=r.get("implementation", ""),
                    d3fend_techniques=nested_d3fend,
                    confidence=r.get("confidence", "medium"),
                )
            )

        # Build standalone D3FEND recommendations
        standalone = [
            DefendRecommendation(
                d3fend_id=d.get("d3fend_id", ""),
                name=d.get("name", ""),
                priority=d.get("priority", "MEDIUM"),
                addresses=d.get("addresses", []),
                implementation=d.get("implementation", ""),
                via_mitigations=d.get("via_mitigations", []),
                confidence=d.get("confidence", "medium"),
            )
            for d in standalone_d3fend
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
            conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(
                rem.confidence.lower() if rem.confidence else "medium", "white"
            )
            conf_label = rem.confidence.capitalize() if rem.confidence else "Medium"

            console.print(
                f"[bold]{i}. {rem.name}[/bold] ({rem.mitigation_id}) - "
                f"[{priority_color}]{rem.priority} PRIORITY[/{priority_color}] "
                f"[dim]([{conf_color}]{conf_label} confidence[/{conf_color}])[/dim]"
            )
            console.print(f"   [dim]Addresses:[/dim] {', '.join(rem.addresses)}")
            console.print(f"   [dim]Implementation:[/dim]")
            for line in rem.implementation.split('\n'):
                console.print(f"   {line}")

            # Show nested D3FEND techniques if present
            if rem.d3fend_techniques:
                d3f_ids = ", ".join(d.d3fend_id for d in rem.d3fend_techniques)
                console.print(f"   [dim]D3FEND:[/dim] {d3f_ids}")
                for d3f in rem.d3fend_techniques:
                    if d3f.implementation:
                        console.print(f"      [dim]{d3f.d3fend_id}:[/dim] {d3f.implementation}")

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
                f"[bold]{i}. {d3f.name}[/bold] ({d3f.d3fend_id}) - "
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
    nested_d3fend_count = sum(len(r.d3fend_techniques) for r in result.remediations)
    total_d3fend = nested_d3fend_count + len(result.defend_recommendations)

    if result.remediations or result.defend_recommendations:
        summary_parts = [f"{len(result.techniques)} techniques"]
        summary_parts.append(f"{len(result.remediations)} mitigations")
        if total_d3fend > 0:
            summary_parts.append(f"{total_d3fend} D3FEND techniques")
        console.print(f"[dim]Summary: {', '.join(summary_parts)}[/dim]")

    # Show filtered IDs if any
    if result.filtered_ids:
        total_filtered = sum(len(ids) for ids in result.filtered_ids.values())
        if total_filtered > 0:
            console.print()
            console.print("[dim yellow]Filtered hallucinated IDs (not in RAG context):[/dim yellow]")
            if result.filtered_ids.get("techniques"):
                console.print(f"  [dim]Techniques: {', '.join(result.filtered_ids['techniques'])}[/dim]")
            if result.filtered_ids.get("mitigations"):
                console.print(f"  [dim]Mitigations: {', '.join(result.filtered_ids['mitigations'])}[/dim]")
            if result.filtered_ids.get("d3fend"):
                console.print(f"  [dim]D3FEND: {', '.join(result.filtered_ids['d3fend'])}[/dim]")
