"""Single-stage LLM analysis with hallucination mitigation."""

import time
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from src.reasoning.encoder import encode_context
from src.reasoning.llm import LLMBackend
from src import debug

console = Console()

SYSTEM_PROMPT = """You are a senior cybersecurity analyst specializing in MITRE ATT&CK threat classification and incident remediation.

### TASK ###
Analyze the security finding using the provided candidate techniques, mitigations, and D3FEND countermeasures. Think through each step systematically before producing output.

### STEP 1: CONTEXT EXTRACTION ###
Extract environmental context from the finding text:
| Indicator | Platform |
|-----------|----------|
| /var/www, systemd, apt, apache2, nginx | Linux |
| C:\\, PowerShell, IIS, .exe, Registry | Windows |
| AWS, Azure, GCP, Lambda, S3 | Cloud |

Note specific products mentioned (FortiOS, ownCloud, Azure AD, etc.).
RULES:
- Reference OS-native capabilities freely (auditd, iptables, Windows Event Logging, Group Policy)
- Strongly prefer products explicitly mentioned in the finding
- For third-party tools (CrowdStrike, Splunk, Okta), only reference if mentioned in the finding
- Generic guidance ("enable MFA", "implement segmentation") is always acceptable

### STEP 2: CLASSIFY FINDING TYPE ###
- "attack_narrative": Past-tense actions, IOCs, log entries showing completed attacker activity
- "vulnerability": CVE references, misconfigurations, or exposures without exploitation evidence

### STEP 3: TECHNIQUE SELECTION (use only provided candidates) ###
For "attack_narrative" findings:
- Select techniques with direct evidence of attacker behavior
- Quote evidence verbatim

For "vulnerability" findings:
- If the vulnerability describes a specific attack mechanism, select matching techniques
- Exposed authentication surfaces (login pages, admin panels, SSO endpoints, APIs) are preconditions for credential attacks — map to relevant techniques (T1110 Brute Force, T1078 Valid Accounts, T1190 Exploit Public-Facing Application) at medium confidence
- Misconfigurations that create a clear attack path (e.g., exposed storage → data theft, default credentials → initial access) also map to techniques
- Only return empty techniques if no candidate describes a plausible attack enabled by this vulnerability

Confidence: high (explicit match), medium (strong inference from exposure/misconfiguration), low (circumstantial)
If no candidates match with at least medium confidence, return empty techniques array.
For vulnerability findings, the "evidence" field should quote the relevant exposure description rather than attacker actions.

### STEP 4: KILL CHAIN ANALYSIS ###
Connect identified techniques chronologically in one sentence.

### STEP 5: REMEDIATION (use only provided candidates) ###
Priority: HIGH (directly prevents), MEDIUM (defense-in-depth), LOW (general hardening)
Confidence: high (well-documented config), medium (correct approach, details vary), low (general guidance)

Implementation: 1-2 specific sentences. When uncertain: "Consult [product] documentation for [capability]"

### STEP 6: DETECTION (use only provided data sources) ###
Build detection recommendations from the <datasources> section in the context.
- Use the EXACT data source name as provided (format is "Data Source: Data Component", e.g., "Application Log: Application Log Content", "Process: Process Creation", "User Account: User Account Authentication")
- Do NOT invent generic names like "Endpoint Process Activity" or "System Discovery Logs"
- Each recommendation should reference a specific data source from the provided list and explain what to look for
- Prefer data sources that cover the most selected techniques

### STEP 7: SELF-VERIFICATION ###
Confirm all IDs appear in provided candidates. Confirm evidence fields are exact quotes. Confirm data_source values match entries from the <datasources> section exactly.

### OUTPUT FORMAT ###
Return valid JSON only.
{
    "techniques": [{"attack_id": "T1110.003", "name": "Password Spraying", "confidence": "high", "evidence": "exact quote", "tactics": ["Credential Access"]}],
    "finding_type": "attack_narrative",
    "kill_chain_analysis": "One sentence connecting techniques.",
    "remediations": [{"mitigation_id": "M1032", "name": "Multi-factor Authentication", "priority": "HIGH", "confidence": "high", "addresses": ["T1110.003"], "implementation": "Enable MFA via Conditional Access."}],
    "defend_recommendations": [{"d3fend_id": "D3-MFA", "name": "Multi-factor Authentication", "priority": "HIGH", "confidence": "medium", "addresses": ["T1110.003"], "implementation": "Deploy TOTP or FIDO2 MFA.", "via_mitigations": ["M1032"]}],
    "detection_recommendations": [{"data_source": "User Account: User Account Authentication", "rationale": "Monitor for distributed authentication failures indicating password spraying", "techniques_covered": ["T1110.003"]}]
}"""


@dataclass
class TechniqueMatch:
    attack_id: str
    name: str
    confidence: str
    evidence: str
    tactics: list[str]


@dataclass
class Remediation:
    mitigation_id: str
    name: str
    priority: str
    confidence: str
    addresses: list[str]
    implementation: str
    d3fend: list[dict[str, str]] = field(default_factory=list)


@dataclass
class Detection:
    data_source: str
    rationale: str
    techniques_covered: list[str]


@dataclass
class AnalysisResult:
    finding: str
    finding_type: str
    techniques: list[TechniqueMatch]
    remediations: list[Remediation]
    detections: list[Detection]
    kill_chain: str
    filtered_ids: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding,
            "finding_type": self.finding_type,
            "techniques": [
                {"attack_id": t.attack_id, "name": t.name, "confidence": t.confidence,
                 "evidence": t.evidence, "tactics": t.tactics}
                for t in self.techniques
            ],
            "remediations": [
                {"mitigation_id": r.mitigation_id, "name": r.name, "priority": r.priority,
                 "confidence": r.confidence, "addresses": r.addresses,
                 "implementation": r.implementation, "d3fend": r.d3fend}
                for r in self.remediations
            ],
            "detections": [
                {"data_source": d.data_source, "rationale": d.rationale,
                 "techniques_covered": d.techniques_covered}
                for d in self.detections
            ],
            "kill_chain_analysis": self.kill_chain,
        }


class AttackAnalyzer:
    """Single-stage LLM analysis pipeline."""

    def __init__(self, engine, llm: LLMBackend, context_format: str = "xml",
                 use_bm25: bool = True):
        self.engine = engine
        self.llm = llm
        self.context_format = context_format
        self.use_bm25 = use_bm25

    def analyze(self, finding: str, top_k: int = 5) -> AnalysisResult:
        # Step 1: Hybrid retrieval
        result = self.engine.query(finding, top_k=top_k, enrich=True, use_bm25=self.use_bm25)

        debug.log_retrieval(finding, [
            {"attack_id": t.attack_id, "name": t.name, "similarity": t.similarity,
             "tactics": t.tactics, "platforms": t.platforms,
             "cooccurrence_boost": t.cooccurrence_boost}
            for t in result.techniques
        ], result.metadata)

        # Step 2: Build context with valid ID constraints
        mitigations, valid_mit_ids = self._collect_mitigations(result.techniques)
        d3fend, valid_d3f_ids = self._collect_d3fend(result.techniques)
        valid_tech_ids = {t.attack_id for t in result.techniques}

        # Prune context to reduce noise for LLM
        mitigations, d3fend = self._prune_context(result.techniques, mitigations, d3fend)
        # Update valid ID sets after pruning
        valid_mit_ids = {m["attack_id"] for m in mitigations}
        valid_d3f_ids = {d["d3fend_id"] for d in d3fend}

        finding_type = result.metadata.get("finding_type", "")
        context = encode_context(
            result.techniques, mitigations, d3fend, self.context_format,
            finding_type=finding_type,
        )

        debug.log_context(self.context_format, context, mitigations, d3fend, {
            "techniques": sorted(valid_tech_ids),
            "mitigations": sorted(valid_mit_ids),
            "d3fend": sorted(valid_d3f_ids),
        })

        # Step 3: LLM call
        prompt = f"Security Finding:\n{finding}\n\n{context}\n\nAnalyze this finding."
        t0 = debug.log_llm_request(prompt, SYSTEM_PROMPT, self.llm.model, type(self.llm).__name__)
        raw = self.llm.generate_json(prompt, system=SYSTEM_PROMPT)
        debug.log_llm_response(raw, time.monotonic() - t0 if debug.enabled() else 0)

        if "error" in raw:
            console.print(f"[red bold]LLM response parse failure[/red bold]")
            return AnalysisResult(
                finding=finding, finding_type="error",
                techniques=[], remediations=[], detections=[],
                kill_chain="", filtered_ids={"error": [raw.get("error", "")]},
            )

        # Step 3b: Log routing vs LLM finding type mismatch
        llm_finding_type = raw.get("finding_type", "attack_narrative")
        router_finding_type = result.metadata.get("finding_type", "")
        if router_finding_type and llm_finding_type != router_finding_type:
            console.print(
                f"[yellow]Router/LLM mismatch: router={router_finding_type}, "
                f"llm={llm_finding_type}[/yellow]"
            )

        # Step 4: Validate (filter hallucinated IDs)
        filtered = {"techniques": [], "mitigations": [], "d3fend": []}

        techniques = []
        for t in raw.get("techniques", []):
            if t.get("attack_id") in valid_tech_ids:
                techniques.append(TechniqueMatch(
                    attack_id=t["attack_id"], name=t.get("name", ""),
                    confidence=t.get("confidence", "medium"),
                    evidence=t.get("evidence", ""), tactics=t.get("tactics", []),
                ))
            else:
                filtered["techniques"].append(t.get("attack_id", ""))

        identified_ids = {t.attack_id for t in techniques}

        remediations = []
        for r in raw.get("remediations", []):
            mid = r.get("mitigation_id", "")
            if mid in valid_mit_ids:
                addrs = [a for a in r.get("addresses", []) if a in identified_ids]
                if addrs:
                    # Collect D3FEND nested under this mitigation
                    nested_d3f = []
                    for d in raw.get("defend_recommendations", []):
                        if mid in d.get("via_mitigations", []) and d.get("d3fend_id") in valid_d3f_ids:
                            nested_d3f.append({
                                "d3fend_id": d["d3fend_id"], "name": d.get("name", ""),
                                "implementation": d.get("implementation", ""),
                            })
                    remediations.append(Remediation(
                        mitigation_id=mid, name=r.get("name", ""),
                        priority=r.get("priority", "MEDIUM"),
                        confidence=r.get("confidence", "medium"),
                        addresses=addrs, implementation=r.get("implementation", ""),
                        d3fend=nested_d3f,
                    ))
            else:
                filtered["mitigations"].append(mid)

        # Build valid data source names from the context
        valid_ds_names = set()
        for tech in result.techniques:
            for ds in tech.data_sources:
                valid_ds_names.add(ds)

        detections = []
        for d in raw.get("detection_recommendations", []):
            ds_name = d.get("data_source", "")
            if valid_ds_names and ds_name not in valid_ds_names:
                filtered.setdefault("data_sources", []).append(ds_name)
                continue
            covered = [t for t in d.get("techniques_covered", []) if t in identified_ids]
            detections.append(Detection(
                data_source=ds_name,
                rationale=d.get("rationale", ""),
                techniques_covered=covered,
            ))

        # Log filtered IDs
        for cat, ids in filtered.items():
            for fid in ids:
                if fid:
                    console.print(f"[yellow]Filtered hallucinated {cat}: {fid}[/yellow]")

        analysis = AnalysisResult(
            finding=finding,
            finding_type=raw.get("finding_type", "attack_narrative"),
            techniques=techniques, remediations=remediations,
            detections=detections,
            kill_chain=raw.get("kill_chain_analysis", ""),
            filtered_ids=filtered,
        )
        debug.log_validation(filtered, analysis.to_dict())
        return analysis

    def _collect_mitigations(self, techniques) -> tuple[list[dict], set[str]]:
        by_id: dict[str, dict] = {}
        for tech in techniques:
            for m in tech.mitigations:
                mid = m["attack_id"]
                if mid not in by_id:
                    by_id[mid] = {**m, "addresses": [tech.attack_id]}
                elif tech.attack_id not in by_id[mid]["addresses"]:
                    by_id[mid]["addresses"].append(tech.attack_id)
        return list(by_id.values()), set(by_id.keys())

    def _collect_d3fend(self, techniques) -> tuple[list[dict], set[str]]:
        by_id: dict[str, dict] = {}
        for tech in techniques:
            for d in tech.d3fend:
                did = d["d3fend_id"]
                if did not in by_id:
                    by_id[did] = {**d, "addresses": [tech.attack_id]}
                elif tech.attack_id not in by_id[did]["addresses"]:
                    by_id[did]["addresses"].append(tech.attack_id)
        return list(by_id.values()), set(by_id.keys())

    @staticmethod
    def _prune_context(
        techniques: list, mitigations: list[dict], d3fend: list[dict],
        max_mitigations: int = 8, max_d3fend: int = 10,
    ) -> tuple[list[dict], list[dict]]:
        """Prune context to reduce noise for LLM.

        Strategy:
        - Focus mitigations on top 3 techniques (highest similarity)
        - Rank mitigations by how many top techniques they address
        - Scope D3FEND to surviving mitigations
        - Cap totals to prevent context bloat
        """
        if not techniques:
            return mitigations, d3fend

        # Focus set: top 3 techniques by similarity, or all if ≤5 total
        if len(techniques) <= 5:
            focus_ids = {t.attack_id for t in techniques}
        else:
            focus_ids = {t.attack_id for t in sorted(
                techniques, key=lambda t: t.similarity, reverse=True,
            )[:3]}

        # Score mitigations: +2 for each focus technique addressed, +1 for others
        def mit_score(m: dict) -> int:
            addrs = set(m.get("addresses", []))
            return 2 * len(addrs & focus_ids) + len(addrs - focus_ids)

        scored = sorted(mitigations, key=mit_score, reverse=True)
        # Keep mitigations that address at least one focus technique, up to cap
        pruned_mits = [m for m in scored if set(m.get("addresses", [])) & focus_ids]
        pruned_mits = pruned_mits[:max_mitigations]
        surviving_mit_ids = {m["attack_id"] for m in pruned_mits}

        # Scope D3FEND to surviving mitigations
        pruned_d3f = [d for d in d3fend if d.get("via_mitigation") in surviving_mit_ids]
        pruned_d3f = pruned_d3f[:max_d3fend]

        return pruned_mits, pruned_d3f
