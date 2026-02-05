"""Deterministic finding-type router for pre-classification before retrieval."""

import re
from dataclasses import dataclass, field
from enum import Enum


class FindingType(Enum):
    VULNERABILITY = "vulnerability"
    ATTACK_NARRATIVE = "attack_narrative"


@dataclass
class RoutingDecision:
    finding_type: FindingType
    confidence: float  # 0.0–1.0
    signals: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)


# --- Vulnerability signals (pattern, weight, label) ---
_VULN_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE), 0.9, "cve_id"),
    (re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE), 0.9, "cwe_id"),
    (re.compile(r"\bCVSS\b", re.IGNORECASE), 0.6, "cvss"),
    (re.compile(r"\bvulnerabilit(?:y|ies)\b", re.IGNORECASE), 0.5, "vulnerability_kw"),
    (re.compile(r"\bmisconfigur(?:ation|ed)\b", re.IGNORECASE), 0.5, "misconfiguration_kw"),
    (re.compile(r"\bexposure\b", re.IGNORECASE), 0.4, "exposure_kw"),
    (re.compile(r"\badvisor(?:y|ies)\b", re.IGNORECASE), 0.5, "advisory_kw"),
    (re.compile(r"\bunpatched\b", re.IGNORECASE), 0.8, "unpatched_kw"),
    (re.compile(r"\b(?:remote code execution|RCE)\b", re.IGNORECASE), 0.7, "rce_kw"),
    (re.compile(r"\b(?:privilege escalation|privesc)\b", re.IGNORECASE), 0.3, "privesc_kw"),
    (re.compile(r"\bauthentication bypass\b", re.IGNORECASE), 0.6, "auth_bypass_kw"),
    (re.compile(r"\bbuffer overflow\b", re.IGNORECASE), 0.7, "buffer_overflow_kw"),
    (re.compile(r"\binjection\b", re.IGNORECASE), 0.3, "injection_kw"),
]

# --- Attack narrative signals (pattern, weight, label) ---
_ATTACK_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r"\bAPT[-\s]?\d+\b", re.IGNORECASE), 0.8, "apt_name"),
    (re.compile(
        r"\b(?:Lazarus|Fancy Bear|Cozy Bear|Turla|Sandworm|Hafnium|Nobelium|Kimsuky"
        r"|Charming Kitten|APT28|APT29|APT41|FIN7|FIN11|Carbanak|Cobalt Group"
        r"|MuddyWater|OilRig|Equation Group|DarkSide|REvil|Conti|LockBit)\b",
        re.IGNORECASE,
    ), 0.8, "threat_actor"),
    # IOCs: IP addresses
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), 0.7, "ip_address"),
    # IOCs: file hashes (MD5, SHA1, SHA256)
    (re.compile(r"\b[0-9a-fA-F]{32}\b"), 0.7, "md5_hash"),
    (re.compile(r"\b[0-9a-fA-F]{64}\b"), 0.8, "sha256_hash"),
    # Past-tense action verbs
    (re.compile(
        r"\b(?:executed|exfiltrated|compromised|deployed|injected|exploited|installed"
        r"|downloaded|uploaded|established|persisted|escalated|moved laterally"
        r"|harvested|captured|encrypted|decrypted|deleted|modified|accessed)\b",
        re.IGNORECASE,
    ), 0.7, "past_tense_action"),
    # Incident keywords
    (re.compile(r"\bcampaign\b", re.IGNORECASE), 0.5, "campaign_kw"),
    (re.compile(r"\bbreach\b", re.IGNORECASE), 0.5, "breach_kw"),
    (re.compile(r"\bincident\b", re.IGNORECASE), 0.4, "incident_kw"),
    (re.compile(r"\bthreat actor\b", re.IGNORECASE), 0.7, "threat_actor_kw"),
    (re.compile(r"\bC2\b|command.and.control\b", re.IGNORECASE), 0.6, "c2_kw"),
    (re.compile(r"\blateral movement\b", re.IGNORECASE), 0.5, "lateral_movement_kw"),
]

# --- Platform detection patterns ---
_PLATFORM_PATTERNS: list[tuple[re.Pattern, list[str], str]] = [
    # Windows
    (re.compile(
        r"\b(?:Windows|PowerShell|\.exe|Registry|HKLM|HKCU|cmd\.exe|Active Directory"
        r"|Group Policy|GPO|WMI|WMIC|Event Log|Sysmon|NTLM|Kerberos)\b",
        re.IGNORECASE,
    ), ["Windows"], "windows"),
    # Linux
    (re.compile(
        r"\b(?:Linux|Ubuntu|Debian|CentOS|RHEL|Red Hat|Fedora|systemd|/bin/bash"
        r"|/etc/passwd|crontab|apt|yum|auditd|iptables|SELinux|sudo)\b",
        re.IGNORECASE,
    ), ["Linux"], "linux"),
    # macOS
    (re.compile(
        r"\b(?:macOS|Mac OS|Darwin|\.app|Gatekeeper|XProtect|launchd|osascript)\b",
        re.IGNORECASE,
    ), ["macOS"], "macos"),
    # Cloud IaaS/SaaS
    (re.compile(
        r"\b(?:AWS|Amazon Web Services|Azure|GCP|Google Cloud|Lambda|S3|EC2|ECS|EKS"
        r"|Kubernetes|K8s|Docker|container|Terraform|CloudFormation|IAM role)\b",
        re.IGNORECASE,
    ), ["IaaS", "SaaS"], "cloud"),
    # Azure AD / Office 365
    (re.compile(
        r"\b(?:Azure AD|Entra|Office 365|O365|M365|Microsoft 365"
        r"|Conditional Access|SharePoint Online|Exchange Online)\b",
        re.IGNORECASE,
    ), ["Azure AD", "Office 365", "SaaS"], "azure_ad"),
    # Network devices
    (re.compile(
        r"\b(?:FortiOS|FortiGate|Citrix|PAN-OS|Palo Alto|VPN|firewall|router|switch"
        r"|Cisco|Juniper|MikroTik|NetScaler|F5|load balancer)\b",
        re.IGNORECASE,
    ), ["Network"], "network"),
]


def detect_platforms(text: str) -> list[str]:
    """Detect platforms mentioned in text."""
    platforms: set[str] = set()
    for pattern, plats, _label in _PLATFORM_PATTERNS:
        if pattern.search(text):
            platforms.update(plats)
    return sorted(platforms)


def route_finding(text: str) -> RoutingDecision:
    """Classify a finding as vulnerability or attack narrative.

    Uses weighted pattern matching. Highest-scoring type wins if above 0.5 threshold.
    Default: attack_narrative.
    """
    vuln_score = 0.0
    attack_score = 0.0
    vuln_signals: list[str] = []
    attack_signals: list[str] = []

    for pattern, weight, label in _VULN_PATTERNS:
        if pattern.search(text):
            vuln_score += weight
            vuln_signals.append(label)

    for pattern, weight, label in _ATTACK_PATTERNS:
        if pattern.search(text):
            attack_score += weight
            attack_signals.append(label)

    platforms = detect_platforms(text)

    if vuln_score > attack_score and vuln_score >= 0.5:
        confidence = min(1.0, vuln_score / (vuln_score + attack_score + 0.001))
        return RoutingDecision(
            finding_type=FindingType.VULNERABILITY,
            confidence=confidence,
            signals=vuln_signals,
            platforms=platforms,
        )

    if attack_score >= 0.5:
        confidence = min(1.0, attack_score / (vuln_score + attack_score + 0.001))
        return RoutingDecision(
            finding_type=FindingType.ATTACK_NARRATIVE,
            confidence=confidence,
            signals=attack_signals,
            platforms=platforms,
        )

    # Default: attack_narrative with low confidence
    return RoutingDecision(
        finding_type=FindingType.ATTACK_NARRATIVE,
        confidence=0.3,
        signals=attack_signals,
        platforms=platforms,
    )
