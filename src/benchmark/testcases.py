"""Test case definitions for model benchmarking.

Each test case defines:
- A security finding (input)
- Expected techniques with relevance tiers
- Expected mitigations with priority tiers
- Context indicators for validation
"""

from dataclasses import dataclass, field
from enum import Enum


class TechniqueRelevance(Enum):
    """Relevance tier for expected techniques."""

    PRIMARY = "primary"  # Core technique, must be identified (+10 pts)
    SECONDARY = "secondary"  # Important but not primary (+5 pts)
    ACCEPTABLE = "acceptable"  # Valid but not ideal (+3 pts)
    IDEAL_SUBTECHNIQUE = "ideal_subtechnique"  # Specific subtechnique bonus (+5 pts)


class MitigationPriority(Enum):
    """Priority tier for expected mitigations."""

    CRITICAL = "critical"  # Essential mitigation (+5 pts)
    HIGH = "high"  # Important mitigation (+3 pts)
    MEDIUM = "medium"  # Helpful mitigation (+2 pts)


@dataclass
class ExpectedTechnique:
    """A technique expected in the analysis output."""

    attack_id: str
    name: str
    relevance: TechniqueRelevance
    parent_id: str | None = None  # For subtechniques, the parent technique ID


@dataclass
class ExpectedMitigation:
    """A mitigation expected in the analysis output."""

    mitigation_id: str
    name: str
    priority: MitigationPriority


@dataclass
class ContextIndicator:
    """Context indicators to validate context awareness."""

    platform: str  # "linux", "windows", "network_appliance", "cloud"
    products: list[str] = field(default_factory=list)
    invalid_recommendations: list[str] = field(default_factory=list)  # Keywords that indicate wrong context


@dataclass
class TestCase:
    """A complete test case for model evaluation."""

    id: str
    name: str
    description: str
    finding_text: str
    expected_techniques: list[ExpectedTechnique]
    expected_mitigations: list[ExpectedMitigation]
    context: ContextIndicator
    tags: list[str] = field(default_factory=list)  # e.g., ["web", "credential", "linux"]

    def get_primary_techniques(self) -> list[str]:
        """Get IDs of primary techniques."""
        return [t.attack_id for t in self.expected_techniques if t.relevance == TechniqueRelevance.PRIMARY]

    def get_secondary_techniques(self) -> list[str]:
        """Get IDs of secondary techniques."""
        return [t.attack_id for t in self.expected_techniques if t.relevance == TechniqueRelevance.SECONDARY]

    def get_acceptable_techniques(self) -> list[str]:
        """Get IDs of acceptable techniques."""
        return [t.attack_id for t in self.expected_techniques if t.relevance == TechniqueRelevance.ACCEPTABLE]

    def get_ideal_subtechniques(self) -> list[str]:
        """Get IDs of ideal subtechniques (bonus points)."""
        return [t.attack_id for t in self.expected_techniques if t.relevance == TechniqueRelevance.IDEAL_SUBTECHNIQUE]

    def get_parent_techniques(self) -> dict[str, str]:
        """Get mapping of subtechnique ID -> parent ID."""
        return {t.attack_id: t.parent_id for t in self.expected_techniques if t.parent_id}

    def get_critical_mitigations(self) -> list[str]:
        """Get IDs of critical mitigations."""
        return [m.mitigation_id for m in self.expected_mitigations if m.priority == MitigationPriority.CRITICAL]

    def get_high_mitigations(self) -> list[str]:
        """Get IDs of high priority mitigations."""
        return [m.mitigation_id for m in self.expected_mitigations if m.priority == MitigationPriority.HIGH]

    def get_medium_mitigations(self) -> list[str]:
        """Get IDs of medium priority mitigations."""
        return [m.mitigation_id for m in self.expected_mitigations if m.priority == MitigationPriority.MEDIUM]


# =============================================================================
# BUILT-IN TEST CASES (from model-comparison-reports)
# =============================================================================

FINDING_03_OWNCLOUD = TestCase(
    id="finding03",
    name="ownCloud Exposed Admin Login",
    description="Admin ownCloud login page exposed to the Internet, allowing potential credential compromise.",
    finding_text="""Administrator Login Pages Accessible to the Internet - ownCloud

Sprocket discovered an admin ownCloud login page exposed to the Internet. The ownCloud administrative login allows user's to manage various file sharing aspects. This increases organizational risk because the compromise of an administrative/user account would have a significant impact on organizational exposure. Any unintended changes to credentials used to access this authentication endpoint in the future could result in compromise.
Proof of Concept

The following screenshot shows the login page shown below when visited:

SCREENSHOT
Remediation

Sprocket recommends restricting access to the admin page using a web application firewall or security controls built into the underlying web server.

A common and effective method to restricting access is to deny everyone access to the login page and whitelist source IP addresses for networks/users that should have access. Under the web root folder (/var/www/html), create or modify the .htaccess file to include the following line:

Options -Indexes

The above recommendation disables directory listing for the entire web server. If more fine-grained control is needed, consider placing the .htaccess file under the owncloud directory. For example:

<Directory /var/www/owncloud>
    Options -Indexes
</Directory>

In both cases, an Apache restart is required. This can be accomplish by executing the following command: service apache2 restart.
References

OWASP guidance on exposed administrator login portals:
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces

CWE-284: Improper Access Control:
https://cwe.mitre.org/data/definitions/284.html""",
    expected_techniques=[
        ExpectedTechnique("T1056.003", "Web Portal Capture", TechniqueRelevance.PRIMARY),
        ExpectedTechnique("T1078.002", "Domain Accounts", TechniqueRelevance.SECONDARY, parent_id="T1078"),
        ExpectedTechnique("T1110", "Brute Force", TechniqueRelevance.ACCEPTABLE),
    ],
    expected_mitigations=[
        ExpectedMitigation("M1032", "Multi-factor Authentication", MitigationPriority.CRITICAL),
        ExpectedMitigation("M1026", "Privileged Account Management", MitigationPriority.HIGH),
        ExpectedMitigation("M1027", "Password Policies", MitigationPriority.MEDIUM),
    ],
    context=ContextIndicator(
        platform="linux",
        products=["ownCloud", "Apache", "Linux"],
        invalid_recommendations=["Windows Registry", "Active Directory Group Policy", "Windows Event Log", "PowerShell"],
    ),
    tags=["web", "credential", "linux", "exposure"],
)

FINDING_04_FORTINET = TestCase(
    id="finding04",
    name="Fortinet Authentication Bypass",
    description="FortiCloud SSO authentication bypass allowing cross-account device access on FortiAnalyzer, FortiManager, FortiOS, FortiProxy.",
    finding_text="""Fortinet FortiAnalyzer, FortiManager, FortiOS, and FortiProxy contain an authentication bypass using an alternate path or channel that could allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.""",
    expected_techniques=[
        ExpectedTechnique("T1556", "Modify Authentication Process", TechniqueRelevance.PRIMARY),
        ExpectedTechnique("T1556.004", "Network Device Authentication", TechniqueRelevance.IDEAL_SUBTECHNIQUE, parent_id="T1556"),
        ExpectedTechnique("T1550", "Use Alternate Authentication Material", TechniqueRelevance.SECONDARY),
    ],
    expected_mitigations=[
        ExpectedMitigation("M1032", "Multi-factor Authentication", MitigationPriority.CRITICAL),
        ExpectedMitigation("M1047", "Audit", MitigationPriority.HIGH),
        ExpectedMitigation("M1028", "Operating System Configuration", MitigationPriority.HIGH),
        ExpectedMitigation("M1026", "Privileged Account Management", MitigationPriority.MEDIUM),
    ],
    context=ContextIndicator(
        platform="network_appliance",
        products=["FortiAnalyzer", "FortiManager", "FortiOS", "FortiProxy", "FortiCloud"],
        invalid_recommendations=["Windows Registry", "Active Directory", "Linux /etc/", "Windows Event Log"],
    ),
    tags=["network", "authentication", "bypass", "fortinet"],
)


# Default test suite
DEFAULT_TEST_SUITE = [FINDING_03_OWNCLOUD, FINDING_04_FORTINET]


def load_test_suite(name: str = "default") -> list[TestCase]:
    """Load a named test suite."""
    if name == "default":
        return DEFAULT_TEST_SUITE
    raise ValueError(f"Unknown test suite: {name}")


def create_test_case(
    id: str,
    name: str,
    finding_text: str,
    primary_techniques: list[tuple[str, str]],  # [(id, name), ...]
    secondary_techniques: list[tuple[str, str]] | None = None,
    acceptable_techniques: list[tuple[str, str]] | None = None,
    ideal_subtechniques: list[tuple[str, str, str]] | None = None,  # [(id, name, parent_id), ...]
    critical_mitigations: list[tuple[str, str]] | None = None,
    high_mitigations: list[tuple[str, str]] | None = None,
    medium_mitigations: list[tuple[str, str]] | None = None,
    platform: str = "unknown",
    products: list[str] | None = None,
    invalid_recommendations: list[str] | None = None,
    description: str = "",
    tags: list[str] | None = None,
) -> TestCase:
    """Helper function to create test cases with a simpler interface."""
    techniques = []
    for tid, tname in primary_techniques:
        techniques.append(ExpectedTechnique(tid, tname, TechniqueRelevance.PRIMARY))
    for tid, tname in secondary_techniques or []:
        techniques.append(ExpectedTechnique(tid, tname, TechniqueRelevance.SECONDARY))
    for tid, tname in acceptable_techniques or []:
        techniques.append(ExpectedTechnique(tid, tname, TechniqueRelevance.ACCEPTABLE))
    for tid, tname, parent in ideal_subtechniques or []:
        techniques.append(ExpectedTechnique(tid, tname, TechniqueRelevance.IDEAL_SUBTECHNIQUE, parent_id=parent))

    mitigations = []
    for mid, mname in critical_mitigations or []:
        mitigations.append(ExpectedMitigation(mid, mname, MitigationPriority.CRITICAL))
    for mid, mname in high_mitigations or []:
        mitigations.append(ExpectedMitigation(mid, mname, MitigationPriority.HIGH))
    for mid, mname in medium_mitigations or []:
        mitigations.append(ExpectedMitigation(mid, mname, MitigationPriority.MEDIUM))

    return TestCase(
        id=id,
        name=name,
        description=description or name,
        finding_text=finding_text,
        expected_techniques=techniques,
        expected_mitigations=mitigations,
        context=ContextIndicator(
            platform=platform,
            products=products or [],
            invalid_recommendations=invalid_recommendations or [],
        ),
        tags=tags or [],
    )
