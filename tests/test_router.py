"""Tests for finding-type router and platform detection."""

from src.query.router import (
    FindingType,
    RoutingDecision,
    detect_platforms,
    route_finding,
)


class TestRouteVulnerability:
    def test_cve_pattern(self):
        r = route_finding("CVE-2024-47575 FortiManager authentication bypass")
        assert r.finding_type == FindingType.VULNERABILITY
        assert "cve_id" in r.signals

    def test_cwe_pattern(self):
        r = route_finding("CWE-79 cross-site scripting in login page")
        assert r.finding_type == FindingType.VULNERABILITY
        assert "cwe_id" in r.signals

    def test_unpatched_advisory(self):
        r = route_finding("Unpatched vulnerability in Apache Struts advisory")
        assert r.finding_type == FindingType.VULNERABILITY

    def test_cvss_with_vuln(self):
        r = route_finding("CVSS 9.8 critical vulnerability in OpenSSL")
        assert r.finding_type == FindingType.VULNERABILITY
        assert "cvss" in r.signals


class TestRouteAttackNarrative:
    def test_threat_actor_past_tense(self):
        r = route_finding("APT29 executed Cobalt Strike beacon and exfiltrated data")
        assert r.finding_type == FindingType.ATTACK_NARRATIVE
        assert "apt_name" in r.signals
        assert "past_tense_action" in r.signals

    def test_ioc_ip_address(self):
        r = route_finding("C2 callback observed to 192.168.1.100 from compromised host")
        assert r.finding_type == FindingType.ATTACK_NARRATIVE
        assert "ip_address" in r.signals

    def test_sha256_hash(self):
        r = route_finding(
            "Malware sample "
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 deployed"
        )
        assert r.finding_type == FindingType.ATTACK_NARRATIVE
        assert "sha256_hash" in r.signals

    def test_campaign_breach(self):
        r = route_finding("SolarWinds breach campaign compromised supply chain")
        assert r.finding_type == FindingType.ATTACK_NARRATIVE
        assert "breach_kw" in r.signals or "campaign_kw" in r.signals


class TestRouteDefault:
    def test_ambiguous_text(self):
        r = route_finding("Check the server configuration for issues")
        assert r.finding_type == FindingType.ATTACK_NARRATIVE  # safe default

    def test_empty_string(self):
        r = route_finding("")
        assert r.finding_type == FindingType.ATTACK_NARRATIVE

    def test_mixed_signals_cve_wins(self):
        """CVE + attack language: CVE signal is stronger, routes as vulnerability."""
        r = route_finding("CVE-2024-1234 exploited by attacker who compromised the server")
        assert r.finding_type == FindingType.VULNERABILITY


class TestRouteConfidence:
    def test_strong_vuln_high_confidence(self):
        r = route_finding("CVE-2024-47575 CWE-306 CVSS 9.8 vulnerability advisory")
        assert r.confidence > 0.7

    def test_ambiguous_low_confidence(self):
        r = route_finding("unknown situation")
        assert r.confidence < 0.5


class TestDetectPlatformsWindows:
    def test_windows_keywords(self):
        p = detect_platforms("PowerShell script modifying Registry HKLM key")
        assert "Windows" in p

    def test_active_directory(self):
        p = detect_platforms("Active Directory Group Policy modification")
        assert "Windows" in p


class TestDetectPlatformsLinux:
    def test_linux_keywords(self):
        p = detect_platforms("Ubuntu server with systemd service and crontab persistence")
        assert "Linux" in p

    def test_audit_iptables(self):
        p = detect_platforms("Configure auditd and iptables rules")
        assert "Linux" in p


class TestDetectPlatformsCloud:
    def test_aws(self):
        p = detect_platforms("AWS Lambda function with S3 bucket access")
        assert "IaaS" in p
        assert "SaaS" in p

    def test_kubernetes(self):
        p = detect_platforms("Kubernetes pod escaped container")
        assert "IaaS" in p

    def test_azure_ad(self):
        p = detect_platforms("Azure AD Conditional Access policy bypass via Entra ID")
        assert "Azure AD" in p
        assert "Office 365" in p
        assert "SaaS" in p


class TestDetectPlatformsNetwork:
    def test_fortios(self):
        p = detect_platforms("FortiOS VPN authentication bypass")
        assert "Network" in p

    def test_palo_alto(self):
        p = detect_platforms("PAN-OS firewall rule misconfiguration")
        assert "Network" in p


class TestDetectPlatformsMultiple:
    def test_multiple_platforms(self):
        p = detect_platforms(
            "Windows server running Docker containers in AWS with FortiGate firewall"
        )
        assert "Windows" in p
        assert "IaaS" in p
        assert "Network" in p


class TestRoutingPlatformIntegration:
    def test_platforms_included_in_routing(self):
        r = route_finding("CVE-2024-47575 FortiManager authentication bypass on FortiOS")
        assert "Network" in r.platforms

    def test_cloud_platforms_in_routing(self):
        r = route_finding("S3 bucket misconfiguration exposing sensitive data in AWS")
        assert "IaaS" in r.platforms
