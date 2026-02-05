"""Tests for BM25 keyword search."""

from src.query.keyword import _tokenize, KeywordResult


class TestTokenize:
    def test_basic(self):
        assert _tokenize("hello world") == ["hello", "world"]

    def test_preserves_technique_ids(self):
        tokens = _tokenize("T1110.003 Password Spraying")
        assert "t1110.003" in tokens
        assert "password" in tokens
        assert "spraying" in tokens

    def test_preserves_hyphenated(self):
        tokens = _tokenize("credential-access defense-evasion")
        assert "credential-access" in tokens
        assert "defense-evasion" in tokens

    def test_case_insensitive(self):
        assert _tokenize("PowerShell") == ["powershell"]

    def test_empty(self):
        assert _tokenize("") == []
        assert _tokenize(None) == []

    def test_strips_special_chars(self):
        tokens = _tokenize("hello! @world #test")
        assert "hello" in tokens
        assert "world" in tokens
        assert "test" in tokens

    def test_tokenize_preserves_cve_ids(self):
        tokens = _tokenize("CVE-2024-1234 exploit found")
        assert "CVE-2024-1234" in tokens
        assert "exploit" in tokens
        assert "found" in tokens

    def test_tokenize_preserves_cwe_ids(self):
        tokens = _tokenize("CWE-79 cross-site scripting")
        assert "CWE-79" in tokens
        assert "cross-site" in tokens
        assert "scripting" in tokens

    def test_tokenize_cve_cwe_uppercased(self):
        tokens = _tokenize("cve-2024-5678 and cwe-89")
        assert "CVE-2024-5678" in tokens
        assert "CWE-89" in tokens

    def test_tokenize_multiple_cve(self):
        tokens = _tokenize("CVE-2024-1234 and CVE-2023-99999")
        assert "CVE-2024-1234" in tokens
        assert "CVE-2023-99999" in tokens
