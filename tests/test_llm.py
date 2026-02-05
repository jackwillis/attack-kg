"""Tests for LLM JSON parsing and backend factory."""

from src.reasoning.llm import _parse_json, get_backend, OllamaBackend, OpenAIBackend


class TestParseJson:
    def test_plain_json(self):
        result = _parse_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_json_with_markdown_fence(self):
        text = '```json\n{"key": "value"}\n```'
        result = _parse_json(text)
        assert result == {"key": "value"}

    def test_json_with_generic_fence(self):
        text = '```\n{"key": "value"}\n```'
        result = _parse_json(text)
        assert result == {"key": "value"}

    def test_json_with_surrounding_text(self):
        text = 'Here is the result:\n```json\n{"techniques": []}\n```\nDone.'
        result = _parse_json(text)
        assert result == {"techniques": []}

    def test_invalid_json_returns_error(self):
        result = _parse_json("not json at all")
        assert "error" in result
        assert result["error"] == "JSON parse failure"

    def test_empty_object(self):
        assert _parse_json("{}") == {}

    def test_nested_json(self):
        text = '{"techniques": [{"id": "T1110", "confidence": "high"}]}'
        result = _parse_json(text)
        assert len(result["techniques"]) == 1

    def test_whitespace_handling(self):
        result = _parse_json('  \n  {"key": "value"}  \n  ')
        assert result == {"key": "value"}


class TestGetBackend:
    def test_ollama_default(self):
        backend = get_backend()
        assert isinstance(backend, OllamaBackend)
        assert backend.model == "llama3.2"

    def test_ollama_custom_model(self):
        backend = get_backend("ollama", "gemma3:4b")
        assert isinstance(backend, OllamaBackend)
        assert backend.model == "gemma3:4b"

    def test_openai(self):
        backend = get_backend("openai")
        assert isinstance(backend, OpenAIBackend)
        assert backend.model == "gpt-4o-mini"

    def test_openai_custom_model(self):
        backend = get_backend("openai", "gpt-4o")
        assert isinstance(backend, OpenAIBackend)
        assert backend.model == "gpt-4o"
