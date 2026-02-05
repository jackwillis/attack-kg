"""LLM backends: Ollama (local) and OpenAI (cloud)."""

import json
import os
from typing import Any

from rich.console import Console

console = Console()


class LLMBackend:
    """Base LLM interface."""
    model: str = "unknown"

    def generate_json(self, prompt: str, system: str | None = None) -> dict[str, Any]:
        raise NotImplementedError


class OllamaBackend(LLMBackend):
    def __init__(self, model: str = "llama3.2", host: str | None = None):
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import ollama
            self._client = ollama.Client(host=self.host)
        return self._client

    def generate_json(self, prompt: str, system: str | None = None) -> dict[str, Any]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt + "\n\nRespond with valid JSON only."})
        resp = self.client.chat(model=self.model, messages=messages)
        text = resp["message"]["content"]
        return _parse_json(text)


class OpenAIBackend(LLMBackend):
    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None):
        self.model = model
        self.api_key = api_key
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key)
        return self._client

    def generate_json(self, prompt: str, system: str | None = None) -> dict[str, Any]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = self.client.chat.completions.create(
            model=self.model, messages=messages,
            response_format={"type": "json_object"},
        )
        return json.loads(resp.choices[0].message.content)


def _parse_json(text: str) -> dict[str, Any]:
    """Extract JSON from LLM response, handling markdown fences."""
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        console.print("[yellow]Failed to parse JSON from LLM[/yellow]")
        return {"error": "JSON parse failure", "raw": text}


def get_backend(backend: str = "ollama", model: str | None = None) -> LLMBackend:
    if backend == "openai":
        return OpenAIBackend(model=model or "gpt-4o-mini")
    return OllamaBackend(model=model or "gpt-oss:20b")
