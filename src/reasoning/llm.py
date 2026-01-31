"""LLM integration for query planning and response synthesis."""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from rich.console import Console

console = Console()


@dataclass
class QueryPlan:
    """A plan for answering a user question."""

    needs_semantic_search: bool
    needs_graph_query: bool
    semantic_query: str | None
    graph_queries: list[str]
    reasoning: str


@dataclass
class SynthesizedResponse:
    """A synthesized response from LLM."""

    answer: str
    citations: list[dict[str, str]]
    confidence: str  # "high", "medium", "low"


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    @abstractmethod
    def generate(self, prompt: str, system: str | None = None) -> str:
        """Generate a response from the LLM."""
        pass

    @abstractmethod
    def generate_json(self, prompt: str, system: str | None = None) -> dict[str, Any]:
        """Generate a JSON response from the LLM."""
        pass


class OllamaBackend(LLMBackend):
    """Ollama local LLM backend."""

    def __init__(self, model: str = "gpt-oss:20b", host: str | None = None):
        """
        Initialize Ollama backend.

        Args:
            model: Model name (e.g., "llama3.2", "mistral", "codellama")
            host: Ollama server URL (defaults to OLLAMA_HOST env var or http://localhost:11434)
        """
        import os

        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import ollama

            self._client = ollama.Client(host=self.host)
        return self._client

    def generate(self, prompt: str, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat(model=self.model, messages=messages)
        return response["message"]["content"]

    def generate_json(self, prompt: str, system: str | None = None) -> dict[str, Any]:
        # Add JSON instruction to prompt
        json_prompt = f"{prompt}\n\nRespond with valid JSON only, no other text."

        response_text = self.generate(json_prompt, system)

        # Try to extract JSON from response
        try:
            # Handle markdown code blocks
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0]

            return json.loads(response_text.strip())
        except json.JSONDecodeError as e:
            console.print(f"[yellow]Failed to parse JSON response: {e}[/yellow]")
            return {"error": "Failed to parse JSON", "raw": response_text}


class OpenAIBackend(LLMBackend):
    """OpenAI API backend."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None):
        """
        Initialize OpenAI backend.

        Args:
            model: Model name (e.g., "gpt-4o", "gpt-4o-mini")
            api_key: OpenAI API key (uses OPENAI_API_KEY env var if not provided)
        """
        self.model = model
        self.api_key = api_key
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(api_key=self.api_key)
        return self._client

    def generate(self, prompt: str, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
        )
        return response.choices[0].message.content

    def generate_json(self, prompt: str, system: str | None = None) -> dict[str, Any]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            response_format={"type": "json_object"},
        )

        return json.loads(response.choices[0].message.content)


class QueryPlanner:
    """Plans how to answer a user question using available tools."""

    SYSTEM_PROMPT = """You are a query planner for a MITRE ATT&CK knowledge base.
Given a user question, determine the best approach to answer it.

Available tools:
1. Semantic search: Find techniques by natural language similarity
2. Graph queries: Query structured relationships (groups, mitigations, tactics, etc.)

Output a JSON plan with:
- needs_semantic_search: boolean
- needs_graph_query: boolean
- semantic_query: string or null (the text to search for)
- graph_queries: list of query descriptions (what relationships to look up)
- reasoning: brief explanation of your plan"""

    def __init__(self, llm: LLMBackend):
        self.llm = llm

    def plan(self, question: str) -> QueryPlan:
        """Create a query plan for answering a question."""
        prompt = f"Question: {question}\n\nCreate a query plan to answer this question."

        result = self.llm.generate_json(prompt, system=self.SYSTEM_PROMPT)

        return QueryPlan(
            needs_semantic_search=result.get("needs_semantic_search", True),
            needs_graph_query=result.get("needs_graph_query", False),
            semantic_query=result.get("semantic_query"),
            graph_queries=result.get("graph_queries", []),
            reasoning=result.get("reasoning", ""),
        )


class ResponseSynthesizer:
    """Synthesizes natural language responses from query results."""

    SYSTEM_PROMPT = """You are a cybersecurity analyst assistant.
Given a question and ATT&CK knowledge base results, synthesize a clear, accurate answer.

Guidelines:
- Be specific and cite technique IDs (e.g., T1110.003)
- Mention relevant threat groups and mitigations when available
- Be concise but complete
- If the results don't fully answer the question, say so

Output a JSON response with:
- answer: string (your synthesized answer)
- citations: list of {attack_id, name} for referenced techniques
- confidence: "high", "medium", or "low" """

    def __init__(self, llm: LLMBackend):
        self.llm = llm

    def synthesize(
        self,
        question: str,
        results: dict[str, Any],
    ) -> SynthesizedResponse:
        """Synthesize a response from query results."""
        prompt = f"""Question: {question}

Query Results:
{json.dumps(results, indent=2)}

Synthesize a response to the question based on these results."""

        result = self.llm.generate_json(prompt, system=self.SYSTEM_PROMPT)

        return SynthesizedResponse(
            answer=result.get("answer", "Unable to synthesize response."),
            citations=result.get("citations", []),
            confidence=result.get("confidence", "low"),
        )


class AttackAssistant:
    """
    High-level assistant combining query planning, execution, and synthesis.

    This is the main interface for natural language interaction with the
    ATT&CK knowledge base.
    """

    def __init__(
        self,
        hybrid_engine,
        llm_backend: LLMBackend | None = None,
    ):
        """
        Initialize the assistant.

        Args:
            hybrid_engine: HybridQueryEngine instance
            llm_backend: LLM backend to use (defaults to Ollama)
        """
        self.hybrid = hybrid_engine
        self.llm = llm_backend or OllamaBackend()
        self.planner = QueryPlanner(self.llm)
        self.synthesizer = ResponseSynthesizer(self.llm)

    def ask(self, question: str) -> dict[str, Any]:
        """
        Answer a natural language question about ATT&CK.

        Args:
            question: User question

        Returns:
            Dictionary with answer, citations, and raw results
        """
        # Step 1: Plan the query
        plan = self.planner.plan(question)
        console.print(f"[dim]Query plan: {plan.reasoning}[/dim]")

        # Step 2: Execute queries based on plan
        results = {}

        if plan.needs_semantic_search and plan.semantic_query:
            semantic_results = self.hybrid.query(
                plan.semantic_query,
                top_k=5,
                enrich=plan.needs_graph_query,
            )
            results["techniques"] = [t.to_dict() for t in semantic_results.techniques]

        # Step 3: Synthesize response
        response = self.synthesizer.synthesize(question, results)

        return {
            "question": question,
            "answer": response.answer,
            "citations": response.citations,
            "confidence": response.confidence,
            "plan": {
                "semantic_query": plan.semantic_query,
                "graph_queries": plan.graph_queries,
                "reasoning": plan.reasoning,
            },
            "raw_results": results,
        }

    def tag_finding(self, finding_text: str) -> dict[str, Any]:
        """
        Auto-tag a penetration testing finding with ATT&CK techniques.

        This is a simplified flow optimized for the common use case.

        Args:
            finding_text: Description of a security finding

        Returns:
            Dictionary with technique suggestions and mitigations
        """
        # Use hybrid engine directly for this common case
        return self.hybrid.find_defenses_for_finding(finding_text, top_k=3)


def get_llm_backend(
    backend: str = "ollama",
    model: str | None = None,
    **kwargs,
) -> LLMBackend:
    """
    Factory function to get an LLM backend.

    Args:
        backend: "ollama" or "openai"
        model: Optional model name override
        **kwargs: Additional backend-specific arguments

    Returns:
        Configured LLM backend
    """
    if backend == "ollama":
        return OllamaBackend(model=model or "gpt-oss:20b", **kwargs)
    elif backend == "openai":
        return OpenAIBackend(model=model or "gpt-4o-mini", **kwargs)
    else:
        raise ValueError(f"Unknown backend: {backend}")
