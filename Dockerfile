# ATT&CK Knowledge Graph CLI
#
# Build:
#   docker build -t attack-kg .
#
# Usage:
#   docker run attack-kg --help
#   docker run attack-kg technique T1110.003
#   docker run attack-kg search "credential theft"
#   docker run attack-kg group APT29
#
# Remediation analysis (requires LLM backend):
#
#   With Ollama on host:
#     docker run --network host attack-kg analyze "Found credentials via password spraying"
#
#   With OpenAI:
#     docker run -e OPENAI_API_KEY attack-kg analyze -b openai "Attacker used mimikatz"
#
#   JSON output:
#     docker run --network host attack-kg analyze --json "Lateral movement via RDP"

FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files first (for layer caching)
COPY pyproject.toml uv.lock README.md ./

# Install dependencies (no dev deps)
RUN uv sync --frozen --no-dev

# Copy application code
COPY src/ ./src/

# Pre-download embedding model + build the knowledge graph
RUN uv run attack-kg download && \
    uv run attack-kg ingest && \
    uv run attack-kg build

ENTRYPOINT ["uv", "run", "attack-kg"]
CMD ["--help"]
