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

# Stage 1: Build with all deps, swap torch for CPU version
FROM python:3.12-slim AS builder

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

# Install deps, swap torch for CPU-only, build knowledge graph
RUN uv sync --frozen --no-dev && \
    uv pip uninstall torch && \
    uv pip install torch --index-url https://download.pytorch.org/whl/cpu && \
    uv run attack-kg download && \
    uv run attack-kg ingest && \
    uv run attack-kg build && \
    # Pre-cache the dependent nomic-bert-2048 model code files
    uv run python -c "from huggingface_hub import snapshot_download; snapshot_download('nomic-ai/nomic-bert-2048', revision='7710840340a098cfb869c4f65e87cf2b1b70caca')"

# Stage 2: Slim runtime image
FROM python:3.12-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy the built venv, data, and HuggingFace model cache from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/data /app/data
COPY --from=builder /root/.cache/huggingface /root/.cache/huggingface
COPY --from=builder /app/pyproject.toml /app/uv.lock /app/README.md ./
COPY --from=builder /app/src /app/src

# Force offline mode - use only cached models, no runtime downloads
ENV HF_HUB_OFFLINE=1

ENTRYPOINT ["uv", "run", "attack-kg"]
CMD ["--help"]
