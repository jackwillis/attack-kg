# ATT&CK Knowledge Graph v2
#
# Build:
#   docker build -t attack-kg .
#
# Usage:
#   docker run attack-kg --help
#   docker run attack-kg analyze "password spraying against Azure AD"
#   docker run attack-kg analyze --file /data/finding.txt
#   docker run attack-kg analyze --json "lateral movement via RDP"
#
# LLM backends (required for analyze/repl):
#
#   With Ollama on host:
#     docker run --network host attack-kg analyze "credential theft via mimikatz"
#
#   With OpenAI:
#     docker run -e OPENAI_API_KEY attack-kg analyze -b openai "password spraying"
#
# Data sources included:
#   - MITRE ATT&CK (STIX 2.1)
#   - MITRE D3FEND (Defensive techniques)
#   - MITRE CAPEC (Attack patterns, CWE mappings)
#   - LOLBAS (Windows LOLBins with technique mappings)
#   - GTFOBins (Linux binaries with function mappings)

# Stage 1: Build with all deps, swap torch for CPU version
FROM python:3.12-slim AS builder

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
COPY src/ ./src/

# Install deps, swap torch for CPU-only, build knowledge graph
RUN uv sync --frozen --no-dev && \
    uv pip uninstall torch && \
    uv pip install torch --index-url https://download.pytorch.org/whl/cpu && \
    uv run attack-kg download && \
    uv run attack-kg ingest && \
    uv run attack-kg build && \
    # Pre-cache the nomic-bert-2048 architecture code (needed by trust_remote_code)
    uv run python -c "from huggingface_hub import snapshot_download; snapshot_download('nomic-ai/nomic-bert-2048', revision='7710840340a098cfb869c4f65e87cf2b1b70caca')"

# Stage 2: Slim runtime image
FROM python:3.12-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy the built venv, data, and HuggingFace model cache from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /root/.attack_kg /root/.attack_kg
COPY --from=builder /root/.cache/huggingface /root/.cache/huggingface
COPY --from=builder /app/pyproject.toml /app/uv.lock ./
COPY --from=builder /app/src /app/src

# Force offline mode - use only cached models, no runtime downloads
ENV HF_HUB_OFFLINE=1
ENV ATTACK_KG_OFFLINE=1

ENTRYPOINT ["uv", "run", "attack-kg"]
CMD ["--help"]
