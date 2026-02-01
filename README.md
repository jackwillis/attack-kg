# ATT&CK Knowledge Graph

A neuro-symbolic system combining MITRE ATT&CK and D3FEND as an RDF knowledge graph with vector embeddings for intelligent threat intelligence querying and defensive recommendations.

## Quick Start

```bash
# Install dependencies
uv sync

# Download ATT&CK and D3FEND data, build stores
uv run attack-kg download           # Download STIX + D3FEND ontology
uv run attack-kg ingest             # Convert ATT&CK to RDF (N-Triples)
uv run attack-kg build              # Load into Oxigraph + build vector store
```

## Usage

```bash
# Look up a technique
uv run attack-kg technique T1110.003

# Find techniques used by a threat group
uv run attack-kg group APT29

# Semantic search
uv run attack-kg search "credential theft from memory"

# Get D3FEND countermeasures for a technique
uv run attack-kg countermeasures T1110.003

# Analyze a finding for ATT&CK techniques and remediation
uv run attack-kg analyze "password spraying against Azure AD"
uv run attack-kg analyze --file finding.txt

# Run SPARQL queries
uv run attack-kg query "SELECT ?name WHERE { ?t a attack:Technique ; rdfs:label ?name } LIMIT 5"

# Interactive REPL
uv run attack-kg repl
uv run attack-kg repl --model gpt-oss:20b  # specify LLM model
```

### Interactive REPL

The REPL provides an interactive session with command history and tab completion:

```
attack-kg> search password spraying
attack-kg> cd T1110.003
attack-kg> countermeasures           # show D3FEND countermeasures
attack-kg> group APT29
attack-kg> analyze credential theft via mimikatz
attack-kg> analyze @finding.txt      # read from file
attack-kg> sparql SELECT ?name WHERE { ?t a attack:Technique ; rdfs:label ?name } LIMIT 5
```

## D3FEND Integration

[MITRE D3FEND](https://d3fend.mitre.org/) provides a knowledge graph of defensive techniques. This system links D3FEND to ATT&CK via mitigation mappings, enabling queries like "what specific countermeasures address T1110.003?"

```bash
# Get D3FEND countermeasures for a technique
uv run attack-kg countermeasures T1110.003

# Output shows:
# - ATT&CK mitigations (e.g., M1032 Multi-factor Authentication)
# - D3FEND techniques (e.g., D3-MFA) with implementation guidance
# - Which mitigation each D3FEND technique addresses
```

The `analyze` command automatically includes D3FEND recommendations alongside ATT&CK mitigations when D3FEND is loaded.

## LLM Model Selection

The default model is `gpt-oss:20b`, selected based on benchmark testing of 10 models on ATT&CK technique identification and remediation quality.

| Use Case | Model | Grade | Notes |
|----------|-------|-------|-------|
| Maximum accuracy | `gpt-oss:20b` (default) | A | Best technique coverage |
| Balanced speed/quality | `gpt-oss-safeguard:20b` | A- | 25% faster |
| Resource-constrained | `gemma3:4b` | B+ | Best small model |
| Maximum speed | `granite4:3b` | B | Needs context filtering |

To use a different model:
```bash
uv run attack-kg analyze --model gemma3:4b "finding text"
uv run attack-kg repl --model gpt-oss-safeguard:20b
```

**Not recommended:** phi3:mini (JSON failures), deepseek-r1 (slow, sparse output)

See `model-comparison-reports/RESULTS.md` for full benchmark results.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_HOST` | Ollama server URL (for Docker/remote) | `http://localhost:11434` |
| `OPENAI_API_KEY` | OpenAI API key (for `--backend openai`) | - |
| `ATTACK_KG_OFFLINE` | Prevent HuggingFace model downloads at runtime | `1` in Docker, `false` otherwise |

## Architecture

- **Oxigraph** - RDF triplestore (pyoxigraph) for structured SPARQL queries
- **ChromaDB** - Vector store for semantic similarity search
- **sentence-transformers** - Local embeddings (nomic-embed-text-v1.5, pinned revision)

## Data

After running `build`, the knowledge graph contains:
- ~800 ATT&CK techniques with descriptions, tactics, platforms
- ~180 threat groups with technique mappings
- ~600 software/malware entries
- ~270 mitigations
- ~500 D3FEND defensive techniques (when loaded)
- 52,000+ RDF triples total

## Features

### Subtechnique Mitigation Inheritance

When querying mitigations for subtechniques (e.g., T1059.001 PowerShell), the system automatically includes mitigations from the parent technique (e.g., T1059 Command and Scripting Interpreter). This ensures you get complete remediation recommendations:

```bash
# Mitigations for T1059.001 include both:
# - Direct mitigations targeting T1059.001 specifically
# - Inherited mitigations from parent T1059 (marked with [inherited])
uv run attack-kg technique T1059.001
```

Inherited mitigations are marked with `[inherited]` in CLI output and with `inherited: true` in JSON responses.

### D3FEND Countermeasure Mapping

D3FEND techniques are linked to ATT&CK through mitigations. When you query countermeasures for a technique:

1. The system finds all mitigations for that technique (including inherited ones for subtechniques)
2. For each mitigation, it finds linked D3FEND defensive techniques
3. Results show which D3FEND technique addresses which ATT&CK technique, via which mitigation

## Project Structure

```
src/
  main.py          # Typer CLI
  ingest/
    download.py    # STIX data download
    d3fend.py      # D3FEND ontology download
    stix_to_rdf.py # STIX → RDF conversion
    embeddings.py  # Vector embedding generation
  store/
    graph.py       # Oxigraph wrapper (ATT&CK + D3FEND)
    vectors.py     # ChromaDB wrapper
  query/
    hybrid.py      # Combined graph + vector queries
  reasoning/
    analyzer.py    # LLM-based attack analysis
```
