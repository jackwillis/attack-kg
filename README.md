# ATT&CK Knowledge Graph

A neuro-symbolic system combining MITRE ATT&CK as an RDF knowledge graph with vector embeddings for intelligent threat intelligence querying.

## Quick Start

```bash
# Install dependencies
uv sync

# Download ATT&CK data and build stores
uv run attack-kg download    # Download STIX data from MITRE
uv run attack-kg ingest      # Convert to RDF (N-Triples)
uv run attack-kg build       # Load into Oxigraph + build vector store
```

## Usage

```bash
# Look up a technique
uv run attack-kg technique T1110.003

# Find techniques used by a threat group
uv run attack-kg group APT29

# Semantic search
uv run attack-kg search "credential theft from memory"

# Analyze a finding for ATT&CK techniques and remediation
uv run attack-kg analyze "password spraying against Azure AD"
uv run attack-kg analyze --file finding.txt

# Run SPARQL queries
uv run attack-kg query "SELECT ?name WHERE { ?t a attack:Technique ; rdfs:label ?name } LIMIT 5"

# Interactive REPL
uv run attack-kg repl
uv run attack-kg repl --model gpt-oss:20b  # specify LLM model
```

## Interactive REPL

The REPL provides an interactive session with command history and tab completion:

```
attack-kg> search password spraying
attack-kg> tech T1110.003
attack-kg> group APT29
attack-kg> analyze credential theft via mimikatz
attack-kg> analyze @finding.txt    # read from file
attack-kg> sparql SELECT ?name WHERE { ?t a attack:Technique ; rdfs:label ?name } LIMIT 5
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_HOST` | Ollama server URL (for Docker/remote) | `http://localhost:11434` |
| `OPENAI_API_KEY` | OpenAI API key (for `--backend openai`) | - |

## Architecture

- **Oxigraph** - RDF triplestore (pyoxigraph) for structured SPARQL queries
- **ChromaDB** - Vector store for semantic similarity search
- **sentence-transformers** - Local embeddings (all-MiniLM-L6-v2)

## Data

After running `build`, the knowledge graph contains:
- ~800 techniques with descriptions, tactics, platforms
- ~180 threat groups with technique mappings
- ~600 software/malware entries
- ~40 mitigations
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

## Project Structure

```
src/
  cli.py           # Typer CLI
  ingest/
    download.py    # STIX data download
    stix_to_rdf.py # STIX → RDF conversion
    embeddings.py  # Vector embedding generation
  store/
    graph.py       # Oxigraph wrapper
    vectors.py     # ChromaDB wrapper
  query/
    hybrid.py      # Combined graph + vector queries
```
