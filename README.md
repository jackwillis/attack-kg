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

# Run SPARQL queries
uv run attack-kg query "SELECT ?name WHERE { ?t a attack:Technique ; rdfs:label ?name } LIMIT 5"

# Interactive REPL
uv run attack-kg repl
```

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
