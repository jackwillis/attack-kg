# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
uv sync

# Data pipeline (run in order for first setup)
uv run attack-kg download    # Download STIX from MITRE GitHub
uv run attack-kg ingest      # Convert STIX → RDF (N-Triples)
uv run attack-kg build       # Load into Oxigraph + build ChromaDB vectors

# CLI usage
uv run attack-kg technique T1110.003    # Lookup technique
uv run attack-kg group APT29            # Group techniques
uv run attack-kg search "credential theft"  # Semantic search
uv run attack-kg analyze "password spraying against Azure AD"  # Remediation suggestions
uv run attack-kg query "SELECT ..."     # Raw SPARQL
uv run attack-kg repl                   # Interactive mode

# Tests
uv run pytest                           # All tests
uv run pytest tests/test_ingest.py -v   # Single file
uv run pytest -k "test_name"            # Single test
```

## Architecture

**Neuro-symbolic pattern**: Combines structured RDF knowledge graph with vector embeddings.

### Data Flow
```
STIX JSON → StixToRdfConverter → N-Triples → Oxigraph (SPARQL)
                                          ↘ ChromaDB (vectors)
```

### Key Components

- **`src/store/graph.py`** - `AttackGraph` wraps pyoxigraph directly (not oxrdflib, which had hanging issues). Provides SPARQL queries and convenience methods for ATT&CK lookups.

- **`src/ingest/stix_to_rdf.py`** - Two-pass conversion: entities first (builds STIX ID → URI mapping), then relationships (resolves references).

- **`src/ingest/embeddings.py`** - Generates embeddings with sentence-transformers (all-MiniLM-L6-v2), stores in ChromaDB.

- **`src/query/hybrid.py`** - `HybridQueryEngine` combines semantic search results with SPARQL graph enrichment.

## Technical Notes

**SPARQL URI handling**: ATT&CK IDs containing dots (T1110.003) break SPARQL prefix notation. Always use full URIs:
```python
# Wrong - will error
sparql = f"attack:technique/{attack_id} ..."

# Correct
tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
sparql = f"{tech_uri} ..."
```

**RDF format**: Use N-Triples (.nt) over Turtle (.ttl) - loads significantly faster.

**Data loading**: `bulk_load` must specify `to_graph=pyoxigraph.DefaultGraph()` or data goes into a named graph and queries return empty.
