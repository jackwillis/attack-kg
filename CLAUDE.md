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
uv run attack-kg analyze "password spraying against Azure AD"  # Full analysis with remediation
uv run attack-kg analyze --file finding.txt  # Analyze from file
uv run attack-kg query "SELECT ..."     # Raw SPARQL
uv run attack-kg repl                   # Interactive mode
uv run attack-kg repl --model gpt-oss:20b   # REPL with specific model

# Graph Browser REPL commands (supports readline history + tab completion)
# Navigation:
#   search <text>    - Find entities across all types (techniques, groups, software, etc.)
#   cd <id>          - Navigate to entity (T1110, G0016, S0154, M1032, C0024, etc.)
#   cd .. / back     - Return to previous entity
#   pwd              - Show current location with breadcrumb trail
#   ls               - Show connections from current entity
#   info             - Show full details of current entity
#
# LLM Queries:
#   ask <question>   - Ask LLM about current entity in context
#   analyze <text>   - Analyze finding for techniques & remediation
#   analyze @<file>  - Analyze finding from file
#
# Advanced:
#   sparql <query>   - Execute raw SPARQL query
#   tech <id>        - Quick technique lookup (navigates + shows info)
#   group <name>     - Quick group lookup (navigates + shows connections)

# Environment variables
# OLLAMA_HOST      - Ollama server URL (default: http://localhost:11434)
# OPENAI_API_KEY   - OpenAI API key (for --backend openai)

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

- **`src/main.py`** - Main CLI application (Typer commands: download, ingest, build, repl, etc.)

- **`src/cli/browser.py`** - `GraphBrowser` provides filesystem-like navigation through the knowledge graph (cd, ls, pwd, back)

- **`src/cli/presenter.py`** - Rich formatted output for each entity type (techniques, groups, software, etc.)

- **`src/store/graph.py`** - `AttackGraph` wraps pyoxigraph directly (not oxrdflib, which had hanging issues). Provides SPARQL queries and convenience methods for ATT&CK lookups.

- **`src/ingest/stix_to_rdf.py`** - Two-pass conversion: entities first (builds STIX ID → URI mapping), then relationships (resolves references).

- **`src/ingest/embeddings.py`** - Generates embeddings with sentence-transformers (nomic-embed-text-v1.5, 8K token context), stores in ChromaDB.

- **`src/query/hybrid.py`** - `HybridQueryEngine` combines semantic search results with SPARQL graph enrichment.

### Supported Entity Types

The system processes these STIX entity types into the RDF graph:
- **Techniques** (attack-pattern) - ~835 techniques with sub-techniques
- **Groups** (intrusion-set) - ~187 threat groups with aliases
- **Software** (malware, tool) - ~787 malware and tools
- **Mitigations** (course-of-action) - ~268 defensive measures
- **Campaigns** - ~52 attack campaigns with timelines
- **Tactics** (x-mitre-tactic) - 14 kill chain phases
- **Data Sources** (x-mitre-data-source) - ~38 detection data sources
- **Data Components** (x-mitre-data-component) - ~109 detection components
- **Detection Strategies** (x-mitre-detection-strategy) - ~691 detection approaches
- **Analytics** (x-mitre-analytic) - ~1739 specific detection analytics

### HybridQueryEngine Methods

**Core Query Methods:**
- `query(question, top_k, enrich)` - Semantic search with SPARQL enrichment
- `find_defenses_for_finding(finding_text)` - Get techniques and mitigations for a finding
- `get_threat_context(technique_id)` - Full context for a technique
- `compare_groups(group1_id, group2_id)` - Compare two threat groups

**Campaign Analysis:**
- `get_campaign_context(campaign_id)` - Full campaign profile with techniques and group
- `find_similar_campaigns(campaign_id)` - Find campaigns with similar TTPs

**Detection & Data Sources:**
- `get_detection_coverage(data_sources)` - Analyze what you can detect with available data
- `find_by_data_source(data_source)` - Find techniques detectable by a data source

**Platform & Kill Chain:**
- `get_attack_surface(platforms)` - Techniques organized by tactic for specific platforms
- `analyze_kill_chain(finding_text)` - Map finding across kill chain phases

**Entity Profiles:**
- `get_group_profile(group_id)` - Comprehensive group profile with TTPs and software
- `get_software_profile(software_id)` - Full software profile with techniques and groups
- `find_groups_by_technique_pattern(technique_ids)` - Find groups using specific techniques

**Entity Search:**
- `list_entities(entity_type)` - List all entities of a type
- `search_entities(query, entity_types)` - Search across multiple entity types
- `get_entity(attack_id)` - Get full details for any entity by ID
- `get_relationships(attack_id)` - Get all relationships for an entity
- `find_related_to_finding(finding_text)` - Find all related entities for a finding

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
