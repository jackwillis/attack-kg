# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
uv sync

# Data pipeline (run in order for first setup)
uv run attack-kg download    # Download STIX + D3FEND + LOLBAS + GTFOBins
uv run attack-kg ingest      # Convert STIX → RDF (N-Triples)
uv run attack-kg build       # Load into Oxigraph + build ChromaDB vectors

# Download options (all enabled by default)
uv run attack-kg download --skip-d3fend     # Omit D3FEND
uv run attack-kg download --skip-lolbas     # Omit LOLBAS
uv run attack-kg download --skip-gtfobins   # Omit GTFOBins

# Build options (all enabled by default)
uv run attack-kg build --skip-lolbas        # Omit LOLBAS from vector store
uv run attack-kg build --skip-gtfobins      # Omit GTFOBins from vector store

# CLI usage
uv run attack-kg technique T1110.003    # Lookup technique
uv run attack-kg group APT29            # Group techniques
uv run attack-kg search "credential theft"  # Semantic search
uv run attack-kg search "certutil download" --hybrid  # Hybrid BM25+semantic search
uv run attack-kg analyze "password spraying against Azure AD"  # Full analysis (TOON, hybrid, kill-chain all default on)
uv run attack-kg analyze --file finding.txt  # Analyze from file
uv run attack-kg analyze --two-stage "finding"  # Enable two-stage LLM pipeline (experimental)
uv run attack-kg analyze --no-toon "finding"  # Use JSON format instead of TOON
uv run attack-kg analyze --no-hybrid "finding"  # Semantic-only retrieval
uv run attack-kg analyze --no-kill-chain "finding"  # Disable kill chain expansion
uv run attack-kg countermeasures T1110.003  # Get D3FEND countermeasures for technique
uv run attack-kg query "SELECT ..."     # Raw SPARQL
uv run attack-kg repl                   # Interactive mode (all features enabled by default)
uv run attack-kg repl --model gemma3:4b # REPL with alternate model
uv run attack-kg repl --two-stage       # REPL with experimental two-stage analysis

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
# D3FEND:
#   countermeasures  - Show D3FEND countermeasures for current technique
#
# Advanced:
#   sparql <query>   - Execute raw SPARQL query
#   tech <id>        - Quick technique lookup (navigates + shows info)
#   group <name>     - Quick group lookup (navigates + shows connections)

# Benchmarking
uv run attack-kg list-testcases                    # List available test cases
uv run attack-kg benchmark gpt-oss:20b             # Single model benchmark
uv run attack-kg benchmark gpt-oss:20b,gemma3:4b   # Multi-model comparison
uv run attack-kg benchmark gpt-oss:20b -o results/ # Save detailed results
uv run attack-kg benchmark gpt-oss:20b --markdown  # Generate markdown report
uv run attack-kg benchmark gpt-oss:20b --two-stage     # Benchmark with experimental two-stage mode

# Environment variables
# OLLAMA_HOST       - Ollama server URL (default: http://localhost:11434)
# OPENAI_API_KEY    - OpenAI API key (for --backend openai)
# ATTACK_KG_OFFLINE - Set to 1 to prevent HuggingFace model downloads at runtime
# ATTACK_KG_DEBUG   - Set to 1 to enable debug logging to ~/.attack_kg/logs/

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
D3FEND TTL ────────────────────────────────↗
                                           ↘
LOLBAS YAML ─┬─ Parsed + Embedded ──────────→ ChromaDB (vectors)
GTFOBins MD ─┘
```

### Key Components

- **`src/main.py`** - Main CLI application (Typer commands: download, ingest, build, repl, etc.)

- **`src/cli/browser.py`** - `GraphBrowser` provides filesystem-like navigation through the knowledge graph (cd, ls, pwd, back)

- **`src/cli/presenter.py`** - Rich formatted output for each entity type (techniques, groups, software, etc.)

- **`src/store/graph.py`** - `AttackGraph` wraps pyoxigraph directly (not oxrdflib, which had hanging issues). Provides SPARQL queries and convenience methods for ATT&CK lookups.

- **`src/ingest/stix_to_rdf.py`** - Two-pass conversion: entities first (builds STIX ID → URI mapping), then relationships (resolves references).

- **`src/ingest/embeddings.py`** - Generates embeddings with sentence-transformers (nomic-embed-text-v1.5, 8K token context), stores in ChromaDB. Includes ATT&CK techniques plus LOLBAS/GTFOBins tool mappings.

- **`src/query/hybrid.py`** - `HybridQueryEngine` combines semantic search and BM25 keyword search using Reciprocal Rank Fusion (RRF), with SPARQL graph enrichment.

- **`src/query/keyword.py`** - `KeywordSearchEngine` provides BM25-based keyword search for exact term matching (technique IDs, tool names, technical terms).

- **`src/ingest/d3fend.py`** - Downloads MITRE D3FEND ontology (TTL format) for defensive technique mapping.

- **`src/ingest/lolbas.py`** - Downloads and parses LOLBAS (Living Off The Land Binaries and Scripts) data. Provides Windows binary → ATT&CK technique mappings (e.g., certutil → T1105).

- **`src/ingest/gtfobins.py`** - Downloads and parses GTFOBins data. Provides Linux binary → ATT&CK technique mappings based on function categories (e.g., curl file-download → T1105).

- **`src/benchmark/`** - Automated model benchmarking harness:
  - `testcases.py` - Test case definitions with ground truth techniques/mitigations
  - `scorer.py` - Automated scoring (JSON compliance, technique accuracy, remediation quality, context awareness, speed)
  - `runner.py` - Benchmark execution engine
  - `reporter.py` - Rich console and markdown report generation

- **`src/reasoning/analyzer.py`** - `AttackAnalyzer` orchestrates the analysis pipeline, supporting both single-stage and two-stage LLM modes.

- **`src/reasoning/toon_encoder.py`** - TOON (Token-Oriented Object Notation) format encoder for 30-60% token reduction in LLM context.

- **`src/reasoning/stages/`** - Experimental two-stage LLM architecture:
  - `selector.py` - `NodeSelector` (Stage 1) selects relevant techniques from candidates
  - `remediator.py` - `RemediationWriter` (Stage 2) writes detailed remediation guidance
  - Note: Two-stage has failure modes with smaller models; single-stage is the default

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
- `query(question, top_k, enrich, use_bm25, use_kill_chain)` - Hybrid search with optional BM25 and kill chain expansion
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

**D3FEND Integration:**
- `get_defenses_with_d3fend(attack_id)` - Get ATT&CK mitigations + D3FEND countermeasures
- `find_defenses_for_finding_with_d3fend(finding)` - Enhanced defense finder with D3FEND

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

**Subtechnique Mitigation Inheritance**: When querying mitigations for subtechniques (e.g., T1059.001 PowerShell), the system automatically includes mitigations from the parent technique (T1059 Command and Scripting Interpreter). This is handled by `get_mitigations_with_inheritance()` in `graph.py`. Inherited mitigations are marked with `inherited: true` in the response and displayed with an `[inherited]` marker in the CLI and REPL.

**D3FEND Integration**: MITRE D3FEND ontology can be loaded alongside ATT&CK to provide detailed defensive technique recommendations. D3FEND techniques are linked to ATT&CK via mitigation IDs (e.g., M1032 → D3-MFA). Key methods in `graph.py`:
- `load_d3fend(path)` - Load D3FEND TTL into the store
- `get_d3fend_technique(d3fend_id)` - Get D3FEND technique details (e.g., D3-MFA)
- `get_d3fend_for_mitigation(mitigation_id)` - Get D3FEND techniques for an ATT&CK mitigation
- `get_d3fend_for_technique(attack_id)` - Get all D3FEND countermeasures for a technique (via mitigations)

## Analysis Pipeline Architecture

### Retrieval Options

**Hybrid Retrieval (BM25 + Embeddings)**: Combines keyword search with semantic search using Reciprocal Rank Fusion (RRF).
- BM25 catches exact matches: technique IDs, tool names, technical terms
- Semantic search finds conceptually similar techniques
- LOLBAS/GTFOBins provide explicit tool → technique mappings (certutil → T1105)
- RRF formula: `score(d) = sum(1 / (k + rank(d)))` where k=60

**Kill Chain Inductive Bias**: When enabled, adds techniques from adjacent kill chain phases:
```
Reconnaissance → Resource Development → Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact
```

### Analysis Pipeline Diagram (Single-Stage, Default)

```
┌─────────────┐
│   Finding   │
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────────┐
│         HYBRID RETRIEVAL (RRF)           │
│  ┌─────────────┐    ┌─────────────┐      │
│  │  Semantic   │    │    BM25     │      │
│  │  (ChromaDB) │    │  (Keyword)  │      │
│  └──────┬──────┘    └──────┬──────┘      │
│         └────────┬─────────┘             │
│                  ▼                       │
│         Reciprocal Rank Fusion           │
└──────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│        KILL CHAIN EXPANSION              │
│  Add techniques from adjacent phases     │
└──────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│      GRAPH ENRICHMENT (SPARQL)           │
│  Fetch mitigations, D3FEND, detections   │
└──────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│     TOON CONTEXT ENCODING (~40% ↓)       │
└──────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│  SINGLE-STAGE LLM ANALYSIS               │
│  "Classify finding + write remediation"  │
│  Output: techniques, mitigations, D3FEND │
│  + Validate IDs against retrieval set    │
└──────────────────────────────────────────┘
       │
       ▼
┌─────────────┐
│   Result    │
└─────────────┘
```

### Default Feature Flags

| Feature | Default | Flag to Change |
|---------|---------|----------------|
| Single-Stage LLM | ✓ Enabled | `--two-stage` to enable experimental two-stage |
| TOON Format | ✓ Enabled | `--no-toon` |
| Hybrid Retrieval | ✓ Enabled | `--no-hybrid` |
| Kill Chain Bias | ✓ Enabled | `--no-kill-chain` |

### LLM Analysis Modes

**Single-Stage (default)**: One LLM call for classification + remediation
```
Finding → Retrieval → LLM (Classify + Remediate) → Results
```
- Simpler, more reliable with smaller models
- Combined prompt handles both technique selection and remediation
- Recommended for most use cases

**Two-Stage (experimental)**: Separate LLM calls for node selection and remediation
```
Finding → Retrieval → LLM1 (Select Nodes) → LLM2 (Write Remediation) → Results
```
- Stage 1 focuses on: "Which candidates apply?"
- Stage 2 focuses on: "How do we fix the selected issues?"
- Use `--two-stage` flag to enable
- **Caution**: Has failure modes with smaller models—when Stage 1 returns empty selections, the entire pipeline returns empty results

### Hallucination Mitigation

The system uses multiple strategies to reduce LLM hallucinations:

1. **ID Validation**: Filter LLM outputs to only include IDs present in retrieval context
2. **Graph Rehydration**: Names/metadata come from authoritative graph, not LLM output
3. **Prompt Constraints**: Explicit anti-hallucination rules in prompts (don't invent config syntax, say "consult documentation" when uncertain)
4. **Confidence Levels**: LLM must report confidence (high/medium/low) on each recommendation

### Graph Enrichment → LLM Context

The graph retrieves rich relationships for each technique. Most are passed to the LLM in TOON format:

**Passed to LLM (in TOON format):**
- Techniques: attack_id, name, tactics, similarity, platforms, description
- Software: software_id, name, type, implements_techniques (top 10 by relevance)
- Campaigns: campaign_id, name, uses_techniques (top 5 by relevance)
- Mitigations: mitigation_id, name, addresses, inherited
- D3FEND: d3fend_id, name, via_mitigation, addresses, definition
- Detection Strategies: strategy, detects_techniques (top 10 by coverage)
- Data Sources: data_source, techniques_covered
- Kill Chain: detected_tactics, adjacent_tactics, adjacent_techniques

**Retrieved but NOT passed to LLM:**
- Groups (which threat actors use each technique) - available in CLI/REPL display only

### TOON Format

Token-Oriented Object Notation reduces LLM context size by ~40%. Example sections:

```
CANDIDATE TECHNIQUES
attack_id, name, tactics, similarity, platforms
T1110.003, Password Spraying, Credential Access, 0.87, Windows;Linux;Azure AD

RELATED SOFTWARE
software_id, name, type, implements_techniques
S0154, Cobalt Strike, Tool, T1110.003;T1059.001

RELATED CAMPAIGNS
campaign_id, name, uses_techniques
C0027, Operation Ghost, T1110.003

AVAILABLE MITIGATIONS
mitigation_id, name, addresses, inherited
M1032, Multi-factor Authentication, T1110.003, false

DETECTION STRATEGIES
strategy, detects_techniques
Credential Access Monitoring, T1110.003;T1078
```

vs JSON which requires ~40% more tokens for the same information.
