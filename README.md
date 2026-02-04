# ATT&CK Knowledge Graph

A neuro-symbolic system combining MITRE ATT&CK, D3FEND, LOLBAS, and GTFOBins as an RDF knowledge graph with vector embeddings for intelligent threat intelligence querying and defensive recommendations.

## Quick Start (Docker)

```bash
# Interactive REPL with Ollama on host (recommended)
docker run -it --network=host -e OLLAMA_HOST=http://localhost:11434 jackwillis/attack-kg repl

# Look up a technique
docker run jackwillis/attack-kg technique T1110.003

# Analyze a finding
docker run --network=host jackwillis/attack-kg analyze "password spraying against Azure AD"
```

## Quick Start (Local)

```bash
# Install dependencies
uv sync

# Download all data sources and build stores
uv run attack-kg download           # Download STIX + D3FEND + LOLBAS + GTFOBins
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

# Hybrid search (BM25 + semantic)
uv run attack-kg search "certutil download" --hybrid

# Get D3FEND countermeasures for a technique
uv run attack-kg countermeasures T1110.003

# Analyze a finding for ATT&CK techniques and remediation
# (defaults: TOON format, hybrid retrieval with co-occurrence boosting)
uv run attack-kg analyze "password spraying against Azure AD"
uv run attack-kg analyze --file finding.txt

# Analyze with specific options
uv run attack-kg analyze --two-stage "finding"     # Experimental two-stage LLM
uv run attack-kg analyze --no-toon "finding"       # Use JSON format (more tokens)
uv run attack-kg analyze --no-hybrid "finding"     # Semantic-only retrieval

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

## LOLBAS and GTFOBins Integration

The system integrates [LOLBAS](https://lolbas-project.github.io/) (Living Off The Land Binaries and Scripts) and [GTFOBins](https://gtfobins.github.io/) to improve tool-to-technique retrieval. These sources provide explicit mappings from common binaries to ATT&CK techniques.

**Why this matters**: ATT&CK technique descriptions don't always mention specific tools. For example, T1105 (Ingress Tool Transfer) doesn't explicitly list "certutil" in its description. With LOLBAS integration, searching for "certutil download" correctly maps to T1105.

```bash
# Search with tool names - LOLBAS/GTFOBins mappings improve results
uv run attack-kg search "certutil download" --hybrid    # → T1105
uv run attack-kg search "curl file download" --hybrid   # → T1105

# Analyze findings mentioning tools
uv run attack-kg analyze "attacker used certutil to download payload"
```

| Source | Coverage | Mappings |
|--------|----------|----------|
| LOLBAS | Windows binaries | certutil, mshta, regsvr32, etc. |
| GTFOBins | Linux binaries | curl, wget, bash, python, etc. |

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
| `ATTACK_KG_DEBUG` | Enable debug logging to `~/.attack_kg/logs/` | `false` |

### Debug Logging

Enable debug logging to see LLM prompts/responses, SPARQL queries, and graph connections:

```bash
ATTACK_KG_DEBUG=1 uv run attack-kg analyze "password spraying attack"
```

Logs are written as JSON Lines to `~/.attack_kg/logs/session_YYYYMMDD_HHMMSS.jsonl`.

## Analysis Pipeline

The `analyze` command uses a sophisticated pipeline with the following features enabled by default:

| Feature | Default | Description |
|---------|---------|-------------|
| **TOON Format** | Enabled | Token-Oriented Object Notation reduces LLM context by ~40% |
| **Hybrid Retrieval** | Enabled | BM25 keyword + semantic search with Reciprocal Rank Fusion |
| **Co-occurrence Bias** | Enabled | Boosts techniques that appear together in real-world attacks |

Optional features:
```bash
uv run attack-kg analyze --two-stage "finding"        # Experimental two-stage LLM
uv run attack-kg analyze --no-toon "finding"          # JSON format
uv run attack-kg analyze --no-hybrid "finding"        # Semantic-only retrieval
```

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ATT&CK Knowledge Graph                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────────┐│
│  │  STIX JSON   │────▶│ RDF Ingest   │────▶│        Oxigraph              ││
│  │  (ATT&CK)    │     │              │     │    (52K+ triples)            ││
│  └──────────────┘     └──────────────┘     │                              ││
│                                            │  • Techniques (835)          ││
│  ┌──────────────┐                          │  • Groups (187)              ││
│  │  D3FEND TTL  │─────────────────────────▶│  • Mitigations (268)         ││
│  │  (Ontology)  │                          │  • Software (787)            ││
│  └──────────────┘                          │  • D3FEND (500+)             ││
│                                            └──────────────────────────────┘│
│                                                         │                   │
│                                                         ▼                   │
│                       ┌──────────────────────────────────────────────────┐ │
│                       │              Embedding Pipeline                   │ │
│                       │  nomic-embed-text-v1.5 (sentence-transformers)   │ │
│                       └──────────────────────────────────────────────────┘ │
│                                            │                                │
│                                            ▼                                │
│                       ┌──────────────────────────────────────────────────┐ │
│                       │                ChromaDB                           │ │
│                       │          (Vector Store + BM25 Index)              │ │
│                       └──────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Analysis Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ANALYSIS PIPELINE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐                                                            │
│  │   Finding   │                                                            │
│  │   Text      │                                                            │
│  └──────┬──────┘                                                            │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    HYBRID RETRIEVAL (RRF)                             │  │
│  │  ┌────────────────────┐    ┌────────────────────┐                     │  │
│  │  │  Semantic Search   │    │   BM25 Keyword     │                     │  │
│  │  │  (ChromaDB)        │    │   Search           │                     │  │
│  │  │                    │    │                    │                     │  │
│  │  │  Embedding-based   │    │  Exact term match  │                     │  │
│  │  │  similarity        │    │  (technique IDs,   │                     │  │
│  │  │                    │    │   tool names)      │                     │  │
│  │  └─────────┬──────────┘    └─────────┬──────────┘                     │  │
│  │            │                         │                                │  │
│  │            └────────────┬────────────┘                                │  │
│  │                         ▼                                             │  │
│  │              ┌──────────────────────┐                                 │  │
│  │              │  Reciprocal Rank     │                                 │  │
│  │              │  Fusion (k=60)       │                                 │  │
│  │              │  score = Σ 1/(k+r)   │                                 │  │
│  │              └──────────────────────┘                                 │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    CO-OCCURRENCE BOOSTING                             │  │
│  │                                                                       │  │
│  │  For top 3 candidates, query: "What techniques appear together       │  │
│  │  in the same campaigns/groups?"                                      │  │
│  │                                                                       │  │
│  │  Boost techniques that co-occur in real-world attacks                │  │
│  │  (grounded in actual threat intelligence, not structural adjacency) │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │              GRAPH ENRICHMENT (SPARQL)                                │  │
│  │                                                                       │  │
│  │  For each candidate technique:                                       │  │
│  │  ├── Get mitigations (with inheritance for subtechniques)           │  │
│  │  ├── Get D3FEND countermeasures (via mitigation mappings)           │  │
│  │  ├── Get software/malware that implements the technique             │  │
│  │  └── Get detection strategies and data sources                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    TOON CONTEXT ENCODING                              │  │
│  │                                                                       │  │
│  │  JSON (~800 tokens) → TOON (~500 tokens)  [~40% reduction]           │  │
│  │                                                                       │  │
│  │  CANDIDATE_TECHNIQUES                                                 │  │
│  │  attack_id, name, tactics, similarity                                 │  │
│  │  T1110.003, Password Spraying, Credential Access, 0.87               │  │
│  │  T1078.002, Domain Accounts, Initial Access;Persistence, 0.72        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    LLM ANALYSIS (Single-Stage)                        │  │
│  │                                                                       │  │
│  │  Input: Finding + TOON context (techniques, mitigations, D3FEND)    │  │
│  │  Task: Classify techniques + write remediation guidance              │  │
│  │  Output: IDs only (validated against retrieval set)                  │  │
│  │                                                                       │  │
│  │  Validation: Filter hallucinated IDs (only keep IDs from candidates) │  │
│  │  Rehydration: Look up names from authoritative graph                 │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                       ANALYSIS RESULT                                 │  │
│  │                                                                       │  │
│  │  ├── Selected Techniques (with confidence, evidence, tactic)         │  │
│  │  ├── ATT&CK Mitigations (prioritized, with implementation steps)    │  │
│  │  ├── D3FEND Recommendations (linked to mitigations)                  │  │
│  │  └── Detection Recommendations (data sources, rationale)            │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

- **Oxigraph** - RDF triplestore (pyoxigraph) for structured SPARQL queries
- **ChromaDB** - Vector store for semantic similarity search
- **sentence-transformers** - Local embeddings (nomic-embed-text-v1.5, pinned revision)
- **BM25** - Keyword-based retrieval using rank-bm25 for exact term matching
- **Co-occurrence Boosting** - Techniques that appear together in real attacks boost each other
- **TOON Encoder** - Token-efficient context format (~40% token reduction)

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
    hybrid.py      # Combined graph + vector + BM25 queries with RRF
    keyword.py     # BM25 keyword search engine
    semantic.py    # Vector similarity search
  reasoning/
    analyzer.py    # LLM-based attack analysis orchestrator
    toon_encoder.py # Token-efficient context encoding
    stages/
      selector.py  # Stage 1: Technique selection from candidates
      remediator.py # Stage 2: Remediation guidance generation
```

## Hallucination Mitigation

The system uses multiple strategies to reduce LLM hallucinations:

1. **ID Validation**: LLM outputs are filtered to only include technique/mitigation/D3FEND IDs that exist in the retrieval context
2. **Graph Rehydration**: Names and metadata come from the authoritative knowledge graph, not LLM output
3. **Constrained Selection**: Stage 1 prompt explicitly restricts selection to provided candidates
4. **Evidence Extraction**: LLM must cite specific text from the finding as evidence

## Roadmap / TODO

- [ ] **CVE Database Integration**: Add NVD (National Vulnerability Database) data to the vector store to improve vulnerability→technique retrieval. Options include:
  - CWE→CAPEC→ATT&CK mapping chains (MITRE maintains these)
  - CVE description embeddings for semantic similarity to ATT&CK techniques
  - CISA KEV (Known Exploited Vulnerabilities) with TTP mappings

- [ ] **Exposure→Technique Mappings**: Create curated mappings from common security exposures to the ATT&CK techniques they enable (similar to LOLBAS for tools→techniques). Examples:
  - `exposed_admin_login` → [T1078, T1110, T1056.003]
  - `default_credentials` → [T1078.001, T1110.001]
  - `missing_mfa` → [T1078, T1110, T1621]
  - `unpatched_public_service` → [T1190, T1210]

  **LLM-assisted generation**: Use LLMs to bootstrap mappings from:
  1. CWE descriptions → identify enabled techniques
  2. Common pentest finding categories → map to ATT&CK
  3. Validate against CAPEC→ATT&CK chains to reduce hallucination
  4. Human review for quality assurance

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.

## Data Sources & Attribution

This project integrates data from the following sources:

| Source | License | Usage |
|--------|---------|-------|
| [MITRE ATT&CK](https://attack.mitre.org/) | [Apache 2.0](https://github.com/mitre/cti/blob/master/LICENSE) | Techniques, tactics, groups, software, mitigations |
| [MITRE D3FEND](https://d3fend.mitre.org/) | [Apache 2.0](https://github.com/d3fend/d3fend-ontology/blob/master/LICENSE) | Defensive techniques ontology |
| [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) | [MIT](https://github.com/LOLBAS-Project/LOLBAS/blob/master/LICENSE) | Windows LOLBin → ATT&CK mappings |
| [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) | [GPL-3.0](https://github.com/GTFOBins/GTFOBins.github.io/blob/master/LICENSE) | Linux binary → ATT&CK mappings |

### Python Dependencies

Key dependencies (see `pyproject.toml` for full list):

| Package | License | Purpose |
|---------|---------|---------|
| [pyoxigraph](https://github.com/oxigraph/oxigraph) | MIT/Apache 2.0 | RDF triplestore |
| [chromadb](https://github.com/chroma-core/chroma) | Apache 2.0 | Vector store |
| [sentence-transformers](https://github.com/UKPLab/sentence-transformers) | Apache 2.0 | Embeddings |
| [rank-bm25](https://github.com/dorianbrown/rank_bm25) | Apache 2.0 | BM25 keyword search |
| [typer](https://github.com/tiangolo/typer) | MIT | CLI framework |
| [rich](https://github.com/Textualize/rich) | MIT | Terminal formatting |

## Acknowledgments

- MITRE Corporation for ATT&CK and D3FEND frameworks
- The open-source security community
