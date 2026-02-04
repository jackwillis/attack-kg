# ATT&CK Knowledge Graph

A neuro-symbolic system combining MITRE ATT&CK, D3FEND, LOLBAS, and GTFOBins as an RDF knowledge graph with vector embeddings for intelligent threat intelligence querying and defensive recommendations.

## Quick Start

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
# (defaults: two-stage LLM, TOON format, hybrid retrieval, kill chain context)
uv run attack-kg analyze "password spraying against Azure AD"
uv run attack-kg analyze --file finding.txt

# Analyze with specific options disabled
uv run attack-kg analyze --single-stage "finding"  # Use single LLM call
uv run attack-kg analyze --no-toon "finding"       # Use JSON format (more tokens)
uv run attack-kg analyze --no-hybrid "finding"     # Semantic-only retrieval
uv run attack-kg analyze --no-kill-chain "finding" # No kill chain expansion

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
| **Two-Stage LLM** | Enabled | Separates node selection (Stage 1) from remediation writing (Stage 2) for reduced hallucination |
| **TOON Format** | Enabled | Token-Oriented Object Notation reduces LLM context by ~40% |
| **Hybrid Retrieval** | Enabled | BM25 keyword + semantic search with Reciprocal Rank Fusion |
| **Kill Chain Bias** | Enabled | Suggests techniques from adjacent kill chain phases |

To disable any feature, use the corresponding flag:
```bash
uv run attack-kg analyze --single-stage "finding"     # Single LLM call
uv run attack-kg analyze --no-toon "finding"          # JSON format
uv run attack-kg analyze --no-hybrid "finding"        # Semantic-only
uv run attack-kg analyze --no-kill-chain "finding"    # No kill chain expansion
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

### Analysis Pipeline (Two-Stage)

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
│  │              │                      │                                 │  │
│  │              │  score = Σ 1/(k+r)   │                                 │  │
│  │              └──────────────────────┘                                 │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    KILL CHAIN EXPANSION                               │  │
│  │                                                                       │  │
│  │  Detected: Initial Access, Execution                                  │  │
│  │      │                                                                │  │
│  │      ▼                                                                │  │
│  │  Adjacent: Persistence, Privilege Escalation (window=2)              │  │
│  │      │                                                                │  │
│  │      ▼                                                                │  │
│  │  Add techniques from adjacent phases to candidates                   │  │
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
│  │                    STAGE 1: NODE SELECTION                            │  │
│  │                                                                       │  │
│  │  Input: Finding + TOON candidates                                    │  │
│  │  Task: Select which techniques apply, with evidence                   │  │
│  │  Output: IDs only (id, confidence, evidence)                         │  │
│  │                                                                       │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │ LLM: "Select techniques from candidates that match the finding" │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  │                                                                       │  │
│  │  Validation: Filter hallucinated IDs (only keep IDs from candidates) │  │
│  │  Rehydration: Look up name, tactic, description from graph          │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │              GRAPH ENRICHMENT (SPARQL)                                │  │
│  │                                                                       │  │
│  │  For each selected technique:                                        │  │
│  │  ├── Get mitigations (with inheritance for subtechniques)           │  │
│  │  ├── Get D3FEND countermeasures (via mitigation mappings)           │  │
│  │  └── Get detection data sources                                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    STAGE 2: REMEDIATION WRITING                       │  │
│  │                                                                       │  │
│  │  Input: Finding + Selected techniques + Mitigations + D3FEND         │  │
│  │  Task: Write product-specific implementation guidance                │  │
│  │  Output: IDs only (id, priority, implementation)                     │  │
│  │                                                                       │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │ LLM: Context extraction → "Write remediation for techniques"    │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  │                                                                       │  │
│  │  Validation: Filter invalid mitigation/D3FEND IDs                    │  │
│  │  Rehydration: Look up names from graph (mitigations, D3FEND)        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                         │                                                   │
│                         ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                       ANALYSIS RESULT                                 │  │
│  │                                                                       │  │
│  │  ├── Selected Techniques (with confidence, evidence, tactic)         │  │
│  │  ├── ATT&CK Mitigations (prioritized, with implementation steps)    │  │
│  │  ├── D3FEND Recommendations (linked to mitigations)                  │  │
│  │  ├── Detection Recommendations (data sources, rationale)            │  │
│  │  └── Kill Chain Analysis (attack lifecycle context)                  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Kill Chain Phases

The system uses MITRE ATT&CK's 14-phase kill chain for inductive bias:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  1. Reconnaissance     │  5. Persistence         │  9. Discovery            │
│  2. Resource Dev       │  6. Privilege Esc       │ 10. Lateral Movement     │
│  3. Initial Access     │  7. Defense Evasion     │ 11. Collection           │
│  4. Execution          │  8. Credential Access   │ 12. C2 / 13. Exfil / 14. │
└─────────────────────────────────────────────────────────────────────────────┘

Example: If finding mentions "Initial Access", system suggests techniques from
         Execution and Persistence phases (window=2 forward in kill chain).
```

### Components

- **Oxigraph** - RDF triplestore (pyoxigraph) for structured SPARQL queries
- **ChromaDB** - Vector store for semantic similarity search
- **sentence-transformers** - Local embeddings (nomic-embed-text-v1.5, pinned revision)
- **BM25** - Keyword-based retrieval using rank-bm25 for exact term matching
- **Two-Stage LLM** - Separate selection and remediation for reduced hallucination
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
