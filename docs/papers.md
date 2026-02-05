# Papers and Resources: CVE/Vulnerability to ATT&CK Retrieval

Research collected for attack-kg v3 planning. Focused on bridging the vocabulary gap between vulnerability descriptions and ATT&CK technique descriptions.

## Cross-Ontology Mapping (CVE/CWE to ATT&CK)

**SMET: Semantic Mapping of CVE to ATT&CK** (Abdeen et al., 2023/2024)
- DBSec 2023: https://link.springer.com/chapter/10.1007/978-3-031-37586-6_15
- Journal of Computer Security 2024: https://journals.sagepub.com/doi/abs/10.3233/JCS-230218
- Three-stage pipeline: Semantic Role Labeling extracts "attack vectors" from CVE text, ATT&CK BERT embeds both sides, logistic regression classifies. SRL is the key insight — extract the attack action before embedding.
- ATT&CK BERT model: https://huggingface.co/basel/ATTACK-BERT (Siamese-trained on CVE/CTI + ATT&CK pairs)

**CVE2ATT&CK: BERT-Based Mapping** (Grigorescu et al., 2022)
- https://www.mdpi.com/1999-4893/15/9/314
- 1,813 labeled CVE→ATT&CK pairs. BERT multi-label classifiers. Dataset useful for fine-tuning.

**Automated CVE-to-Tactic Mapping** (2024)
- https://www.mdpi.com/2078-2489/15/4/214
- SecRoBERTa best at F1 77.81%. GPT-4 zero-shot only 22.04% — general LLMs struggle without fine-tuning.

**Mapping Vulnerability Description to ATT&CK by LLM** (2025)
- https://www.researchgate.net/publication/387775087
- GPT-3.5/4o/o1 with domain-specific prompts approaches fine-tuned BERT performance.

**MITRE CTID: Mapping ATT&CK to CVE for Impact**
- https://ctid.mitre.org/projects/mapping-attck-to-cve-for-impact/
- Official MITRE methodology and dataset. Authoritative mappings available in Mappings Explorer.

**BRON: Bidirectional Graph** (Hemberg et al., MIT CSAIL)
- https://github.com/ALFA-group/BRON
- Bidirectional KG: ATT&CK <-> CAPEC <-> CWE <-> CVE. Traversable edges for path-based queries.

## Query Expansion

**Query2doc** (Wang, Yang, Wei — Microsoft, EMNLP 2023)
- https://aclanthology.org/2023.emnlp-main.585/
- LLM generates pseudo-document, concatenated with original query for BM25. 3-15% boost on benchmarks. More conservative than HyDE (keeps original signal).

**HyDE: Hypothetical Document Embeddings** (Gao et al., ACL 2023)
- https://arxiv.org/abs/2212.10496
- LLM generates hypothetical answer document, embed that instead of query. Dense bottleneck filters hallucinations. Needs domain-constrained prompting for cybersecurity.

**AC_MAPPER** (Albarrak et al., 2025)
- https://link.springer.com/article/10.1007/s10207-025-01146-5
- Input augmentation + class rebalancing for ATT&CK classification. 93.59% accuracy on TRAM benchmark.

## CTI Retrieval

**TTPXHunter** (Rani et al., Digital Threats 2024)
- https://dl.acm.org/doi/10.1145/3696427
- Domain-specific NLP with data augmentation for minority TTP classes. 97.09% F1. Key finding: class imbalance in technique frequency biases embeddings.

**Automated Discovery of ATT&CK Tactics/Techniques** (Computers & Security, 2024)
- https://www.sciencedirect.com/science/article/abs/pii/S0167404824001160
- DistilBERT multi-label classifiers. Post-processing correction fixes common misclassifications.

**MITRE ATT&CK: State of the Art** (ACM Computing Surveys, 2024)
- https://dl.acm.org/doi/10.1145/3687300
- Survey of 417 publications. Confirms transformer dominance. Vulnerability-to-technique mapping remains open challenge.

## Graph-Augmented Retrieval

**CyKG-RAG** (Kurniawan et al., ISWC/RAGE-KG 2024)
- https://ceur-ws.org/Vol-3950/paper1.pdf
- KG + vector search with query routing. Routes structured queries to SPARQL, semantic queries to embeddings. Key insight: route vulnerability queries through graph traversal.

**AgCyRAG: Agentic KG-based RAG** (2025)
- https://ceur-ws.org/Vol-4079/paper11.pdf
- Multiple agents adaptively select retrieval strategy (KG traversal vs vector search vs hybrid).

**GraphCyRAG** (PNNL, 2024)
- https://www.pnnl.gov/publications/retrieval-augmented-generation-robust-cyber-defense
- Neo4j KG traversal over CVE->CWE->CAPEC->ATT&CK. Validates that graph traversal outperforms embedding search for vulnerability-to-technique mapping.

**Graph RAG Survey** (arXiv 2024 / ACM TOIS 2025)
- https://arxiv.org/abs/2408.08921
- Formalizes GraphRAG: Graph-Based Indexing, Graph-Guided Retrieval, Graph-Enhanced Generation.

**CTI-Thinker** (Springer Cybersecurity, 2025)
- https://link.springer.com/article/10.1186/s42400-025-00505-y
- LLM-driven CTI KG construction + GraphRAG reasoning engine for tactical inference.

**Unified Cybersecurity Ontology** (Akbar et al., 2023)
- https://link.springer.com/chapter/10.1007/978-3-031-49099-6_2
- Merges ATT&CK + D3FEND + ENGAGE + CWE + CVE into unified RDF. SPARQL patterns for cross-ontology traversal.

## Key Takeaway

For vulnerability-to-technique mapping, graph traversal through structured ontology chains (CWE->CAPEC->ATT&CK) consistently outperforms pure embedding retrieval across the literature. Embedding search works well for incident reports and behavior descriptions. The optimal system routes between strategies based on finding type.
