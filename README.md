# Cloud Migration

How to evolve attack-kg from a local CLI tool to a cloud-native service, in four progressive levels.

```
 Local CLI ──► HTTP API ──► Concurrent ──► External State ──► Cloud Native
   (now)      (Level 1)    (Level 2)       (Level 3)         (Level 4)
  1 user      1 request    N requests      stateless          auto-scale
  embedded    embedded     duplicated      shared stores      managed services
  stores      stores      per worker      (network)          (AWS)
```

---

## Level 1: HTTP API

Wrap the CLI in FastAPI. Single process, single worker, local stores.

**What changes:**
- FastAPI app with `/analyze` endpoint around `_build_analyzer()` (`src/main.py:110`)
- Pydantic request/response models mirroring the existing `AnalysisResult`
- Graph + vectors loaded once at startup (~5s cold start)

**Example:**

```python
# api.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from pydantic import BaseModel

analyzer = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global analyzer
    from src.main import _build_analyzer, DEFAULT_DIR
    analyzer = _build_analyzer(DEFAULT_DIR, "gpt-oss:20b", "ollama", "xml", False)
    yield

app = FastAPI(lifespan=lifespan)

class AnalyzeRequest(BaseModel):
    finding: str
    context_format: str = "xml"

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    result = analyzer.analyze(req.finding)
    return result.to_dict()
```

```bash
uvicorn api:app --host 0.0.0.0 --port 8000
curl -X POST localhost:8000/analyze -H 'Content-Type: application/json' \
  -d '{"finding": "password spraying against Azure AD"}'
```

**Trade-offs:**
- Gain: any HTTP client can call it; no Python/CLI dependency for consumers
- Cost: one request at a time (async won't help — the LLM call blocks), no scaling

**When to stop here:** personal use, demos, or feeding results into another local tool.

---

## Level 2: Concurrent Requests

Production server handling multiple connections via process-based parallelism.

**What changes:**
- Gunicorn with uvicorn workers — each worker is a separate process with its own graph/vectors
- Process isolation gives thread safety for free (pyoxigraph reads are thread-safe, but ChromaDB's `PersistentClient` is not — separate processes sidestep the issue entirely)
- Health check endpoint for load balancer probes

**Example:**

```bash
gunicorn api:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --graceful-timeout 30
```

```python
# Add to api.py
@app.get("/health")
async def health():
    stats = analyzer.engine.graph.stats()
    return {"status": "ok", "triples": stats.get("triples", 0)}
```

```dockerfile
# Dockerfile (replace ENTRYPOINT)
ENTRYPOINT ["uv", "run", "gunicorn", "api:app", \
  "-w", "4", "-k", "uvicorn.workers.UvicornWorker", \
  "--bind", "0.0.0.0:8000"]
```

**Trade-offs:**
- Gain: handles 4+ concurrent requests; production-grade process management
- Cost: 4 workers x ~2 GB = ~8 GB RAM (graph, vectors, and embedding model duplicated per worker)

**When to stop here:** team-internal service behind a VPN, moderate traffic, single host is acceptable.

---

## Level 3: Externalize State

Decouple storage from compute so workers become stateless.

**What changes:**
- Replace file-based pyoxigraph (RocksDB) with a shared SPARQL endpoint — [Oxigraph server](https://github.com/oxigraph/oxigraph#server) or Amazon Neptune
- Replace file-based ChromaDB (SQLite) with a vector service — [Amazon OpenSearch Serverless](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-vector-search.html) (vector search collection) or [Qdrant](https://qdrant.tech/) on ECS
- Move the embedding model out of workers — use a [Hugging Face Text Embeddings Inference](https://github.com/huggingface/text-embeddings-inference) sidecar or a SageMaker endpoint, so workers don't need torch at all
- Data seeding becomes a separate job (`download → ingest → build → load into services`), not baked into the Docker image

**Example — docker-compose sketch:**

```yaml
services:
  api:
    build: .
    environment:
      SPARQL_ENDPOINT: http://oxigraph:7878
      CHROMA_HOST: chroma
      CHROMA_PORT: "8001"
    ports: ["8000:8000"]
    deploy:
      replicas: 4
      resources:
        limits: { memory: 512M }  # no local stores, no torch

  oxigraph:
    image: ghcr.io/oxigraph/oxigraph:latest
    command: serve --location /data
    volumes: ["oxigraph-data:/data"]
    ports: ["7878:7878"]

  chroma:
    image: chromadb/chroma:latest
    volumes: ["chroma-data:/chroma/chroma"]
    ports: ["8001:8000"]

  embeddings:
    image: ghcr.io/huggingface/text-embeddings-inference:cpu-latest
    command: --model-id nomic-ai/nomic-embed-text-v1.5
    ports: ["8080:80"]

volumes:
  oxigraph-data:
  chroma-data:
```

Workers drop from ~2 GB to ~50 MB each. Total memory is lower even with the external services running.

**Trade-offs:**
- Gain: workers are stateless and disposable; scale horizontally; deploy stores once, not per-worker
- Cost: network latency on every query (~1-5 ms per hop), operational complexity of running 3-4 services

**When to stop here:** multi-team service, moderate scale, comfortable managing a few containers.

---

## Level 4: Cloud Native (AWS)

Horizontal auto-scaling on managed services, infrastructure-as-code.

**What changes:**
- **Compute:** ECS Fargate tasks behind an ALB, auto-scaling on request count or CPU
- **Graph store:** Amazon Neptune (managed SPARQL) or Oxigraph on ECS with EFS-backed storage
- **Vector store:** Amazon OpenSearch Serverless (vector search collection) — fully managed, scales to zero
- **Embeddings:** SageMaker real-time endpoint running nomic-embed-text-v1.5 (or Bedrock Titan Embeddings if model-agnostic is fine)
- **LLM backend:** Amazon Bedrock (Claude) or OpenAI — drop the Ollama dependency entirely
- **Data pipeline:** Step Functions workflow: EventBridge schedule → Lambda (download STIX) → ECS task (ingest + build) → load into Neptune/OpenSearch
- **Observability:** CloudWatch Logs (structured JSON), X-Ray tracing, CloudWatch metrics + alarms

**Example — CDK sketch:**

```python
from aws_cdk import (
    Stack, aws_ecs as ecs, aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_opensearchserverless as oss,
)

class AttackKgStack(Stack):
    def __init__(self, scope, id, **kwargs):
        super().__init__(scope, id, **kwargs)

        vpc = ec2.Vpc(self, "Vpc", max_azs=2)
        cluster = ecs.Cluster(self, "Cluster", vpc=vpc)

        task = ecs.FargateTaskDefinition(self, "ApiTask",
            cpu=1024, memory_limit_mib=2048)
        task.add_container("api",
            image=ecs.ContainerImage.from_asset("."),
            port_mappings=[ecs.PortMapping(container_port=8000)],
            environment={
                "SPARQL_ENDPOINT": "https://neptune-endpoint:8182/sparql",
                "VECTOR_ENDPOINT": "https://opensearch-endpoint",
                "LLM_BACKEND": "bedrock",
                "LLM_MODEL": "anthropic.claude-sonnet-4-5-20250929-v1:0",
            },
            logging=ecs.LogDrivers.aws_logs(stream_prefix="attack-kg"))

        service = ecs.FargateService(self, "ApiService",
            cluster=cluster, task_definition=task,
            desired_count=2)

        scaling = service.auto_scale_task_count(min_capacity=1, max_capacity=10)
        scaling.scale_on_request_count("ReqScale",
            requests_per_target=50,
            target_group=target_group)

        lb = elbv2.ApplicationLoadBalancer(self, "ALB", vpc=vpc, internet_facing=True)
        listener = lb.add_listener("Http", port=80)
        target_group = listener.add_targets("Api",
            port=8000, targets=[service],
            health_check=elbv2.HealthCheck(path="/health"))
```

**Trade-offs:**
- Gain: auto-scaling, managed ops, no servers to patch, pay-per-use
- Cost: AWS bill (~$200-500/mo baseline for Neptune + OpenSearch Serverless + Fargate), vendor lock-in, CDK/CloudFormation complexity

**When to stop here:** production SaaS, org-wide security tooling, or anything customer-facing.

---

## Quick Reference

| | Level 1 | Level 2 | Level 3 | Level 4 |
|---|---|---|---|---|
| **Concurrency** | 1 | N (workers) | N (horizontal) | auto-scale |
| **RAM per worker** | ~2 GB | ~2 GB | ~50 MB | ~50 MB |
| **Graph store** | pyoxigraph (file) | pyoxigraph (file) | Oxigraph server / Neptune | Neptune |
| **Vector store** | ChromaDB (file) | ChromaDB (file) | Chroma server / OpenSearch | OpenSearch Serverless |
| **Embedding model** | in-process (torch) | in-process (torch) | TEI sidecar / SageMaker | SageMaker / Bedrock |
| **LLM** | Ollama / OpenAI | Ollama / OpenAI | Ollama / OpenAI | Bedrock / OpenAI |
| **Infra** | `uvicorn` | `gunicorn` | docker-compose | ECS Fargate + CDK |
| **Effort** | 1 hour | 1 hour | 1-2 days | 1-2 weeks |
