"""Debug logging for ATT&CK Knowledge Graph.

Enable with ATTACK_KG_DEBUG=1 environment variable.
Logs are written to ~/.attack_kg/logs/ as JSON files.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Check if debug logging is enabled
DEBUG_ENABLED = os.environ.get("ATTACK_KG_DEBUG", "").lower() in ("1", "true", "yes")

# Log directory
LOG_DIR = Path.home() / ".attack_kg" / "logs"

# Current session log file
_log_file: Path | None = None
_log_handle = None


def _get_log_file() -> Path:
    """Get or create the current session's log file."""
    global _log_file, _log_handle

    if _log_file is None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        _log_file = LOG_DIR / f"session_{timestamp}.jsonl"
        _log_handle = open(_log_file, "a")

        # Log session start
        _write_entry({
            "event": "session_start",
            "timestamp": datetime.now().isoformat(),
            "pid": os.getpid(),
            "python_version": sys.version,
        })

        # Print to stderr so user knows where logs are
        print(f"[DEBUG] Logging to {_log_file}", file=sys.stderr)

    return _log_file


def _write_entry(entry: dict[str, Any]) -> None:
    """Write a log entry to the current log file."""
    global _log_handle

    if _log_handle is None:
        _get_log_file()

    if _log_handle:
        _log_handle.write(json.dumps(entry, default=str) + "\n")
        _log_handle.flush()


def log_llm_request(prompt: str, system: str | None = None, model: str | None = None) -> str:
    """Log an LLM request. Returns a request ID for correlation."""
    if not DEBUG_ENABLED:
        return ""

    request_id = datetime.now().strftime("%H%M%S%f")

    _write_entry({
        "event": "llm_request",
        "timestamp": datetime.now().isoformat(),
        "request_id": request_id,
        "model": model,
        "system_prompt": system,
        "user_prompt": prompt,
    })

    return request_id


def log_llm_response(request_id: str, response: str, parsed: Any = None, error: str | None = None) -> None:
    """Log an LLM response."""
    if not DEBUG_ENABLED:
        return

    entry = {
        "event": "llm_response",
        "timestamp": datetime.now().isoformat(),
        "request_id": request_id,
        "raw_response": response,
    }

    if parsed is not None:
        entry["parsed"] = parsed

    if error:
        entry["error"] = error

    _write_entry(entry)


def log_sparql_query(query: str, context: str | None = None) -> str:
    """Log a SPARQL query. Returns a query ID for correlation."""
    if not DEBUG_ENABLED:
        return ""

    query_id = datetime.now().strftime("%H%M%S%f")

    _write_entry({
        "event": "sparql_query",
        "timestamp": datetime.now().isoformat(),
        "query_id": query_id,
        "query": query,
        "context": context,
    })

    return query_id


def log_sparql_result(query_id: str, results: list[dict], count: int | None = None) -> None:
    """Log SPARQL query results."""
    if not DEBUG_ENABLED:
        return

    # Limit results in log to avoid huge files
    max_results = 20
    truncated = len(results) > max_results

    _write_entry({
        "event": "sparql_result",
        "timestamp": datetime.now().isoformat(),
        "query_id": query_id,
        "result_count": count if count is not None else len(results),
        "results": results[:max_results],
        "truncated": truncated,
    })


def log_semantic_search(query: str, top_k: int) -> str:
    """Log a semantic search query. Returns a search ID for correlation."""
    if not DEBUG_ENABLED:
        return ""

    search_id = datetime.now().strftime("%H%M%S%f")

    _write_entry({
        "event": "semantic_search",
        "timestamp": datetime.now().isoformat(),
        "search_id": search_id,
        "query": query,
        "top_k": top_k,
    })

    return search_id


def log_semantic_result(search_id: str, results: list[dict]) -> None:
    """Log semantic search results."""
    if not DEBUG_ENABLED:
        return

    _write_entry({
        "event": "semantic_result",
        "timestamp": datetime.now().isoformat(),
        "search_id": search_id,
        "result_count": len(results),
        "results": results,
    })


def log_graph_connection(entity_id: str, entity_type: str, connections: dict[str, Any]) -> None:
    """Log graph connections for an entity."""
    if not DEBUG_ENABLED:
        return

    # Summarize connections
    summary = {}
    for key, value in connections.items():
        if isinstance(value, list):
            summary[key] = len(value)
        elif isinstance(value, dict):
            summary[key] = 1
        else:
            summary[key] = value

    _write_entry({
        "event": "graph_connections",
        "timestamp": datetime.now().isoformat(),
        "entity_id": entity_id,
        "entity_type": entity_type,
        "connection_counts": summary,
        "connections": connections,
    })


def log_d3fend_lookup(attack_id: str, mitigations: list[dict], d3fend_techniques: list[dict]) -> None:
    """Log D3FEND countermeasure lookup."""
    if not DEBUG_ENABLED:
        return

    _write_entry({
        "event": "d3fend_lookup",
        "timestamp": datetime.now().isoformat(),
        "attack_id": attack_id,
        "mitigation_count": len(mitigations),
        "mitigations": [m.get("attack_id") for m in mitigations],
        "d3fend_count": len(d3fend_techniques),
        "d3fend_techniques": d3fend_techniques,
    })


def log_analysis_context(finding: str, techniques: list[dict], mitigations: list[dict], d3fend: list[dict]) -> None:
    """Log the full context being sent to the analyzer."""
    if not DEBUG_ENABLED:
        return

    _write_entry({
        "event": "analysis_context",
        "timestamp": datetime.now().isoformat(),
        "finding": finding,
        "candidate_techniques": [
            {"attack_id": t.attack_id, "name": t.name, "similarity": t.similarity}
            for t in techniques
        ],
        "available_mitigations": mitigations,
        "available_d3fend": d3fend,
    })


def is_debug_enabled() -> bool:
    """Check if debug logging is enabled."""
    return DEBUG_ENABLED
