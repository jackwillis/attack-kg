"""Debug JSONL logger for the analysis pipeline."""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_log_dir: Path | None = None


def init(log_dir: Path | None = None) -> None:
    """Enable debug logging to a directory. Call once at startup."""
    global _log_dir
    if log_dir is None:
        return
    log_dir.mkdir(parents=True, exist_ok=True)
    _log_dir = log_dir


def enabled() -> bool:
    return _log_dir is not None


def _write(event: str, data: dict[str, Any]) -> None:
    if _log_dir is None:
        return
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **data,
    }
    path = _log_dir / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(record, default=str) + "\n")


def log_retrieval(finding: str, techniques: list[dict], metadata: dict) -> None:
    _write("retrieval", {
        "finding": finding,
        "techniques": techniques,
        "metadata": metadata,
    })


def log_context(context_format: str, context: str, mitigations: list[dict],
                d3fend: list[dict], valid_ids: dict[str, list[str]]) -> None:
    _write("context", {
        "format": context_format,
        "context_length": len(context),
        "context": context,
        "mitigations": mitigations,
        "d3fend": d3fend,
        "valid_ids": valid_ids,
    })


def log_llm_request(prompt: str, system: str | None, model: str, backend: str) -> float:
    """Log the LLM request and return the start time."""
    _write("llm_request", {
        "model": model,
        "backend": backend,
        "prompt_length": len(prompt),
        "prompt": prompt,
        "system": system,
    })
    return time.monotonic()


def log_llm_response(raw: dict[str, Any], elapsed: float) -> None:
    _write("llm_response", {
        "elapsed_s": round(elapsed, 2),
        "raw": raw,
    })


def log_validation(filtered: dict[str, list[str]], result: dict[str, Any]) -> None:
    _write("validation", {
        "filtered_ids": filtered,
        "result": result,
    })
