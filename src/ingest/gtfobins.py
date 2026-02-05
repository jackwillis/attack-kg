"""Parse GTFOBins YAML files into documents for embedding."""

from pathlib import Path
from typing import Any

import yaml
from rich.console import Console

console = Console()

FUNCTION_TO_TECHNIQUE: dict[str, str] = {
    "download": "T1105", "upload": "T1048",
    "shell": "T1059", "command": "T1059",
    "reverse-shell": "T1059", "bind-shell": "T1059",
    "sudo": "T1548.003", "suid": "T1548.001",
    "capabilities": "T1548", "limited-suid": "T1548.001",
    "file-read": "T1005", "file-write": "T1565.001",
    "library-load": "T1574.006",
    "file-download": "T1105", "file-upload": "T1048",
}


def parse_gtfobins(gtfo_dir: Path) -> list[dict[str, Any]]:
    """Parse GTFOBins files into embedding documents.

    Returns list of dicts with: id, text, metadata (type, tool, attack_id, function, platform).
    """
    if not gtfo_dir.exists():
        return []
    docs, seen = [], set()
    files = [f for f in gtfo_dir.iterdir() if f.is_file() and not f.name.startswith(".")]
    for fp in files:
        try:
            data = yaml.safe_load(fp.read_text())
            if not data or not isinstance(data, dict):
                continue
            name = fp.name
            funcs = data.get("functions", {})
            if not isinstance(funcs, dict):
                continue
            seen_techs: set[str] = set()
            for func_name, examples in funcs.items():
                tid = FUNCTION_TO_TECHNIQUE.get(func_name)
                if not tid or tid in seen_techs:
                    continue
                seen_techs.add(tid)
                doc_id = f"gtfobins:{name}:{func_name}"
                if doc_id in seen:
                    continue
                seen.add(doc_id)
                code = ""
                if isinstance(examples, list) and examples:
                    ex = examples[0]
                    if isinstance(ex, dict):
                        code = (ex.get("code", "") or "")[:500]
                text = f"Tool: {name}\nFunction: {func_name}\nTechnique: {tid}"
                if code:
                    text += f"\nExample: {code}"
                docs.append({
                    "id": doc_id, "text": text,
                    "metadata": {"type": "gtfobins", "tool": name,
                                 "attack_id": tid, "function": func_name,
                                 "platform": "Linux"},
                })
        except Exception:
            pass
    console.print(f"[green]Parsed {len(docs)} GTFOBins documents[/green]")
    return docs
