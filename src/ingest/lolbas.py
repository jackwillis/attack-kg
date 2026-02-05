"""Parse LOLBAS YAML files into documents for embedding."""

from pathlib import Path
from typing import Any

import yaml
from rich.console import Console

console = Console()


def parse_lolbas(lolbas_dir: Path) -> list[dict[str, Any]]:
    """Parse LOLBAS YAML files into embedding documents.

    Returns list of dicts with: id, text, metadata (type, tool, attack_id, platform).
    """
    if not lolbas_dir.exists():
        return []
    docs, seen = [], set()
    yaml_files = list(lolbas_dir.glob("*.yml")) + list(lolbas_dir.glob("*.yaml"))
    for yf in yaml_files:
        try:
            data = yaml.safe_load(yf.read_text())
            if not data or not isinstance(data, dict):
                continue
            name = data.get("Name", "")
            if not name:
                continue
            for cmd in data.get("Commands", []) or []:
                if not isinstance(cmd, dict):
                    continue
                mid = cmd.get("MitreID")
                if not mid:
                    continue
                doc_id = f"lolbas:{name}:{mid}"
                if doc_id in seen:
                    continue
                seen.add(doc_id)
                desc = cmd.get("Description", "")
                command = (cmd.get("Command", "") or "")[:500]
                text = f"Tool: {name}\nTechnique: {mid}"
                if desc:
                    text += f"\nDescription: {desc}"
                if command:
                    text += f"\nCommand: {command}"
                if data.get("Description"):
                    text += f"\nBinary: {data['Description']}"
                docs.append({
                    "id": doc_id, "text": text,
                    "metadata": {"type": "lolbas", "tool": name,
                                 "attack_id": mid, "platform": "Windows"},
                })
        except Exception:
            pass
    console.print(f"[green]Parsed {len(docs)} LOLBAS documents[/green]")
    return docs
