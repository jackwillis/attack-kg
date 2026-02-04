"""Download and parse LOLBAS (Living Off The Land Binaries and Scripts) data.

LOLBAS provides explicit mappings from Windows binaries to ATT&CK techniques,
which improves tool-to-technique retrieval (e.g., certutil → T1105).

License: MIT
Source: https://github.com/LOLBAS-Project/LOLBAS
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# GitHub API URLs for LOLBAS
LOLBAS_API_BASE = "https://api.github.com/repos/LOLBAS-Project/LOLBAS/contents"
LOLBAS_RAW_BASE = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master"

# Directories containing LOLBAS YAML files
LOLBAS_DIRS = [
    "yml/OSBinaries",
    "yml/OSLibraries",
    "yml/OSScripts",
    "yml/OtherMSBinaries",
]


@dataclass
class LOLBASCommand:
    """A command example from a LOLBAS entry."""

    command: str
    description: str
    mitre_id: str | None = None
    mitre_tactic: str | None = None
    usecase: str | None = None
    category: str | None = None
    privileges: str | None = None
    operatingsystem: str | None = None


@dataclass
class LOLBASEntry:
    """A LOLBAS entry representing a Windows binary/script."""

    name: str
    description: str
    author: str | None = None
    paths: list[str] = field(default_factory=list)
    commands: list[LOLBASCommand] = field(default_factory=list)
    detection: list[dict[str, str]] = field(default_factory=list)
    resources: list[dict[str, str]] = field(default_factory=list)
    acknowledgement: list[dict[str, str]] = field(default_factory=list)

    def get_techniques(self) -> list[tuple[str, str, str]]:
        """
        Get unique (mitre_id, description, command) tuples from all commands.

        Returns:
            List of (mitre_id, description, command) tuples
        """
        techniques = []
        seen = set()
        for cmd in self.commands:
            if cmd.mitre_id and cmd.mitre_id not in seen:
                seen.add(cmd.mitre_id)
                techniques.append((cmd.mitre_id, cmd.description, cmd.command))
        return techniques


def _parse_yaml_file(content: str) -> dict[str, Any] | None:
    """
    Parse a LOLBAS YAML file.

    Args:
        content: YAML file content

    Returns:
        Parsed YAML dict or None if parsing fails
    """
    try:
        import yaml
        return yaml.safe_load(content)
    except Exception as e:
        console.print(f"[yellow]YAML parse error: {e}[/yellow]")
        return None


def _parse_lolbas_entry(data: dict[str, Any]) -> LOLBASEntry | None:
    """
    Parse a LOLBAS YAML dict into a LOLBASEntry.

    Args:
        data: Parsed YAML dict

    Returns:
        LOLBASEntry or None if invalid
    """
    if not data or not isinstance(data, dict):
        return None

    name = data.get("Name", "")
    if not name:
        return None

    commands = []
    for cmd_data in data.get("Commands", []) or []:
        if isinstance(cmd_data, dict):
            commands.append(LOLBASCommand(
                command=cmd_data.get("Command", ""),
                description=cmd_data.get("Description", ""),
                mitre_id=cmd_data.get("MitreID"),
                mitre_tactic=cmd_data.get("MitreTactic"),
                usecase=cmd_data.get("Usecase"),
                category=cmd_data.get("Category"),
                privileges=cmd_data.get("Privileges"),
                operatingsystem=cmd_data.get("OperatingSystem"),
            ))

    paths = data.get("Full Path", []) or []
    if isinstance(paths, str):
        paths = [paths]

    return LOLBASEntry(
        name=name,
        description=data.get("Description", ""),
        author=data.get("Author"),
        paths=paths,
        commands=commands,
        detection=data.get("Detection", []) or [],
        resources=data.get("Resources", []) or [],
        acknowledgement=data.get("Acknowledgement", []) or [],
    )


def download_lolbas(
    output_dir: Path | str = "data",
    force: bool = False,
) -> Path:
    """
    Download LOLBAS YAML files from GitHub.

    Args:
        output_dir: Directory to save the downloaded files
        force: Re-download even if files exist

    Returns:
        Path to the LOLBAS data directory
    """
    output_dir = Path(output_dir)
    lolbas_dir = output_dir / "lolbas"

    # Check if already downloaded
    marker_file = lolbas_dir / ".downloaded"
    if marker_file.exists() and not force:
        console.print(f"[green]Using cached LOLBAS data:[/green] {lolbas_dir}")
        return lolbas_dir

    lolbas_dir.mkdir(parents=True, exist_ok=True)

    console.print("[blue]Downloading LOLBAS data...[/blue]")

    downloaded = 0
    errors = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        with httpx.Client(timeout=30.0) as client:
            # First, get list of files from each directory
            all_files: list[tuple[str, str]] = []  # (dir_name, filename)

            for lolbas_subdir in LOLBAS_DIRS:
                task = progress.add_task(f"Listing {lolbas_subdir}...", total=None)
                try:
                    api_url = f"{LOLBAS_API_BASE}/{lolbas_subdir}"
                    response = client.get(api_url)
                    response.raise_for_status()
                    files = response.json()
                    for f in files:
                        if isinstance(f, dict) and f.get("name", "").endswith((".yml", ".yaml")):
                            all_files.append((lolbas_subdir, f["name"]))
                except Exception as e:
                    console.print(f"[yellow]Could not list {lolbas_subdir}: {e}[/yellow]")
                progress.update(task, completed=1, total=1)

            # Download each file
            if all_files:
                download_task = progress.add_task("Downloading YAML files...", total=len(all_files))

                for subdir, filename in all_files:
                    try:
                        raw_url = f"{LOLBAS_RAW_BASE}/{subdir}/{filename}"
                        response = client.get(raw_url)
                        response.raise_for_status()

                        # Save to flat structure with subdir prefix
                        safe_subdir = subdir.replace("/", "_")
                        out_file = lolbas_dir / f"{safe_subdir}_{filename}"
                        out_file.write_text(response.text)
                        downloaded += 1
                    except Exception as e:
                        console.print(f"[yellow]Failed to download {filename}: {e}[/yellow]")
                        errors += 1

                    progress.update(download_task, advance=1)

    # Write marker file
    marker_file.write_text(f"downloaded={downloaded}, errors={errors}")

    console.print(f"[green]Downloaded {downloaded} LOLBAS files[/green] (errors: {errors})")
    return lolbas_dir


def parse_lolbas(lolbas_dir: Path | str) -> list[LOLBASEntry]:
    """
    Parse all LOLBAS YAML files in a directory.

    Args:
        lolbas_dir: Directory containing LOLBAS YAML files

    Returns:
        List of LOLBASEntry objects
    """
    lolbas_dir = Path(lolbas_dir)

    if not lolbas_dir.exists():
        console.print(f"[yellow]LOLBAS directory not found: {lolbas_dir}[/yellow]")
        return []

    entries = []
    yaml_files = list(lolbas_dir.glob("*.yml")) + list(lolbas_dir.glob("*.yaml"))

    console.print(f"[dim]Parsing {len(yaml_files)} LOLBAS files...[/dim]")

    for yaml_file in yaml_files:
        try:
            content = yaml_file.read_text()
            data = _parse_yaml_file(content)
            if data:
                entry = _parse_lolbas_entry(data)
                if entry:
                    entries.append(entry)
        except Exception as e:
            console.print(f"[yellow]Error parsing {yaml_file.name}: {e}[/yellow]")

    console.print(f"[green]Parsed {len(entries)} LOLBAS entries[/green]")
    return entries


def lolbas_to_documents(entries: list[LOLBASEntry]) -> list[dict[str, Any]]:
    """
    Convert LOLBAS entries to documents for vector store.

    Each command with an ATT&CK technique mapping becomes a separate document,
    allowing tool names to be searchable and linked to techniques.

    Args:
        entries: List of LOLBASEntry objects

    Returns:
        List of document dicts with id, text, and metadata
    """
    documents = []
    seen_ids = set()

    for entry in entries:
        for mitre_id, description, command in entry.get_techniques():
            # Create unique ID for this tool-technique pair
            doc_id = f"lolbas:{entry.name}:{mitre_id}"

            # Skip duplicates (same tool can map to same technique via different commands)
            if doc_id in seen_ids:
                continue
            seen_ids.add(doc_id)

            # Build searchable text
            # Include tool name prominently, plus description and command
            text_parts = [
                f"Tool: {entry.name}",
                f"Technique: {mitre_id}",
            ]
            if description:
                text_parts.append(f"Description: {description}")
            if command:
                # Truncate very long commands
                cmd_text = command[:500] if len(command) > 500 else command
                text_parts.append(f"Command: {cmd_text}")
            if entry.description:
                text_parts.append(f"Binary Description: {entry.description}")

            documents.append({
                "id": doc_id,
                "text": "\n".join(text_parts),
                "metadata": {
                    "type": "lolbas",
                    "tool": entry.name,
                    "attack_id": mitre_id,
                    "description": description[:200] if description else "",
                    "platform": "Windows",
                },
            })

    console.print(f"[green]Created {len(documents)} LOLBAS documents for embedding[/green]")
    return documents


if __name__ == "__main__":
    # Quick test
    lolbas_dir = download_lolbas("data", force=False)
    entries = parse_lolbas(lolbas_dir)

    # Show some examples
    for entry in entries[:3]:
        print(f"\n{entry.name}: {entry.description[:80]}...")
        for mitre_id, desc, cmd in entry.get_techniques()[:2]:
            print(f"  - {mitre_id}: {desc[:60]}...")

    # Test document generation
    docs = lolbas_to_documents(entries)
    print(f"\nGenerated {len(docs)} documents")
