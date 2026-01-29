"""Download MITRE ATT&CK STIX data from GitHub."""

import json
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# MITRE ATT&CK STIX data URLs
ATTACK_STIX_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
ENTERPRISE_ATTACK_URL = f"{ATTACK_STIX_BASE}/enterprise-attack/enterprise-attack.json"

# Alternative domains (ICS, Mobile) if needed later
ICS_ATTACK_URL = f"{ATTACK_STIX_BASE}/ics-attack/ics-attack.json"
MOBILE_ATTACK_URL = f"{ATTACK_STIX_BASE}/mobile-attack/mobile-attack.json"


def download_attack_data(
    output_dir: Path | str = "data",
    domain: str = "enterprise",
    force: bool = False,
) -> Path:
    """
    Download MITRE ATT&CK STIX bundle from GitHub.

    Args:
        output_dir: Directory to save the downloaded file
        domain: ATT&CK domain - "enterprise", "ics", or "mobile"
        force: Re-download even if file exists

    Returns:
        Path to the downloaded JSON file
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    urls = {
        "enterprise": ENTERPRISE_ATTACK_URL,
        "ics": ICS_ATTACK_URL,
        "mobile": MOBILE_ATTACK_URL,
    }

    if domain not in urls:
        raise ValueError(f"Unknown domain: {domain}. Must be one of: {list(urls.keys())}")

    url = urls[domain]
    output_file = output_dir / f"{domain}-attack.json"

    if output_file.exists() and not force:
        console.print(f"[green]Using cached data:[/green] {output_file}")
        return output_file

    console.print(f"[blue]Downloading ATT&CK {domain} data...[/blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching STIX bundle...", total=None)

        with httpx.Client(timeout=60.0) as client:
            response = client.get(url)
            response.raise_for_status()

        progress.update(task, description="Writing to disk...")
        output_file.write_text(response.text)

    console.print(f"[green]Downloaded:[/green] {output_file}")
    return output_file


def load_stix_bundle(path: Path | str) -> dict[str, Any]:
    """
    Load a STIX bundle from a JSON file.

    Args:
        path: Path to the STIX JSON file

    Returns:
        Parsed STIX bundle as a dictionary
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"STIX file not found: {path}")

    with open(path) as f:
        bundle = json.load(f)

    # Validate it's a STIX bundle
    if bundle.get("type") != "bundle":
        raise ValueError(f"Expected STIX bundle, got type: {bundle.get('type')}")

    return bundle


def get_objects_by_type(bundle: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """
    Group STIX objects by their type.

    Args:
        bundle: STIX bundle dictionary

    Returns:
        Dictionary mapping object types to lists of objects
    """
    objects_by_type: dict[str, list[dict[str, Any]]] = {}

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type", "unknown")
        if obj_type not in objects_by_type:
            objects_by_type[obj_type] = []
        objects_by_type[obj_type].append(obj)

    return objects_by_type


def print_stix_summary(bundle: dict[str, Any]) -> None:
    """Print a summary of the STIX bundle contents."""
    objects_by_type = get_objects_by_type(bundle)

    console.print("\n[bold]STIX Bundle Summary[/bold]")
    console.print(f"  Spec version: {bundle.get('spec_version', 'unknown')}")
    console.print(f"  Bundle ID: {bundle.get('id', 'unknown')}")
    console.print(f"\n[bold]Object counts by type:[/bold]")

    # Sort by count descending
    sorted_types = sorted(objects_by_type.items(), key=lambda x: -len(x[1]))
    for obj_type, objects in sorted_types:
        console.print(f"  {obj_type}: {len(objects)}")


if __name__ == "__main__":
    # Quick test
    data_file = download_attack_data()
    bundle = load_stix_bundle(data_file)
    print_stix_summary(bundle)
