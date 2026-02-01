"""Download MITRE D3FEND ontology."""

from pathlib import Path

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# D3FEND ontology URL
D3FEND_URL = "https://d3fend.mitre.org/ontologies/d3fend.ttl"


def download_d3fend(
    output_dir: Path | str = "data",
    force: bool = False,
) -> Path:
    """
    Download MITRE D3FEND ontology (TTL format).

    Args:
        output_dir: Directory to save the downloaded file
        force: Re-download even if file exists

    Returns:
        Path to the downloaded TTL file
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "d3fend.ttl"

    if output_file.exists() and not force:
        console.print(f"[green]Using cached D3FEND data:[/green] {output_file}")
        return output_file

    console.print("[blue]Downloading D3FEND ontology...[/blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching D3FEND TTL...", total=None)

        with httpx.Client(timeout=60.0) as client:
            response = client.get(D3FEND_URL)
            response.raise_for_status()

        progress.update(task, description="Writing to disk...")
        output_file.write_text(response.text)

    console.print(f"[green]Downloaded:[/green] {output_file}")
    return output_file


if __name__ == "__main__":
    # Quick test
    download_d3fend()
