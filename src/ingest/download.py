"""Download ATT&CK, D3FEND, LOLBAS, and GTFOBins data."""

from pathlib import Path

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
D3FEND_URL = "https://d3fend.mitre.org/ontologies/d3fend.ttl"
LOLBAS_API = "https://api.github.com/repos/LOLBAS-Project/LOLBAS/contents"
LOLBAS_RAW = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master"
LOLBAS_DIRS = ["yml/OSBinaries", "yml/OSLibraries", "yml/OSScripts", "yml/OtherMSBinaries"]
GTFOBINS_API = "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents/_gtfobins"
GTFOBINS_RAW = "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins"


def _fetch(url: str, client: httpx.Client, desc: str) -> bytes:
    resp = client.get(url)
    resp.raise_for_status()
    return resp.content


def download_attack(data_dir: Path, force: bool = False) -> Path:
    out = data_dir / "enterprise-attack.json"
    if out.exists() and not force:
        console.print(f"[green]Cached:[/green] {out}")
        return out
    console.print("[blue]Downloading ATT&CK STIX data...[/blue]")
    with httpx.Client(timeout=60.0) as c:
        out.write_bytes(_fetch(ATTACK_URL, c, "ATT&CK"))
    console.print(f"[green]Downloaded:[/green] {out}")
    return out


def download_d3fend(data_dir: Path, force: bool = False) -> Path:
    out = data_dir / "d3fend.ttl"
    if out.exists() and not force:
        console.print(f"[green]Cached:[/green] {out}")
        return out
    console.print("[blue]Downloading D3FEND ontology...[/blue]")
    with httpx.Client(timeout=60.0) as c:
        out.write_bytes(_fetch(D3FEND_URL, c, "D3FEND"))
    console.print(f"[green]Downloaded:[/green] {out}")
    return out


def download_lolbas(data_dir: Path, force: bool = False) -> Path:
    lolbas_dir = data_dir / "lolbas"
    marker = lolbas_dir / ".downloaded"
    if marker.exists() and not force:
        console.print(f"[green]Cached:[/green] {lolbas_dir}")
        return lolbas_dir
    lolbas_dir.mkdir(parents=True, exist_ok=True)
    console.print("[blue]Downloading LOLBAS data...[/blue]")
    count, errors = 0, 0
    with httpx.Client(timeout=30.0) as client:
        files: list[tuple[str, str]] = []
        for subdir in LOLBAS_DIRS:
            try:
                resp = client.get(f"{LOLBAS_API}/{subdir}")
                resp.raise_for_status()
                for f in resp.json():
                    if isinstance(f, dict) and f.get("name", "").endswith((".yml", ".yaml")):
                        files.append((subdir, f["name"]))
            except Exception as e:
                console.print(f"[yellow]Listing {subdir}: {e}[/yellow]")
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                      TextColumn("{task.completed}/{task.total}"), console=console) as prog:
            task = prog.add_task("LOLBAS files", total=len(files))
            for subdir, name in files:
                try:
                    resp = client.get(f"{LOLBAS_RAW}/{subdir}/{name}")
                    resp.raise_for_status()
                    safe = subdir.replace("/", "_")
                    (lolbas_dir / f"{safe}_{name}").write_text(resp.text)
                    count += 1
                except Exception:
                    errors += 1
                prog.update(task, advance=1)
    marker.write_text(f"{count}")
    console.print(f"[green]Downloaded {count} LOLBAS files[/green] (errors: {errors})")
    return lolbas_dir


def download_gtfobins(data_dir: Path, force: bool = False) -> Path:
    gtfo_dir = data_dir / "gtfobins"
    marker = gtfo_dir / ".downloaded"
    if marker.exists() and not force:
        console.print(f"[green]Cached:[/green] {gtfo_dir}")
        return gtfo_dir
    gtfo_dir.mkdir(parents=True, exist_ok=True)
    console.print("[blue]Downloading GTFOBins data...[/blue]")
    count, errors = 0, 0
    with httpx.Client(timeout=30.0) as client:
        try:
            resp = client.get(GTFOBINS_API)
            resp.raise_for_status()
            files = [f["name"] for f in resp.json() if isinstance(f, dict) and f.get("type") == "file"]
        except Exception as e:
            console.print(f"[red]Listing GTFOBins: {e}[/red]")
            return gtfo_dir
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                      TextColumn("{task.completed}/{task.total}"), console=console) as prog:
            task = prog.add_task("GTFOBins files", total=len(files))
            for name in files:
                try:
                    resp = client.get(f"{GTFOBINS_RAW}/{name}")
                    resp.raise_for_status()
                    (gtfo_dir / name).write_text(resp.text)
                    count += 1
                except Exception:
                    errors += 1
                prog.update(task, advance=1)
    marker.write_text(f"{count}")
    console.print(f"[green]Downloaded {count} GTFOBins files[/green] (errors: {errors})")
    return gtfo_dir
