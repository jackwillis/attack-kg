"""CLI application for attack-kg v2."""

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(help="Security remediation engine powered by MITRE ATT&CK")
console = Console()

DEFAULT_DIR = Path("data")


@app.command()
def download(
    data_dir: Path = typer.Option(DEFAULT_DIR, "--data-dir", "-d", help="Data directory"),
    skip_d3fend: bool = typer.Option(False, "--skip-d3fend", help="Skip D3FEND download"),
    skip_lolbas: bool = typer.Option(False, "--skip-lolbas", help="Skip LOLBAS download"),
    skip_gtfobins: bool = typer.Option(False, "--skip-gtfobins", help="Skip GTFOBins download"),
    skip_capec: bool = typer.Option(False, "--skip-capec", help="Skip CAPEC download"),
    force: bool = typer.Option(False, "--force", "-f", help="Re-download even if cached"),
):
    """Download ATT&CK, D3FEND, LOLBAS, GTFOBins, and CAPEC data."""
    from src.ingest.download import download_attack, download_d3fend, download_lolbas, download_gtfobins
    from src.ingest.capec import download_capec

    data_dir.mkdir(parents=True, exist_ok=True)
    download_attack(data_dir, force=force)
    if not skip_d3fend:
        download_d3fend(data_dir, force=force)
    if not skip_lolbas:
        download_lolbas(data_dir, force=force)
    if not skip_gtfobins:
        download_gtfobins(data_dir, force=force)
    if not skip_capec:
        download_capec(data_dir, force=force)
    console.print("[bold green]Download complete.[/bold green]")


@app.command()
def ingest(
    data_dir: Path = typer.Option(DEFAULT_DIR, "--data-dir", "-d"),
):
    """Convert STIX JSON and CAPEC XML to RDF N-Triples."""
    from src.ingest.stix_to_rdf import convert_stix_file
    from src.ingest.capec import convert_capec_file

    stix = data_dir / "enterprise-attack.json"
    if not stix.exists():
        console.print("[red]Run 'download' first.[/red]")
        raise typer.Exit(1)
    convert_stix_file(stix, data_dir / "attack.nt")
    capec_xml = data_dir / "capec_latest.xml"
    if capec_xml.exists():
        convert_capec_file(capec_xml, data_dir / "capec.nt")
    console.print("[bold green]Ingest complete.[/bold green]")


@app.command()
def build(
    data_dir: Path = typer.Option(DEFAULT_DIR, "--data-dir", "-d"),
    skip_lolbas: bool = typer.Option(False, "--skip-lolbas"),
    skip_gtfobins: bool = typer.Option(False, "--skip-gtfobins"),
    skip_capec: bool = typer.Option(False, "--skip-capec"),
):
    """Load RDF into Oxigraph and build vector store."""
    from src.store.graph import AttackGraph
    from src.ingest.embeddings import build_vector_store

    store_path = data_dir / "graph"
    vector_path = data_dir / "vectors"

    graph = AttackGraph(store_path)
    nt = data_dir / "attack.nt"
    if not nt.exists():
        console.print("[red]Run 'ingest' first.[/red]")
        raise typer.Exit(1)
    graph.load_file(nt, fmt="nt", clear=True)

    # Load D3FEND (additive — no clear)
    d3fend = data_dir / "d3fend.ttl"
    if d3fend.exists():
        graph.load_file(d3fend, fmt="ttl")

    # Load CAPEC (additive — no clear)
    capec_nt = data_dir / "capec.nt"
    if capec_nt.exists():
        graph.load_file(capec_nt, fmt="nt")

    stats = graph.get_stats()
    console.print(f"[green]Graph: {stats}[/green]")

    build_vector_store(
        graph, persist_dir=vector_path, data_dir=data_dir,
        include_lolbas=not skip_lolbas, include_gtfobins=not skip_gtfobins,
        include_capec=not skip_capec,
    )
    console.print("[bold green]Build complete.[/bold green]")


LOG_DIR = Path("log")


def _init_debug(debug: bool) -> None:
    """Initialize debug logging if enabled."""
    if debug or os.environ.get("ATTACK_KG_DEBUG") == "1":
        from src import debug as dbg
        dbg.init(LOG_DIR)
        console.print(f"[dim]Debug logging to {LOG_DIR}/[/dim]")


def _build_analyzer(
    data_dir: Path, model: str, backend: str,
    context_format: str, no_hybrid: bool,
):
    """Construct the full analysis pipeline."""
    from src.store.graph import AttackGraph
    from src.query.semantic import SemanticSearch
    from src.query.engine import HybridQueryEngine
    from src.reasoning.llm import get_backend
    from src.reasoning.analyzer import AttackAnalyzer

    graph = AttackGraph(data_dir / "graph")
    semantic = SemanticSearch(data_dir / "vectors")
    engine = HybridQueryEngine(graph, semantic, enable_bm25=not no_hybrid)
    llm = get_backend(backend, model)
    return AttackAnalyzer(engine, llm, context_format=context_format, use_bm25=not no_hybrid)


@app.command()
def analyze(
    finding: Optional[str] = typer.Argument(None, help="Finding text to analyze"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read finding from file"),
    model: str = typer.Option("gpt-oss:20b", "--model", "-m", help="LLM model name"),
    backend: str = typer.Option("ollama", "--backend", "-b", help="LLM backend (ollama|openai)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    context_format: str = typer.Option("xml", "--context-format", "-c", help="Context format (xml|toon|json)"),
    no_hybrid: bool = typer.Option(False, "--no-hybrid", help="Semantic-only retrieval"),
    debug: bool = typer.Option(False, "--debug", help="Write debug JSONL to log/"),
    data_dir: Path = typer.Option(DEFAULT_DIR, "--data-dir", "-d"),
):
    """Analyze a security finding for techniques and remediation."""
    import json

    _init_debug(debug)
    if file:
        text = file.read_text().strip()
    elif finding:
        text = finding
    else:
        console.print("[red]Provide a finding as argument or --file[/red]")
        raise typer.Exit(1)

    analyzer = _build_analyzer(data_dir, model, backend, context_format, no_hybrid)
    result = analyzer.analyze(text)

    if json_output:
        console.print_json(json.dumps(result.to_dict(), indent=2))
    else:
        from src.cli.output import render_analysis
        render_analysis(result, console)


@app.command()
def repl(
    model: str = typer.Option("gpt-oss:20b", "--model", "-m", help="LLM model name"),
    backend: str = typer.Option("ollama", "--backend", "-b", help="LLM backend"),
    context_format: str = typer.Option("xml", "--context-format", "-c"),
    no_hybrid: bool = typer.Option(False, "--no-hybrid"),
    debug: bool = typer.Option(False, "--debug", help="Write debug JSONL to log/"),
    data_dir: Path = typer.Option(DEFAULT_DIR, "--data-dir", "-d"),
):
    """Interactive analysis REPL."""
    import json
    import readline
    from src.cli.output import render_analysis

    _init_debug(debug)
    history_file = data_dir / ".repl_history"
    try:
        readline.read_history_file(str(history_file))
    except FileNotFoundError:
        pass

    analyzer = _build_analyzer(data_dir, model, backend, context_format, no_hybrid)
    console.print(f"[bold]attack-kg v2 REPL[/bold] (model={model}, backend={backend})")
    console.print("Type a finding to analyze, or @/path/to/file to load from file. Ctrl-D to exit.\n")

    while True:
        try:
            line = input("finding> ").strip()
        except (EOFError, KeyboardInterrupt):
            try:
                readline.write_history_file(str(history_file))
            except Exception:
                pass
            console.print("\n[dim]Bye.[/dim]")
            break
        if not line:
            continue
        if line.startswith("@"):
            try:
                text = Path(line[1:]).expanduser().read_text().strip()
            except Exception as e:
                from rich.markup import escape as _esc
                console.print(f"[red]Error reading file: {_esc(str(e))}[/red]")
                continue
        else:
            text = line

        try:
            result = analyzer.analyze(text)
            render_analysis(result, console)
        except Exception as e:
            from rich.markup import escape as _esc
            console.print(f"[red]Error: {_esc(str(e))}[/red]")

        try:
            readline.write_history_file(str(history_file))
        except Exception:
            pass
