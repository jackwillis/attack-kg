"""Command-line interface for ATT&CK Knowledge Graph."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(
    name="attack-kg",
    help="MITRE ATT&CK Neuro-Symbolic Knowledge Graph",
    no_args_is_help=True,
)
console = Console()

# Default paths
DEFAULT_DATA_DIR = Path("data")
DEFAULT_GRAPH_DIR = Path("data/graph")
DEFAULT_VECTOR_DIR = Path("data/vectors")


@app.command()
def download(
    domain: str = typer.Option("enterprise", help="ATT&CK domain: enterprise, ics, or mobile"),
    output_dir: Path = typer.Option(DEFAULT_DATA_DIR, help="Output directory"),
    force: bool = typer.Option(False, "--force", "-f", help="Re-download even if exists"),
):
    """Download MITRE ATT&CK STIX data from GitHub."""
    from src.ingest.download import download_attack_data, load_stix_bundle, print_stix_summary

    data_file = download_attack_data(output_dir, domain, force)
    bundle = load_stix_bundle(data_file)
    print_stix_summary(bundle)


@app.command()
def ingest(
    data_file: Optional[Path] = typer.Argument(None, help="STIX JSON file to ingest"),
    output: Path = typer.Option(DEFAULT_DATA_DIR / "attack.nt", help="Output N-Triples file"),
):
    """Convert STIX data to RDF and save as N-Triples (fast to load)."""
    from src.ingest.download import download_attack_data, load_stix_bundle
    from src.ingest.stix_to_rdf import StixToRdfConverter

    # Use provided file or download
    if data_file is None:
        data_file = download_attack_data(DEFAULT_DATA_DIR)

    bundle = load_stix_bundle(data_file)

    converter = StixToRdfConverter()
    converter.convert(bundle)

    # Determine format from extension
    fmt = "nt" if output.suffix == ".nt" else "turtle"
    converter.save(output, format=fmt)


@app.command()
def build(
    rdf_file: Optional[Path] = typer.Option(None, help="Input RDF file (.nt or .ttl)"),
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
    vector_dir: Path = typer.Option(DEFAULT_VECTOR_DIR, help="ChromaDB store directory"),
    skip_vectors: bool = typer.Option(False, help="Skip building vector store"),
    force_reload: bool = typer.Option(False, "--force", "-f", help="Force reload even if store has data"),
):
    """Build the knowledge graph and vector store from RDF."""
    import time
    from src.store.graph import AttackGraph
    from src.ingest.embeddings import build_vector_store

    start_time = time.time()

    # Find RDF file: prefer .nt (faster), fall back to .ttl
    if rdf_file is None:
        nt_file = DEFAULT_DATA_DIR / "attack.nt"
        ttl_file = DEFAULT_DATA_DIR / "attack.ttl"
        if nt_file.exists():
            rdf_file = nt_file
        elif ttl_file.exists():
            rdf_file = ttl_file
        else:
            console.print(f"[red]No RDF file found in {DEFAULT_DATA_DIR}[/red]")
            console.print("Run 'attack-kg ingest' first to create it.")
            raise typer.Exit(1)

    if not rdf_file.exists():
        console.print(f"[red]RDF file not found:[/red] {rdf_file}")
        console.print("Run 'attack-kg ingest' first to create it.")
        raise typer.Exit(1)

    # Determine format from extension
    fmt = "nt" if rdf_file.suffix == ".nt" else "turtle"

    # Load into Oxigraph
    console.print("\n[bold]Building RDF graph store...[/bold]")
    graph = AttackGraph(graph_dir)
    graph.load_from_file(rdf_file, format=fmt, force=force_reload)

    # Print stats
    stats = graph.get_stats()
    console.print(Panel(
        f"Techniques: {stats.get('techniques', 0)}\n"
        f"Groups: {stats.get('groups', 0)}\n"
        f"Software: {stats.get('software', 0)}\n"
        f"Mitigations: {stats.get('mitigations', 0)}\n"
        f"Tactics: {stats.get('tactics', 0)}\n"
        f"Total triples: {stats.get('total_triples', 0)}",
        title="Knowledge Graph Stats",
    ))

    if not skip_vectors:
        console.print("\n[bold]Building vector store (this may take 1-2 minutes)...[/bold]")
        build_vector_store(graph, vector_dir)
    else:
        console.print("\n[dim]Skipping vector store (use without --skip-vectors to build)[/dim]")

    elapsed = time.time() - start_time
    console.print(f"\n[green]Build complete in {elapsed:.1f}s[/green]")


@app.command()
def stats(
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
):
    """Show knowledge graph statistics."""
    from src.store.graph import AttackGraph

    graph = AttackGraph(graph_dir)
    stats = graph.get_stats()

    console.print(Panel(
        f"Techniques: {stats.get('techniques', 0)}\n"
        f"Groups: {stats.get('groups', 0)}\n"
        f"Software: {stats.get('software', 0)}\n"
        f"Mitigations: {stats.get('mitigations', 0)}\n"
        f"Tactics: {stats.get('tactics', 0)}\n"
        f"Total triples: {stats.get('total_triples', 0)}",
        title="Knowledge Graph Stats",
    ))


@app.command()
def query(
    sparql: str = typer.Argument(..., help="SPARQL query to execute"),
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
):
    """Execute a SPARQL query against the knowledge graph."""
    from src.store.graph import AttackGraph

    graph = AttackGraph(graph_dir)
    graph.print_query_results(sparql)


@app.command()
def technique(
    attack_id: str = typer.Argument(..., help="ATT&CK technique ID (e.g., T1110.003)"),
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
    show_groups: bool = typer.Option(True, help="Show groups using this technique"),
    show_mitigations: bool = typer.Option(True, help="Show mitigations"),
    show_software: bool = typer.Option(True, help="Show software using this technique"),
):
    """Get details about a specific ATT&CK technique."""
    from src.store.graph import AttackGraph
    from rich.markdown import Markdown

    graph = AttackGraph(graph_dir)
    tech = graph.get_technique(attack_id)

    if not tech:
        console.print(f"[red]Technique not found:[/red] {attack_id}")
        raise typer.Exit(1)

    # Basic info
    console.print(Panel(
        f"[bold]{tech['name']}[/bold] ({attack_id})\n\n{tech['description'][:500]}..."
        if len(tech['description']) > 500 else f"[bold]{tech['name']}[/bold] ({attack_id})\n\n{tech['description']}",
        title="Technique",
    ))

    if show_groups:
        groups = graph.get_groups_using_technique(attack_id)
        if groups:
            console.print(f"\n[bold]Groups using {attack_id}:[/bold]")
            for g in groups:
                console.print(f"  • {g['name']} ({g['attack_id']})")

    if show_mitigations:
        mitigations = graph.get_mitigations_for_technique(attack_id)
        if mitigations:
            console.print(f"\n[bold]Mitigations:[/bold]")
            for m in mitigations:
                console.print(f"  • {m['name']} ({m['attack_id']})")

    if show_software:
        software = graph.get_software_using_technique(attack_id)
        if software:
            console.print(f"\n[bold]Software:[/bold]")
            for s in software:
                console.print(f"  • {s['name']} ({s['attack_id']}) [{s['type']}]")

    # Sub-techniques
    subtechs = graph.get_subtechniques(attack_id)
    if subtechs:
        console.print(f"\n[bold]Sub-techniques:[/bold]")
        for st in subtechs:
            console.print(f"  • {st['name']} ({st['attack_id']})")


@app.command()
def group(
    identifier: str = typer.Argument(..., help="Group ID (e.g., G0016) or name (e.g., APT29)"),
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
):
    """Get details about a threat group and their techniques."""
    from src.store.graph import AttackGraph

    graph = AttackGraph(graph_dir)

    # Try to find by name if not a G-ID
    if not identifier.startswith("G"):
        matches = graph.find_group_by_name(identifier)
        if not matches:
            console.print(f"[red]No groups found matching:[/red] {identifier}")
            raise typer.Exit(1)
        if len(matches) > 1:
            console.print(f"[yellow]Multiple groups found:[/yellow]")
            for m in matches:
                console.print(f"  • {m['name']} ({m['attack_id']})")
            return
        identifier = matches[0]["attack_id"]

    techniques = graph.get_techniques_for_group(identifier)

    if not techniques:
        console.print(f"[red]No techniques found for group:[/red] {identifier}")
        return

    console.print(f"\n[bold]Techniques used by {identifier}:[/bold]")
    for t in techniques:
        console.print(f"  • {t['name']} ({t['attack_id']})")

    console.print(f"\n[dim]Total: {len(techniques)} techniques[/dim]")


@app.command()
def search(
    query_text: str = typer.Argument(..., help="Natural language query"),
    top_k: int = typer.Option(5, "-k", help="Number of results"),
    tactic: Optional[str] = typer.Option(None, help="Filter by tactic"),
    vector_dir: Path = typer.Option(DEFAULT_VECTOR_DIR, help="ChromaDB store directory"),
):
    """Semantic search for techniques matching a description."""
    from src.store.vectors import SemanticSearch

    searcher = SemanticSearch(vector_dir)
    searcher.print_search_results(query_text, n_results=top_k, tactic=tactic)


@app.command()
def analyze(
    finding: Optional[str] = typer.Argument(None, help="Attack narrative or finding text"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read finding from file"),
    backend: str = typer.Option("ollama", "--backend", "-b", help="LLM backend: ollama or openai"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name override"),
    top_k: int = typer.Option(5, "-k", help="Number of candidate techniques to consider"),
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
    vector_dir: Path = typer.Option(DEFAULT_VECTOR_DIR, help="ChromaDB store directory"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Analyze an attack narrative to identify ATT&CK techniques and suggest remediation.

    Examples:
        attack-kg analyze "Found valid credentials through password spraying against Azure AD"
        attack-kg analyze --file finding.txt
        attack-kg analyze --backend openai "Attacker used mimikatz to dump credentials"
    """
    import json
    from src.query.hybrid import HybridQueryEngine
    from src.reasoning.llm import get_llm_backend
    from src.reasoning.analyzer import AttackAnalyzer, print_analysis_result

    # Get finding text
    if file:
        if not file.exists():
            console.print(f"[red]File not found:[/red] {file}")
            raise typer.Exit(1)
        finding_text = file.read_text().strip()
    elif finding:
        finding_text = finding
    else:
        console.print("[red]Error:[/red] Provide finding text or use --file")
        raise typer.Exit(1)

    if not finding_text:
        console.print("[red]Error:[/red] Finding text is empty")
        raise typer.Exit(1)

    # Initialize components
    console.print("[dim]Initializing knowledge graph and LLM...[/dim]")

    try:
        llm = get_llm_backend(backend=backend, model=model)
    except Exception as e:
        console.print(f"[red]Error initializing LLM backend ({backend}):[/red] {e}")
        if backend == "ollama":
            console.print("[dim]Make sure Ollama is running: ollama serve[/dim]")
        elif backend == "openai":
            console.print("[dim]Make sure OPENAI_API_KEY is set[/dim]")
        raise typer.Exit(1)

    hybrid = HybridQueryEngine(graph_dir, vector_dir)
    analyzer = AttackAnalyzer(hybrid, llm)

    # Run analysis
    console.print("[dim]Analyzing finding...[/dim]\n")

    try:
        result = analyzer.analyze(finding_text, top_k=top_k)
    except Exception as e:
        console.print(f"[red]Analysis error:[/red] {e}")
        raise typer.Exit(1)

    # Output
    if output_json:
        console.print(json.dumps(result.to_dict(), indent=2))
    else:
        print_analysis_result(result)


@app.command()
def repl(
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
    vector_dir: Path = typer.Option(DEFAULT_VECTOR_DIR, help="ChromaDB store directory"),
    backend: str = typer.Option("ollama", "--backend", "-b", help="LLM backend: ollama or openai"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name override"),
):
    """Start an interactive query session."""
    import atexit
    import readline

    from src.store.graph import AttackGraph
    from src.query.semantic import SemanticSearchEngine

    # Set up readline history
    history_file = Path.home() / ".attack_kg_history"
    try:
        readline.read_history_file(history_file)
    except FileNotFoundError:
        pass
    readline.set_history_length(1000)
    atexit.register(readline.write_history_file, history_file)

    # Set up tab completion
    commands = ["sparql", "search", "tech", "group", "analyze", "quit", "exit", "help"]

    def completer(text: str, state: int) -> str | None:
        options = [cmd for cmd in commands if cmd.startswith(text)]
        return options[state] if state < len(options) else None

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")

    graph = AttackGraph(graph_dir)
    semantic = SemanticSearchEngine(vector_dir)

    # Lazy-loaded analyzer components
    analyzer = None

    def get_analyzer():
        nonlocal analyzer
        if analyzer is None:
            from src.query.hybrid import HybridQueryEngine
            from src.reasoning.llm import get_llm_backend
            from src.reasoning.analyzer import AttackAnalyzer

            console.print("[dim]Initializing LLM...[/dim]")
            try:
                llm = get_llm_backend(backend=backend, model=model)
                hybrid = HybridQueryEngine(graph=graph, semantic=semantic)
                analyzer = AttackAnalyzer(hybrid, llm)
            except Exception as e:
                console.print(f"[red]Error initializing analyzer:[/red] {e}")
                if backend == "ollama":
                    console.print("[dim]Make sure Ollama is running: ollama serve[/dim]")
                return None
        return analyzer

    console.print(Panel(
        "Commands:\n"
        "  sparql <query>     - Execute SPARQL query\n"
        "  search <text>      - Semantic search\n"
        "  tech <id>          - Get technique details\n"
        "  group <name>       - Get group techniques\n"
        "  analyze <text>     - Analyze finding for techniques & remediation\n"
        "  analyze @<file>    - Analyze finding from file\n"
        "  quit               - Exit\n"
        "\n"
        "Tab completion and command history enabled.",
        title="ATT&CK Knowledge Graph REPL",
    ))

    while True:
        try:
            user_input = console.input("[bold green]attack-kg>[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not user_input:
            continue

        parts = user_input.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break
        elif cmd == "sparql" and arg:
            try:
                graph.print_query_results(arg)
            except Exception as e:
                console.print(f"[red]Query error:[/red] {e}")
        elif cmd == "search" and arg:
            from rich.table import Table
            results = semantic.search(arg, top_k=5)
            if results:
                table = Table(title=f"Techniques similar to: '{arg}'")
                table.add_column("ID", style="cyan")
                table.add_column("Name", style="green")
                table.add_column("Tactics")
                table.add_column("Similarity", justify="right")
                for r in results:
                    table.add_row(r.attack_id, r.name, ", ".join(r.tactics), f"{r.similarity:.3f}")
                console.print(table)
            else:
                console.print("[yellow]No results found[/yellow]")
        elif cmd == "tech" and arg:
            tech = graph.get_technique(arg)
            if tech:
                console.print(f"\n[bold]{tech['name']}[/bold] ({arg})")
                console.print(tech['description'][:500] + "..." if len(tech['description']) > 500 else tech['description'])
            else:
                console.print(f"[yellow]Technique not found: {arg}[/yellow]")
        elif cmd == "group" and arg:
            if not arg.startswith("G"):
                matches = graph.find_group_by_name(arg)
                if matches:
                    arg = matches[0]["attack_id"]
            techniques = graph.get_techniques_for_group(arg)
            if techniques:
                for t in techniques[:10]:
                    console.print(f"  • {t['name']} ({t['attack_id']})")
                if len(techniques) > 10:
                    console.print(f"  ... and {len(techniques) - 10} more")
            else:
                console.print(f"[yellow]No techniques found for: {arg}[/yellow]")
        elif cmd == "analyze" and arg:
            from src.reasoning.analyzer import print_analysis_result

            # Support @filename to read from file
            if arg.startswith("@"):
                file_path = Path(arg[1:]).expanduser()
                if not file_path.exists():
                    console.print(f"[red]File not found:[/red] {file_path}")
                    continue
                finding_text = file_path.read_text().strip()
                console.print(f"[dim]Reading from {file_path}[/dim]")
            else:
                finding_text = arg

            anlzr = get_analyzer()
            if anlzr:
                try:
                    console.print("[dim]Analyzing...[/dim]")
                    result = anlzr.analyze(finding_text, top_k=5)
                    print_analysis_result(result)
                except Exception as e:
                    console.print(f"[red]Analysis error:[/red] {e}")
        else:
            console.print("[yellow]Unknown command. Try: sparql, search, tech, group, analyze, quit[/yellow]")

    console.print("\n[dim]Goodbye![/dim]")


if __name__ == "__main__":
    app()
