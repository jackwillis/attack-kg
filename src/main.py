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
    skip_d3fend: bool = typer.Option(False, "--skip-d3fend", help="Skip downloading D3FEND ontology"),
    skip_lolbas: bool = typer.Option(False, "--skip-lolbas", help="Skip downloading LOLBAS data"),
    skip_gtfobins: bool = typer.Option(False, "--skip-gtfobins", help="Skip downloading GTFOBins data"),
):
    """Download MITRE ATT&CK STIX data, D3FEND ontology, and external tool mappings."""
    from src.ingest.download import download_attack_data, load_stix_bundle, print_stix_summary

    data_file = download_attack_data(output_dir, domain, force)
    bundle = load_stix_bundle(data_file)
    print_stix_summary(bundle)

    if not skip_d3fend:
        from src.ingest.d3fend import download_d3fend
        download_d3fend(output_dir, force=force)

    if not skip_lolbas:
        from src.ingest.lolbas import download_lolbas
        download_lolbas(output_dir, force=force)

    if not skip_gtfobins:
        from src.ingest.gtfobins import download_gtfobins
        download_gtfobins(output_dir, force=force)


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
    skip_d3fend: bool = typer.Option(False, help="Skip loading D3FEND ontology"),
    skip_lolbas: bool = typer.Option(False, help="Skip LOLBAS in vector store"),
    skip_gtfobins: bool = typer.Option(False, help="Skip GTFOBins in vector store"),
    force_reload: bool = typer.Option(False, "--force", "-f", help="Force reload even if store has data"),
):
    """Build the knowledge graph and vector store from RDF and external sources."""
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

    # Load D3FEND if available
    if not skip_d3fend:
        d3fend_file = DEFAULT_DATA_DIR / "d3fend.ttl"
        if d3fend_file.exists():
            console.print("\n[bold]Loading D3FEND ontology...[/bold]")
            graph.load_d3fend(d3fend_file, force=force_reload)
        else:
            console.print("\n[dim]D3FEND not found. Run 'attack-kg download && attack-kg build' to enable.[/dim]")

    # Print stats
    stats = graph.get_stats()
    d3fend_stats = graph.get_d3fend_stats()
    stats_text = (
        f"Techniques: {stats.get('techniques', 0)}\n"
        f"Groups: {stats.get('groups', 0)}\n"
        f"Software: {stats.get('software', 0)}\n"
        f"Mitigations: {stats.get('mitigations', 0)}\n"
        f"Tactics: {stats.get('tactics', 0)}\n"
        f"Total triples: {stats.get('total_triples', 0)}"
    )
    if d3fend_stats.get("d3fend_techniques", 0) > 0:
        stats_text += f"\n\nD3FEND Techniques: {d3fend_stats['d3fend_techniques']}"

    console.print(Panel(stats_text, title="Knowledge Graph Stats"))

    if not skip_vectors:
        console.print("\n[bold]Building vector store (this may take 1-2 minutes)...[/bold]")
        build_vector_store(
            graph,
            vector_dir,
            data_dir=DEFAULT_DATA_DIR,
            include_lolbas=not skip_lolbas,
            include_gtfobins=not skip_gtfobins,
        )
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
        f"[bold]{tech['name']}[/bold] ({attack_id})\n\n{tech['description']}",
        title="Technique",
    ))

    if show_groups:
        groups = graph.get_groups_using_technique(attack_id)
        if groups:
            console.print(f"\n[bold]Groups using {attack_id}:[/bold]")
            for g in groups:
                console.print(f"  • {g['name']} ({g['attack_id']})")

    if show_mitigations:
        mitigations = graph.get_mitigations_with_inheritance(attack_id)
        if mitigations:
            console.print(f"\n[bold]Mitigations:[/bold]")
            for m in mitigations:
                inherited_marker = " [inherited]" if m.get("inherited") else ""
                console.print(f"  • {m['name']} ({m['attack_id']}){inherited_marker}")

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
def countermeasures(
    attack_id: str = typer.Argument(..., help="ATT&CK technique ID (e.g., T1110.003)"),
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
    show_mitigations: bool = typer.Option(True, help="Also show ATT&CK mitigations"),
):
    """Get D3FEND countermeasures for an ATT&CK technique.

    Shows defensive techniques from MITRE D3FEND that address the specified
    ATT&CK technique via its mitigations.

    Examples:
        attack-kg countermeasures T1110.003
        attack-kg countermeasures T1059.001
    """
    from src.store.graph import AttackGraph

    graph = AttackGraph(graph_dir)

    # Check if D3FEND is loaded
    d3fend_stats = graph.get_d3fend_stats()
    if d3fend_stats.get("d3fend_techniques", 0) == 0:
        console.print("[yellow]D3FEND not loaded.[/yellow]")
        console.print("Run 'attack-kg download && attack-kg build' to enable.")
        raise typer.Exit(1)

    # Get the technique first
    tech = graph.get_technique(attack_id)
    if not tech:
        console.print(f"[red]Technique not found:[/red] {attack_id}")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold]{tech['name']}[/bold] ({attack_id})",
        title="Countermeasures",
    ))

    # Show ATT&CK mitigations if requested
    if show_mitigations:
        mitigations = graph.get_mitigations_with_inheritance(attack_id)
        if mitigations:
            console.print(f"\n[bold]ATT&CK Mitigations:[/bold]")
            for m in mitigations:
                inherited_marker = " [dim][inherited][/dim]" if m.get("inherited") else ""
                console.print(f"  • {m['name']} ({m['attack_id']}){inherited_marker}")

    # Get D3FEND countermeasures
    d3fend_techniques = graph.get_d3fend_for_technique(attack_id)

    if d3fend_techniques:
        console.print(f"\n[bold]D3FEND Countermeasures:[/bold]")
        for d3f in d3fend_techniques:
            inherited_marker = " [dim][inherited][/dim]" if d3f.get("inherited") else ""
            console.print(f"  • [cyan]{d3f['d3fend_id']}[/cyan] {d3f['name']}")
            console.print(f"    [dim]via {d3f['via_mitigation']} ({d3f['via_mitigation_name']}){inherited_marker}[/dim]")
            if d3f.get("definition"):
                # Truncate long definitions
                definition = d3f["definition"]
                if len(definition) > 200:
                    definition = definition[:200] + "..."
                console.print(f"    [dim]{definition}[/dim]")

            # Show additional mitigations if any
            additional = d3f.get("additional_mitigations", [])
            if additional:
                for add in additional:
                    console.print(f"    [dim]also via {add['mitigation_id']} ({add['name']})[/dim]")
    else:
        console.print(f"\n[yellow]No D3FEND countermeasures found for {attack_id}[/yellow]")
        console.print("[dim]This may mean no mitigations are linked to D3FEND techniques.[/dim]")

    console.print(f"\n[dim]Total: {len(d3fend_techniques)} D3FEND techniques[/dim]")


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
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
    hybrid: bool = typer.Option(False, "--hybrid", help="Use hybrid BM25+semantic retrieval"),
):
    """Semantic search for techniques matching a description.

    Examples:
        attack-kg search "credential theft"
        attack-kg search "certutil download" --hybrid
        attack-kg search "T1059.001" --hybrid
    """
    if hybrid:
        from src.query.hybrid import HybridQueryEngine
        from rich.table import Table

        engine = HybridQueryEngine(graph_dir, vector_dir, enable_bm25=True)
        result = engine.query(query_text, top_k=top_k, enrich=False, use_bm25=True)

        table = Table(title=f"Hybrid Search Results for: {query_text}")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Tactics", style="dim")
        table.add_column("Score", style="green")

        for tech in result.techniques:
            tactics = ", ".join(tech.tactics[:2]) if tech.tactics else ""
            table.add_row(tech.attack_id, tech.name, tactics, f"{tech.similarity:.3f}")

        console.print(table)
        console.print(f"\n[dim]Retrieval mode: {result.metadata.get('retrieval_mode', 'unknown')}[/dim]")
    else:
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
    two_stage: bool = typer.Option(False, "--two-stage/--single-stage", help="Use two-stage LLM (separate selection and remediation)"),
    toon: bool = typer.Option(True, "--toon/--no-toon", help="Use TOON format for reduced token usage"),
    hybrid: bool = typer.Option(True, "--hybrid/--no-hybrid", help="Use hybrid BM25+semantic retrieval"),
    expand_mitigations: bool = typer.Option(True, "--expand-mitigations/--no-expand-mitigations", help="Expand candidates via shared mitigations"),
):
    """Analyze an attack narrative to identify ATT&CK techniques and suggest remediation.

    Examples:
        attack-kg analyze "Found valid credentials through password spraying against Azure AD"
        attack-kg analyze --file finding.txt
        attack-kg analyze --single-stage "Simple finding without two-stage"
        attack-kg analyze --expand-mitigations "Finding with mitigation-based expansion"
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
    mode_info = []
    if two_stage:
        mode_info.append("two-stage")
    if toon:
        mode_info.append("TOON")
    if hybrid:
        mode_info.append("hybrid-retrieval")
    if expand_mitigations:
        mode_info.append("mitigation-expansion")

    mode_str = ", ".join(mode_info) if mode_info else "default"
    console.print(f"[dim]Initializing knowledge graph and LLM (mode: {mode_str})...[/dim]")

    try:
        llm = get_llm_backend(backend=backend, model=model)
    except Exception as e:
        console.print(f"[red]Error initializing LLM backend ({backend}):[/red] {e}")
        if backend == "ollama":
            console.print("[dim]Make sure Ollama is running: ollama serve[/dim]")
        elif backend == "openai":
            console.print("[dim]Make sure OPENAI_API_KEY is set[/dim]")
        raise typer.Exit(1)

    hybrid_engine = HybridQueryEngine(graph_dir, vector_dir, enable_bm25=hybrid)
    analyzer = AttackAnalyzer(
        hybrid_engine,
        llm,
        two_stage=two_stage,
        use_toon=toon,
        use_bm25=hybrid,
        expand_by_mitigation=expand_mitigations,
    )

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


@app.command("list-testcases")
def list_testcases():
    """List available benchmark test cases."""
    from src.benchmark import load_test_suite, DEFAULT_TEST_SUITE

    console.print("\n[bold]Available Benchmark Test Cases[/bold]")
    console.print("━" * 60)

    for tc in DEFAULT_TEST_SUITE:
        console.print(f"\n[cyan]{tc.id}[/cyan]: {tc.name}")
        console.print(f"  [dim]{tc.description}[/dim]")
        console.print(f"  Platform: {tc.context.platform}")
        console.print(f"  Products: {', '.join(tc.context.products[:3])}")
        console.print(f"  Expected techniques: {len(tc.expected_techniques)}")
        console.print(f"  Expected mitigations: {len(tc.expected_mitigations)}")
        console.print(f"  Tags: {', '.join(tc.tags)}")

    console.print(f"\n[dim]Total: {len(DEFAULT_TEST_SUITE)} test cases[/dim]")


@app.command()
def benchmark(
    models: str = typer.Argument(..., help="Comma-separated list of models to test (e.g., gpt-oss:20b,gemma3:4b)"),
    backend: str = typer.Option("ollama", "--backend", "-b", help="LLM backend: ollama or openai"),
    test_suite: str = typer.Option("default", "--suite", "-s", help="Test suite name"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for results"),
    top_k: int = typer.Option(5, "-k", help="Number of candidate techniques"),
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
    vector_dir: Path = typer.Option(DEFAULT_VECTOR_DIR, help="ChromaDB store directory"),
    markdown: bool = typer.Option(False, "--markdown", "-md", help="Generate markdown report"),
    two_stage: bool = typer.Option(False, "--two-stage/--single-stage", help="Use two-stage LLM architecture"),
    toon: bool = typer.Option(True, "--toon/--no-toon", help="Use TOON format for reduced token usage"),
    hybrid: bool = typer.Option(True, "--hybrid/--no-hybrid", help="Use hybrid BM25+semantic retrieval"),
):
    """Run benchmark tests against LLM models for ATT&CK analysis.

    Evaluates models on technique identification, remediation quality, context
    awareness, and speed. Uses automated scoring based on ground truth test cases.

    Examples:
        attack-kg benchmark gpt-oss:20b,gemma3:4b
        attack-kg benchmark gpt-oss:20b --output results/
        attack-kg benchmark gpt-oss:20b,granite4:3b --markdown
        attack-kg benchmark gpt-oss:20b --two-stage --toon
    """
    from src.store.graph import AttackGraph
    from src.query.hybrid import HybridQueryEngine
    from src.benchmark import (
        BenchmarkRunner,
        BenchmarkConfig,
        print_results,
        generate_markdown_report,
        generate_detailed_report,
    )

    # Parse models
    model_list = [m.strip() for m in models.split(",") if m.strip()]
    if not model_list:
        console.print("[red]Error:[/red] No models specified")
        raise typer.Exit(1)

    console.print(f"[bold]ATT&CK Model Benchmark[/bold]")
    console.print(f"[dim]Models: {', '.join(model_list)}[/dim]")
    console.print(f"[dim]Backend: {backend}[/dim]")

    # Initialize components
    console.print("\n[dim]Loading knowledge graph...[/dim]")
    graph = AttackGraph(graph_dir)

    from src.query.semantic import SemanticSearchEngine
    semantic = SemanticSearchEngine(vector_dir)
    hybrid_engine = HybridQueryEngine(graph=graph, semantic=semantic, enable_bm25=hybrid)

    # Create config
    config = BenchmarkConfig(
        models=model_list,
        test_suite=test_suite,
        backend=backend,
        top_k=top_k,
        output_dir=output_dir,
        save_raw_outputs=output_dir is not None,
        two_stage=two_stage,
        use_toon=toon,
        use_bm25=hybrid,
    )

    # Run benchmark
    runner = BenchmarkRunner(hybrid_engine=hybrid_engine, graph=graph)
    result = runner.run(config)

    # Print results
    print_results(result)

    # Generate reports if requested
    if markdown:
        report_path = (output_dir or Path(".")) / "benchmark_report.md"
        generate_detailed_report(result, report_path)

    if output_dir:
        console.print(f"\n[dim]Full results saved to {output_dir}[/dim]")


@app.command()
def repl(
    graph_dir: Path = typer.Option(DEFAULT_GRAPH_DIR, help="Oxigraph store directory"),
    vector_dir: Path = typer.Option(DEFAULT_VECTOR_DIR, help="ChromaDB store directory"),
    backend: str = typer.Option("ollama", "--backend", "-b", help="LLM backend: ollama or openai"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name override"),
    two_stage: bool = typer.Option(False, "--two-stage/--single-stage", help="Use two-stage LLM for analyze"),
    toon: bool = typer.Option(True, "--toon/--no-toon", help="Use TOON format for reduced token usage"),
    hybrid: bool = typer.Option(True, "--hybrid/--no-hybrid", help="Use hybrid BM25+semantic retrieval"),
):
    """Start an interactive graph browser session."""
    import atexit
    import readline

    from src.store.graph import AttackGraph
    from src.query.semantic import SemanticSearchEngine
    from src.query.hybrid import HybridQueryEngine
    from src.cli.browser import GraphBrowser
    from src.cli.presenter import (
        present_entity,
        present_connections,
        present_search_results,
    )

    # Set up readline history
    history_file = Path.home() / ".attack_kg_history"
    try:
        readline.read_history_file(history_file)
    except FileNotFoundError:
        pass
    readline.set_history_length(1000)
    atexit.register(readline.write_history_file, history_file)

    # Set up tab completion
    commands = [
        "search", "cd", "back", "pwd", "ls", "info", "ask", "countermeasures",
        "sparql", "tech", "group", "analyze", "quit", "exit", "help",
    ]

    def completer(text: str, state: int) -> str | None:
        options = [cmd for cmd in commands if cmd.startswith(text)]
        return options[state] if state < len(options) else None

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")

    # Initialize components
    graph = AttackGraph(graph_dir)
    semantic = SemanticSearchEngine(vector_dir)
    hybrid_engine = HybridQueryEngine(graph=graph, semantic=semantic, enable_bm25=hybrid)
    browser = GraphBrowser(graph, hybrid_engine)

    # Lazy-loaded LLM for ask command
    _llm = None

    def get_llm():
        nonlocal _llm
        if _llm is None:
            from src.reasoning.llm import get_llm_backend
            console.print("[dim]Initializing LLM...[/dim]")
            try:
                _llm = get_llm_backend(backend=backend, model=model)
            except Exception as e:
                console.print(f"[red]Error initializing LLM:[/red] {e}")
                if backend == "ollama":
                    console.print("[dim]Make sure Ollama is running: ollama serve[/dim]")
                return None
        return _llm

    # Lazy-loaded analyzer
    _analyzer = None

    def get_analyzer():
        nonlocal _analyzer
        if _analyzer is None:
            from src.reasoning.analyzer import AttackAnalyzer
            llm = get_llm()
            if llm:
                _analyzer = AttackAnalyzer(
                    hybrid_engine,
                    llm,
                    two_stage=two_stage,
                    use_toon=toon,
                    use_bm25=hybrid,
                )
        return _analyzer

    def show_help():
        console.print(Panel(
            "[bold]Navigation:[/bold]\n"
            "  search <text>      - Find entities across all types\n"
            "  cd <id>            - Navigate to entity (T1110, G0016, S0154, etc.)\n"
            "  cd .. / back       - Return to previous entity\n"
            "  pwd                - Show current location\n"
            "  ls                 - Show connections from current entity\n"
            "  info               - Show full details of current entity\n"
            "\n"
            "[bold]LLM Queries:[/bold]\n"
            "  ask <question>     - Ask a question in context of current entity\n"
            "  analyze <text>     - Analyze finding for techniques & remediation\n"
            "  analyze @<file>    - Analyze finding from file\n"
            "\n"
            "[bold]D3FEND:[/bold]\n"
            "  countermeasures    - Show D3FEND countermeasures for current technique\n"
            "\n"
            "[bold]Advanced:[/bold]\n"
            "  sparql <query>     - Execute raw SPARQL query\n"
            "  tech <id>          - Quick technique lookup\n"
            "  group <name>       - Quick group lookup\n"
            "\n"
            "[bold]Other:[/bold]\n"
            "  help               - Show this help\n"
            "  quit               - Exit\n"
            "\n"
            "[dim]Tab completion and command history enabled.[/dim]",
            title="ATT&CK Graph Browser",
        ))

    def show_root_info():
        """Show info when at root."""
        summary = browser._get_root_summary()
        stats = summary.get("summary", {})
        console.print("\n[bold]ATT&CK Knowledge Graph[/bold]")
        console.print("━" * 40)
        console.print(f"  Techniques:    {stats.get('techniques', 0):,}")
        console.print(f"  Groups:        {stats.get('groups', 0):,}")
        console.print(f"  Software:      {stats.get('software', 0):,}")
        console.print(f"  Mitigations:   {stats.get('mitigations', 0):,}")
        console.print(f"  Campaigns:     {stats.get('campaigns', 0):,}")
        console.print(f"  Tactics:       {stats.get('tactics', 0):,}")
        console.print(f"  Data Sources:  {stats.get('data_sources', 0):,}")
        console.print(f"\n  [dim]Total triples: {stats.get('total_triples', 0):,}[/dim]")
        console.print(f"\n[dim]Use 'search <text>' to find entities or 'cd <ID>' to navigate[/dim]")

    def get_prompt() -> str:
        """Get the current prompt based on browser state."""
        path = browser.pwd()
        # Use plain text for readline compatibility
        return f"\n{path}> "

    # Show initial help
    show_help()

    while True:
        try:
            # Use standard input() for proper readline integration
            user_input = input(get_prompt()).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()  # Clean newline on exit
            break

        if not user_input:
            continue

        parts = user_input.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        # Navigation commands
        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "help":
            show_help()

        elif cmd == "pwd":
            console.print(f"\n[bold]Location:[/bold] {browser.breadcrumb()}")

        elif cmd == "cd":
            if not arg:
                console.print("[yellow]Usage: cd <entity_id> or cd ..[/yellow]")
                continue

            success, entity = browser.cd(arg)
            if success:
                if browser.at_root:
                    show_root_info()
                elif entity:
                    present_entity(entity, browser.current_type)
            else:
                console.print(f"[yellow]Entity not found: {arg}[/yellow]")

        elif cmd == "back":
            success, entity = browser.back()
            if success:
                if browser.at_root:
                    show_root_info()
                elif entity:
                    present_entity(entity, browser.current_type)
            else:
                console.print("[dim]Already at root[/dim]")

        elif cmd == "ls":
            if browser.at_root:
                show_root_info()
            else:
                relationships = browser.ls()
                if relationships:
                    present_connections(relationships, browser.current_type, browser.current_name)

        elif cmd == "info":
            if browser.at_root:
                show_root_info()
            else:
                entity = browser.info()
                if entity:
                    present_entity(entity, browser.current_type, full=True)
                    # Also show connections summary
                    relationships = browser.ls()
                    if relationships:
                        present_connections(relationships, browser.current_type, browser.current_name)

        elif cmd == "search":
            if not arg:
                console.print("[yellow]Usage: search <query>[/yellow]")
                continue

            console.print(f"\n[dim]Searching for: '{arg}'...[/dim]")
            results = browser.search(arg)
            present_search_results(results)

        elif cmd == "ask":
            if not arg:
                console.print("[yellow]Usage: ask <question>[/yellow]")
                continue

            llm = get_llm()
            if llm:
                console.print("[dim]Thinking...[/dim]")
                response = browser.ask(arg, llm)
                from rich.markdown import Markdown
                console.print()
                console.print(Markdown(response))

        # Legacy/advanced commands
        elif cmd == "sparql" and arg:
            try:
                graph.print_query_results(arg)
            except Exception as e:
                console.print(f"[red]Query error:[/red] {e}")

        elif cmd == "tech":
            if not arg:
                console.print("[yellow]Usage: tech <technique_id>[/yellow]")
                continue
            # Navigate to the technique
            success, entity = browser.cd(arg)
            if success and entity:
                present_entity(entity, browser.current_type, full=True)
            else:
                console.print(f"[yellow]Technique not found: {arg}[/yellow]")

        elif cmd == "group":
            if not arg:
                console.print("[yellow]Usage: group <name_or_id>[/yellow]")
                continue
            # Try to find and navigate to the group
            if not arg.upper().startswith("G"):
                matches = graph.find_group_by_name(arg)
                if matches:
                    arg = matches[0]["attack_id"]
                else:
                    console.print(f"[yellow]Group not found: {arg}[/yellow]")
                    continue

            success, entity = browser.cd(arg)
            if success and entity:
                present_entity(entity, browser.current_type)
                relationships = browser.ls()
                if relationships:
                    present_connections(relationships, browser.current_type, browser.current_name)
            else:
                console.print(f"[yellow]Group not found: {arg}[/yellow]")

        elif cmd == "analyze":
            if not arg:
                console.print("[yellow]Usage: analyze <finding_text> or analyze @<file>[/yellow]")
                continue

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

        elif cmd == "countermeasures":
            if browser.at_root:
                console.print("[yellow]Navigate to a technique first (cd T1110.003)[/yellow]")
                continue

            if browser.current_type != "technique":
                console.print(f"[yellow]Countermeasures only available for techniques, not {browser.current_type}[/yellow]")
                continue

            if not browser.has_d3fend():
                console.print("[yellow]D3FEND not loaded.[/yellow]")
                console.print("[dim]Run 'attack-kg download && attack-kg build' to enable.[/dim]")
                continue

            d3fend_techniques = browser.get_countermeasures()
            if d3fend_techniques:
                console.print(f"\n[bold]D3FEND Countermeasures for {browser.current_id}:[/bold]")
                console.print("━" * 50)
                for d3f in d3fend_techniques:
                    inherited_marker = " [dim][inherited][/dim]" if d3f.get("inherited") else ""
                    console.print(f"  [cyan]{d3f['d3fend_id']}[/cyan] {d3f['name']}")
                    console.print(f"    [dim]via {d3f['via_mitigation']} ({d3f['via_mitigation_name']}){inherited_marker}[/dim]")
                    if d3f.get("definition"):
                        definition = d3f["definition"]
                        if len(definition) > 150:
                            definition = definition[:150] + "..."
                        console.print(f"    [dim]{definition}[/dim]")
                console.print(f"\n[dim]Total: {len(d3fend_techniques)} D3FEND techniques[/dim]")
            else:
                console.print(f"[yellow]No D3FEND countermeasures found for {browser.current_id}[/yellow]")

        else:
            console.print(f"[yellow]Unknown command: {cmd}. Type 'help' for available commands.[/yellow]")

    console.print("\n[dim]Goodbye![/dim]")


if __name__ == "__main__":
    app()
