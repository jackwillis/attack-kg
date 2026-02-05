"""Rich formatted output for analysis results."""

from rich.console import Console


def render_analysis(result, console: Console):
    """Render an AnalysisResult with rich formatting."""
    # Finding type
    ft = result.finding_type.replace("_", " ").title()
    console.print(f"\n[bold]Finding Type:[/bold] {ft}")

    # Techniques
    if result.techniques:
        console.print("\n[bold]Identified Techniques:[/bold]")
        for t in result.techniques:
            conf = t.confidence.upper()
            color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(conf, "white")
            tactics_str = ", ".join(t.tactics) if t.tactics else ""
            console.print(f"  [bold]{t.attack_id}[/bold] {t.name} [{color}][{conf} confidence][/{color}]")
            if tactics_str:
                console.print(f"    Tactics: {tactics_str}")
            if t.evidence:
                console.print(f'    Evidence: [italic]"{t.evidence}"[/italic]')
    else:
        console.print("\n[dim]No techniques identified with sufficient confidence.[/dim]")

    # Remediations
    if result.remediations:
        console.print("\n[bold]Remediation (prioritized):[/bold]")
        for i, r in enumerate(result.remediations, 1):
            pri = r.priority.upper()
            color = {"HIGH": "red bold", "MEDIUM": "yellow", "LOW": "dim"}.get(pri, "white")
            console.print(f"  {i}. [{color}][{pri}][/{color}] {r.name} ({r.mitigation_id})")
            console.print(f"     {r.implementation}")
            if r.d3fend:
                for d in r.d3fend:
                    console.print(f"     [cyan]D3FEND: {d.get('d3fend_id', '')} ({d.get('name', '')})[/cyan]")

    # Detections
    if result.detections:
        console.print("\n[bold]Detection:[/bold]")
        for d in result.detections:
            console.print(f"  [green]\u2022[/green] {d.rationale}")
            if d.data_source:
                console.print(f"    Data source: {d.data_source}")

    # Kill chain
    if result.kill_chain:
        console.print(f"\n[bold]Kill Chain:[/bold] {result.kill_chain}")

    # Filtered IDs warning
    total_filtered = sum(len(v) for v in result.filtered_ids.values())
    if total_filtered:
        console.print(f"\n[dim]({total_filtered} hallucinated IDs filtered)[/dim]")

    console.print()
