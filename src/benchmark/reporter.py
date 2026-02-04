"""Report generation for benchmark results."""

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.benchmark.runner import BenchmarkResult
from src.benchmark.scorer import ModelScore

console = Console()


def print_results(result: BenchmarkResult) -> None:
    """Print benchmark results to console with rich formatting."""
    rankings = result.get_rankings()

    if not rankings:
        console.print("[yellow]No results to display[/yellow]")
        return

    # Header
    console.print()
    console.print(Panel("[bold]BENCHMARK RESULTS[/bold]", border_style="cyan"))
    console.print()

    # Rankings table
    table = Table(title="Model Rankings", show_header=True, header_style="bold cyan")
    table.add_column("Rank", justify="right", width=5)
    table.add_column("Model", width=25)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Grade", justify="center", width=6)
    table.add_column("JSON", justify="right", width=5)
    table.add_column("Tech", justify="right", width=5)
    table.add_column("Rem", justify="right", width=5)
    table.add_column("Det", justify="right", width=5)
    table.add_column("Ctx", justify="right", width=5)
    table.add_column("Spd", justify="right", width=5)

    for i, r in enumerate(rankings, 1):
        avg_total = r.get("avg_total", 0)
        pct = r.get("avg_percentage", 0)
        grade = _get_grade(pct)
        grade_color = _grade_color(grade)

        table.add_row(
            str(i),
            r.get("model", ""),
            f"{avg_total:.1f}",
            f"[{grade_color}]{grade}[/{grade_color}]",
            f"{r.get('avg_json_compliance', 0):.1f}",
            f"{r.get('avg_technique_accuracy', 0):.1f}",
            f"{r.get('avg_remediation_quality', 0):.1f}",
            f"{r.get('avg_detection_quality', 0):.1f}",
            f"{r.get('avg_context_awareness', 0):.1f}",
            f"{r.get('avg_speed_factor', 0):.1f}",
        )

    console.print(table)
    console.print()

    # Recommendations
    _print_recommendations(rankings)

    # Per-test-case breakdown if multiple test cases
    test_cases = set(r.test_case_id for r in result.results)
    if len(test_cases) > 1:
        console.print()
        console.print("[bold cyan]PER-TEST-CASE BREAKDOWN[/bold cyan]")
        console.print()

        for tc_id in sorted(test_cases):
            _print_test_case_breakdown(result, tc_id)


def _print_recommendations(rankings: list[dict[str, Any]]) -> None:
    """Print model recommendations."""
    console.print("[bold cyan]RECOMMENDATIONS[/bold cyan]")
    console.print()

    if not rankings:
        return

    top = rankings[0]
    runner_up = rankings[1] if len(rankings) > 1 else None

    # Best overall
    top_grade = _get_grade(top.get("avg_percentage", 0))
    console.print(f"[green]BEST OVERALL:[/green] {top['model']}")
    console.print(f"  Grade: {top_grade} ({top.get('avg_total', 0):.1f}/100)")
    console.print()

    # Runner up
    if runner_up:
        ru_grade = _get_grade(runner_up.get("avg_percentage", 0))
        console.print(f"[yellow]RUNNER-UP:[/yellow] {runner_up['model']}")
        console.print(f"  Grade: {ru_grade} ({runner_up.get('avg_total', 0):.1f}/100)")
        console.print()

    # Fastest good option
    fast_good = next(
        (r for r in rankings if r.get("avg_speed_factor", 0) >= 8 and r.get("avg_total", 0) >= 60),
        None,
    )
    if fast_good and fast_good != top:
        fg_grade = _get_grade(fast_good.get("avg_percentage", 0))
        console.print(f"[cyan]BEST FAST OPTION:[/cyan] {fast_good['model']}")
        console.print(f"  Grade: {fg_grade} ({fast_good.get('avg_total', 0):.1f}/100)")
        console.print()

    # Models to avoid
    avoid = [r for r in rankings if r.get("avg_total", 0) < 45]
    if avoid:
        console.print("[red]MODELS TO AVOID:[/red]")
        for r in avoid:
            grade = _get_grade(r.get("avg_percentage", 0))
            console.print(f"  - {r['model']} ({grade}, {r.get('avg_total', 0):.1f}/100)")
        console.print()


def _print_test_case_breakdown(result: BenchmarkResult, tc_id: str) -> None:
    """Print breakdown for a single test case."""
    tc_results = [r for r in result.results if r.test_case_id == tc_id]
    if not tc_results:
        return

    tc_name = tc_results[0].test_case_name

    table = Table(title=f"{tc_id}: {tc_name}", show_header=True, header_style="bold")
    table.add_column("Model", width=25)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Grade", justify="center", width=6)
    table.add_column("Time", justify="right", width=8)
    table.add_column("Notes", width=40)

    # Sort by score
    tc_results.sort(key=lambda x: x.score.total, reverse=True)

    for r in tc_results:
        grade = r.score.grade()
        grade_color = _grade_color(grade)
        notes = "; ".join(r.score.notes[:2]) if r.score.notes else ""
        if len(r.score.notes) > 2:
            notes += f" (+{len(r.score.notes) - 2} more)"

        table.add_row(
            r.model,
            f"{r.score.total}",
            f"[{grade_color}]{grade}[/{grade_color}]",
            f"{r.runtime_seconds:.1f}s",
            notes,
        )

    console.print(table)
    console.print()


def generate_markdown_report(result: BenchmarkResult, output_path: Path | None = None) -> str:
    """Generate a markdown report of benchmark results."""
    rankings = result.get_rankings()

    lines = [
        "# ATT&CK Analysis Model Benchmark Results",
        "",
        f"**Timestamp:** {result.timestamp}",
        f"**Models Tested:** {len(result.config.models)}",
        f"**Test Cases:** {len(set(r.test_case_id for r in result.results))}",
        "",
        "## Rankings",
        "",
        "| Rank | Model | Score | Grade | JSON | Tech | Rem | Det | Ctx | Spd |",
        "|------|-------|-------|-------|------|------|-----|-----|-----|-----|",
    ]

    for i, r in enumerate(rankings, 1):
        grade = _get_grade(r.get("avg_percentage", 0))
        lines.append(
            f"| {i} | {r.get('model', '')} | {r.get('avg_total', 0):.1f} | {grade} | "
            f"{r.get('avg_json_compliance', 0):.1f} | {r.get('avg_technique_accuracy', 0):.1f} | "
            f"{r.get('avg_remediation_quality', 0):.1f} | {r.get('avg_detection_quality', 0):.1f} | "
            f"{r.get('avg_context_awareness', 0):.1f} | {r.get('avg_speed_factor', 0):.1f} |"
        )

    lines.extend(["", "## Recommendations", ""])

    if rankings:
        top = rankings[0]
        top_grade = _get_grade(top.get("avg_percentage", 0))
        lines.append(f"**Best Overall:** {top['model']} ({top_grade}, {top.get('avg_total', 0):.1f}/100)")
        lines.append("")

        if len(rankings) > 1:
            runner_up = rankings[1]
            ru_grade = _get_grade(runner_up.get("avg_percentage", 0))
            lines.append(f"**Runner-Up:** {runner_up['model']} ({ru_grade}, {runner_up.get('avg_total', 0):.1f}/100)")
            lines.append("")

    # Scoring legend
    lines.extend(
        [
            "",
            "## Scoring Criteria",
            "",
            "| Category | Max Points | Description |",
            "|----------|------------|-------------|",
            "| JSON Compliance | 10 | Valid JSON output parsing |",
            "| Technique Accuracy | 30 | Correct technique identification |",
            "| Remediation Quality | 25 | Appropriate mitigations |",
            "| Detection Quality | 15 | Relevant detection sources |",
            "| Context Awareness | 10 | Platform-appropriate guidance |",
            "| Speed Factor | 10 | Response time |",
            "",
            "---",
            "*Generated by attack-kg benchmark harness*",
        ]
    )

    report = "\n".join(lines)

    if output_path:
        output_path.write_text(report)
        console.print(f"[dim]Markdown report saved to {output_path}[/dim]")

    return report


def generate_detailed_report(result: BenchmarkResult, output_path: Path | None = None) -> str:
    """Generate a detailed markdown report with per-model breakdowns."""
    rankings = result.get_rankings()

    lines = [
        "# ATT&CK Analysis Model Benchmark - Detailed Report",
        "",
        f"**Timestamp:** {result.timestamp}",
        f"**Backend:** {result.config.backend}",
        f"**Models Tested:** {', '.join(result.config.models)}",
        "",
    ]

    # Summary table
    lines.extend(
        [
            "## Summary Rankings",
            "",
            "| Rank | Model | Score | Grade |",
            "|------|-------|-------|-------|",
        ]
    )

    for i, r in enumerate(rankings, 1):
        grade = _get_grade(r.get("avg_percentage", 0))
        lines.append(f"| {i} | {r.get('model', '')} | {r.get('avg_total', 0):.1f}/100 | {grade} |")

    lines.append("")

    # Per-model detailed breakdown
    lines.append("## Detailed Model Analysis")
    lines.append("")

    for r in rankings:
        model = r.get("model", "")
        grade = _get_grade(r.get("avg_percentage", 0))

        lines.extend(
            [
                f"### {model}",
                "",
                f"**Overall:** {r.get('avg_total', 0):.1f}/100 ({grade})",
                "",
                "| Category | Score | Max |",
                "|----------|-------|-----|",
                f"| JSON Compliance | {r.get('avg_json_compliance', 0):.1f} | 10 |",
                f"| Technique Accuracy | {r.get('avg_technique_accuracy', 0):.1f} | 30 |",
                f"| Remediation Quality | {r.get('avg_remediation_quality', 0):.1f} | 25 |",
                f"| Detection Quality | {r.get('avg_detection_quality', 0):.1f} | 15 |",
                f"| Context Awareness | {r.get('avg_context_awareness', 0):.1f} | 10 |",
                f"| Speed Factor | {r.get('avg_speed_factor', 0):.1f} | 10 |",
                "",
            ]
        )

        # Per-test-case scores
        scores = r.get("scores", [])
        if scores:
            lines.append("**Per-Test-Case:**")
            lines.append("")
            for s in scores:
                if isinstance(s, dict):
                    lines.append(f"- {s.get('test_case_id', '')}: {s.get('total', 0)}/100 ({s.get('grade', '')})")
                elif isinstance(s, ModelScore):
                    lines.append(f"- {s.test_case_id}: {s.total}/100 ({s.grade()})")
            lines.append("")

    report = "\n".join(lines)

    if output_path:
        output_path.write_text(report)
        console.print(f"[dim]Detailed report saved to {output_path}[/dim]")

    return report


def _get_grade(percentage: float) -> str:
    """Get letter grade from percentage."""
    if percentage >= 90:
        return "A+"
    elif percentage >= 85:
        return "A"
    elif percentage >= 80:
        return "A-"
    elif percentage >= 75:
        return "B+"
    elif percentage >= 70:
        return "B"
    elif percentage >= 65:
        return "B-"
    elif percentage >= 60:
        return "C+"
    elif percentage >= 55:
        return "C"
    elif percentage >= 50:
        return "C-"
    elif percentage >= 45:
        return "D+"
    elif percentage >= 40:
        return "D"
    else:
        return "F"


def _grade_color(grade: str) -> str:
    """Get color for a grade."""
    if grade.startswith("A"):
        return "green"
    elif grade.startswith("B"):
        return "yellow"
    elif grade.startswith("C"):
        return "orange3"
    else:
        return "red"
