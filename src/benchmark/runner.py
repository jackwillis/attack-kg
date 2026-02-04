"""Benchmark runner for executing test cases against LLM models."""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from src.benchmark.scorer import AutomatedScorer, ModelScore, aggregate_scores
from src.benchmark.testcases import TestCase, load_test_suite

console = Console()


@dataclass
class BenchmarkConfig:
    """Configuration for a benchmark run."""

    models: list[str]
    test_suite: str = "default"
    test_cases: list[TestCase] | None = None  # Override test suite
    backend: str = "ollama"
    top_k: int = 5
    output_dir: Path | None = None
    save_raw_outputs: bool = True
    # New analysis options (single-stage default, others enabled)
    two_stage: bool = False
    use_toon: bool = True
    use_bm25: bool = True
    use_kill_chain: bool = True


@dataclass
class TestCaseResult:
    """Result of running a single test case."""

    model: str
    test_case_id: str
    test_case_name: str
    runtime_seconds: float
    raw_result: dict[str, Any]
    score: ModelScore
    error: str | None = None


@dataclass
class BenchmarkResult:
    """Complete results of a benchmark run."""

    config: BenchmarkConfig
    results: list[TestCaseResult] = field(default_factory=list)
    model_summaries: dict[str, dict[str, Any]] = field(default_factory=dict)
    timestamp: str = ""

    def add_result(self, result: TestCaseResult) -> None:
        """Add a test case result."""
        self.results.append(result)

    def compute_summaries(self) -> None:
        """Compute aggregate summaries for each model."""
        # Group scores by model
        by_model: dict[str, list[ModelScore]] = {}
        for r in self.results:
            if r.model not in by_model:
                by_model[r.model] = []
            by_model[r.model].append(r.score)

        # Aggregate each model's scores
        for model, scores in by_model.items():
            self.model_summaries[model] = aggregate_scores(scores)

    def get_rankings(self) -> list[dict[str, Any]]:
        """Get models ranked by average total score."""
        if not self.model_summaries:
            self.compute_summaries()

        ranked = sorted(self.model_summaries.values(), key=lambda x: x.get("avg_total", 0), reverse=True)
        return ranked


class BenchmarkRunner:
    """Runs benchmark test cases against LLM models."""

    def __init__(self, hybrid_engine=None, graph=None):
        """
        Initialize the runner.

        Args:
            hybrid_engine: Optional pre-initialized HybridQueryEngine
            graph: Optional pre-initialized AttackGraph
        """
        self._hybrid_engine = hybrid_engine
        self._graph = graph
        self.scorer = AutomatedScorer()

    @property
    def hybrid_engine(self):
        """Lazy-load hybrid engine."""
        if self._hybrid_engine is None:
            from src.query.hybrid import HybridQueryEngine

            self._hybrid_engine = HybridQueryEngine(graph=self.graph)
        return self._hybrid_engine

    @property
    def graph(self):
        """Lazy-load graph."""
        if self._graph is None:
            from pathlib import Path

            from src.store.graph import AttackGraph

            # Use default persistent store path
            self._graph = AttackGraph(Path("data/graph"))
        return self._graph

    def run(self, config: BenchmarkConfig) -> BenchmarkResult:
        """
        Run a complete benchmark.

        Args:
            config: Benchmark configuration

        Returns:
            BenchmarkResult with all scores and summaries
        """
        from datetime import datetime

        result = BenchmarkResult(config=config, timestamp=datetime.now().isoformat())

        # Load test cases
        test_cases = config.test_cases or load_test_suite(config.test_suite)

        total_runs = len(config.models) * len(test_cases)
        console.print(f"\n[bold]Starting benchmark: {len(config.models)} models x {len(test_cases)} test cases = {total_runs} runs[/bold]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            for model in config.models:
                task = progress.add_task(f"[cyan]Testing {model}...", total=len(test_cases))

                for test_case in test_cases:
                    progress.update(task, description=f"[cyan]{model}[/cyan] - {test_case.name}")

                    try:
                        tc_result = self._run_single(model, test_case, config)
                        result.add_result(tc_result)

                        # Print inline score
                        score = tc_result.score
                        grade = score.grade()
                        color = {"A+": "green", "A": "green", "A-": "green", "B+": "yellow", "B": "yellow", "B-": "yellow"}.get(grade, "red")
                        console.print(f"  [{color}]{grade}[/{color}] {test_case.id}: {score.total}/100 ({tc_result.runtime_seconds:.1f}s)")

                    except Exception as e:
                        console.print(f"  [red]ERROR[/red] {test_case.id}: {e}")
                        result.add_result(
                            TestCaseResult(
                                model=model,
                                test_case_id=test_case.id,
                                test_case_name=test_case.name,
                                runtime_seconds=0,
                                raw_result={},
                                score=ModelScore(model=model, test_case_id=test_case.id),
                                error=str(e),
                            )
                        )

                    progress.advance(task)

                progress.remove_task(task)

        # Compute summaries
        result.compute_summaries()

        # Save outputs if configured
        if config.output_dir and config.save_raw_outputs:
            self._save_outputs(result, config.output_dir)

        return result

    def _run_single(self, model: str, test_case: TestCase, config: BenchmarkConfig) -> TestCaseResult:
        """Run a single test case against a model."""
        from src.reasoning.analyzer import AttackAnalyzer
        from src.reasoning.llm import get_llm_backend

        # Get LLM backend for this model
        llm = get_llm_backend(backend=config.backend, model=model)

        # Create analyzer with config options
        analyzer = AttackAnalyzer(
            hybrid_engine=self.hybrid_engine,
            llm_backend=llm,
            two_stage=config.two_stage,
            use_toon=config.use_toon,
            use_bm25=config.use_bm25,
            use_kill_chain=config.use_kill_chain,
        )

        # Run analysis with timing
        start = time.time()
        analysis_result = analyzer.analyze(test_case.finding_text, top_k=config.top_k)
        runtime = time.time() - start

        # Convert to dict for scoring
        raw_result = analysis_result.to_dict()

        # Score the result
        score = self.scorer.score(model, test_case, raw_result, runtime)

        return TestCaseResult(
            model=model,
            test_case_id=test_case.id,
            test_case_name=test_case.name,
            runtime_seconds=runtime,
            raw_result=raw_result,
            score=score,
        )

    def _save_outputs(self, result: BenchmarkResult, output_dir: Path) -> None:
        """Save raw outputs and scores to disk."""
        import json

        output_dir.mkdir(parents=True, exist_ok=True)

        # Save each model's results
        for tc_result in result.results:
            # Sanitize model name for filename
            model_safe = tc_result.model.replace(":", "-").replace("/", "-")
            filename = f"{model_safe}_{tc_result.test_case_id}.json"
            filepath = output_dir / filename

            output = {
                "model": tc_result.model,
                "test_case": tc_result.test_case_id,
                "test_case_name": tc_result.test_case_name,
                "runtime_seconds": tc_result.runtime_seconds,
                "score": {
                    "total": tc_result.score.total,
                    "grade": tc_result.score.grade(),
                    "json_compliance": tc_result.score.json_compliance,
                    "technique_accuracy": tc_result.score.technique_accuracy,
                    "remediation_quality": tc_result.score.remediation_quality,
                    "detection_quality": tc_result.score.detection_quality,
                    "context_awareness": tc_result.score.context_awareness,
                    "speed_factor": tc_result.score.speed_factor,
                    "notes": tc_result.score.notes,
                },
                "raw_result": tc_result.raw_result,
                "error": tc_result.error,
            }

            with open(filepath, "w") as f:
                json.dump(output, f, indent=2)

        # Save summary
        summary_file = output_dir / "benchmark_summary.json"
        summary = {
            "timestamp": result.timestamp,
            "config": {
                "models": result.config.models,
                "test_suite": result.config.test_suite,
                "backend": result.config.backend,
            },
            "rankings": result.get_rankings(),
        }

        # Convert ModelScore objects to dicts in rankings
        for r in summary["rankings"]:
            if "scores" in r:
                r["scores"] = [
                    {
                        "test_case_id": s.test_case_id,
                        "total": s.total,
                        "grade": s.grade(),
                    }
                    for s in r["scores"]
                ]

        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        console.print(f"\n[dim]Results saved to {output_dir}[/dim]")


def run_quick_benchmark(
    models: list[str],
    finding_text: str | None = None,
    test_case: TestCase | None = None,
    backend: str = "ollama",
) -> BenchmarkResult:
    """
    Run a quick benchmark with minimal setup.

    Args:
        models: List of model names to test
        finding_text: Optional custom finding text (uses default test case if None)
        test_case: Optional custom test case
        backend: LLM backend ("ollama" or "openai")

    Returns:
        BenchmarkResult
    """
    runner = BenchmarkRunner()

    if test_case:
        test_cases = [test_case]
    elif finding_text:
        # Create a minimal test case for custom finding
        from src.benchmark.testcases import create_test_case

        test_cases = [
            create_test_case(
                id="custom",
                name="Custom Finding",
                finding_text=finding_text,
                primary_techniques=[],  # No ground truth
            )
        ]
    else:
        test_cases = None  # Use default suite

    config = BenchmarkConfig(
        models=models,
        test_cases=test_cases,
        backend=backend,
        save_raw_outputs=False,
    )

    return runner.run(config)
