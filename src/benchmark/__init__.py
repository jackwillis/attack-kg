"""Benchmark module for model evaluation.

This module provides tools for evaluating LLM models on ATT&CK technique
identification and remediation tasks.

Usage:
    # CLI
    uv run attack-kg benchmark --models gpt-oss:20b,gemma3:4b

    # Programmatic
    from src.benchmark import BenchmarkRunner, BenchmarkConfig

    runner = BenchmarkRunner()
    result = runner.run(BenchmarkConfig(models=["gpt-oss:20b", "gemma3:4b"]))
"""

from src.benchmark.reporter import (
    generate_detailed_report,
    generate_markdown_report,
    print_results,
)
from src.benchmark.runner import BenchmarkConfig, BenchmarkResult, BenchmarkRunner, run_quick_benchmark
from src.benchmark.scorer import AutomatedScorer, ModelScore, aggregate_scores
from src.benchmark.testcases import (
    DEFAULT_TEST_SUITE,
    FINDING_03_OWNCLOUD,
    FINDING_04_FORTINET,
    ContextIndicator,
    ExpectedMitigation,
    ExpectedTechnique,
    MitigationPriority,
    TechniqueRelevance,
    TestCase,
    create_test_case,
    load_test_suite,
)

__all__ = [
    # Runner
    "BenchmarkRunner",
    "BenchmarkConfig",
    "BenchmarkResult",
    "run_quick_benchmark",
    # Scorer
    "AutomatedScorer",
    "ModelScore",
    "aggregate_scores",
    # Test cases
    "TestCase",
    "ExpectedTechnique",
    "ExpectedMitigation",
    "TechniqueRelevance",
    "MitigationPriority",
    "ContextIndicator",
    "create_test_case",
    "load_test_suite",
    "DEFAULT_TEST_SUITE",
    "FINDING_03_OWNCLOUD",
    "FINDING_04_FORTINET",
    # Reporter
    "print_results",
    "generate_markdown_report",
    "generate_detailed_report",
]
