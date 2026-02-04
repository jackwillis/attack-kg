"""Automated scoring for model benchmark results.

Scoring criteria based on model-comparison-reports/GRADING_PROMPT.md:
1. JSON_COMPLIANCE (0-10 pts)
2. TECHNIQUE_ACCURACY (0-30 pts)
3. REMEDIATION_QUALITY (0-25 pts)
4. DETECTION_QUALITY (0-15 pts)
5. CONTEXT_AWARENESS (0-10 pts)
6. SPEED_FACTOR (0-10 pts)
"""

from dataclasses import dataclass, field
from typing import Any

from src.benchmark.testcases import TestCase


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of scoring for each category."""

    # JSON compliance
    json_parsed: bool = False
    json_partial: bool = False

    # Technique accuracy
    primary_found: list[str] = field(default_factory=list)
    secondary_found: list[str] = field(default_factory=list)
    acceptable_found: list[str] = field(default_factory=list)
    subtechnique_bonus: list[str] = field(default_factory=list)
    parent_bonus: list[str] = field(default_factory=list)  # Parent when subtechnique expected
    hallucinations: list[str] = field(default_factory=list)

    # Remediation quality
    critical_mitigations_found: list[str] = field(default_factory=list)
    high_mitigations_found: list[str] = field(default_factory=list)
    medium_mitigations_found: list[str] = field(default_factory=list)
    other_mitigations: list[str] = field(default_factory=list)
    context_specific_guidance: bool = False
    irrelevant_mitigations: list[str] = field(default_factory=list)

    # Detection quality
    specific_log_sources: list[str] = field(default_factory=list)
    generic_log_sources: list[str] = field(default_factory=list)
    product_specific_detection: bool = False

    # Context awareness
    mentions_technology: bool = False
    specific_commands: bool = False
    coherent_kill_chain: bool = False
    no_platform_mismatch: bool = True


@dataclass
class ModelScore:
    """Complete score for a model on a test case."""

    model: str
    test_case_id: str
    json_compliance: int = 0  # 0-10
    technique_accuracy: int = 0  # 0-30
    remediation_quality: int = 0  # 0-25
    detection_quality: int = 0  # 0-15
    context_awareness: int = 0  # 0-10
    speed_factor: int = 0  # 0-10
    runtime_seconds: float = 0.0
    breakdown: ScoreBreakdown = field(default_factory=ScoreBreakdown)
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            self.json_compliance
            + self.technique_accuracy
            + self.remediation_quality
            + self.detection_quality
            + self.context_awareness
            + self.speed_factor
        )

    @property
    def max_possible(self) -> int:
        return 100

    @property
    def percentage(self) -> float:
        return (self.total / self.max_possible) * 100

    def grade(self) -> str:
        pct = self.percentage
        if pct >= 90:
            return "A+"
        elif pct >= 85:
            return "A"
        elif pct >= 80:
            return "A-"
        elif pct >= 75:
            return "B+"
        elif pct >= 70:
            return "B"
        elif pct >= 65:
            return "B-"
        elif pct >= 60:
            return "C+"
        elif pct >= 55:
            return "C"
        elif pct >= 50:
            return "C-"
        elif pct >= 45:
            return "D+"
        elif pct >= 40:
            return "D"
        else:
            return "F"


class AutomatedScorer:
    """Scores model outputs against test case ground truth."""

    def __init__(self):
        # Common hallucination indicators
        self.common_hallucinations = [
            "password spraying",  # Unless explicitly in finding
            "phishing",
            "malware",
        ]

    def score(
        self,
        model: str,
        test_case: TestCase,
        result: dict[str, Any],
        runtime_seconds: float,
    ) -> ModelScore:
        """
        Score a model's output against the test case ground truth.

        Args:
            model: Model name
            test_case: The test case with ground truth
            result: The parsed analysis result (from AttackAnalyzer)
            runtime_seconds: How long the analysis took

        Returns:
            ModelScore with detailed breakdown
        """
        score = ModelScore(model=model, test_case_id=test_case.id, runtime_seconds=runtime_seconds)

        # Score each category
        self._score_json_compliance(score, result)
        self._score_technique_accuracy(score, test_case, result)
        self._score_remediation_quality(score, test_case, result)
        self._score_detection_quality(score, test_case, result)
        self._score_context_awareness(score, test_case, result)
        self._score_speed_factor(score, runtime_seconds)

        return score

    def _score_json_compliance(self, score: ModelScore, result: dict[str, Any]) -> None:
        """Score JSON parsing success (0-10 pts)."""
        if "error" in result:
            # Complete parse failure
            score.json_compliance = 0
            score.breakdown.json_parsed = False
            score.notes.append("JSON parse failure")
        elif not result.get("techniques") and not result.get("remediations"):
            # Partial parse - empty result
            score.json_compliance = 5
            score.breakdown.json_partial = True
            score.notes.append("JSON parsed but empty result")
        else:
            # Successful parse
            score.json_compliance = 10
            score.breakdown.json_parsed = True

    def _score_technique_accuracy(self, score: ModelScore, test_case: TestCase, result: dict[str, Any]) -> None:
        """Score technique identification accuracy (0-30 pts)."""
        points = 0
        techniques = result.get("techniques", [])
        found_ids = {t.get("attack_id", "") for t in techniques}

        primary = set(test_case.get_primary_techniques())
        secondary = set(test_case.get_secondary_techniques())
        acceptable = set(test_case.get_acceptable_techniques())
        ideal_sub = set(test_case.get_ideal_subtechniques())
        parent_map = test_case.get_parent_techniques()

        # All expected technique IDs (any tier)
        all_expected = primary | secondary | acceptable | ideal_sub
        # Add parent IDs as "partial credit" options
        all_expected_with_parents = all_expected | set(parent_map.values())

        for tid in found_ids:
            if not tid:
                continue

            if tid in primary:
                points += 10
                score.breakdown.primary_found.append(tid)
            elif tid in secondary:
                points += 5
                score.breakdown.secondary_found.append(tid)
            elif tid in acceptable:
                points += 3
                score.breakdown.acceptable_found.append(tid)
            elif tid in ideal_sub:
                # Ideal subtechnique bonus (+5 on top of parent credit)
                points += 8
                score.breakdown.subtechnique_bonus.append(tid)
                score.notes.append(f"Found ideal subtechnique {tid} (+5 bonus)")
            elif tid in parent_map.values():
                # Found parent when subtechnique expected (+2)
                points += 2
                score.breakdown.parent_bonus.append(tid)
            elif self._is_related_technique(tid, all_expected_with_parents):
                # Related technique (same parent family) - no points but not a hallucination
                pass
            else:
                # Potential hallucination - check if it's truly irrelevant
                if self._is_hallucination(tid, test_case):
                    points -= 3
                    score.breakdown.hallucinations.append(tid)
                    score.notes.append(f"Hallucination: {tid}")

        # Bonus for finding ideal subtechnique (additional +5)
        if score.breakdown.subtechnique_bonus:
            points += 5
            score.notes.append("Subtechnique bonus applied")

        score.technique_accuracy = min(30, max(0, points))

    def _score_remediation_quality(self, score: ModelScore, test_case: TestCase, result: dict[str, Any]) -> None:
        """Score remediation quality (0-25 pts)."""
        points = 0
        remediations = result.get("remediations", [])
        found_ids = set()

        critical = set(test_case.get_critical_mitigations())
        high = set(test_case.get_high_mitigations())
        medium = set(test_case.get_medium_mitigations())

        for rem in remediations:
            mid = rem.get("mitigation_id", "")
            implementation = rem.get("implementation", "")
            if not mid:
                continue

            found_ids.add(mid)

            if mid in critical:
                points += 5
                score.breakdown.critical_mitigations_found.append(mid)
            elif mid in high:
                points += 3
                score.breakdown.high_mitigations_found.append(mid)
            elif mid in medium:
                points += 2
                score.breakdown.medium_mitigations_found.append(mid)
            else:
                points += 1  # Generic but potentially useful
                score.breakdown.other_mitigations.append(mid)

            # Check for irrelevant recommendations
            if self._has_invalid_context(implementation, test_case):
                points -= 2
                score.breakdown.irrelevant_mitigations.append(mid)
                score.notes.append(f"Irrelevant mitigation context: {mid}")

        # Bonus for context-specific implementation guidance (+5)
        if self._has_product_specific_guidance(remediations, test_case):
            points += 5
            score.breakdown.context_specific_guidance = True
            score.notes.append("Context-specific implementation guidance")

        score.remediation_quality = min(25, max(0, points))

    def _score_detection_quality(self, score: ModelScore, test_case: TestCase, result: dict[str, Any]) -> None:
        """Score detection recommendations (0-15 pts)."""
        points = 0
        detections = result.get("detection_recommendations", [])

        specific_sources = [
            "authentication logs",
            "web server logs",
            "network traffic",
            "process monitoring",
            "file monitoring",
            "command-line logging",
            "api logs",
        ]
        generic_sources = ["logs", "monitoring", "alerting"]

        for det in detections:
            source = det.get("data_source", "").lower()
            rationale = det.get("rationale", "").lower()

            # Check for specific log sources
            is_specific = any(s in source for s in specific_sources)
            is_generic = any(s in source for s in generic_sources) and not is_specific

            if is_specific:
                points += 3
                score.breakdown.specific_log_sources.append(det.get("data_source", ""))
            elif is_generic:
                points += 1
                score.breakdown.generic_log_sources.append(det.get("data_source", ""))

        # Bonus for product-specific detection sources (+3)
        all_detection_text = " ".join(d.get("data_source", "") + " " + d.get("rationale", "") for d in detections).lower()
        if any(p.lower() in all_detection_text for p in test_case.context.products):
            points += 3
            score.breakdown.product_specific_detection = True
            score.notes.append("Product-specific detection sources")

        score.detection_quality = min(15, max(0, points))

    def _score_context_awareness(self, score: ModelScore, test_case: TestCase, result: dict[str, Any]) -> None:
        """Score context awareness (0-10 pts)."""
        points = 0

        # Collect all text from remediations and detections
        all_text = ""
        for rem in result.get("remediations", []):
            all_text += " " + rem.get("implementation", "")
        for det in result.get("detection_recommendations", []):
            all_text += " " + det.get("rationale", "")
        all_text = all_text.lower()

        # Check if mentions specific technology (+3)
        if any(p.lower() in all_text for p in test_case.context.products):
            points += 3
            score.breakdown.mentions_technology = True

        # Check for specific commands/config (+3)
        command_indicators = ["configure", "enable", "disable", "set", "command", "cli", "admin", "settings"]
        if any(c in all_text for c in command_indicators):
            points += 3
            score.breakdown.specific_commands = True

        # Check kill chain coherence (+2)
        kill_chain = result.get("kill_chain_analysis", "")
        if kill_chain and len(kill_chain) > 50:  # Non-trivial analysis
            points += 2
            score.breakdown.coherent_kill_chain = True

        # Check for platform mismatches (+2 if no mismatches)
        if not self._has_invalid_context(all_text, test_case):
            points += 2
            score.breakdown.no_platform_mismatch = True
        else:
            score.breakdown.no_platform_mismatch = False
            score.notes.append("Platform mismatch detected")

        score.context_awareness = min(10, max(0, points))

    def _score_speed_factor(self, score: ModelScore, runtime_seconds: float) -> None:
        """Score based on runtime (0-10 pts)."""
        if runtime_seconds <= 60:
            score.speed_factor = 10
        elif runtime_seconds <= 90:
            score.speed_factor = 8
        elif runtime_seconds <= 120:
            score.speed_factor = 6
        elif runtime_seconds <= 180:
            score.speed_factor = 4
        elif runtime_seconds <= 300:
            score.speed_factor = 2
        else:
            score.speed_factor = 0
            score.notes.append(f"Slow runtime: {runtime_seconds:.0f}s")

    def _is_related_technique(self, tid: str, expected: set[str]) -> bool:
        """Check if technique is in the same family as expected techniques."""
        # Extract parent ID (e.g., T1110.003 -> T1110)
        if "." in tid:
            parent = tid.split(".")[0]
            return parent in expected or any(e.startswith(parent) for e in expected)
        return False

    def _is_hallucination(self, tid: str, test_case: TestCase) -> bool:
        """Check if a technique is a hallucination (not related to finding)."""
        # For now, any technique not in expected or related families is a hallucination
        # This is a simple heuristic - could be improved with semantic similarity
        all_expected = (
            set(test_case.get_primary_techniques())
            | set(test_case.get_secondary_techniques())
            | set(test_case.get_acceptable_techniques())
            | set(test_case.get_ideal_subtechniques())
        )

        # Check if it's in the same family
        if self._is_related_technique(tid, all_expected):
            return False

        # Check if parent of expected subtechnique
        for sub in test_case.get_ideal_subtechniques():
            if sub.startswith(tid):
                return False

        return True

    def _has_invalid_context(self, text: str, test_case: TestCase) -> bool:
        """Check if text contains recommendations for wrong platform."""
        text_lower = text.lower()
        for invalid in test_case.context.invalid_recommendations:
            if invalid.lower() in text_lower:
                return True
        return False

    def _has_product_specific_guidance(self, remediations: list[dict], test_case: TestCase) -> bool:
        """Check if remediations mention product-specific guidance."""
        all_text = " ".join(r.get("implementation", "") for r in remediations).lower()
        return any(p.lower() in all_text for p in test_case.context.products)


def aggregate_scores(scores: list[ModelScore]) -> dict[str, Any]:
    """Aggregate scores across multiple test cases for a model."""
    if not scores:
        return {}

    model = scores[0].model
    total_json = sum(s.json_compliance for s in scores)
    total_tech = sum(s.technique_accuracy for s in scores)
    total_rem = sum(s.remediation_quality for s in scores)
    total_det = sum(s.detection_quality for s in scores)
    total_ctx = sum(s.context_awareness for s in scores)
    total_spd = sum(s.speed_factor for s in scores)
    n = len(scores)

    return {
        "model": model,
        "test_cases": n,
        "avg_json_compliance": total_json / n,
        "avg_technique_accuracy": total_tech / n,
        "avg_remediation_quality": total_rem / n,
        "avg_detection_quality": total_det / n,
        "avg_context_awareness": total_ctx / n,
        "avg_speed_factor": total_spd / n,
        "avg_total": sum(s.total for s in scores) / n,
        "avg_percentage": sum(s.percentage for s in scores) / n,
        "total_runtime": sum(s.runtime_seconds for s in scores),
        "scores": scores,
    }
