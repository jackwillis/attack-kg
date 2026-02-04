"""Two-stage LLM architecture for attack analysis.

Stage 1 (NodeSelector): Selects relevant ATT&CK techniques from candidates
Stage 2 (RemediationWriter): Writes detailed remediation for selected nodes
"""

from src.reasoning.stages.selector import NodeSelector, SelectionResult
from src.reasoning.stages.remediator import RemediationWriter, RemediationResult

__all__ = [
    "NodeSelector",
    "SelectionResult",
    "RemediationWriter",
    "RemediationResult",
]
