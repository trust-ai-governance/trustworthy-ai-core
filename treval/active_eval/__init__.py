"""Active-eval harness (EV-AE0) — generate governed evidence, then measure it.

Drives an adversarial corpus through a Target (the real gateway) and measures
efficacy (caught / total) as an EV-0 Measurement the rubric consumes. Imported
explicitly (`from treval.active_eval import ...`); not pulled in by `import
treval`. GatewayTarget needs httpx (lazy import; install requirements-eval.txt).
"""

from __future__ import annotations

from treval.active_eval.checks import (
    KNOWN_SUCCESS_TOKENS,
    SuccessWhenError,
    evaluate,
    injection_succeeded,
    is_sensitive_disclosed,
    scope_enforced,
    sensitive_disclosed,
)
from treval.active_eval.corpus import CorpusCase, CorpusError, load_corpus
from treval.active_eval.indicators import (
    CanaryLeakRate,
    CorpusIndicator,
    FalsePositiveRate,
    InjectionCatchRate,
    InjectionSuccessRate,
    SensitiveDisclosureRate,
    SystemPromptLeakRate,
    ToolScopeViolationRate,
    UnsafeOutputPassthroughRate,
)
from treval.active_eval.perturb import (
    PERTURBATIONS,
    perturb_case,
    perturb_corpus,
)
from treval.active_eval.reporting import (
    attack_class_breakdown,
    format_attribution_report,
    format_variant_report,
    rule_robustness,
    write_evading_seed,
)
from treval.active_eval.runner import run_corpus
from treval.active_eval.target import GatewayTarget, ProbeResult, Target

__all__ = [
    "CorpusCase",
    "CorpusError",
    "load_corpus",
    "KNOWN_SUCCESS_TOKENS",
    "SuccessWhenError",
    "evaluate",
    "injection_succeeded",
    "is_sensitive_disclosed",
    "sensitive_disclosed",
    "scope_enforced",
    "ProbeResult",
    "Target",
    "GatewayTarget",
    "run_corpus",
    "CorpusIndicator",
    "InjectionCatchRate",
    "InjectionSuccessRate",
    "CanaryLeakRate",
    "SensitiveDisclosureRate",
    "SystemPromptLeakRate",
    "UnsafeOutputPassthroughRate",
    "ToolScopeViolationRate",
    "FalsePositiveRate",
    "attack_class_breakdown",
    "format_attribution_report",
    # EV-AE7 — adversarial variants + rule-robustness diagnostic
    "PERTURBATIONS",
    "perturb_case",
    "perturb_corpus",
    "rule_robustness",
    "write_evading_seed",
    "format_variant_report",
]
