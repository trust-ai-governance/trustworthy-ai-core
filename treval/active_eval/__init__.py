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
    caught_by_tier2,
    evaluate,
    injection_score,
    injection_succeeded,
    is_sensitive_disclosed,
    scope_enforced,
    sensitive_disclosed,
)
from treval.active_eval.corpus import (
    ContentPart,
    CorpusCase,
    CorpusError,
    WireMessage,
    load_corpus,
)
from treval.active_eval.indicators import (
    BenignFlagRate,
    BenignShadowFlagRate,
    CanaryLeakRate,
    CorpusIndicator,
    CostRunawayCaught,
    FalsePositiveRate,
    InjectionCatchRate,
    InjectionSuccessRate,
    OutputNeutralizeFidelityRate,
    OutputNeutralizeInertRate,
    SensitiveDisclosureRate,
    SystemPromptLeakRate,
    Tier2ShadowRecallLift,
    ToolScopeViolationRate,
    UnsafeOutputPassthroughRate,
    WireIndirectCatchRate,
    WithinCostBudget,
)
from treval.active_eval.perturb import (
    PERTURBATIONS,
    perturb_case,
    perturb_corpus,
)
from treval.active_eval.reporting import (
    attack_class_breakdown,
    false_positive_by_content_class,
    format_attribution_report,
    format_variant_report,
    rule_robustness,
    write_evading_seed,
)
from treval.active_eval.runner import run_corpus
from treval.active_eval.score_metrics import (
    CaseStability,
    CurveReport,
    StabilityReport,
    first_vendor_label_score,
    normalization_attested,
    roc_curve,
    score_stability,
    two_way_normalized,
)
from treval.active_eval.target import GatewayTarget, ProbeResult, Target, VendorLabel
from treval.active_eval.verdict_loader import load_verdict_runs, verdict_to_probe

__all__ = [
    "CorpusCase",
    "WireMessage",
    "ContentPart",
    "CorpusError",
    "load_corpus",
    "KNOWN_SUCCESS_TOKENS",
    "SuccessWhenError",
    "evaluate",
    "caught_by_tier2",
    "injection_score",
    "injection_succeeded",
    "is_sensitive_disclosed",
    "sensitive_disclosed",
    "scope_enforced",
    "ProbeResult",
    "Target",
    "GatewayTarget",
    "run_corpus",
    # P3C-harness C1-STABILITY-CURVE — score-driven spike metrics (bearer seam + stability + curve)
    "VendorLabel",
    "StabilityReport",
    "CaseStability",
    "score_stability",
    "first_vendor_label_score",
    "CurveReport",
    "roc_curve",
    "two_way_normalized",
    "normalization_attested",
    # C1-STABILITY-CURVE 提交 C — verdicts.jsonl → ProbeResult loader (I3 joint-run seam)
    "load_verdict_runs",
    "verdict_to_probe",
    "CorpusIndicator",
    "InjectionCatchRate",
    "InjectionSuccessRate",
    "CanaryLeakRate",
    "SensitiveDisclosureRate",
    "SystemPromptLeakRate",
    "UnsafeOutputPassthroughRate",
    "ToolScopeViolationRate",
    "FalsePositiveRate",
    "BenignFlagRate",
    "CostRunawayCaught",
    "WithinCostBudget",
    "WireIndirectCatchRate",
    # EV-AE13 — output-neutralize efficacy (inert ∧ fidelity, declared HTML sink)
    "OutputNeutralizeInertRate",
    "OutputNeutralizeFidelityRate",
    # EV-AE12 — async Tier-2 shadow-judge recall lift + benign shadow-flag
    "Tier2ShadowRecallLift",
    "BenignShadowFlagRate",
    "attack_class_breakdown",
    # P3C-harness C3-2 — per-content_class FPR slice (honest-absence 3-tuple)
    "false_positive_by_content_class",
    "format_attribution_report",
    # EV-AE7 — adversarial variants + rule-robustness diagnostic
    "PERTURBATIONS",
    "perturb_case",
    "perturb_corpus",
    "rule_robustness",
    "write_evading_seed",
    "format_variant_report",
]
