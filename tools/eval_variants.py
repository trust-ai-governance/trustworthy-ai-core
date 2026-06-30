"""LLM01 Tier-1 rule-robustness + Tier-2 seed (OPERATOR CLI, EV-AE7).

Drives the base LLM01 corpus, perturbs the CAUGHT cases with deterministic,
render-identical / canonicalization-defeatable obfuscations (case-flip, zero-width,
punctuate, homoglyph), re-drives the variants, and reports rule-robustness: the fraction
of caught attacks whose obfuscated variants are STILL caught. A big drop ⇒ Tier-1 matched
the literal phrasing, not the technique (overfit). The variants that EVADE (caught at
base, missed when perturbed) are the Tier-2 seed handed to Platform.

Requires P2-a Tier-1 live (merged) — with no rule, base catch ≈0 and there is nothing to
perturb. Determinism: re-running yields identical robustness (catch is rule-on-input).

SECURITY: the robustness report + evading seed are a working-bypass set for the DEPLOYED
gateway — INTERNAL Platform artifacts under the gitignored `reports/`; do NOT commit. The
generator code here is generic measurement (safe to commit); only its OUTPUT is sensitive.

Usage (same env as the integration test):
  TREVAL_EVAL_GATEWAY_URL=http://127.0.0.1:8080 TREVAL_EVAL_WAL_DIR=/home/olvan/wal \\
  TREVAL_EVAL_TENANT=__eval__ TREVAL_EVAL_USER=jack TREVAL_EVAL_TIMEOUT=120 \\
    python tools/eval_variants.py
  python tools/eval_variants.py --out reports/run2.md --seed reports/run2.jsonl
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from treval.active_eval import (
    GatewayTarget,
    evaluate,
    format_variant_report,
    load_corpus,
    perturb_corpus,
    rule_robustness,
    run_corpus,
    write_evading_seed,
)

_ROOT = Path(__file__).resolve().parents[1]
_LLM01 = _ROOT / "corpus" / "llm01_prompt_injection"


def _target() -> GatewayTarget:
    url = os.environ.get("TREVAL_EVAL_GATEWAY_URL")
    if not url:
        sys.exit(
            "set TREVAL_EVAL_GATEWAY_URL (+ TREVAL_EVAL_WAL_DIR) — see the docstring"
        )
    return GatewayTarget(
        url,
        wal_dir=os.environ.get("TREVAL_EVAL_WAL_DIR"),
        tenant_id=os.environ.get("TREVAL_EVAL_TENANT", "__eval__"),
        user_id=os.environ.get("TREVAL_EVAL_USER", "eval-user"),
        model=os.environ.get("TREVAL_EVAL_MODEL", "deepseek-v4-flash"),
        timeout=float(os.environ.get("TREVAL_EVAL_TIMEOUT", "120")),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LLM01 Tier-1 rule-robustness + Tier-2 seed"
    )
    parser.add_argument("--out", default=str(_ROOT / "reports" / "llm01_variants.md"))
    parser.add_argument(
        "--seed", default=str(_ROOT / "reports" / "llm01_variants_seed.jsonl")
    )
    args = parser.parse_args()

    target = _target()

    base = load_corpus(_LLM01)
    base_results = run_corpus(base, target)
    caught_ids = {
        r.case_id
        for r in base_results
        if r.evidence is not None and evaluate("blocked_or_flagged", r)
    }
    caught = [c for c in base if c.id in caught_ids]
    print(f"base: {len(base)} probes, {len(caught)} caught — perturbing the caught set")
    if not caught:
        sys.exit("nothing caught at base — is the P2-a Tier-1 injection ruleset live?")

    variants = perturb_corpus(caught)
    variant_results = run_corpus(variants, target)
    stats = rule_robustness(base, base_results, variants, variant_results)

    report = format_variant_report(stats)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    write_evading_seed(stats["evading"], args.seed)

    print(report)
    print(f"wrote {out}  +  {args.seed} ({len(stats['evading'])} evading variants)")


if __name__ == "__main__":
    main()
