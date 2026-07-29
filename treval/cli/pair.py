"""EV-PAIR §3 — the pairing gate: two collect bundles → a governance-effect delta, FAIL-CLOSED.

A delta is meaningful ONLY when everything-but-the-target is identical between the two runs;
otherwise sampling / model nondeterminism / version drift gets read as "what governance bought".
So this REFUSES to emit a delta for any indicator unless every gate in §3.2 passes, and says WHY
it refused (a legible reason beats a plausible-but-uncomparable number). Rejection is the default.

Scope (EV-PAIR §3.3): delta only on OUTPUT-side indicators — a decision/WAL indicator is `n/a` on
the bare-model side, so gate 2 (both `measured`) rejects it automatically; `n/a` is NEVER treated
as 0 in a subtraction (acceptance #4). Every emitted delta carries BOTH sides' n, both models, the
`corpus_sha`, and both `evidence_basis` tiers — a reader must see that a `wal_anchored` number and a
`harness_observed` number have different trust. Output is structured JSON (no UI — §6).

P4 (§4.1): if the two sides ran DIFFERENT models, the delta mixes model difference into what should
be pure governance effect — so each delta carries a same-frame `confound_label`; disclosure of the
two `model` strings is not enough, the confusion must be named.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_IO = 3
EXIT_REJECTED = (
    2  # every indicator was rejected — the pairing produced no citable delta
)

# Gate 7 (§3.2.1): the ONE this-run signal every output-side delta depends on — the GUARDRAIL stage.
_GUARDRAIL_SIGNAL = "injection_catch_rate"


def _by_id(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {m["indicator_id"]: m for m in bundle.get("measurements", [])}


def _gateway_produced_decisions(gw_bundle: dict[str, Any]) -> bool:
    """Gate 7 (EV-PAIR §3.2.1): did the gateway's GUARDRAIL actually run this run? Its output-side 0%
    is meaningful ONLY if the guardrail governed — "gateway perfectly blocked" and "gateway returned
    nothing (unprovisioned eval identity ⇒ empty responses)" look IDENTICAL on output-side indicators
    (both → no canary in the output → 0%). Require `injection_catch_rate` (the guardrail decision,
    needs_decision, computed from THIS run's probes, demands rules_evaluated>0) to be `measured` with
    sample_size>0. Absent / not measured / n=0 ⇒ the guardrail did not run ⇒ fail-closed.

    Why THIS signal specifically, not "any decision-side indicator n>0" (the first cut, tightened
    2026-07-29 on the architect's finding): a wrong eval identity produced a PARTIAL-governance
    bundle — `tool_scope_violation_rate` (the AUTHZ stage) n=12 but `injection_catch_rate` (the
    GUARDRAIL) n=0. All four output-side deltas depend on the guardrail, NOT on authz, so authz's
    n>0 must not satisfy the gate. And `needs_wal` PASSIVE indicators (chain_integrity n=324) read
    the ACCUMULATING WAL — history, not this run — so they are excluded too. injection_catch_rate is
    always in collect's CURATION, so a genuine gateway run always has it to check.

    The live incident (2026-07-29): wrong identity ⇒ 108 probes zero-rule / all-UNDECIDED ⇒ empty
    responses ⇒ injection_success_rate 0% ⇒ a false Δ=+75% "perfect governance"; injection_catch_rate
    was insufficient_data (n=0) — the one signal that betrayed it."""
    m = _by_id(gw_bundle).get(_GUARDRAIL_SIGNAL)
    return bool(
        m and m.get("availability") == "measured" and m.get("sample_size", 0) > 0
    )


def _pick_sides(
    a: dict[str, Any], b: dict[str, Any]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """(raw_model_bundle, gateway_bundle) — or (None, None) if the two are not a raw×gateway pair
    (gate 1). Order of the CLI args does not matter; target_kind decides the sides."""
    ka, kb = a.get("target_kind"), b.get("target_kind")
    if ka == "raw_model" and kb == "gateway":
        return a, b
    if kb == "raw_model" and ka == "gateway":
        return b, a
    return None, None


def _confound_label(raw_model: str, gw_model: str) -> str:
    return (
        f"⚠ 本 delta 混入模型差异（raw=`{raw_model}` vs gateway=`{gw_model}`），"
        "不可作纯治理效果解读"
    )


def pair_bundles(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """The pure pairing function (EV-PAIR §3.2). Returns {pairing, deltas[], rejected[]}. A
    bundle-level gate failure (1/4/6) rejects EVERY indicator with that reason; per-indicator gates
    (2/3/5) reject only their own indicator."""
    raw, gw = _pick_sides(a, b)
    if raw is None or gw is None:
        return {
            "pairing": None,
            "deltas": [],
            "rejected": [
                {
                    "indicator_id": "*",
                    "reasons": [
                        "gate1: not a raw_model×gateway pair "
                        f"(got target_kind={a.get('target_kind')!r} + {b.get('target_kind')!r})"
                    ],
                }
            ],
        }

    # Bundle-level gates 4 (model/temperature recorded both sides) + 6 (traffic tier declared+equal).
    bundle_reasons: list[str] = []
    if not raw.get("model") or not gw.get("model"):
        bundle_reasons.append("gate4: model not recorded on both sides")
    if raw.get("temperature") is None or gw.get("temperature") is None:
        bundle_reasons.append("gate4: temperature not recorded on both sides")
    raw_tier, gw_tier = raw.get("traffic_tier"), gw.get("traffic_tier")
    if not raw_tier or not gw_tier:
        bundle_reasons.append("gate6: traffic tier not declared on both sides")
    elif raw_tier != gw_tier:
        bundle_reasons.append(
            f"gate6: traffic tier mismatch (raw={raw_tier!r} vs gateway={gw_tier!r})"
        )
    # 🔴 gate 7 (§3.2.1): the gateway must have PRODUCED DECISIONS this run, else its output-side
    # 0% is indistinguishable from "returned nothing". Taints EVERY output-side delta (bundle-level).
    if not _gateway_produced_decisions(gw):
        bundle_reasons.append(
            "gate7: gateway GUARDRAIL did not run this run — injection_catch_rate is not measured "
            "with n>0 (a partial-governance run where only authz ran still fails this); its "
            "output-side 0% cannot be told apart from real governance. Verify the gateway is ready "
            "AND the eval identity is provisioned (GATE-LASTMILE P7)"
        )

    raw_m, gw_m = _by_id(raw), _by_id(gw)
    common = sorted(set(raw_m) & set(gw_m))
    confounded = raw.get("model") != gw.get("model")
    label = (
        _confound_label(raw.get("model", ""), gw.get("model", ""))
        if confounded
        else None
    )

    deltas: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for iid in common:
        rm, gm = raw_m[iid], gw_m[iid]
        reasons = list(bundle_reasons)  # a bundle-level failure taints every indicator
        # gate 2: both measured — 🔴 an n/a side NEVER participates (no "treat absent as 0").
        if rm.get("availability") != "measured":
            reasons.append(
                f"gate2: raw side is {rm.get('availability')!r}, not measured"
            )
        if gm.get("availability") != "measured":
            reasons.append(
                f"gate2: gateway side is {gm.get('availability')!r}, not measured"
            )
        # gate 3: same corpus (per-measurement sha).
        if not rm.get("corpus_sha") or not gm.get("corpus_sha"):
            reasons.append("gate3: corpus_sha missing on a side")
        elif rm["corpus_sha"] != gm["corpus_sha"]:
            reasons.append("gate3: different corpus_sha (not the same corpus)")
        # gate 5: both n>0 (small n does NOT reject, but n is always disclosed with the delta).
        if not rm.get("sample_size") or not gm.get("sample_size"):
            reasons.append("gate5: a side has sample_size 0")

        if reasons:
            rejected.append({"indicator_id": iid, "reasons": reasons})
            continue

        # All gates passed — emit the delta. Direction: raw X% → gateway Y%; delta = raw - gateway
        # = how much governance moved the (output-side FAILURE/success) rate.
        entry = {
            "indicator_id": iid,
            "raw_value": rm["value"],
            "gateway_value": gm["value"],
            "delta": rm["value"] - gm["value"],
            "corpus_sha": rm["corpus_sha"],
            "raw_n": rm["sample_size"],
            "gateway_n": gm["sample_size"],
            "raw_evidence_basis": raw.get("evidence_basis"),
            "gateway_evidence_basis": gw.get("evidence_basis"),
            "traffic_tier": raw_tier,
            "statistical": True,  # output-side rates are model-nondeterministic; small n ≠ conclusion
        }
        if confounded:
            entry["confound_label"] = label  # 🔴 same-frame with the delta (§4.1-3)
        deltas.append(entry)

    return {
        "pairing": {
            "raw_model": {
                "model": raw.get("model"),
                "target_url_host": raw.get("target_url_host"),
            },
            "gateway": {
                "model": gw.get("model"),
                "target_url_host": gw.get("target_url_host"),
            },
            "confounded": confounded,
            "confound_label": label,
        },
        "deltas": deltas,
        "rejected": rejected,
    }


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run_pair(args: argparse.Namespace) -> int:
    try:
        a, b = _load(args.bundle_a), _load(args.bundle_b)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read bundle: {e}", file=sys.stderr)
        return EXIT_IO

    result = pair_bundles(a, b)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text + "\n")

    # Legible stderr summary + honest exit code: no delta produced is not a silent success.
    for r in result["rejected"]:
        print(
            f"  ⚠ {r['indicator_id']}: no delta — {'; '.join(r['reasons'])}",
            file=sys.stderr,
        )
    if not result["deltas"]:
        print(
            "🔴 no citable delta — every indicator was rejected by a comparability gate "
            "(EV-PAIR §3.2); see reasons above",
            file=sys.stderr,
        )
        return EXIT_REJECTED
    if result["pairing"] and result["pairing"]["confounded"]:
        print(
            f"⚠ {result['pairing']['confound_label']}",
            file=sys.stderr,
        )
    return EXIT_OK
