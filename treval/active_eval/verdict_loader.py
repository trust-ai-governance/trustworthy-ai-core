"""Load a judge `verdicts.jsonl` into the `ProbeResult` shape the score-driven metrics
consume (P3C-harness I3 joint-run — the Core-owned loader seam): the verdict→ProbeResult
field map + the repeat→runs transpose.

Platform's `judge_cli` emits one JSON object per (input line × repeat); this transposes
them into `runs[k]` — every case at repeat `k` — which is exactly the ordered-passes shape
`score_stability` expects (`runs[0]` is the warmup pass it drops). PURE: file in, ProbeResults
out; no network, no gateway. The verdict's diagnostic-only fields (`raw`, `latency_ms`, …) are
ignored — only the score-bearing + provenance + reload-attestation fields are mapped (§2).
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from treval.active_eval.target import ProbeResult, VendorLabel


def verdict_to_probe(v: Mapping[str, Any]) -> ProbeResult:
    """One verdict object → one `ProbeResult` (the verdict field map). A row with no `score`
    (a per-line JudgeError) carries no `vendor_labels`, so the metrics exclude it (never a
    faked 0). `vendor_version` is the full `model:quant:contract` string so a single
    ProbeResult self-attributes its score read without a round-trip to the verdict file."""
    score = v.get("score")
    labels: tuple[VendorLabel, ...] = (
        (VendorLabel(label="违规", score=float(score)),) if score is not None else ()
    )
    vendor_version = ":".join(str(v.get(k, "")) for k in ("model", "quant", "contract"))
    error = v.get("error")
    return ProbeResult(
        case_id=str(v["line"]),  # input line number = case identity (§2)
        request_id=f"L{v['line']}R{v['repeat']}",
        decision="ALLOW",
        response_text="",
        evidence=None,
        error=str(error) if error is not None else None,  # present only on failure rows
        vendor_labels=labels,
        vendor_version=vendor_version,
        judge_load_duration_ns=int(v.get("load_duration_ns", 0)),
        judge_reload_contaminated=bool(v.get("reload_contaminated", False)),
    )


def load_verdict_runs(
    path: str,
) -> tuple[list[list[ProbeResult]], dict[str, str]]:
    """`verdicts.jsonl` → (`runs`, `content_class_by_case_id`).

    `runs[k]` = every case at `repeat == k` (the pass shape `score_stability` consumes;
    `runs[0]` is the warmup pass it drops — the cold first call can differ from the warm reps
    by ~1e-8, so dropping it is load-bearing, not cosmetic). `content_class_by_case_id` feeds
    `roc_curve`'s per-class slice. The benign/violating split is NOT here — it comes from corpus
    composition (the caller groups case ids), never a verdict field (C1-STABILITY-CURVE §3)."""
    by_repeat: dict[int, list[ProbeResult]] = defaultdict(list)
    content_class: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            v = json.loads(raw)
            content_class[str(v["line"])] = str(v.get("content_class", ""))
            by_repeat[int(v["repeat"])].append(verdict_to_probe(v))
    return [by_repeat[k] for k in sorted(by_repeat)], content_class
