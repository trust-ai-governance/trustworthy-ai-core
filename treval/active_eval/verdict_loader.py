"""Load a judge `verdicts.jsonl` into the `ProbeResult` shape the score-driven metrics
consume (P3C-harness I3 joint-run — the Core-owned loader seam): the verdict→ProbeResult
field map + the repeat→runs transpose.

Platform's `judge_cli` emits one JSON object per (input line × repeat); this transposes
them into `runs[k]` — every case at repeat `k` — which is exactly the ordered-passes shape
`score_stability` expects (`runs[0]` is the warmup pass it drops). PURE: file in, ProbeResults
out; no network, no gateway. The verdict's diagnostic-only fields (`raw`, `latency_ms`, …) are
ignored — only the score-bearing + provenance + reload-attestation fields are mapped.

Two intake shapes (I3-MULTIFILE-INTAKE §2):
  * `load_verdict_runs(path)`      — one mixed file; the caller splits by line id (smoke).
  * `load_verdict_groups({group: path})` — one file per group (violating / benign /
    benign_meta), the real-corpus shape: benign-vs-violating rides FILE MEMBERSHIP, and case
    ids are namespaced `{group}:{line}` so the same line number in two files cannot collide.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from treval.active_eval.target import ProbeResult, VendorLabel

# Which side of the two-sided curve each verdict group feeds. `benign_meta` (the benign-meta
# controls) is still the BENIGN/FPR side — an over-refusal there is a false positive like any
# other. Unknown group names are rejected rather than defaulted: a typo must not silently drop
# a whole file out of one side of the gate.
_SIDE_OF_GROUP = {
    "violating": "violating",
    "benign": "benign",
    "benign_meta": "benign",
}


class VerdictError(Exception):
    """A verdict file is unusable — malformed row, unknown group, more than one `contract`
    under one case, or a repeat numbering that would make the warmup drop non-uniform. Loud,
    never silent: each of these would otherwise surface as FAKE non-determinism (§2.1)."""


def verdict_to_probe(v: Mapping[str, Any], *, group: str = "") -> ProbeResult:
    """One verdict object → one `ProbeResult` (the verdict field map). A row with no `score`
    (a per-line JudgeError) carries no `vendor_labels`, so the metrics exclude it (never a
    faked 0). `vendor_version` is the full `model:quant:contract` string so a single
    ProbeResult self-attributes its score read without a round-trip to the verdict file.

    `group` namespaces the case id (`{group}:{line}`) for the multi-file intake; empty keeps
    the bare line id of the single-file form. The FIELD MAP itself is identical either way."""
    score = v.get("score")
    labels: tuple[VendorLabel, ...] = (
        (VendorLabel(label="违规", score=float(score)),) if score is not None else ()
    )
    vendor_version = ":".join(str(v.get(k, "")) for k in ("model", "quant", "contract"))
    error = v.get("error")
    line = v["line"]
    case_id = f"{group}:{line}" if group else str(line)
    return ProbeResult(
        case_id=case_id,  # input line number (group-namespaced) = case identity
        request_id=f"{case_id}R{v['repeat']}",
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


def _rows(path: str) -> list[tuple[int, dict[str, Any]]]:
    """Every non-blank JSONL row of `path` as `(file_line_no, object)`. Fail-closed: a
    malformed row raises rather than being skipped — a silently dropped verdict would
    understate the sample without anyone noticing."""
    out: list[tuple[int, dict[str, Any]]] = []
    try:
        with open(path, encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError as e:
                    raise VerdictError(f"{path}:{lineno}: not valid JSON: {e}") from e
                if not isinstance(obj, dict):
                    raise VerdictError(f"{path}:{lineno}: row must be a JSON object")
                for key in ("line", "repeat"):
                    if key not in obj:
                        raise VerdictError(f"{path}:{lineno}: missing {key!r}")
                out.append((lineno, obj))
    except OSError as e:
        raise VerdictError(f"cannot read verdict file {path}: {e}") from e
    return out


def load_verdict_groups(
    files_by_group: Mapping[str, str],
) -> tuple[list[list[ProbeResult]], dict[str, list[str]], dict[str, str]]:
    """One verdict file per group → `(runs, side_case_ids, content_class_by_case_id)`.

    The real-corpus intake: benign-vs-violating is FILE MEMBERSHIP, never a verdict field, so
    the caller passes `{"violating": path, "benign": path, "benign_meta": path}` (meta optional).

    * `runs[k]` = every case at the k-th repeat, transposed ACROSS ALL GROUPS. This is the same
      pass shape `score_stability` consumes, so its `runs[0]` drop still removes each case's
      COLD first call — the transpose is load-bearing and must not be flattened away.
    * `side_case_ids` = `{"benign": [...], "violating": [...]}` — benign is the UNION of the
      benign and benign_meta groups — the two-sided split `roc_curve` takes.
    * `content_class_by_case_id` feeds the per-class slice.

    Fail-loud (never fake non-determinism, §2.1):
    * more than one `contract` under one case id ⇒ `VerdictError`. Mixing two contracts puts a
      case's repeats across two distributions ⇒ `span>0` ⇒ the whole run reads as
      non-deterministic and the curve is silently gated off. Load one contract at a time.
    * groups whose repeat numbering STARTS at different values ⇒ `VerdictError`. The drop is by
      POSITION (`runs[0]` = the lowest repeat present), so a group starting at 1 while another
      starts at 0 would keep its own cold pass while the other's is dropped — a non-uniform
      warmup drop that also surfaces as fake non-determinism. Differing repeat COUNTS are fine.
    """
    by_repeat: dict[int, list[ProbeResult]] = defaultdict(list)
    side_case_ids: dict[str, list[str]] = {"benign": [], "violating": []}
    content_class: dict[str, str] = {}
    contract_by_case: dict[str, str] = {}
    contract_by_group: dict[str, set[str]] = defaultdict(set)
    min_repeat_by_group: dict[str, int] = {}

    for group, path in files_by_group.items():
        side = _SIDE_OF_GROUP.get(group)
        if side is None:
            raise VerdictError(
                f"unknown verdict group {group!r}; expected one of "
                f"{sorted(_SIDE_OF_GROUP)}"
            )
        seen: set[str] = set()
        repeats: list[int] = []
        for lineno, v in _rows(path):
            case_id = f"{group}:{v['line']}"
            contract = str(v.get("contract", ""))
            known = contract_by_case.setdefault(case_id, contract)
            if known != contract:
                raise VerdictError(
                    f"{path}:{lineno}: case {case_id!r} carries more than one contract "
                    f"({known!r} and {contract!r}). Load ONE contract per run — mixing them "
                    "spreads a case's repeats across two distributions and reads as fake "
                    "non-determinism (§2.1)."
                )
            contract_by_group[group].add(contract)
            if case_id not in seen:
                seen.add(case_id)
                side_case_ids[side].append(case_id)
            content_class[case_id] = str(v.get("content_class", ""))
            repeat = int(v["repeat"])
            repeats.append(repeat)
            by_repeat[repeat].append(verdict_to_probe(v, group=group))
        if repeats:
            min_repeat_by_group[group] = min(repeats)

    # ONE contract per load — the check is LOAD-level, not per case: two groups can each be
    # internally consistent yet carry different contracts (e.g. a violate-contract violating
    # file paired with a safe-contract meta file, whose filenames differ by one word). That
    # pairs a recall measured on one scale with an FPR measured on another — the curve looks
    # perfectly normal and means nothing. The D3 fork is TWO separate loads, never one.
    all_contracts = {c for cs in contract_by_group.values() for c in cs}
    if len(all_contracts) > 1:
        per_group = {g: sorted(cs) for g, cs in sorted(contract_by_group.items())}
        raise VerdictError(
            f"this load mixes more than one contract {sorted(all_contracts)} across groups "
            f"({per_group}). One contract per load: a recall read on one contract's scale and "
            "an FPR read on another's do not belong on the same curve. Load each contract "
            "separately and compare the results in the analysis step."
        )

    starts = set(min_repeat_by_group.values())
    if len(starts) > 1:
        raise VerdictError(
            f"verdict groups start at different repeat numbers ({min_repeat_by_group}); "
            "the warmup drop is by position, so only the lowest-numbered group's cold pass "
            "would be dropped. Re-run the groups with the same repeat numbering."
        )
    return [by_repeat[k] for k in sorted(by_repeat)], side_case_ids, content_class


def preflight_verdict_groups(
    files_by_group: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Verdict-level pre-check for `--dry-run`: per group, the row count, the repeat count per
    line, the content_class coverage, the contracts seen, and any parse errors — WITHOUT
    scoring anything. Lenient by design (it collects parse errors instead of raising) because
    its whole job is to report what is wrong with a file before a real run.

    Verdict level only. Corpus-level pre-check (the `{text, content_class}` layer) belongs to
    the generation side's own validator — two levels, deliberately not merged into one entry."""
    report: dict[str, dict[str, Any]] = {}
    for group, path in files_by_group.items():
        repeats_by_line: dict[str, int] = defaultdict(int)
        classes: dict[str, int] = defaultdict(int)
        contracts: set[str] = set()
        parse_errors: list[str] = []
        rows = 0
        try:
            with open(path, encoding="utf-8") as f:
                for lineno, raw in enumerate(f, 1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    rows += 1
                    try:
                        v = json.loads(raw)
                        if not isinstance(v, dict):
                            raise ValueError("row is not a JSON object")
                        repeats_by_line[str(v["line"])] += 1
                        classes[str(v.get("content_class", ""))] += 1
                        contracts.add(str(v.get("contract", "")))
                    except (json.JSONDecodeError, ValueError, KeyError) as e:
                        parse_errors.append(f"line {lineno}: {e}")
        except OSError as e:
            parse_errors.append(f"cannot read: {e}")
        report[group] = {
            "known_group": group in _SIDE_OF_GROUP,
            "side": _SIDE_OF_GROUP.get(group, ""),
            "rows": rows,
            "cases": len(repeats_by_line),
            "repeats_by_line": dict(sorted(repeats_by_line.items())),
            "content_classes": dict(sorted(classes.items())),
            "contracts": sorted(contracts),
            "parse_errors": parse_errors,
        }
    return report
