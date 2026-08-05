"""GATE-EGRESS 件一 — content-egress regression gate (CI), isomorphic to the other three gates.

🔴 What it defends (§1): the decoded WAL record (`AuditEvidence.record`) carries the VERBATIM,
un-redacted user prompt, and every passive indicator holds it. Nothing MECHANICAL stops that content
from reaching an auto-produced artifact — only "no one has written that line yet". This gate makes
"no one wrote it" into "it can't get out": it plants a unique SENTINEL in BOTH channels — the ACTIVE
response fields (response_text / raw_response) AND the PASSIVE record fields production actually writes
(`invocation.params_indexed` / `params_raw`) — then runs the ACTIVE indicators AND the PASSIVE ones
(chain_integrity / unclosed_loop_rate / duration_p99) so their measurements enter the bundle + report,
and asserts the sentinel appears in ZERO products (§1.4). Both channels, because §1.1 argues necessity
from the passive side — a gate that only seeded the active side would be narrower than its own claim.
Two roads, because either alone is a hollow check (§1.3):

  • VALUE road — the sentinel (catches a renamed / concatenated / f-string'd content field);
  • NAME road  — the WAL-record content KEY names (catches a raw record serialized under any wrapper).

🔴 Honest boundary (§1.5): the sentinel is matched VERBATIM. A path that hashes / base64s / summarises
the content evades the value road; the name road catches the known derived keys (response_body_sha256
…) but a NEW derived form is a known residual — stated, not hidden. This proves the paths WE RUN do
not leak, not that no code ever could.

Run:  PYTHONPATH=$PWD python tools/check_egress.py
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

# A unique, high-entropy stand-in for un-redacted user prompt content. It has no benign reason to
# appear in any artifact, so ANY occurrence in a product is a real content leak.
SENTINEL = "SENTINEL-EGRESS-3f9a2c7b1d-user-prompt-body-verbatim"

# §1.3 NAME road — the WAL-record CONTENT field key names. Their presence in a product means a raw
# record (or a projection of one) was serialized, whatever the wrapper field was renamed to.
_FORBIDDEN_KEYS = (
    "params_indexed",
    "params_raw",
    "response_body_preview",
    "response_body_sha256",
    "hint_variables",
)

# The one product that is SUPPOSED to carry content — Tier-1 is `internal_handoff` by definition
# (§1.4). Excluded from the must-be-clean set AND asserted to actually carry the sentinel (§1.4 末段 /
# 带牙三): if it silently stopped carrying content, the whole gate would be vacuously green.
_TIER1_PRODUCT = "case_contract_tier1_internal_handoff"


def _evidence(cid: str, decision: int, sentinel: str, *, hint: bool):
    from trustworthy_ai.v1 import request_context_pb2 as rc_pb

    from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    # 🔴 The PASSIVE channel §1.1 names: production writes the VERBATIM prompt into the decoded record
    # — params_indexed (per-field, un-truncated) + params_raw (bytes). Every passive indicator holds
    # this. Plant the sentinel HERE so the gate proves the record→indicator→product path stays clean,
    # not only the active response side.
    ctx.invocation.tool_id = "chat"
    ctx.invocation.params_indexed["messages.0.content"] = sentinel
    ctx.invocation.params_raw = f'{{"messages":[{{"content":"{sentinel}"}}]}}'.encode()
    ctx.decision.final_decision = decision  # type: ignore[assignment]
    rule = ctx.decision.rules_evaluated.add()
    rule.rule_id = "inj-1"
    rule.matched = decision == rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
    if hint:
        ctx.audit.hint_emitted = True
    return AuditEvidence(
        ref=EvidenceRef(source="wal:/w/000.wal", seq=1, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__egress__",
        received_at_ns=0,
        record=ctx,
    )


def _sentinel_run(sentinel: str):
    """A small injection run whose CONTENT fields all carry `sentinel` (as a real user prompt would).
    Returns (cases, results) — decided cases so the case contract serializes cleanly."""
    from trustworthy_ai.v1 import request_context_pb2 as rc_pb

    from treval.active_eval import CorpusCase, ProbeResult

    _BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
    _ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
    marker = "ZZPWN"

    def case(cid: str) -> CorpusCase:
        return CorpusCase(
            id=cid,
            owasp="LLM01",
            dimension="robustness",
            attack_class="direct",
            input=f"benign wrapper {sentinel}",  # the sentinel rides in as the user prompt
            success_when="blocked_or_flagged",
            severity="high",
            source="core-authored",
            output_marker=marker,
            attack_technique="egress_probe",
        )

    def probe(cid: str, *, decision, followed: bool, hint: bool = False) -> ProbeResult:
        text = f"{marker} {sentinel}" if followed else f"refused {sentinel}"
        return ProbeResult(
            case_id=cid,
            request_id=f"req-{cid}",
            decision="",
            response_text=text,  # 🔴 content — must never reach a Tier-0 product
            raw_response=f"raw {sentinel}",
            evidence=_evidence(cid, decision, sentinel, hint=hint),
            output_marker=marker,
        )

    cases = [case("succ"), case("hard"), case("soft")]
    results = [
        probe("succ", decision=_ALLOW, followed=True),
        probe("hard", decision=_BLOCK, followed=False),
        probe("soft", decision=_ALLOW, followed=False, hint=True),
    ]
    return cases, results


def build_products(sentinel: str, *, leak_via_notes: bool = False) -> dict[str, str]:
    """Run every §1.4 product from the sentinel-bearing run and return {name: serialized_text}.

    `leak_via_notes=True` simulates 场景 A (someone f-strings content into a Measurement.notes) so a
    test can prove the gate has teeth — it is NOT used by the real CI run."""
    from treval.active_eval import (
        FalsePositiveRate,
        InjectionCatchRate,
        InjectionSuccessRate,
        serialize_case_contract,
    )
    from treval.active_eval.coverage import corpus_coverage
    from treval.active_eval.corpus import load_corpus_tree
    from treval.cli.bundle import build_bundle
    from treval.cli.pair import pair_bundles
    from treval.cli.render import render_human
    from treval.indicators.chain_integrity import ChainIntegrity
    from treval.indicators.duration_percentiles import DurationP99
    from treval.indicators.terminal_error_ratio import TerminalErrorRatio
    from treval.indicators.unclosed_loop_rate import UnclosedLoopRate
    from treval.models import Measurement
    from treval.registry import load_registry
    from treval.report_store import ReportStore, write_bundle
    from treval.rubric import (
        bundle_to_json,
        evaluate,
        self_contained_bundle_to_json,
    )

    cases, results = _sentinel_run(sentinel)
    # 🔴 the PASSIVE indicators §1.1 names: each HOLDS the full decoded record (which now carries the
    # sentinel in params_indexed/params_raw). Run them so their measurements enter the bundle + report
    # — the gate then proves the record→passive-indicator→product path does not leak, which is the
    # channel §1.1 argues necessity from (the active side alone left the docstring wider than the test).
    evidence = [r.evidence for r in results if r.evidence is not None]
    meas = (
        list(InjectionCatchRate().measure(results))
        + list(InjectionSuccessRate().measure(results))
        + list(FalsePositiveRate().measure(results))
        + list(ChainIntegrity().measure(evidence))
        + list(UnclosedLoopRate().measure(evidence))
        + list(DurationP99().measure(evidence))
        + list(TerminalErrorRatio().measure(evidence))
    )
    if leak_via_notes:
        from dataclasses import replace

        # 🔴 场景 A on the PASSIVE side: a passive indicator f-strings the record's params_indexed
        # (which holds the verbatim prompt) into its notes. The leaked thing is the record content,
        # NOT the key name — so only the VALUE road can catch it (§1.3).
        leaked = dict(evidence[0].record.invocation.params_indexed)
        meas[-1] = replace(
            meas[-1], notes=meas[-1].notes + f" unmatched-record={leaked}"
        )
    measurements: tuple[Measurement, ...] = tuple(meas)

    window = (0, 0)
    tenant = "__egress__"
    reg = load_registry()
    report = evaluate(reg, measurements, [], window=window, tenant_id=tenant)

    products: dict[str, str] = {}
    products["collect_bundle"] = json.dumps(
        build_bundle(measurements, tenant_id=tenant, window=window, mode="active")
    )
    from treval.active_eval import EVIDENCE_REQUIREMENTS

    products["report_json"] = bundle_to_json(
        report,
        measurements,
        target_kind="gateway",
        evidence_requirements=EVIDENCE_REQUIREMENTS,
    )
    products["report_human"] = render_human(reg, report, measurements, (), color=False)
    self_contained = self_contained_bundle_to_json(report, measurements, reg)
    products["self_contained_bundle"] = self_contained
    with tempfile.TemporaryDirectory() as td:
        entry = write_bundle(td, self_contained, generated_at_ns=1)
        products["report_store_stored_bytes"] = (
            ReportStore(td).read_bytes(entry).decode("utf-8")
        )

    products["case_contract_tier0"] = json.dumps(
        serialize_case_contract(
            cases, results, target_kind="gateway", tenant_id=tenant, generated_at_ns=1
        )
    )
    products[_TIER1_PRODUCT] = json.dumps(
        serialize_case_contract(
            cases,
            results,
            target_kind="gateway",
            tenant_id=tenant,
            generated_at_ns=1,
            include_response_content=True,
        )
    )

    raw = build_bundle(
        measurements,
        tenant_id=tenant,
        window=window,
        mode="active",
        target_kind="raw_model",
    )
    gw = build_bundle(measurements, tenant_id=tenant, window=window, mode="active")
    products["pair_delta"] = json.dumps(pair_bundles(raw, gw))

    _ROOT = Path(__file__).resolve().parents[1]
    products["coverage_report"] = json.dumps(
        corpus_coverage(load_corpus_tree(_ROOT / "corpus"))
    )
    return products


def scan_products(products: dict[str, str]) -> list[tuple[str, str]]:
    """(product, why) for every leak. Tier-1 is excluded (it is supposed to carry content)."""
    hits: list[tuple[str, str]] = []
    for name, text in products.items():
        if name == _TIER1_PRODUCT:
            continue
        if SENTINEL in text:
            hits.append(
                (
                    name,
                    "response content (sentinel) appears — a content leak (§1.4 VALUE road)",
                )
            )
        for key in _FORBIDDEN_KEYS:
            if f'"{key}"' in text:
                hits.append(
                    (
                        name,
                        f"WAL-record content field {key!r} serialized (§1.3 NAME road)",
                    )
                )
    return hits


def run() -> tuple[list[tuple[str, str]], dict[str, str]]:
    """(hits, products). hits ⇒ exit 1. Also fails if the Tier-1 positive control lost its content
    (a vacuous-green guard, §1.4 末段 / 带牙三)."""
    products = build_products(SENTINEL)
    hits = scan_products(products)
    if SENTINEL not in products.get(_TIER1_PRODUCT, ""):
        hits.append(
            (
                _TIER1_PRODUCT,
                "🔴 Tier-1 (internal_handoff) did NOT carry the sentinel — the whole check is "
                "vacuous; Tier-1 is DEFINED to carry content (§1.4 末段)",
            )
        )
    return hits, products


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(prog="check_egress", description=__doc__).parse_args(argv)
    hits, products = run()
    if not hits:
        print(
            f"egress gate: PASS —— sentinel absent from all {len(products) - 1} content-free "
            "products; Tier-1 carries it (non-vacuous)"
        )
        return 0
    out = sys.stderr
    print(
        "egress gate: FAIL —— response content reached an auto-produced artifact\n",
        file=out,
    )
    for product, why in hits:
        print(f"[{product}] {why}", file=out)
    print(
        "\n处置：产物不得携带响应正文。把逐字正文从该产物移除（Tier-1 除外——它本就是 "
        "internal_handoff）。名字改了也拦不住值那道（§1.3）。",
        file=out,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
