"""EV-R2 §9.3 — `treval cases verify <cases.json>`: re-add ONE case contract's rows to its OWN
declared aggregates. 🔴 Takes exactly one file — never a second bundle (§9.1: two runs = two
samplings of a statistical rate, so comparing across runs would false-report a "fork", the
EV-CIGATE F1 mis-diagnosis all over again).

What it is, precisely (§9.5): a SELF-CONSISTENCY check plus a tamper layer — for an auditor who did
NOT watch us write the file, re-adding the rows IS a real independent check. What it is NOT: proof
the probes ran or that the numbers are true (§9.4). That separation is printed on every PASS and is
not silenceable — an auditor seeing green in their own terminal must not read it as "verified true".
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# UI-3 §5.1 — read the pure contract module, NOT active_eval.cases: `cases verify` re-adds rows and
# never runs a probe, so it must not pull the harness (module-level import, no longer lazy).
from treval.case_contract import (
    AGGREGATES_INTRODUCED_IN,
    TENANT_INTRODUCED_IN,
    CaseContractError,
    compare_cases_to_aggregates,
    contract_is_empty,
    validate_case_contract,
)

EXIT_OK = 0
EXIT_MISMATCH = 2  # tamper / fork / un-verifiable file — a refusal, never a silent pass
EXIT_IO = 3

# §9.4 — the scope declaration, VERBATIM and MANDATORY on PASS (condition (a); not silenceable).
# 🔴 Printed because an auditor reads green in their OWN terminal and slides "self-consistent" into
# "verified true" — the exact "don't let a self-check masquerade as end-to-end" discipline, so the
# two layers are written into the output, not left to memory.
# 🔴 §12.1 件二 — TWO parts, each defined ONCE, composed for the CLI. They are different TEXTS (zh
# and en), not two copies of one text, so this is not the `_is_not_measured` second-definition
# disease: editing either part reds both the CLI and the web assertion, which is the property the
# rule is actually protecting.
#   • the WEB renders the CHINESE part only — the operators reading this deployment read Chinese, and
#     an English block they skip is a warning that did not happen;
#   • the CLI prints BOTH — `treval cases verify` is what an external auditor runs, and this repo is
#     public and English-first.
# CHINESE FIRST in the CLI too: this sentence exists to stop someone reading "self-consistent" as
# "verified", so it goes first to whoever would misread it.
_SCOPE_DECLARATION_ZH = """🔴 这项检查覆盖什么 —— 引用前请先读：
   它只证明：本文件中的逐案行相加，等于本文件中声明的聚合数。
   它不证明：探针真的跑过，也不证明这些数字为真。
   要证明那两件事，请顺着每条 evidence_ref 进入审计日志，自己验哈希链：
       python tools/wal_verify.py <audit-log>"""

_SCOPE_DECLARATION_EN = """🔴 WHAT THIS CHECK COVERS — read before quoting it:
   It proves ONLY that the rows in this file sum to the aggregates in this file.
   It does NOT prove the probes ever ran, nor that the numbers are true.
   For that, follow each evidence_ref into the audit log and verify the hash chain
   yourself:   python tools/wal_verify.py <audit-log>"""

# What the CLI prints. The web imports `_SCOPE_DECLARATION_ZH` directly (never a literal copy).
_SCOPE_DECLARATION = _SCOPE_DECLARATION_ZH + "\n\n" + _SCOPE_DECLARATION_EN

# The cell display order — 🔴 §9.3(d): label WHICH cell each case landed in; never a `!= hard_blocked`
# binary (that "good cell" framing is injection-specific and does not generalise). The got-through /
# ambiguous cells lead so "which rule to fix" is answerable, but every case is labelled by its cell.
_CELL_ORDER = (
    "succeeded",
    "soft_flag_declined",
    "declined_by_model",
    "hard_blocked",
    "unmeasurable",
    "errored",
)


def _load(path: str) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise CaseContractError(f"no such file: {path}") from e
    except json.JSONDecodeError as e:
        raise CaseContractError(f"{path} is not valid JSON: {e}") from e
    validate_case_contract(
        doc
    )  # disclosure_class mandatory + closed verdict/observable_via vocab
    return doc


def _fmt_aggregates(agg: dict) -> list[str]:
    catch = agg.get("injection_catch_rate", {})
    succ = agg.get("injection_success_rate", {})
    fc = agg.get("four_cell", {})
    cells = " ".join(
        f"{c}={fc.get(c)}"
        for c in (
            "hard_blocked",
            "soft_flag_declined",
            "succeeded",
            "declined_by_model",
        )
    )
    return [
        "aggregates (declared in the file, re-added from the rows):",
        f"  injection_catch_rate   = {catch.get('value', 0.0):.1%}  (n={catch.get('n')})",
        f"  injection_success_rate = {succ.get('value', 0.0):.1%}  (n={succ.get('n')})",
        f"  four_cell (n={fc.get('n')}): {cells}",
    ]


def _cell_block(header: str, rows: list[dict]) -> list[str]:
    """One block of the per-case list, grouped by cell (content-free — verdict + technique + the WAL
    pointer only, never a byte of response text). Empty ⇒ printed as `(none)` so the population's
    absence is explicit, not implied."""
    by_cell: dict[str, list[dict]] = {}
    for c in rows:
        by_cell.setdefault(c.get("verdict", "?"), []).append(c)
    lines = ["", header]
    if not rows:
        lines.append("  (none)")
        return lines
    for cell in _CELL_ORDER:
        group = by_cell.get(cell)
        if not group:
            continue
        lines.append(f"  {cell} ({len(group)}):")
        for c in sorted(group, key=lambda r: str(r.get("case_id"))):
            tech = c.get("attack_technique") or "?"
            ptr = c.get("request_id") or "(no request_id)"
            lines.append(f"    - {c.get('case_id')}  ({tech})  {ptr}")
    return lines


def _fmt_cases(cases: list[dict], aggregates: dict) -> list[str]:
    """🔴 §9.3(d)/(e) + architect review — per-case list, CONTENT-FREE, SPLIT BY DENOMINATOR. The
    four-cell aggregate is added from the output_marker subset ONLY; a detection-only case
    (observable_via ≠ output_marker) is in the CATCH denominator but INVISIBLE to the four cells.

    Printing all cases in ONE flat list made a cell read `0` in the aggregate yet list N cases in the
    rows — the exact cross-denominator fallacy EV-ATTRIB §3.1 exists to kill (catch n vs success n),
    re-surfacing in the very tool meant to make numbers checkable. Splitting makes the two populations
    STRUCTURALLY visible (not "trust this note"): the reader sees on the page that the gateway-missed
    evasive cases (base64_smuggle / language_switch / translate — §9.7) are exactly the unobservable
    ones the four cells cannot see."""
    marker = [c for c in cases if c.get("observable_via") == "output_marker"]
    other = [c for c in cases if c.get("observable_via") != "output_marker"]
    fc_n = aggregates.get("four_cell", {}).get("n")
    lines = [
        "",
        "per-case verdicts (the cell each case landed in — content-free), "
        "🔴 SPLIT BY DENOMINATOR so the four-cell population is visible:",
    ]
    lines += _cell_block(
        f"── output_marker subset ({len(marker)}) — the four-cell aggregate (n={fc_n}) is added from "
        "EXACTLY these ──",
        marker,
    )
    lines += _cell_block(
        f"── detection-only ({len(other)}) — observable_via ≠ output_marker ⇒ counted in CATCH but "
        "INVISIBLE to the four cells ──",
        other,
    )
    return lines


def run_cases_verify(args: argparse.Namespace) -> int:
    try:
        doc = _load(args.cases_file)
    except CaseContractError as e:
        print(f"🔴 cannot verify: {e}", flush=True)
        return (
            EXIT_IO if "JSON" in str(e) or "no such file" in str(e) else EXIT_MISMATCH
        )

    # §9.8 — a pre-aggregates file (schema_version 1) is UN-VERIFIABLE here, NOT a fork: say so
    # plainly (the EV-CIGATE F1 version-fork discipline — never mis-diagnose an old shape as broken).
    version = doc.get("schema_version")
    if (
        not isinstance(version, int)
        or version < AGGREGATES_INTRODUCED_IN
        or "aggregates" not in doc
    ):
        print(
            f"🔴 cannot verify: this file predates the `aggregates` block (schema_version="
            f"{version!r}; needs ≥ {AGGREGATES_INTRODUCED_IN}). Re-emit it with a current treval "
            "(`--cases-out`) — this is NOT a fork.",
            flush=True,
        )
        return EXIT_MISMATCH

    # §5.2 — a v2 file (aggregates but no tenant_id) still VERIFIES here; note that it predates
    # tenant scoping so the reader knows a tenant-scoped case store will refuse it (re-run for v3).
    if version < TENANT_INTRODUCED_IN:
        print(
            f"ℹ note: schema_version {version} predates tenant scoping (v{TENANT_INTRODUCED_IN}) — "
            "this file verifies, but a tenant-scoped case store will refuse it; re-run the eval to "
            "produce a v3 contract.",
            flush=True,
        )

    # §9.10 — accept a Tier-1 (internal_handoff) file (re-adding reads only Tier-0 fields, never the
    # content), but WARN: rejecting would push the operator to write their own script and bypass the
    # scope declaration below; accept + warn守住纪律.
    if doc.get("disclosure_class") == "internal_handoff":
        print(
            "⚠ this file carries Tier-1 response content (internal_handoff) — it is a handoff "
            "artifact and should not be circulating.",
            flush=True,
        )

    cases = doc.get("cases", [])
    mismatches = compare_cases_to_aggregates(cases, doc["aggregates"])
    if mismatches:
        # §9.8 tamper teeth — name which aggregate the rows no longer re-add to.
        print(
            "🔴 NOT self-consistent — the rows do NOT re-add to this file's aggregates:"
        )
        for m in mismatches:
            print(f"   • {m}")
        print(
            "\nSomething was edited — a verdict row, or a number in `aggregates` — so the file no "
            "longer re-adds. Do not trust it.",
            flush=True,
        )
        return EXIT_MISMATCH

    # 🔴 §5.4 — an EMPTY contract (all aggregates n=0, e.g. an all-errored / gateway-unreachable run)
    # re-adds trivially (0 = 0). Accepting it is correct (this IS a file self-consistency check), but
    # it must NOT print ✅: an empty read as a pass is the same disease the scope declaration guards
    # (a self-check read as verified) — the second form is "empty read as measured".
    if contract_is_empty(doc):
        errored = sum(1 for c in cases if c.get("verdict") == "errored")
        print(
            f"⚠️ self-consistent but EMPTY — 0 measurable cases ({errored} of {len(cases)} errored).\n"
            '   本次跑没有可测样本；"自洽"在这里只是 0 = 0。网关不可达或评测身份未开通会产生这种契约 ——\n'
            "   见 GATE-LASTMILE P4 / EV-PAIR 门 7（确认网关就绪、身份已开通后重跑）。\n"
        )
        print(_SCOPE_DECLARATION + "\n")
        for line in _fmt_aggregates(doc["aggregates"]):
            print(line)
        return EXIT_OK

    # PASS — the scope declaration (§9.4) is MANDATORY and always printed.
    print(
        f"✅ self-consistent — {len(cases)} case rows re-add to the aggregates declared in this file.\n"
    )
    print(_SCOPE_DECLARATION + "\n")
    for line in _fmt_aggregates(doc["aggregates"]):
        print(line)
    for line in _fmt_cases(cases, doc["aggregates"]):
        print(line)
    return EXIT_OK
