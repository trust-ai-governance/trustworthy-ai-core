"""`treval` CLI (EV-8) — grade a Measurement bundle into a maturity report.

    python -m treval.cli report  --measurement-bundle b.json [--posture p.yaml]
                                 [--format json|human|csv] [--out f]
    python -m treval.cli collect --gateway URL --wal DIR [--corpus DIR] [--out b.json]
    python -m treval.cli run     ...            # collect ∘ report (convenience)

`report` is the authoritative PURE path: bundle + posture + registry → EV-7 `evaluate`
→ render. No gateway, no clock, deterministic, CI-testable. `collect` is the operator
path (drives the live gateway; may fail on the environment) and is split out so a
collection failure never touches the grade/render logic (§0②).

Exit codes (mirroring tools/wal_verify.py): 0 ok (even with warnings) · 2 grading
failure (ambiguous binding) · 3 io/arg (bad bundle / registry / posture).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any

from treval.cli.bundle import CI_INTRODUCED_IN, BundleError, load_bundle
from treval.cli.render import render_csv, render_human
from treval.models import MaturityReport, Measurement
from treval.posture import PostureFileError, PostureFileReader
from treval.registry import DimensionRegistry, RegistryError, load_registry
from treval.report_store import ReportEntry, ReportStoreError, write_bundle
from treval.rubric import (
    DuplicateIndicatorError,
    RubricError,
    bundle_to_json,
    evaluate,
    self_contained_bundle_to_json,
)
from treval.rubric.serialize import TARGET_KINDS

EXIT_OK = 0
EXIT_GRADING = 2
EXIT_IO = 3


def _grade(
    bundle_path: str | Path,
    posture_path: str | Path | None,
    registry: DimensionRegistry | None,
) -> tuple[
    DimensionRegistry,
    MaturityReport,
    tuple[Measurement, ...],
    list[str],
    dict[str, Any] | None,
    str,
]:
    """The shared grade step: measurement bundle + posture + registry → graded report,
    plus the run's pin `provenance` (None when the source bundle predates EV-PIN) and its
    `target_kind` (R1). Pure (no clock, no gateway). Used by both `report` renderings and the
    `--self-contained` store producer, so they can never grade differently."""
    reg = registry if registry is not None else load_registry()
    bundle = load_bundle(bundle_path)
    warnings = list(bundle.warnings)

    posture = []
    if posture_path is not None:
        facts = list(
            PostureFileReader(posture_path).collect(tenant_id=bundle.tenant_id)
        )
        if not facts:
            warnings.append(
                f"posture file had no attestations for tenant {bundle.tenant_id!r} "
                "— attested objectives are all unmet"
            )
        posture = facts
    else:
        warnings.append("no --posture file: attested objectives are all unmet")

    try:
        report = evaluate(
            reg,
            bundle.measurements,
            posture,
            window=bundle.window,
            tenant_id=bundle.tenant_id,
        )
    except RubricError as e:
        # 🔴 EV-CIGATE F1: a missing interval on a PRE-CI bundle is "produced before the fields
        # existed", NOT "a non-rate indicator". Only the CLI knows the bundle's schema_version, so it
        # forks the diagnosis here — the engine stays bundle-agnostic.
        if bundle.schema_version < CI_INTRODUCED_IN:
            raise RubricError(
                f"bundle predates the EV-CIGATE interval fields (schema_version "
                f"{bundle.schema_version} < {CI_INTRODUCED_IN}) — re-collect it so measurements carry "
                f"ci_low/ci_high; the point estimate alone can no longer be graded. (raw: {e})"
            ) from e
        raise
    return (
        reg,
        report,
        bundle.measurements,
        warnings,
        bundle.provenance,
        bundle.target_kind,
    )


def run_self_contained(
    bundle_path: str | Path,
    posture_path: str | Path | None,
    out_dir: str | Path,
    *,
    registry: DimensionRegistry | None = None,
    generated_at_ns: int | None = None,
) -> tuple[ReportEntry, list[str]]:
    """Grade, then store the EV-R1 SELF-CONTAINED delivery bundle (EV-W1 §7.1).

    This is the artifact the read-only web service serves: `{schema_version,
    registry_fingerprint, report, registry, measurements}` — distinct from
    `--format json`, which emits the core-layer (decoupled) form. `generated_at_ns` is
    store metadata (a wall-clock fact about the run, NOT part of the deterministic
    report); it defaults to now and is injectable for tests."""
    reg, report, measurements, warnings, provenance, target_kind = _grade(
        bundle_path, posture_path, registry
    )
    # EV-FWD: the per-indicator evidence_requirement map drives each measurement's `availability`.
    # Imported lazily (active_eval is the harness) so the pure grade/render path stays isolated
    # from a collection-only dependency (§0②); it's httpx-free at import.
    from treval.active_eval import EVIDENCE_REQUIREMENTS

    # EV-PIN §1.5-1: carry the pin stamp into the delivery artifact so a third party can
    # tell from the bundle ALONE whether it is citable. R1: carry target_kind too.
    bundle_json = self_contained_bundle_to_json(
        report,
        measurements,
        reg,
        provenance,
        target_kind=target_kind,
        evidence_requirements=EVIDENCE_REQUIREMENTS,
    )
    entry = write_bundle(
        out_dir,
        bundle_json,
        generated_at_ns=generated_at_ns
        if generated_at_ns is not None
        else time.time_ns(),
    )
    return entry, warnings


def run_report(
    bundle_path: str | Path,
    posture_path: str | Path | None,
    fmt: str,
    *,
    registry: DimensionRegistry | None = None,
    color: bool = False,
) -> tuple[str, list[str]]:
    """The pure grade+render path. Returns (rendered_text, warnings). Raises BundleError /
    RegistryError / PostureFileError (→ io exit) or DuplicateIndicatorError (→ grading exit);
    a partial/empty bundle renders an honest report, it does not raise (§5)."""
    reg, report, measurements, warnings, _prov, target_kind = _grade(
        bundle_path, posture_path, registry
    )

    if fmt == "human":
        # EV-CITE 件一: the human report leads with the citability verdict. Derived from the same
        # provenance/integrity the delivery bundle carries (evidence_basis follows target_kind).
        from treval.citability import report_citability
        from treval.rubric.serialize import derive_evidence_basis

        _citable, _blockers = report_citability(
            {
                "evidence_basis": derive_evidence_basis(target_kind),
                "provenance": _prov,
                "report": {"integrity_summary": dict(report.integrity_summary)},
            }
        )

    if fmt == "json":
        from treval.active_eval import EVIDENCE_REQUIREMENTS

        text = bundle_to_json(
            report,
            measurements,
            target_kind=target_kind,
            evidence_requirements=EVIDENCE_REQUIREMENTS,
        )
    elif fmt == "csv":
        text = render_csv(reg, report, measurements)
    else:  # human
        text = render_human(
            reg,
            report,
            measurements,
            tuple(warnings),
            color=color,
            citable=_citable,
            citable_blockers=tuple(_blockers),
        )
    return text, warnings


def _emit(text: str, out: str | None) -> None:
    if out is None:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    else:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)


def _use_color(fmt: str, out: str | None) -> bool:
    return (
        fmt == "human"
        and out is None
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
    )


def _warn(warnings: list[str]) -> None:
    if warnings:
        print(f"⚠ {len(warnings)} warning(s):", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)


def _cmd_report(args: argparse.Namespace) -> int:
    # --self-contained is the STORE PRODUCER path (EV-W1 §7.1): it writes the EV-R1
    # delivery bundle the read-only service serves, rather than rendering to stdout.
    if getattr(args, "self_contained", False):
        if not args.out_dir:
            print("error: --self-contained requires --out-dir DIR", file=sys.stderr)
            return EXIT_IO
        try:
            entry, warnings = run_self_contained(
                args.measurement_bundle, args.posture, args.out_dir
            )
        except (DuplicateIndicatorError, RubricError) as e:
            print(f"error: cannot grade bundle — {e}", file=sys.stderr)
            return EXIT_GRADING
        except (
            BundleError,
            RegistryError,
            PostureFileError,
            ReportStoreError,
            OSError,
        ) as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_IO
        _warn(warnings)
        print(
            f"stored {entry.file} (tenant={entry.tenant_id} "
            f"window={entry.window[0]}-{entry.window[1]})",
            file=sys.stderr,
        )
        return EXIT_OK

    try:
        text, warnings = run_report(
            args.measurement_bundle,
            args.posture,
            args.format,
            color=_use_color(args.format, args.out),
        )
    except DuplicateIndicatorError as e:
        print(f"error: ambiguous bundle — {e}", file=sys.stderr)
        return EXIT_GRADING
    except RubricError as e:
        # EV-CIGATE §7-B: a CI gate written on a non-rate indicator (or the interval is missing).
        print(f"error: registry/measurement mismatch — {e}", file=sys.stderr)
        return EXIT_GRADING
    except (BundleError, RegistryError, PostureFileError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_IO

    # Warnings always go to stderr (json/csv stdout stays clean; human embeds them too).
    _warn(warnings)
    _emit(text, args.out)
    return EXIT_OK


def _cmd_collect(args: argparse.Namespace) -> int:
    # Operator path — imported lazily so the pure `report` path never pulls in the
    # active-eval harness / its httpx dependency (fault isolation, §0②).
    from treval.cli.collect import run_collect

    return run_collect(args)


def _cmd_pair(args: argparse.Namespace) -> int:
    # EV-PAIR §3: the pairing gate is a function of TWO bundles, so it is its own subcommand (P2),
    # not a flag on any single-run path. Imported lazily like the other operator paths.
    from treval.cli.pair import run_pair

    return run_pair(args)


def _cmd_coverage(args: argparse.Namespace) -> int:
    # EV-COVERAGE §4.3-B: pure corpus read → the four-axis vector. Lazy import keeps the harness out
    # of the `report` path, same as the other operator commands.
    from treval.cli.coverage_report import run_coverage

    return run_coverage(args)


def _cmd_cases_verify(args: argparse.Namespace) -> int:
    # EV-R2 §9.3: pure re-add of ONE case contract against its own aggregates. Lazy import keeps
    # the harness out of the `report` path, like the other operator commands.
    from treval.cli.cases_verify import run_cases_verify

    return run_cases_verify(args)


def _cmd_cases_store(args: argparse.Namespace) -> int:
    # UI-3 §5.3: the fail-closed ingest gate into the tenant-scoped case store (pure — no engine).
    from treval.cli.cases_store import run_cases_store

    return run_cases_store(args)


def _cmd_run(args: argparse.Namespace) -> int:
    from treval.cli.collect import run_collect

    # `run` must not overload one path: --out is the REPORT destination (what the user
    # wants written, e.g. report.csv); the intermediate bundle goes to --bundle-out
    # (default bundle.json). Swap args.out for the collect call so the two don't collide.
    report_out = args.out
    args.out = args.bundle_out
    rc = run_collect(args)
    if rc != EXIT_OK:
        return rc
    args.measurement_bundle = args.bundle_out or "bundle.json"
    args.out = report_out
    return _cmd_report(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="treval", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    rep = sub.add_parser("report", help="grade a bundle → json/human/csv (pure)")
    rep.add_argument("--measurement-bundle", required=True)
    rep.add_argument("--posture", default=None)
    rep.add_argument("--format", choices=("json", "human", "csv"), default="human")
    rep.add_argument("--out", default=None)
    rep.add_argument(
        "--self-contained",
        action="store_true",
        help="write the EV-R1 self-contained delivery bundle into the report store "
        "(--out-dir) instead of rendering; this is what treval-web serves",
    )
    rep.add_argument(
        "--out-dir", default=None, help="report store directory (--self-contained)"
    )
    rep.set_defaults(func=_cmd_report)

    # EV-PAIR §3 / P2: `pair RAW.json GATEWAY.json` — the fail-closed governance-effect delta.
    pair = sub.add_parser(
        "pair",
        help="two collect bundles → governance-effect delta (fail-closed; EV-PAIR)",
    )
    pair.add_argument("bundle_a", help="a collect bundle (raw_model or gateway)")
    pair.add_argument("bundle_b", help="the other collect bundle")
    pair.add_argument(
        "--out", default=None, help="write the delta JSON here (else stdout)"
    )
    pair.set_defaults(func=_cmd_pair)

    # EV-COVERAGE §4.3-B: `coverage --corpus DIR` — the four-axis vector (①②③④) framed with corpus_sha.
    cov = sub.add_parser(
        "coverage",
        help="corpus coverage vector (category / technique / observable / hold-out; EV-COVERAGE)",
    )
    cov.add_argument(
        "--corpus", default=None, help="corpus root (default: repo corpus/)"
    )
    cov.add_argument("--format", choices=("json", "human"), default="human")
    cov.add_argument("--out", default=None, help="write here (else stdout)")
    cov.set_defaults(func=_cmd_coverage)

    # EV-R2 §9.3: `cases verify <file>` — re-add ONE case contract's rows to its own aggregates
    # (self-consistency + tamper check; 🔴 NOT a proof the numbers are true — §9.4).
    cases = sub.add_parser("cases", help="EV-R2 case-level contract tools")
    cases_sub = cases.add_subparsers(dest="cases_command", required=True)
    verify = cases_sub.add_parser(
        "verify",
        help="re-add a case contract's rows to its own aggregates (self-consistency + tamper "
        "check; does NOT prove the numbers are true)",
    )
    verify.add_argument(
        "cases_file", help="a Tier-0 case contract JSON (from --cases-out)"
    )
    verify.set_defaults(func=_cmd_cases_verify)

    # UI-3 §5.3: `cases store <file> --store DIR` — fail-closed ingest into the tenant-scoped store.
    store_cases = cases_sub.add_parser(
        "store",
        help="ingest a v3 case contract into a tenant-scoped case store (fail-closed gate)",
    )
    store_cases.add_argument("cases_file", help="a v3 case contract JSON")
    store_cases.add_argument(
        "--store",
        default=None,
        help="case store dir (default $TREVAL_CASE_STORE). 🔴 NEVER the report store — no fallback.",
    )
    store_cases.set_defaults(func=_cmd_cases_store)

    from treval.cli.collect import (
        CORPUS_SETS,
    )  # 件2 — the closed corpus-set enum (single source)

    for name, help_text in (
        ("collect", "drive the live gateway → Measurement bundle (operator)"),
        ("run", "collect ∘ report (convenience)"),
    ):
        col = sub.add_parser(name, help=help_text)
        # EV-FWD D3: the target is (URL, kind). `--gateway` is retained as SUGAR for a gateway
        # run (⇒ --target-url=<gw> --target-kind=gateway); it is mutually exclusive with the
        # explicit pair. `--target-kind` is a CLOSED enum and is NEVER inferred from the URL —
        # a bare-model URL must not be silently mislabelled as a governed gateway (R1 honesty).
        col.add_argument("--gateway", default=os.environ.get("TREVAL_EVAL_GATEWAY_URL"))
        col.add_argument(
            "--target-url",
            default=None,
            help="target endpoint URL (with --target-kind); alternative to --gateway",
        )
        col.add_argument(
            "--target-kind",
            choices=TARGET_KINDS,
            default=None,
            help="what the target IS (never inferred): gateway | raw_model | moderation_api",
        )
        col.add_argument("--wal", default=os.environ.get("TREVAL_EVAL_WAL_DIR"))
        col.add_argument("--corpus", default=None)
        # 🔴 EV-CN-BASELINE 件2 — which curated producer set to run. `en` (default) is CURATION,
        # bit-identical to every existing run; `cn` is CURATION_CN (the out-of-repo Chinese diagnostic
        # batch). NEVER inferred — a CN run must be declared, so an English `--language-scope` can never
        # silently probe the Chinese corpus.
        col.add_argument("--corpus-set", choices=CORPUS_SETS, default="en")
        # 🔴 认证跑的分母由【判据】产生，不由"臂里有多少件"产生。仓内注入臂 212 件，
        # 而分母是 134（剔 control_ 59 · behaviour 痕迹 4 · holdout 15）。不给这个清单，
        # 跑出来的数分母是 212，与门（k ≥ 117/134）不是同一个量 —— 而它跑得完、退出码 0、
        # 报告完全正常。臂名守卫拦不住它：问题不是"哪条臂"，是"臂里的哪些件"。
        col.add_argument(
            "--denominator-manifest",
            default=None,
            help="分母清单（p8 形态 JSON：arm / excluded_for_behaviour / excluded_holdout / "
            "denominator）。按 attack_class 剔 control_ 前缀 + 两份具名剔除表，并断言筛出的件数"
            "等于清单声明的数 —— 不等就非零退出。只作用于清单点名的那条臂",
        )
        # 🔴 C2A0 —— 一份对不上的输入，代价应该是零。今天唯一会红的是配对那一刻的拒发门，
        # 而那时语料已经花掉。不传这个参数**不是静默通过**：产物记 `baseline_compared:
        # not_declared`，因为「比过且一致」与「根本没比」半年后没人分得清。
        col.add_argument(
            "--baseline-bundle",
            default=None,
            help=(
                "基线产物（collect bundle JSON）的路径。跑前只比一格："
                "本跑的 build_fingerprint_before.runtime.ruleset_sha256 是否等于该产物里的同一格；"
                "不等 ⇒ 非零退出、一件语料不发。🔴 不比路径（路径是自述，哈希是测量），"
                "也不比整块指纹（里面含我们自己发流量就会动的计数器 ⇒ 会假红）。"
                "不传 ⇒ 不做本项比对，且在产物里记 not_declared"
            ),
        )
        col.add_argument(
            "--benign-arm",
            default="",
            help=(
                "英文良性臂的子目录名，覆盖默认的 llm01_benign_holdout。"
                "🔴 新臂叫别的名字时必须给它，否则 Producer 找不到那条臂 —— "
                "语料在、判据在，而那条臂在这条路上根本跑不了。只重映射良性臂，不通配"
            ),
        )
        col.add_argument(
            "--tenant", default=os.environ.get("TREVAL_EVAL_TENANT", "__eval__")
        )
        # The eval user MUST be provisioned on the target (an unprovisioned user makes
        # every probe unmeasurable — silently). Mirror eval_report's env contract so a
        # `collect` run isn't quietly empty. Model likewise deployment-specific.
        col.add_argument(
            "--user", default=os.environ.get("TREVAL_EVAL_USER", "eval-user")
        )
        # 🔴 The gateway REQUIRES `x-agent-id` unless it has a `default_agent_id` config — observed
        # live: 194/194 probes died at IDENTIFY_FAILED before reaching any detection stage, and
        # `target.py` only sent the header when a CASE declared `agent_id` (the EV-AE13 route
        # selector). A run-wide default was simply unreachable from the CLI. The agent must ALSO be
        # in the target's identity registry — an unregistered agent fails exactly like a missing one.
        col.add_argument(
            "--agent",
            default=os.environ.get("TREVAL_EVAL_AGENT", ""),
            help="agent id sent as `x-agent-id` on every probe (must be provisioned on the target); "
            "a case's own `agent_id` still wins for per-case route selection. Env: TREVAL_EVAL_AGENT",
        )
        # 🔴 DECLARE that the target has no upstream model (an echo forwarder: 被测方=无). Then a
        # non-blocked 200 with no parseable completion is the target's DESIGNED behaviour, not an
        # extraction failure — without this every probe errors out of every denominator and a
        # decision-side-only run measures nothing. Refused if any active producer reads the response.
        col.add_argument(
            "--no-output-side",
            action="store_true",
            help="declare the target has NO upstream model (echo forwarder) ⇒ an absent completion is "
            "expected, not a probe failure. REFUSED alongside any output-side indicator",
        )
        # EV-PAIR-A2 §2: no hard default — `deepseek-v4-flash` is the gateway deployment's model,
        # meaningless on an arbitrary endpoint. gateway falls back to it in code; raw_model /
        # moderation_api REQUIRE it. Reads TREVAL_EVAL_MODEL (NOT TREVAL_TARGET_MODEL — a doc
        # footgun: exporting the latter is silently ignored ⇒ a wasted run).
        col.add_argument(
            "--model",
            default=os.environ.get("TREVAL_EVAL_MODEL"),
            help="model id — REQUIRED for --target-kind raw_model/moderation_api (no default "
            "for an arbitrary endpoint); gateway defaults to deepseek-v4-flash. Env: "
            "TREVAL_EVAL_MODEL (NOT TREVAL_TARGET_MODEL).",
        )
        # EV-Coverage E3: per-probe HTTP timeout for a --gateway run. Opt-in — absent ⇒
        # GatewayTarget's own 30.0 default (LLM10 runaway runs rely on it). Raise it (e.g. 90)
        # so slow encoding-smuggle cases return a real verdict instead of a ReadTimeout that
        # silently excludes them from the frozen number.
        col.add_argument(
            "--timeout",
            type=float,
            default=None,
            help="per-probe HTTP timeout in seconds for a --gateway run (default 30.0); raise "
            "it (e.g. 90) so slow encoding-smuggle cases return a real verdict instead of a "
            "ReadTimeout that excludes them",
        )
        col.add_argument("--out", default=None)
        # EV-R2: also write the LLM01 injection Tier-0 case contract from THIS run (per-case verdict
        # + the two recompute signals, POINTERS ONLY — no response content). This is the on-disk,
        # product-produced contract `cases verify` re-adds. disclosure_class=operator_only — a
        # tenant-internal bypass map; do NOT publish. Mirrors tools/eval_report.py --cases-out.
        col.add_argument(
            "--cases-out",
            default=None,
            help="also write the EV-R2 Tier-0 LLM01 injection case contract here (gateway run "
            "only; POINTERS only, disclosure_class=operator_only — do NOT publish)",
        )
        # 🔴 EV-CN-BASELINE 件4 — the BENIGN-side mirror: a Tier-0 case table so a blocked benign case is
        # answerable by case_id (拦截来源 via decision_injection_source). Gateway-only, POINTERS only.
        col.add_argument(
            "--benign-cases-out",
            default=None,
            help="also write the 件4 Tier-0 benign case table here (gateway run only; POINTERS + "
            "decision-stage FPR/flag口径 per case, disclosure_class=operator_only — do NOT publish)",
        )
        # EV-PIN: freeze the run's window. Supplying BOTH bounds makes the run reproducible
        # (same WAL + same bounds ⇒ same records) and stamps `pinned: true`. Bounds are
        # HALF-OPEN [from, to) — matching the WAL reader's filter — so `to` is exclusive.
        # Without them the bundle records the window actually observed and is `pinned:false`,
        # which external documents must not cite (EV-PIN §1.4).
        col.add_argument(
            "--window-from-ns",
            type=int,
            default=None,
            help="pin the run's window start (inclusive, ns since epoch)",
        )
        col.add_argument(
            "--window-to-ns",
            type=int,
            default=None,
            help="pin the run's window end (EXCLUSIVE, ns since epoch)",
        )
        # EV-CITE C13 — make a citable product reachable in ONE command.
        col.add_argument(
            "--passive-only",
            action="store_true",
            help="read the WAL and send NO probes (requires --wal, no target) — measure the passive "
            "indicators alone, without re-paying the whole active side",
        )
        col.add_argument(
            "--pin-observed-window",
            action="store_true",
            help="pin to the window the passive scan actually covered (an explicit口径 declaration). "
            "One command, zero extra probes, window correct by construction; combinable with --gateway. "
            "Mutually exclusive with --window-from-ns/--window-to-ns.",
        )
        # EV-COVERAGE E3-h/E3-m (§3.1 / §5): declare what SCOPES the numbers — the freeze pack must
        # carry these for a wal_anchored run to be citable (they enter provenance + citation_form).
        # Declaration-based today (no queryable version/config endpoint exists); provenance records
        # config_source. 🔴 --language-scope is the #1 axis and is an operator STATEMENT (e.g. "英文为主
        # · 含跨语言手法件 · 中文金融流量未测"), NEVER inferred from case bytes (E3-m §5).
        col.add_argument(
            "--language-scope",
            default=None,
            help="which language(s)/traffic the numbers represent, operator-declared (e.g. "
            "'英文为主 · 含跨语言手法件 · 中文金融流量未测') — required for a citable wal_anchored run; "
            "an English-majority batch that INCLUDES cross-language cases still says so here (E3-m §5)",
        )
        col.add_argument(
            "--tested-version",
            default=None,
            help="the tested party's version identifier (e.g. deepseek-v4-flash@2026-01-30) — "
            "required for a citable wal_anchored run (E3-h §3.1)",
        )
        col.add_argument(
            "--detect-config",
            default=None,
            help="key detection config switches, esp. encode/decode on-off (e.g. "
            "'encode_decode=off; multiturn=on') — on/off directly changes the catch number (E3-h §3.1)",
        )
        col.add_argument(
            "--exec-mode",
            choices=("block", "flag"),
            default=None,
            help="execution mode: block = hit⇒deny, or flag = mark-only (τ_fpr's scope varies by "
            "this — E3-h §2.2.2)",
        )
        # EV-COVERAGE E3-n ③ — the freeze pack must ALSO pin the detection-layer status and the tested
        # party's UPSTREAM request-timeout (its own hardcoded value). Both fold into missing_run_config.
        col.add_argument(
            "--detection-layer-status",
            default=None,
            help="which detection layers are live (operator-declared, e.g. 'tier1_only (tier2 shadow "
            "off)') — required for a citable wal_anchored run (E3-n ③)",
        )
        col.add_argument(
            "--upstream-timeout-s",
            type=float,
            default=None,
            help="the tested party's DECLARED upstream request-timeout in seconds (its hardcoded "
            "value, e.g. 60) — the gateway --timeout is then DERIVED as 2× this (not guessed), and the "
            "value is pinned into the freeze pack (E3-n ③)",
        )
        col.add_argument(
            "--drain-timeout-s",
            type=float,
            default=None,
            help="Tier-2 排空的绝对上限（秒）。不传 ⇒ 按件数推导（5.0 s/件，下限 20 s）——"
            "而那个 5.0 是在另一套栈上按 median 2.84 s/件 标定的。🔴 实测同一条臂的判官延迟会在"
            "几跑之内从 3.5 s/件 劣化到 9.5 s/件（语料没变、栈没变），届时排空追不上，"
            "该跑的 Tier-2 全部变 not_measured。⇒ 跑 read-once 臂【必须】显式传："
            "跑前量一次 s/件，按 3 倍余量给（例：257 件 × 9.5 × 3 ≈ 7300）",
        )
        # 🔴 EV-CN-BENIGN-N180 件0 — the JUDGE/τ declaration axes (operator-declared, like
        # --language-scope). Absent ⇒ not a citable run: a number that didn't record which τ / measurement
        # path / judge form it used cannot be cited as a product capability. `--measurement-path` IS the
        # assembly axis (offline_judge_harness vs in_product_gateway).
        col.add_argument(
            "--judge-form",
            default=None,
            help="the judge form these numbers were measured under: 'single' | 'union:<n>' (N180 件0)",
        )
        col.add_argument(
            "--measurement-path",
            choices=("offline_judge_harness", "in_product_gateway"),
            default=None,
            help="where the numbers were measured — the assembly axis; a gateway run is "
            "in_product_gateway (N180 件0)",
        )
        col.add_argument(
            "--tau-declared",
            default=None,
            help="the τ these numbers were computed with (N180 件0)",
        )
        col.add_argument(
            "--tau-source",
            choices=("shipped", "fitted", "other"),
            default=None,
            help="where that τ came from — 'shipped' (detection_switches) is the only citable source; "
            "'fitted'/'other' ⇒ a calibration diagnostic, not_citable (N180 件6)",
        )
        # 🔴 弱门（PM 2026-09-07）—— 判官指纹的**声明**。不 block citability（按裁定不许红任何
        # 现存可引产物），只把"缺席"从沉默变成产物里一个具名的第三态。
        col.add_argument(
            "--judge-imprint",
            default=None,
            metavar="PATH|none",
            help="path to this run's judge-imprint JSON, or the literal 'none' to DECLARE that no "
            "imprint was taken. Omitted ⇒ 'not_declared' (indistinguishable from a pre-gate bundle). "
            "🔴 A 0-byte/unreadable file is REFUSED, never downgraded to 'none': an empty imprint's "
            "sha256 is a perfectly valid hash, and accepting it would make this gate certify the very "
            "run it exists to flag. It does NOT check that the imprint was taken within this run's "
            "window — that gate needs `taken_at` on the imprint side (next round)",
        )
        # 🔴 D1 —— 对"本跑规则集与基线是否相同"的【事前声明】。
        # 形态改判（规则专家 2026-09-13 提）：旧形态「不一致就拦」会拦住我们正要跑的那一跑
        # —— 块一落地之后 ruleset_sha256 是【故意】改的。⇒ 记录 + 要求显式声明，
        # 不一致【且未声明】才红；而一致却声明"预期不同"同样出声（反方向的不符一样是错）。
        col.add_argument(
            "--baseline-expect",
            # 🔴 字面量而不是从 collect 导入常量:collect 是惰性导入的（§0② 故障隔离，
            # 纯 report 路径不该拉进 active-eval/httpx）。为一个 choices 破坏那条隔离不值。
            # ⚠️ 代价：两处各有一份取值域 ⇒ 由 tests 钉住它们必须相等。
            choices=("same", "different"),
            default=None,
            help="declare BEFORE the run whether this run's ruleset is expected to be the SAME as "
            "or DIFFERENT from --baseline-bundle's. mismatch + 'different' ⇒ recorded and allowed; "
            "mismatch + undeclared ⇒ 🔴 halt; matched + 'different' ⇒ also surfaced (a declaration "
            "that disagrees with the fact in EITHER direction is wrong). Omitted ⇒ any mismatch halts",
        )
        # 🔴 A2 件⑧ —— 留出语料【落地那一刻】网关加载的 ruleset_sha256。
        # 它与本跑的 build_fingerprint_before 比对，回答「这批材料落地之后，有没有人照着它改规则」。
        # ⚠️ 必须由操作者声明，**不得从本跑推导**：两侧同源 ⇒ 这道门恒为 matched，
        # 而一道恒真的门与没有门的区别只在它会让人以为有人在守。
        col.add_argument(
            "--material-ruleset-sha256",
            default=None,
            metavar="SHA256",
            help="the ruleset_sha256 in force when this run's HOLDOUT material landed (operator-"
            "declared). Compared against build_fingerprint_before.runtime.ruleset_sha256 ⇒ "
            "matched / mismatch. Omitted ⇒ 'unverifiable' — NEVER read as 'no problem'. "
            "🔴 Do not pass this run's own sha to make it green: both sides would come from one "
            "source and the gate would certify nothing",
        )
        # EV-COVERAGE E3-n ④ — the gateway admin base (GET /admin/v1/buildinfo). Passed to
        # GatewayTarget so collect can capture the build fingerprint before AND after the run and prove
        # zero-change during the freeze (also the drain-cursor base). Env: TREVAL_EVAL_ADMIN_URL.
        col.add_argument(
            "--admin-url",
            default=os.environ.get("TREVAL_EVAL_ADMIN_URL"),
            help="gateway admin base URL (GET /admin/v1/buildinfo — captures the tested party's build "
            "fingerprint before/after the run to VERIFY zero-change during the freeze; E3-n ④)",
        )
        if name == "run":
            col.add_argument("--posture", default=None)
            col.add_argument(
                "--format", choices=("json", "human", "csv"), default="human"
            )
            # --out is the REPORT output (e.g. report.csv); the bundle goes here.
            col.add_argument("--bundle-out", default=None)
            col.set_defaults(func=_cmd_run)
        else:
            col.set_defaults(func=_cmd_collect)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # argparse guarantees `func` (required subcommand + set_defaults on each).
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
