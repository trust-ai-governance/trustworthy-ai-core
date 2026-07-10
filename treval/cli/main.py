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
from pathlib import Path

from treval.cli.bundle import BundleError, load_bundle
from treval.cli.render import render_csv, render_human
from treval.posture import PostureFileError, PostureFileReader
from treval.registry import DimensionRegistry, RegistryError, load_registry
from treval.rubric import DuplicateIndicatorError, bundle_to_json, evaluate

EXIT_OK = 0
EXIT_GRADING = 2
EXIT_IO = 3


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

    report = evaluate(
        reg,
        bundle.measurements,
        posture,
        window=bundle.window,
        tenant_id=bundle.tenant_id,
    )

    if fmt == "json":
        text = bundle_to_json(report, bundle.measurements)
    elif fmt == "csv":
        text = render_csv(reg, report, bundle.measurements)
    else:  # human
        text = render_human(
            reg, report, bundle.measurements, tuple(warnings), color=color
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


def _cmd_report(args: argparse.Namespace) -> int:
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
    except (BundleError, RegistryError, PostureFileError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_IO

    # Warnings always go to stderr (json/csv stdout stays clean; human embeds them too).
    if warnings:
        print(f"⚠ {len(warnings)} warning(s):", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)
    _emit(text, args.out)
    return EXIT_OK


def _cmd_collect(args: argparse.Namespace) -> int:
    # Operator path — imported lazily so the pure `report` path never pulls in the
    # active-eval harness / its httpx dependency (fault isolation, §0②).
    from treval.cli.collect import run_collect

    return run_collect(args)


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
    rep.set_defaults(func=_cmd_report)

    for name, help_text in (
        ("collect", "drive the live gateway → Measurement bundle (operator)"),
        ("run", "collect ∘ report (convenience)"),
    ):
        col = sub.add_parser(name, help=help_text)
        col.add_argument("--gateway", default=os.environ.get("TREVAL_EVAL_GATEWAY_URL"))
        col.add_argument("--wal", default=os.environ.get("TREVAL_EVAL_WAL_DIR"))
        col.add_argument("--corpus", default=None)
        col.add_argument(
            "--tenant", default=os.environ.get("TREVAL_EVAL_TENANT", "__eval__")
        )
        # The eval user MUST be provisioned on the target (an unprovisioned user makes
        # every probe unmeasurable — silently). Mirror eval_report's env contract so a
        # `collect` run isn't quietly empty. Model likewise deployment-specific.
        col.add_argument(
            "--user", default=os.environ.get("TREVAL_EVAL_USER", "eval-user")
        )
        col.add_argument(
            "--model", default=os.environ.get("TREVAL_EVAL_MODEL", "deepseek-v4-flash")
        )
        col.add_argument("--out", default=None)
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
