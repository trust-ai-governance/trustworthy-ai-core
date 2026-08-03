"""Threshold-registry gate (CI) — every judgment threshold must be registered with a real code home.

**Why this exists (two incidents, both caught by a person, not a gate):** a `0.05` that lived only in
the README with no code that ever compared to it; and two different `0.80`s (τ_recall vs a coverage
target) that collided for rounds until PM had to pick among options. Implementer debt is caught by
architect review; architect debt had no gate. This is that gate (GATE-CONSISTENCY 件二), built in the
SHAPE of tools/check_doc_disclosure.py / check_corpus_coverage.py — same `location / rule / why` output,
exit 1 on FAIL, run in CI (🔴 with PYTHONPATH — the corpus gate learned that the hard way).

It reads docs/THRESHOLDS.md (the single registry) and enforces:
  rule 1  — every registered `location` actually holds that value (empty/mismatch ⇒ FAIL);
  rule 2  — two names sharing a value with a BLANK scope ⇒ WARN (a value re-used without a stated
            reason is the "two 0.80s" trap — name both, demand the scope column);
  rule 3  — a registry `satisfied_when` threshold that is NOT registered here ⇒ FAIL (a new gate whose
            number lives nowhere in this table — the "0.05 in prose" trap).

Run:  PYTHONPATH=$PWD python tools/check_thresholds.py
"""

from __future__ import annotations

import argparse
import importlib
import sys
from dataclasses import dataclass
from pathlib import Path

from treval.registry import load_registry
from treval.registry.satisfied_when import parse_satisfied_when

_ROOT = Path(__file__).resolve().parents[1]
_TABLE = _ROOT / "docs" / "THRESHOLDS.md"
_EPS = 1e-9


@dataclass(frozen=True)
class Threshold:
    name: str
    value: float
    location: str
    scope: str


def _num(text: str) -> float:
    return float(text.strip().strip("`"))


def parse_table(md: str) -> list[Threshold]:
    """The registered thresholds from the THRESHOLDS.md markdown table (the one row `| name | value |
    location | scope | … |`). A row whose value/location won't parse is skipped — the header and the
    `|---|` separator among them."""
    out: list[Threshold] = []
    for line in md.splitlines():
        if not line.startswith("|") or "---" in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[0] in ("name", ""):
            continue
        name = cells[0].strip("`")
        try:
            value = _num(cells[1])
        except ValueError:
            continue  # header-ish / non-numeric row
        out.append(Threshold(name, value, cells[2].strip("`"), cells[3]))
    return out


def _sample_size_values(reg) -> set[float]:
    vals: set[float] = set()
    for dim in reg.dimensions.values():
        for objs in dim.levels.values():
            for o in objs:
                ev = o.evidence
                if ev.kind == "measured" and ev.satisfied_when:
                    field, _op, num = parse_satisfied_when(ev.satisfied_when)
                    if field == "sample_size":
                        vals.add(num)
    return vals


def _objective_threshold(reg, oid: str) -> float | None:
    for dim in reg.dimensions.values():
        for objs in dim.levels.values():
            for o in objs:
                if (
                    o.id == oid
                    and o.evidence.kind == "measured"
                    and o.evidence.satisfied_when
                ):
                    return parse_satisfied_when(o.evidence.satisfied_when)[2]
    return None


def _const_value(location: str) -> float | None:
    """`const:<module>:<NAME>` → the live constant, or None if it can't be resolved."""
    _kind, module, name = location.split(":", 2)
    try:
        mod = importlib.import_module(module)
        return float(getattr(mod, name))
    except (ImportError, AttributeError, TypeError, ValueError):
        return None


def check_rule1_locations(regs: list[Threshold], reg) -> list[tuple[str, str, str]]:
    """Each registered location must actually hold the value. (rule, name, why)."""
    ss_values = _sample_size_values(reg)
    problems: list[tuple[str, str, str]] = []
    for t in regs:
        if t.location == "registry:sample_size":
            if t.value not in ss_values:
                problems.append(
                    (
                        "rule1",
                        t.name,
                        f"no registry sample_size gate carries {t.value:g}",
                    )
                )
        elif t.location.startswith("registry:"):
            oid = t.location.split(":", 1)[1]
            found = _objective_threshold(reg, oid)
            if found is None:
                problems.append(
                    (
                        "rule1",
                        t.name,
                        f"objective {oid!r} has no measured satisfied_when (empty location)",
                    )
                )
            elif abs(found - t.value) > _EPS:
                problems.append(
                    (
                        "rule1",
                        t.name,
                        f"{oid} threshold is {found:g}, table says {t.value:g}",
                    )
                )
        elif t.location.startswith("const:"):
            found = _const_value(t.location)
            if found is None:
                problems.append(
                    ("rule1", t.name, f"cannot resolve {t.location} (empty location)")
                )
            elif abs(found - t.value) > _EPS:
                problems.append(
                    (
                        "rule1",
                        t.name,
                        f"{t.location} is {found:g}, table says {t.value:g}",
                    )
                )
        else:
            problems.append(
                (
                    "rule1",
                    t.name,
                    f"unresolvable location {t.location!r} — must be registry:/const:",
                )
            )
    return problems


def check_rule2_shared_values(regs: list[Threshold]) -> list[tuple[str, str, str]]:
    """Two+ names on one value with a BLANK scope on any of them ⇒ WARN (name both)."""
    by_value: dict[float, list[Threshold]] = {}
    for t in regs:
        by_value.setdefault(round(t.value, 9), []).append(t)
    warns: list[tuple[str, str, str]] = []
    for value, group in sorted(by_value.items()):
        if len(group) > 1 and any(not t.scope for t in group):
            names = ", ".join(t.name for t in group)
            warns.append(
                (
                    "rule2",
                    names,
                    f"share value {value:g} but a scope is BLANK — state why they don't collide",
                )
            )
    return warns


def check_rule3_unregistered(regs: list[Threshold], reg) -> list[tuple[str, str, str]]:
    """Every registry `satisfied_when` threshold value must be registered here (a new gate whose number
    lives nowhere in this table). Values are matched, not objective ids — a re-used value is rule 2's
    job, an UN-registered value is this one's."""
    registered = {round(t.value, 9) for t in regs}
    problems: list[tuple[str, str, str]] = []
    for dim in reg.dimensions.values():
        for objs in dim.levels.values():
            for o in objs:
                ev = o.evidence
                if ev.kind == "measured" and ev.satisfied_when:
                    _field, _op, num = parse_satisfied_when(ev.satisfied_when)
                    if round(num, 9) not in registered:
                        problems.append(
                            (
                                "rule3",
                                o.id,
                                f"satisfied_when {ev.satisfied_when!r} uses {num:g}, not registered in THRESHOLDS.md",
                            )
                        )
    return problems


def run(table_path: Path = _TABLE) -> tuple[list, list]:
    """(fails, warns). fails ⇒ exit 1."""
    regs = parse_table(table_path.read_text(encoding="utf-8"))
    reg = load_registry()
    fails = check_rule1_locations(regs, reg) + check_rule3_unregistered(regs, reg)
    warns = check_rule2_shared_values(regs)
    return fails, warns


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(prog="check_thresholds", description=__doc__).parse_args(
        argv
    )
    fails, warns = run()
    if not fails and not warns:
        print("threshold gate: PASS —— 全部判级/门控阈值已登记且落点非空")
        return 0
    out = sys.stderr if fails else sys.stdout
    print(f"threshold gate: {'FAIL' if fails else 'PASS(有 warn)'}\n", file=out)
    for rule, who, why in fails:
        print(f"[{rule}] {who}: {why}", file=out)
    for rule, who, why in warns:
        print(f"[{rule}] {who}: {why}", file=out)
    print(
        f"\nFAIL {len(fails)} 处 · WARN {len(warns)} 处。"
        "处置：把阈值登记进 docs/THRESHOLDS.md（引名字不引数值），或补上'作用域'列说明为何同值不冲突。",
        file=out,
    )
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
