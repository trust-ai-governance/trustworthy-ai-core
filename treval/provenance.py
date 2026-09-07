"""Run provenance — pin an evaluation run to a reproducible window + WAL bytes (EV-PIN).

**The problem this exists to kill.** A report whose window is "the latest" is a snapshot of a
MOVING target: the WAL tail advances and the same citation stops reproducing. That already bit
us — a whitepaper cited `chain_integrity 100% n=463` taken from the live `__eval__` window, and
once the window moved 463 could never be reproduced again.

**The rule.** An externally-quoted number must come from a PINNED run: explicit window bounds +
the WAL segment bytes it read + the date. Given the same WAL and the same bounds, a third party
recomputes the same n and the same value. `pinned: false` marks a moving-window snapshot, which
external documents must not cite.

Pure: stdlib + `tools._wal_format`. No engine grading, no web, no network.

---

**Half-open windows — the off-by-one that would silently break reproducibility.**
`WalEvidenceReader` filters `received_at_ns >= time_from_ns` and `< time_to_ns` — `to` is
EXCLUSIVE. So the observed window of a scan is `[min, max + 1)`, NOT `[min, max]`: re-running
with `to = max` would drop the very last record and yield a different n. `observed_window`
therefore returns the half-open form, which round-trips exactly.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools._wal_format import list_segments
from treval.models import AuditEvidence


@dataclass(frozen=True)
class WalSegments:
    """The WAL segment range a run read, plus a content hash over their bytes — the handle a
    third party uses to confirm "you ran THIS batch of WAL", not some other one."""

    first: str
    last: str
    count: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "first": self.first,
            "last": self.last,
            "count": self.count,
            "sha256": self.sha256,
        }


def segment_provenance(wal_dir: str | Path) -> WalSegments | None:
    """Hash the WAL segments present in `wal_dir`, in segment order.

    The digest binds each segment's NAME and its BYTES (name, NUL, bytes, NUL), so neither a
    rename nor a content edit can pass unnoticed. Returns None for an empty/absent directory —
    a run over no segments has no provenance to claim."""
    directory = Path(wal_dir)
    try:
        paths = list_segments(directory)
    except (OSError, ValueError):
        return None
    if not paths:
        return None

    digest = hashlib.sha256()
    for path in paths:  # list_segments sorts by start seq — deterministic order
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return WalSegments(
        first=paths[0].name,
        last=paths[-1].name,
        count=len(paths),
        sha256="sha256:" + digest.hexdigest(),
    )


def observed_window(evidence: Iterable[AuditEvidence]) -> tuple[int, int] | None:
    """The HALF-OPEN window `[min, max + 1)` actually covered by `evidence`.

    `+1` is not cosmetic: the reader's upper bound is exclusive, so this is the interval that
    re-selects exactly these records. Returns None for an empty scan (no window to claim —
    the caller must not invent one)."""
    times = [ev.received_at_ns for ev in evidence]
    if not times:
        return None
    return (min(times), max(times) + 1)


class JudgeImprintError(Exception):
    """`--judge-imprint` 指向的文件不能当作一份指纹 —— fail-closed，不降级成"没取"。

    🔴 降级会把**操作者以为取到了**和**明确说没取**合成一格，而前者是 09-05 那次的形状。
    """


def resolve_judge_imprint(value: str | None) -> dict[str, Any] | str | None:
    """把 `--judge-imprint` 的取值解析成 provenance 里那一格（三态之一）。

        未传        ⇒ None          这一跑没声明（老产物同形）
        "none"      ⇒ "not_taken"   操作者明确说这一跑没取
        <路径>      ⇒ {path, sha256, bytes}

    🔴 **0 字节 / 读不出的文件一律拒（抛错），不许记成 `taken`。**
    空文件的 sha256 是一个完全合法的哈希（`e3b0c442…`）—— 若照单收下，这一格会对
    2026-09-05 那份 **0 字节的 `judge_imprint_pre_…_1528.json`** 输出 `taken:e3b0c442`。
    **那正是这道门要拦的那一跑，而它会说"通过"。** 一道对着自己要拦的那件事说通过的门，
    比没有门贵 —— 所以这里 fail-closed，且**不**回落成 `not_taken`：
    "我以为取到了"与"我明确说没取"是两件事，合成一格就把前者洗成了一个像样的声明。
    """
    if value is None:
        return None
    if value == "none":
        return "not_taken"
    p = Path(value)
    try:
        data = p.read_bytes()
    except OSError as e:
        raise JudgeImprintError(f"🔴 --judge-imprint 读不出：{p} —— {e}") from e
    if not data:
        raise JudgeImprintError(
            f"🔴 --judge-imprint 指向的文件是 0 字节：{p}\n"
            "  一次失败的 imprint 不是一份指纹。若这一跑确实没取，显式写 `--judge-imprint none`\n"
            "  （那会记成 not_taken —— 一个可读的缺席，而不是一个看起来取到了的哈希）"
        )
    return {
        "path": str(p),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def build_provenance(
    *,
    wal_dir: str | Path | None,
    window: tuple[int, int] | None,
    pinned: bool,
    tenant_id: str,
    record_count: int,
    observed_window: tuple[int, int] | None = None,
    generated_at_ns: int | None = None,
    language_scope: str | None = None,
    tested_version: str | None = None,
    detect_config: str | None = None,
    exec_mode: str | None = None,
    detection_layer_status: str | None = None,
    upstream_timeout_s: float | None = None,
    judge_form: str | None = None,
    measurement_path: str | None = None,
    tau_declared: str | None = None,
    tau_source: str | None = None,
    judge_imprint: dict[str, Any] | str | None = None,
    material_ruleset_sha256: str | None = None,
    policy_snapshots: tuple[str, ...] = (),
    config_source: str = "declared",
    tier2_drain_executed: bool = False,
    build_fingerprint_before: dict[str, Any] | None = None,
    build_fingerprint_after: dict[str, Any] | None = None,
    admin_url_declared: bool = False,
    probe_window: tuple[int, int] | None = None,
    arm_parity: str = "hard_or_flag",
    benign_arm: str = "",
    canary_set_id: str | None = None,
    guardrail_cursor_before: dict[str, Any] | None = None,
    guardrail_cursor_after: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The run's pin artifact, embedded in the collect bundle (EV-PIN §1.3).

    `pinned` is True only when the operator supplied BOTH window bounds — that is the whole
    claim: this run is reproducible from its inputs. A run whose window was merely *observed*
    is honest about covering that range but is still a snapshot of wherever the WAL happened
    to be, so it reports `pinned: false` and must not be cited externally (§1.4).

    EV-COVERAGE E3-h (§3.1) — the freeze pack must also record what SCOPES the numbers: the
    tested party's `tested_version`, its detection `detect_config` (esp. encode/decode on-off),
    and the `exec_mode` (`block` = hit⇒deny, `flag` = mark-only). 🔴 These keys are ALWAYS emitted
    (empty when the operator didn't declare them) so citability can tell a v2 run that DIDN'T declare
    (keys present-but-empty) apart from a pre-E3 bundle (keys absent). `config_source` records HOW
    they arrived (`declared` now; `queried` reserved for a future version/config endpoint) — it is
    metadata, NOT part of the citability criterion (the criterion is fields-present, not their source)."""
    segments = segment_provenance(wal_dir) if wal_dir else None
    return {
        # What KIND of data this is, declared positively. A run built here always read a real
        # WAL, so it is `measured`. The demo generator declares `synthetic_demo` instead —
        # both sides state their kind rather than one being inferred from the other's absence,
        # because a synthetic report that renders identically to a measured one is how a
        # fabricated sample size reached an external document once already (PROV §5, n=520).
        "data_source": "measured",
        "pinned": pinned,
        "tenant_id": tenant_id,
        "window": list(window) if window else None,
        "window_semantics": "half-open [from_ns, to_ns)",
        "wal_dir": str(wal_dir) if wal_dir else None,
        "wal_segments": segments.as_dict() if segments else None,
        "record_count": record_count,
        # EV-CITE C12 — the window the records ACTUALLY occupy. For a normal run it is the span
        # covered by the scan; when a PINNED window caught nothing (record_count==0), the caller
        # supplies the UNFILTERED span so the citability blocker can hand the operator a window to
        # re-pin (they must never have to compute nanoseconds themselves). None ⇒ no records to point at.
        "observed_window": list(observed_window) if observed_window else None,
        # EV-CITE C15 — the wall clock at collect time, stamped INTO the product. citability judges an
        # unclosed (future-upper-bound) window from this field, never by reading the clock at report
        # time — a bundle carries its own basis so it stays judgeable after it changes hands. None ⇒
        # a pre-C15 bundle with no stamp; the future-upper-bound blocker then skips (no clock fallback).
        "generated_at_ns": generated_at_ns,
        # EV-COVERAGE E3-h/E3-m (§3.1 / §2.2.2 / §5) — what scopes "89%": the #1 axis is the
        # `language_scope` (upstream rules English numbers fail-closed for the Chinese market), then
        # the tested party's version, its key detection config switches, and the execution mode
        # (block / flag). 🔴 ALL ALWAYS present (empty when undeclared) so present-but-empty (a v2 run
        # that didn't declare) is distinguishable from absent (a pre-E3 bundle). 🔴 language_scope is
        # an operator DECLARATION (the --language-scope flag), NEVER inferred from case bytes.
        # `config_source` is HOW they arrived — metadata, not the criterion.
        "language_scope": language_scope or "",
        "tested_version": tested_version or "",
        "detect_config": detect_config or "",
        "exec_mode": exec_mode or "",
        # EV-COVERAGE E3-n ③ — the freeze pack must ALSO pin the DETECTION-LAYER STATUS (which layers
        # are live, e.g. tier1_only / tier2 shadow off) and the tested party's UPSTREAM REQUEST-TIMEOUT
        # (its OWN hardcoded value, DECLARED — the client --timeout is then derived as 2×, not guessed).
        # Both fold into the SAME missing_run_config citability criterion. Present-but-empty (""/null on
        # a v2 run that didn't declare) is distinguishable from ABSENT (a pre-E3-n bundle), like the four
        # keys above. upstream_timeout_s stays a number (the declared seconds), null when undeclared.
        "detection_layer_status": detection_layer_status or "",
        "upstream_timeout_s": upstream_timeout_s,
        # 🔴 EV-CN-BENIGN-N180 件0 (= EV-JUDGE-UNION 件3(a2)) — the JUDGE/τ declaration axes ride WITH the
        # numbers, folding into the SAME missing_run_config criterion (present-but-empty ⇒ a run that
        # didn't declare; absent ⇒ a pre-N180 bundle diagnosed as DRIFT). `measurement_path` IS the
        # assembly axis (offline harness vs in-product gateway); no separate `assembly` / `config_literal`.
        "judge_form": judge_form or "",
        "measurement_path": measurement_path or "",
        "tau_declared": tau_declared or "",
        "tau_source": tau_source or "",
        # 🔴 弱门（PM 2026-09-07）—— 这一跑的判官指纹取了没有。三态，`None` 与 `"not_taken"` 不许合并：
        #   None        这一跑连声明都没有（老产物 / 忘了）
        #   "not_taken" 操作者**明确说**这一跑没取
        #   {...}       取了，记路径 + sha256 + 字节数
        # ⚠️ 它**不**判"这份指纹取于本跑窗口之内"（09-05 那份取于跑后 15 分钟，一样会是 taken）——
        # 同窗门是下一轮，卡在 imprint 侧还没有 `taken_at`。见 citability.judge_imprint_state。
        "judge_imprint": judge_imprint,
        # 件⑧ — the ruleset_sha256 at HOLDOUT-MATERIAL-LANDING time; compared against the run-start
        # fingerprint so "nobody tuned to the material" is a fingerprint fact, not an attestation.
        "material_ruleset_sha256": material_ruleset_sha256 or "",
        # 🔴 本跑读的是**哪一条良性臂**（`--benign-arm`，默认 llm01_benign_holdout）。
        # 在此之前它只活在运行参数里，产物答不出「这个数出自哪一条臂」—— 而随数走的分母构成声明
        # 恰恰只对其中一条臂成立：不记臂名，那条声明要么挂不上，要么挂上就是一句假话。
        # "" = 未声明（不是"跑在默认臂上"：两者在下游读起来一样，所以不许合并）。
        "benign_arm": benign_arm or "",
        # 🔴 本跑【实测】跑在哪些规则内容指纹上（被测方在每条决策记录上盖的章）。
        # 与 `detect_config`（操作者声明的字符串）是两回事：后者填错了没人知道，指纹填不了错。
        # 它在这里的用途是【记账】：对同一批语料改了检测内容又跑了几次，
        # 第三方数产物里不同指纹的个数就能答，不必相信任何人的自述 ——
        # 而按"跑批次数"记会漏掉秒级迭代（改一条 Tier-1 不需要判官、不需要真上游）。
        "policy_snapshots": list(policy_snapshots),
        "config_source": config_source,
        # EV-COVERAGE E3-n ② — did the async Tier-2 drain execute this run? Recorded so a Tier-2 layer
        # that was never drained cannot be read as "0% lift" — the freeze pack states the layer's status.
        "tier2_drain_executed": tier2_drain_executed,
        # EV-COVERAGE E3-n ④ — the tested party's self-reported build fingerprint (git_sha +
        # detection_switches, GET /admin/v1/buildinfo) captured BEFORE and AFTER the run, stored
        # VERBATIM (evidence in the artifact, not just compared-then-discarded). citability compares
        # them: any bit of difference ⇒ the tested party changed mid-run ⇒ NOT citable. null when no
        # admin endpoint was queried (no --admin-url).
        "build_fingerprint_before": build_fingerprint_before,
        "build_fingerprint_after": build_fingerprint_after,
        # E3-n ④ — whether --admin-url was declared. citability fail-closes a declared-but-unfetched
        # build-fingerprint check (both-None blocks ONLY when the admin endpoint was actually named).
        "admin_url_declared": admin_url_declared,
        # E3-n ② — this run's probe span [first, last+ε), half-open. The ACTIVE rates (catch / FPR /
        # four-cell / success) cite THIS in their citation_form; passive / census indicators keep
        # `observed_window` (the WAL range they actually read). None when nothing was probed.
        "probe_window": list(probe_window) if probe_window else None,
        # E3F §1 (F1) — injection_catch_rate now counts a catch ONLY when a matched INJECTION rule
        # earned it (rule-scoped attribution), never "the gateway reacted for any reason". Stamped as a
        # CONSTANT because Core always attributes post-F1: its PRESENCE marks the new epoch, so a
        # rule_scoped run's catch number is 🔴 NOT comparable to a pre-F1 (key-absent) run's (§1.4).
        "catch_attribution": "rule_scoped",
        # E3F §4 (F4) — the ARM-PARITY口径 the catch AND benign arms shared this run (hard_or_flag /
        # hard_only). Recorded so a run whose two arms disagreed can be refused (§4.4-4) and so the
        # benign gate is read on the same basis the catch number was.
        "arm_parity": arm_parity,
        # F7 (E3F §7.3-③/§7.4-4) — this run's canary-set identity: a sha256-of-salt handle, 🔴 NEVER the
        # salt or any canary plaintext. Pins WHICH canary epoch produced the numbers, so two runs stay
        # comparable (same corpus_sha, rotated canaries). None when nothing was probed / no canary set.
        "canary_set_id": canary_set_id or None,
        # 🔴 序8 件3 — the /admin/v1/audit:cursor readings taken BEFORE (pre-flight) and AFTER the Tier-2
        # drain, stored VERBATIM (guardrail_effective_coverage / guardrail_skipped_total / degraded /
        # degraded_since_ns / batch_failures / unread_hole_seqs / cursor_seq / … — the endpoint's own
        # field names, unchanged, unselected). 🔴 emit-NOT-interpret, same discipline as
        # build_fingerprint: the gateway's guardrail_* is a SELF-REPORTED counter, our no_async is
        # MEASURED from the WAL record-by-record — we store BOTH so R5 can CROSS-CHECK them (a mismatch
        # is itself a finding: a dropped counter, or a record that never reached the WAL). We do NOT
        # adopt the counter over the measurement (that is the build_facts direction, backwards). null
        # when the cursor endpoint was absent / unreachable (a warning records which).
        "guardrail_cursor_before": guardrail_cursor_before,
        "guardrail_cursor_after": guardrail_cursor_after,
    }
