"""EV-CITE 件一 — the report-level CITABILITY gate (+ the per-measurement `citation_form`, T3).

Pure stdlib, no rendering / HTTP, so the verdict is unit-testable alone — the same reason UI-3 split
`cases_auth` out. It reuses the pairing path's vocabulary VERBATIM (`pair.py`): `citable = not
blockers`; `citable_blockers` is a `list[str]` and EVERY entry NAMES A FIX; disclosure, not refusal
(EV-PAIR §5.4) — the product is emitted either way, the gate only says whether a number may leave
the room.

🔴 Only STANDING-UP blockers, never GOOD-LOOKING ones (§0). `unmet` (measured-but-below) and
`insufficient_data` are CITABLE — an honest "we measured, the interval is too wide" is the whole
measured>attested point (that lives in `measured_gap`, 件二, not here). The blockers are report-wide
PROVENANCE facts only:

  1. a broken integrity chain  (report.integrity_summary.broken > 0)  — FIRST, it voids everything;
  2. an unpinned window        (provenance.pinned is false);
  3. a missing segment hash     (provenance.wal_segments.sha256 empty);
  4. non-chain-anchored evidence (evidence_basis != "wal_anchored");
  5. missing run config         (freeze pack lacks language_scope / tested_version / detect_config /
                                 exec_mode / detection_layer_status / upstream_timeout_s — E3-h/m/n);
  6. a mid-run build change     (E3-n ④: /admin/v1/buildinfo fingerprint before != after).

🔴 There is NO dimension-level citable (C7): every blocker above is report-wide, and a forever-true
`citable ✅` pinned to a dimension would read as an endorsement it never earned.
"""

from __future__ import annotations

from typing import Any

from treval.models import INTERVAL_CENSUS, INTERVAL_TOTAL_FUNCTION, Measurement
from treval.registry.satisfied_when import (
    SatisfiedWhenError,
    compile_satisfied_when,
    parse_satisfied_when,
)

WAL_ANCHORED = "wal_anchored"

_UNPINNED_FIX = (
    "unpinned run（未固定窗口）：补 --window-from-ns / --window-to-ns 重跑 —— unpinned 的窗口是移动"
    "快照，第三方复算不出同一个数"
)
_SEGHASH_FIX = (
    "段哈希缺失（provenance.wal_segments.sha256 空）：补 pinned 重跑 —— 那段 sha256 就是第三方据以复"
    "算同一窗口的锚点"
)
_EVIDENCE_FIX = "证据基不是链锚定（evidence_basis != wal_anchored）：换 WAL 证据源 —— 索引/自述来源不可链校验"
_INTEGRITY_FIX = (
    "完整性破损（integrity_summary.broken > 0）：链断则其下所有结论不成立 —— 先用 wal_verify.py 查 "
    "WAL、修复链后重出报告"
)
_FUTURE_UPPER_FIX = (
    "固定窗口的上界在未来（window[1] 晚于本报告的生成时刻 generated_at_ns）：未闭合的窗口锚不住任何数 "
    "—— 明天重读同一份 WAL 会返回更多记录，数就变了。用一个已闭合的、过去的上界重新 pin"
    "（--window-to-ns 取一个已过去的时刻）"
)
_NO_STAMP_FIX = (
    "这份产物没有生成时刻 generated_at_ns，无法判断固定窗口是否已闭合 —— 用当前版本重新采集（collect）"
    "并重出报告，使其带上生成时刻；仅重跑 report 补不上这个采集期的数据"
)
# E3-n ④ — the tested party changed DURING the freeze. The build fingerprint (git_sha +
# detection_switches, GET /admin/v1/buildinfo) is fetched before AND after the run; a single-bit
# difference means the numbers describe no single system.
_BUILD_CHANGED_FIX = (
    "被测方在冻结期间发生变更（/admin/v1/buildinfo 的 build fingerprint 跑前跑后逐位不一致，git_sha/"
    "detection_switches 变了）：这一跑测的不是同一个系统 —— 作废重跑，不产 corpus_sha。冻结期零变更是"
    "【可验证的】（比对指纹，不是相信时间戳）"
)
# E3-n ④ fail-CLOSED — the SAME identity (build_fingerprint_changed), the OTHER failure mode: --admin-url
# was DECLARED but a snapshot could not be fetched (wrong port / non-200 / parse). "取不到" is a check
# that FAILED, not "no claim made" — treating it as the latter is exactly the fail-open that let a run
# built for verifying invariance emit a bare claim. Warnings say which side / why.
_BUILD_UNVERIFIED_FIX = (
    "声明了 --admin-url 却取不到被测方构建指纹（跑前或跑后 /admin/v1/buildinfo 失败 —— 见 warnings 里"
    "哪一侧、什么原因；常见是 admin 面在 :8081 而给成了 :8080）：取不到 = 无法核验冻结期间零变更，按 "
    "fail-closed 判不可引 —— 修正 admin 地址重跑，不产 corpus_sha。'取不到'不是'没声明'"
)
# E3-h/E3-m (§3.1/§5) — ONE blocker identity, TWO messages chosen by absent-vs-empty (timing-
# independent). The scope now leads with language_scope (E3-m); updating these strings is a 文案
# change only (the identity `missing_run_config` is unchanged), so it does NOT bump CRITERIA_VERSION.
_CONFIG_DRIFT_FIX = (
    "本报告按旧判据（config 尚未要求时）产出，冻结包缺语言作用域/被测方版本/检测配置/执行模式/检测层状态/"
    "上游超时 —— 不是坏了，用当前版本重新采集（collect）即可引"
)
_CONFIG_UNDECLARED_FIX = (
    "这次跑没声明语言作用域/被测方版本/检测配置/执行模式/检测层状态/上游超时（决定「89%」代表哪种语言"
    "流量、在哪个版本、编码解码开关、拦截还是只标记、哪些检测层在跑、被测方上游超时多少下测的）—— 补声明"
    "重跑：--language-scope / --tested-version / --detect-config / --exec-mode / --detection-layer-status "
    "/ --upstream-timeout-s"
)

# --------------------------------------------------------------------------- #
# 🔴 C16 — a citability verdict is a serialized boolean baked in at generation time, so on its own it
# is UNFALSIFIABLE: a reader cannot tell WHICH criteria produced it. The gate has already tightened
# (C15's fail-closed no-stamp rule; then E3-h's freeze-pack config requirement), so a stored
# `citable=true` (old gate) can disagree with a fresh report_citability on the SAME immutable bundle
# — pure criteria drift, otherwise invisible. So the verdict must travel WITH a version, and the
# version is bound to the IDENTITY of the blockers this gate can emit — not to their message wording.
# --------------------------------------------------------------------------- #
# 1→2: E3-h added the missing_run_config blocker (freeze-pack config required). E3-m then FOLDED
# language_scope INTO that same criterion (same `missing_run_config` identity, no re-bump). E3-n now
# folds into the SAME uncommitted v2 (no re-bump, exactly like E3-m): ③ EXTENDS _config_keys under the
# SAME missing_run_config identity (detection_layer_status + upstream_timeout_s — fields present-or-not,
# no new identity); ② adds NO blocker (a not-drained Tier-2 layer emits n/a, and n/a is CITABLE); only
# ④ adds ONE new identity (`build_fingerprint_changed`). All three land BEFORE commit, so v2 covers
# them at zero cost (a post-commit fold would have been a second bump + a second wave of invalidation).
CRITERIA_VERSION = 2

# The stable identity keys this version's gate can emit — one per blocker-append site in
# report_citability. 🔴 add / remove / repurpose any entry ⇒ BUMP CRITERIA_VERSION (a stricter OR a
# looser gate is a DIFFERENT gate, and any verdict judged under the old set must be re-judged).
# Editing only a message VALUE (文案) of a `_*_FIX` string is NOT a criteria change and does NOT bump
# — what would have changed is the prose, not the identity set below.
CRITERIA_BLOCKERS: frozenset[str] = frozenset(
    {
        "integrity_broken",  # _INTEGRITY_FIX
        "pinned_empty_window",  # C12 empty-window blocker
        "future_upper_bound",  # _FUTURE_UPPER_FIX (C15)
        "no_generated_at_ns",  # _NO_STAMP_FIX (C15, fail-closed)
        "unpinned",  # _UNPINNED_FIX
        "missing_segment_hash",  # _SEGHASH_FIX
        "not_wal_anchored",  # _EVIDENCE_FIX
        "missing_run_config",  # _CONFIG_DRIFT_FIX / _CONFIG_UNDECLARED_FIX (E3-h/m/n) — ONE identity,
        # E3-n ③ EXTENDS its _config_keys (detection_layer_status + upstream_timeout_s), no new identity
        "build_fingerprint_changed",  # _BUILD_CHANGED_FIX (E3-n ④) — the ONE new identity this fold adds
    }
)


def report_citability(bundle: dict[str, Any]) -> tuple[bool, list[str]]:
    """`(citable, citable_blockers)` for a SELF-CONTAINED bundle (it alone carries `provenance`).

    🔴 `citable == (citable_blockers == [])` — identical semantics to the pairing path. The list is
    ordered so a broken chain is the FIRST blocker (acceptance 6): it is the deepest failure, and its
    fix (verify the WAL) precedes everything else."""
    prov = bundle.get("provenance") or {}
    report = bundle.get("report") or {}
    integrity = report.get("integrity_summary") or {}
    segments = prov.get("wal_segments") or {}

    blockers: list[str] = []
    if int(integrity.get("broken", 0) or 0) > 0:
        blockers.append(
            _INTEGRITY_FIX
        )  # FIRST — a broken chain voids all conclusions beneath it
    # 🔴 C14 — the WINDOW-FAMILY blockers (C12 / C15 / unpinned / segment-hash) apply when this run
    # DECLARED a WAL evidence source (provenance.wal_dir set), OR when it carries NO provenance at
    # all. The trigger is INTENT ("a WAL source was named"), NOT a RESULT: keying on `mode`/
    # record_count would exempt a pinned-EMPTY-window run (record_count==0 ⇒ the C12 symptom) from
    # the very C12 blocker built to catch it — "代理不是判据". The exemption (skip these) is ONLY the
    # genuine pure-active case: a PRESENT provenance that explicitly names no WAL source (wal_dir
    # None) — a raw_model run, or a gateway run given no --wal — where a window pins nothing and
    # reproducibility rests on corpus_sha + evidence_refs. A run that named --wal but read 0 records
    # keeps wal_dir SET ⇒ NOT exempt. 🔴 A bundle with provenance ABSENT (null — a pre-EV-PIN or
    # unknown bundle) is NOT that declaration; it made no active-anchoring claim either, so it must
    # fail closed (window-family applies ⇒ unpinned blocks it), never slip through the exemption.
    if bundle.get("provenance") is None or prov.get("wal_dir"):
        # 🔴 C12 — a pin over an EMPTY window: "运营方声明了窗口 W" is a claim someone must stand
        # behind, so we never auto-pin; but the claim is machine-checked. A pinned window with 0
        # records anchors NOTHING (a proxy — "人传了参" ≠ "参对得上数"). The report hands over the
        # ACTUAL observed window so the operator re-pins by copying, never by computing nanoseconds
        # (acceptance 21). 🔴 C15: it also tells them NOT to widen into the future — else the report
        # itself teaches踩洞 (the fix invites the unclosed-window hole).
        if prov.get("pinned") and prov.get("record_count") == 0:
            ow = prov.get("observed_window")
            where = (
                f"本次实际观测到的窗口是 [{ow[0]}, {ow[1]})，用它重新 pin。"
                if isinstance(ow, (list, tuple)) and len(ow) == 2
                else "该 WAL 内也没有该租户的任何记录 —— 先确认 --wal 目录与 --tenant。"
            )
            blockers.append(
                f"固定窗口内没有任何 WAL 记录 —— 该窗口锚不住本报告的任何数字。{where}"
                "🔴 不要把上界放宽到未来 —— 未闭合的窗口锚不住任何数。"
            )
        # 🔴 C15 — an UNCLOSED pin is not a pin. The judgement uses data INSIDE the product
        # (generated_at_ns), NEVER the wall clock at read time, so the verdict survives the bundle
        # changing hands. A PINNED run MUST carry generated_at_ns (a collect-time datum): MISSING it
        # is fail-CLOSED — the pin's closure is unverifiable, so it blocks (same repo posture as C12:
        # an unverifiable claim ⇒ refuse). "不在读取时取时钟" is about the datum's SOURCE, not "skip
        # when absent". 🔴 口径: this makes ALL pre-C15 pinned bundles NOT citable until regenerated
        # (incl. the stored __eval__ report, wal_dir set + generated_at_ns=None) — intended, they
        # genuinely cannot prove the window is closed. window[1] > generated_at_ns ⇒ the upper bound
        # has not passed: re-reading later returns MORE records and the number moves.
        if prov.get("pinned"):
            gen = prov.get("generated_at_ns")
            window = prov.get("window")
            if gen is None:
                blockers.append(_NO_STAMP_FIX)
            elif window and window[1] > gen:
                blockers.append(_FUTURE_UPPER_FIX)
        if not prov.get("pinned", False):
            blockers.append(_UNPINNED_FIX)
        if not segments.get("sha256"):
            blockers.append(_SEGHASH_FIX)
        # 🔴 E3-h/E3-m (§3.1 / §5) — the freeze pack must carry what SCOPES the numbers: the #1 axis
        # LANGUAGE_SCOPE (which language(s)/traffic — upstream rules English numbers fail-closed for the
        # Chinese market), then the tested party's VERSION, its key detection CONFIG (esp. encode/decode
        # on-off), and the EXECUTION MODE (block/flag). Without them "89%" is unscoped and not citable.
        # 🔴 The criterion is fields-PRESENT — INDEPENDENT of HOW they arrived (config_source is
        # metadata, never the gate): baking "declared" into it would force a SECOND re-judge wave when a
        # query endpoint lands. 🔴 language_scope is a DECLARATION (the --language-scope flag), NEVER
        # inferred from case bytes. ONE identity (`missing_run_config`), TWO messages chosen by
        # ABSENT-vs-EMPTY (timing-independent): keys absent ⇒ a pre-E3 bundle, diagnosed as DRIFT not a
        # defect (mirrors C16's stored-vs-recompute face); present-but-empty ⇒ a v2 run that just
        # didn't declare (fixable by re-running with the flags).
        # 🔴 E3-n ③ — detection_layer_status + upstream_timeout_s fold into the SAME missing_run_config
        # identity (fields present-or-not, INDEPENDENT of how the value arrived — E3-h criterion). NOT a
        # new blocker identity: the append site below is unchanged, so CRITERIA_BLOCKERS' identity set
        # gains nothing from ③ (only ④ adds one), and CRITERIA_VERSION stays 2.
        _config_keys = (
            "language_scope",
            "tested_version",
            "detect_config",
            "exec_mode",
            "detection_layer_status",
            "upstream_timeout_s",
        )
        if not all(prov.get(k) for k in _config_keys):
            _keys_present = all(k in prov for k in _config_keys)
            blockers.append(
                _CONFIG_UNDECLARED_FIX if _keys_present else _CONFIG_DRIFT_FIX
            )
    # 🔴 E3-n ④ — the tested party's zero-change-during-freeze claim, VERIFIED not trusted. The build
    # fingerprint (git_sha + detection_switches, GET /admin/v1/buildinfo) is captured before AND after
    # the run and stored verbatim. NOT gated on wal_dir (a build change voids any run). 🔴 A fingerprint
    # COMPARE, never a timestamp (a self-reported "stopped at T" is exactly the attest this repo replaces).
    # 🔴 E3-n ④ THREE-STATE (fail-CLOSED) — a binary `both-present-and-differ` was fail-OPEN: a run
    # that DECLARED --admin-url but fetched nothing (wrong port ⇒ both null) slipped through as "no
    # claim". So key on `admin_url_declared` (the CLAIM): given the claim, the run is citable ONLY if
    # BOTH snapshots were fetched AND are bit-identical. Either side missing ⇒ the check FAILED ⇒ block
    # (a distinct message; warnings name which side / why). No --admin-url ⇒ no claim ⇒ not checked.
    before = prov.get("build_fingerprint_before")
    after = prov.get("build_fingerprint_after")
    if prov.get("admin_url_declared"):
        _fp_fix = None
        if before is None or after is None:
            _fp_fix = _BUILD_UNVERIFIED_FIX  # declared but unreachable = check failed, not absent
        elif before != after:
            _fp_fix = _BUILD_CHANGED_FIX  # changed mid-run
        if _fp_fix:
            blockers.append(_fp_fix)
    if bundle.get("evidence_basis") != WAL_ANCHORED:
        blockers.append(_EVIDENCE_FIX)
    return (not blockers, blockers)


# --------------------------------------------------------------------------- #
# EV-R2 §9.7 — the observable-subset bias, as ONE shared note. `injection_success_rate` and the
# `@outcome_observable` stratum of `injection_catch_rate` are measured over the output_marker-bearing
# subset ONLY, which favours lexically-salient, detector-easy attacks (evasive-encoding /
# language-switch / translation cases plant no marker) ⇒ the number is OPTIMISTICALLY biased vs a
# representative attack distribution. 🔴 The pairing path (pair.py) and the citation_form MUST share
# this ONE note — a second copy would drift ("建成 ≠ live"). "number", not "delta", so it fits both.
# --------------------------------------------------------------------------- #
OBSERVABLE_BIAS_NOTE = (
    "🔴 measured on the output_marker-bearing subset ONLY — biased toward detector-easy attacks; this "
    "number is OPTIMISTICALLY biased vs a representative attack distribution (mechanism-consistent, "
    "NOT proven; EV-R2 §9.7)"
)
OBSERVABLE_BIASED_IDS = frozenset({"injection_success_rate"})
_OUTCOME_OBSERVABLE_SUBJECT = "outcome_observable"

# --------------------------------------------------------------------------- #
# E3-i (§2.2.3 ③) — `injection_catch_rate` NAMES an attribution ("injection detection caught it"), but
# a blocked case might have been blocked by a CONTENT rule. The口径 must therefore state HOW that
# attribution was established: via the CONTROL ARM (a verbatim external payload re-run with the
# injection SKELETON removed — if the bare payload is ALSO caught, the partner's catch is not credited
# to injection). 🔴 A SIEVE, not a certificate: it FALSIFIES a claim, it never proves one. This rides
# WITH the number (like the config note + the observable-bias caveat) so the scope + attribution method
# travel with a quoted "89%".
# --------------------------------------------------------------------------- #
ATTRIBUTION_ESTABLISHED_IDS = frozenset({"injection_catch_rate"})
ATTRIBUTION_ESTABLISHED_NOTE = (
    "🔴 归因作用域：'注入检测'的归因经【对照臂】确立（§2.2.3，非声称）—— 对每个逐字外部载荷再跑一次"
    "【去掉注入骨架的裸载荷】：裸载荷仍被拦的件，其搭档已退出本分母；无对照探针的逐字外部件不计入。"
    "对照是筛子非证书：能证伪归因，不能单证某次 catch 必来自注入规则"
)

# --------------------------------------------------------------------------- #
# E3-n ① / §2.2.4③ (acceptance 24) — false_positive_rate is an INPUT-stage lexical detector, and §4's
# honesty boundary requires its citation to STATE what it cannot do: "明知一类合法请求会被误拦却只出
# 'FPR ≤ τ' —— 技术上为真，实质上误导". Two disclosures ride WITH the FPR number (the way
# OBSERVABLE_BIAS_NOTE rides with injection_success_rate): the input-stage口径 (this states the ①
# denied_at_decision change in the citation itself), and the GENERAL lexical-layer known-limitation
# (§2.2.4②). The third required item — the detection-layer STATUS — rides via run_config_note (a
# run-scope axis, see below). 🔴 GENERAL mechanism ONLY: no specific case / rule_id / number ever
# enters this repo (§2.2.4 lines 225-226 — the tested party's specific state stays out).
# --------------------------------------------------------------------------- #
FPR_DISCLOSURE_IDS = frozenset({"false_positive_rate"})
FPR_STAGE_NOTE = (
    "🔴 阶段口径：false_positive_rate 仅在【决策(输入)阶段】测（final_decision==BLOCK，denied_at_"
    "decision）—— 响应侧的拦截拦的是模型【输出】内容，不是注入检测误判了这条【输入】，不计入本率"
    "（前提：响应侧无注入类规则；前提若变须重判 §2.2.4①）"
)
FPR_KNOWN_LIMITATION_NOTE = (
    "🔴 已知限制（词面层能力边界，记录并公示，非待修缺陷 §2.2.4②）：词面规则匹配的是【短语】不是"
    "【言语行为】——「提到」某注入模式与「实施」它在字面上可以完全一样，而可用于区分二者的表面特征"
    "（如引号）本身就是一条可公开的绕过方法；因此一类合法请求（引用/讲解某注入短语）可能被误拦。"
    "收紧词面规则=拿一个真实误拦换一个平凡绕过，故不靠收紧去消，而是记录+公示"
)


def is_observable_biased(indicator_id: str, subject: str) -> bool:
    """True when a value is measured over the marker-bearing subset only (EV-R2 §9.7): either an
    inherently subset-only indicator, or the `@outcome_observable` stratum of one that also has an
    all-decided aggregate (injection_catch_rate). The caveat must ride WITH such a number."""
    return (
        indicator_id in OBSERVABLE_BIASED_IDS or subject == _OUTCOME_OBSERVABLE_SUBJECT
    )


# --------------------------------------------------------------------------- #
# T3 §1.4 — `citation_form`: let the number carry its own口径 so it can be pasted whole.
# The recurring miss is lifting `89%` out on its own; the fix is that every rate travels WITH its n
# and interval, a census says "no sampling uncertainty" instead of a fake interval, and a
# not-citable number is prefixed so it can't be quoted bare.
# --------------------------------------------------------------------------- #
def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _verdict(satisfied_when: str | None, m: Measurement) -> str:
    """ "按 ci_low >= 0.80 判定：未达标（样本不足，非能力低）" — the gate and its outcome, so the number
    never travels without the bar it was judged against. Silent when the objective has no predicate
    or the predicate can't apply (e.g. a CI gate over a census with no interval)."""
    if not satisfied_when:
        return ""
    try:
        field, op, tau = parse_satisfied_when(satisfied_when)
        passed = compile_satisfied_when(satisfied_when)(m)
    except SatisfiedWhenError:
        return ""
    if passed:
        return f"按 {field} {op} {tau:g} 判定：达标"
    # a failed CI-width gate is a sample-size shortfall, not a capability failure (§1.4)
    qualifier = "（样本不足，非能力低）" if field in ("ci_low", "ci_high") else ""
    return f"按 {field} {op} {tau:g} 判定：未达标{qualifier}"


_EXEC_MODE_LABEL = {"block": "拦截(命中即拒)", "flag": "只标记(mark-only)"}


def run_config_note(provenance: dict[str, Any] | None) -> str:
    """E3-h/E3-m (§3.1/§2.2.2/§5) — the freeze-pack scope as a paste-whole clause for citation_form.
    🔴 The #1 axis is LANGUAGE_SCOPE (which language(s)/traffic the numbers represent — an operator
    DECLARATION, NEVER inferred from case bytes), so it leads; then tested VERSION, detection CONFIG
    (esp. encode/decode on-off), and EXECUTION MODE (τ_fpr's meaning varies by block vs flag). Empty
    when ANY of the four is undeclared — such a run is not citable, so its citation_form carries the
    NOT CITABLE prefix instead. Built here (not in serialize) so the wording has ONE source of truth."""
    prov = provenance or {}
    lang, v, c, e = (
        prov.get("language_scope"),
        prov.get("tested_version"),
        prov.get("detect_config"),
        prov.get("exec_mode"),
    )
    if not (lang and v and c and e):
        return ""
    note = f"作用域 {lang} · 被测方 {v} · 检测配置 {c} · 执行模式 {_EXEC_MODE_LABEL.get(e, e)}"
    # E3-n ③ / §2.2.4③ (acceptance 24) — the DETECTION-LAYER STATUS rides with the number too: it is
    # a run-scope axis (like version / exec-mode), and §2.2.4③ requires it in the FPR citation. A
    # citable run always declares it (missing_run_config blocks otherwise), so it is normally present.
    dl = prov.get("detection_layer_status")
    if dl:
        note += f" · 检测层 {dl}"
    return note


def citation_form(
    m: Measurement,
    *,
    pinned: bool,
    window: Any,
    evidence_basis: str,
    citable: bool,
    first_blocker: str | None,
    satisfied_when: str | None = None,
    config_note: str = "",
) -> str:
    """A copy-pasteable口径 for one measurement. 🔴 Interval BY MECHANISM (EV-CIGATE §1.5, THREE ways
    — never two): a partial detector (ci_low/ci_high present) carries `n` + the 95% interval; a
    default-deny TOTAL FUNCTION (`interval_basis == total_function`) has no interval because its
    residual is a hole in the allow-list, NOT a rate; a CENSUS (`interval_basis == census`) says
    "普查 n/n，无抽样不确定性". 🔴 The class comes from the indicator's DECLARATION, not from `ci is
    None` — that proxy collapsed the last two and made a 12-probe deny-check read as an exhausted
    census. `config_note` (E3-h) rides along so the number states which version/config/exec-mode it was
    measured under. Not citable ⇒ the SAME string, prefixed `🔴 NOT CITABLE —` (never blank)."""
    # 🔴 a STRATIFIED measurement (subject != "") must name its stratum — else a paste-whole string
    # for injection_catch_rate@outcome_observable (the marker subset, 100% by construction) reads as
    # "injection catch rate = 100%", the exact observable-subset bias EV-R2 §9.7 warns about.
    ind = m.indicator_id + (f"@{m.subject}" if m.subject else "")
    n, val = m.sample_size, m.value
    cl, ch = m.ci_low, m.ci_high
    pin_phrase = f"pinned run {window}" if pinned and window else "unpinned run"
    tail = f"{pin_phrase}, {evidence_basis}"
    if n == 0:
        body = f"{ind}（n=0，本次未采到数据 —— 不可引）"
    elif cl is not None and ch is not None:
        # a partial detector — the attached Wilson interval IS the "sampled" declaration
        body = (
            f"{ind} {_pct(val)} ({round(val * n)}/{n}, 95% CI [{_pct(cl)}, "
            f"{_pct(ch)}], {tail})"
        )
    elif m.interval_basis == INTERVAL_TOTAL_FUNCTION:
        clean = n - round(val * n)  # probes that saw no violation
        body = (
            f"{ind} {_pct(val)}（默认拒绝的全函数：{clean}/{n} 条探针未见失效；区间不适用 —— "
            f"失效是允许表上的洞，不是一个比率；{tail}）—— 残余在覆盖面，不在抽样"
        )
    elif m.interval_basis == INTERVAL_CENSUS:
        body = f"{ind} {_pct(val)}（普查 {n}/{n}，无抽样不确定性；{tail}）"
    elif m.unit == "ratio":
        # 🔴 a ci-None RATE that declared no mechanism — do NOT claim census (that was the bug). State
        # honestly that interval-applicability is undeclared; the gate keeps real indicators out of here.
        body = f"{ind} {_pct(val)}（n={n}；区间适用性未声明 —— 按不外推处理；{tail}）"
    else:
        body = f"{ind} {val:g} {m.unit}（n={n}，非比率，不适用区间；{tail}）"
    verdict = _verdict(satisfied_when, m)
    if verdict:
        body += f" —— {verdict}"
    # E3-h (§3.1) — the freeze-pack config rides WITH the number, so a quoted "89%" states which
    # tested version / detection config / execution mode it was measured under (a bare rate is unscoped).
    if config_note:
        body += f"（{config_note}）"
    # EV-R2 §9.7 — the observable-subset caveat rides WITH the number (the SAME note the pairing path
    # uses), so a 100% on the marker subset can never be quoted as the catch rate.
    if is_observable_biased(m.indicator_id, m.subject):
        body += f" —— {OBSERVABLE_BIAS_NOTE}"
    # E3-i (§2.2.3 ③) — injection_catch_rate NAMES an attribution, so its口径 states HOW that
    # attribution was established (the control arm), alongside the scope/config above.
    if m.indicator_id in ATTRIBUTION_ESTABLISHED_IDS:
        body += f" —— {ATTRIBUTION_ESTABLISHED_NOTE}"
    # E3-n ① / §2.2.4③ (acceptance 24) — false_positive_rate rides WITH its input-stage口径 AND the
    # general lexical-layer known-limitation (the detection-layer status already rode via config_note
    # above). §4 honesty: "FPR ≤ τ" without these is technically-true-but-misleading.
    if m.indicator_id in FPR_DISCLOSURE_IDS:
        body += f" —— {FPR_STAGE_NOTE} —— {FPR_KNOWN_LIMITATION_NOTE}"
    if not citable:
        return f"🔴 NOT CITABLE — {first_blocker or '不可引用'}；{body}"
    return body
