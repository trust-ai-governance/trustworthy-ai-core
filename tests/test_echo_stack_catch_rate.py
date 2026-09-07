"""🔴 在 echo 栈上，每条探针的响应期都会 fail-closed 返回 403 —— 检出率必须不受影响。

认证跑的攻击侧在 echo 上跑（零 token、零出域；注入判决在转发【之前】）。但 echo 回的不是
chat.completion，响应期规则解析不到正文 ⇒ 按 `response_dlp_unparsed_policy=fail_closed` 一律拦下。
实测：一条 `ping` 也是 `HTTP 403 + x-upstream-status: 200`。

⚠️ 而 `hard_blocked` 把【响应期 terminal BLOCK】也算作"用户被拒" ——
⇒ 于是 echo 上每条探针都 `reacted=True`。若"反应"直接等于"检出"，
   **检出率会读成 100%**：一个干净、可引、完全错误的满分，而且是在认证跑上。

拦住它的是 F1 那道归属门：**反应只有在【注入规则】赚来时才算检出**。
本文件把那道门钉死 —— 整个 134 件跑批的有效性压在它上面。
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval.indicators import InjectionCatchRate
from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK


def _ev(ctx: rc_pb.RequestContext) -> AuditEvidence:
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=1, request_id=ctx.envelope.request_id),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _decision(cid: str, *, final, matched_rule: str | None) -> AuditEvidence:
    """入口决策记录：15 条注入规则【全部求值】，其中至多一条匹配。"""
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = final  # type: ignore[assignment]
    for rid in ("inj-instruction-override", "inj-persona-hijack"):
        r = ctx.decision.rules_evaluated.add()
        r.rule_id = rid
        r.matched = rid == matched_rule
        r.tags["dimension"] = "robustness"
        if r.matched:
            r.actions_fired.append("block")
    return _ev(ctx)


def _echo_response(cid: str) -> AuditEvidence:
    """echo 栈的响应记录：terminal BLOCKED，而【没有任何响应期规则命中】(fail-closed)。"""
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.response.final_terminal = "BLOCKED"
    ctx.response.response_status_code = 200
    for rid in ("dlp-canary-response", "pii-block-response"):
        r = ctx.response.on_tool_response_rules.add()
        r.rule_id = rid
        r.matched = False  # 🔴 一条都没匹配 —— 拦它的是 fail-closed，不是规则
    return _ev(ctx)


def _pr(cid: str, *, final, matched_rule: str | None) -> ProbeResult:
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="BLOCK",  # echo 上 HTTP 恒 403 ⇒ 采集端读到的就是 BLOCK
        response_text="",
        evidence=_decision(cid, final=final, matched_rule=matched_rule),
        response_evidence=_echo_response(cid),
        attack_class="prompt_injection",
    )


def test_an_echo_fail_closed_block_is_not_a_catch() -> None:
    """🔴 本文件的核心。入口【放行】、响应期 fail-closed 拦下 ⇒ 这是一次 MISS，不是检出。

    什么让它红：去掉 `injection_attribution_source` 那道门（让 `reacted` 直接算 caught）。
    那时下面这条 100% 未被注入规则拦下的件会变成"检出"，而整条臂会读成满分。
    """
    (m,) = InjectionCatchRate().measure([_pr("miss1", final=_ALLOW, matched_rule=None)])
    assert m.value == 0.0, "响应期 fail-closed 被读成了注入检出 —— echo 上这会给出 100%"
    assert m.sample_size == 1, "它是一次真实的漏检，必须【留在分母里】，不是不可测"


def test_a_real_injection_catch_still_counts() -> None:
    """门不能矫枉过正：入口由注入规则硬拦 ⇒ 仍然是检出。

    什么让它红：把归属门收得过紧（例如要求响应期也命中注入规则）。
    """
    (m,) = InjectionCatchRate().measure(
        [_pr("hit1", final=_BLOCK, matched_rule="inj-instruction-override")]
    )
    assert m.value == 1.0 and m.sample_size == 1


def test_the_two_are_separated_in_one_batch() -> None:
    """一批里两种同时存在 ⇒ 1/2，而不是 2/2（echo 的假满分）也不是 1/1（把漏检踢出分母）。"""
    (m,) = InjectionCatchRate().measure(
        [
            _pr("hit1", final=_BLOCK, matched_rule="inj-instruction-override"),
            _pr("miss1", final=_ALLOW, matched_rule=None),
        ]
    )
    assert (m.value, m.sample_size) == (0.5, 2)
