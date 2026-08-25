"""Target seam + GatewayTarget (EV-AE0 §3.2).

A Target drives a system with a corpus case and returns a ProbeResult correlated
by request_id. GatewayTarget drives the REAL gateway invoke path under a reserved
eval tenant — it never makes the gateway eval-aware, and correlation/isolation
live outside the governance record (request_id + tenant_id). BYO targets (any
Target.probe) let an enterprise evaluate their own system without core owning it.

httpx is imported lazily inside probe(), so importing this module — and
`import treval` — stays httpx-free; httpx is only needed to drive a live gateway
(install `requirements-eval.txt`).
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval.corpus import CorpusCase, WireMessage
from treval.models import AuditEvidence
from treval.readers import WalEvidenceReader


# 🔴 The drain ceiling, derived from the batch (see drain_governance). The shadow tailer is SERIAL,
# so n probes need ~n × judge-latency. PER_CASE is set above the observed per-case spacing (median
# 2.84 s, max 4.26 s on the CN certification stack) so a slow case does not truncate the batch;
# FLOOR keeps small batches on the previous 20 s behaviour.
_DRAIN_PER_CASE_S = 5.0
_DRAIN_FLOOR_S = 20.0


class AdminAuthError(Exception):
    """The gateway admin API REJECTED our credential (401/403) — distinct from "there is no admin
    API". Raised, never absorbed: a one-shot corpus arm must not be spent on a run whose whole
    Tier-2 half is already known to be unmeasurable."""


# Record-type enum numbers, resolved from the descriptor (no hard-coded ints). A
# request emits a DECISION_MADE record (the authorization/decision stage) and, when
# governance observes the response, a RESPONSE_OBSERVED record (output-DLP etc.).
_RECORD_TYPE = rc_pb.RequestContext.DESCRIPTOR.fields_by_name["record_type"].enum_type
if _RECORD_TYPE is None:  # record_type is an enum field — descriptor always set
    raise RuntimeError("record_type field descriptor has no enum_type")
_DECISION_MADE = _RECORD_TYPE.values_by_name["AUDIT_RECORD_TYPE_DECISION_MADE"].number
_RESPONSE_OBSERVED = _RECORD_TYPE.values_by_name[
    "AUDIT_RECORD_TYPE_RESPONSE_OBSERVED"
].number
# The async governance record (AUDIT_RECORD_TYPE_GOVERNANCE_OBSERVED = 3): the Tier-2
# shadow-judge observation, written ~2s AFTER the probe by the background evaluator — NOT
# visible in the synchronous decision read. Resolved from the descriptor by name (no
# hard-coded int), same as the two above.
_GOVERNANCE_OBSERVED = _RECORD_TYPE.values_by_name[
    "AUDIT_RECORD_TYPE_GOVERNANCE_OBSERVED"
].number


@dataclass(frozen=True)
class VendorLabel:
    """One label a judge/classifier returned for a probe (P3C-harness §2.2.4 carrier seam).
    `score` is the continuous confidence the score-driven metrics consume; `sub_label`/`level`
    carry a multi-level taxonomy when the candidate emits one. Vendor-neutral by design — the
    self-built logprob judge emits ONE label (违规); a multi-label vendor emits several."""

    label: str
    sub_label: str = ""
    score: float = 0.0
    level: str = ""


@dataclass(frozen=True)
class ProbeResult:
    case_id: str
    request_id: str  # from x-request-id header / body — the correlation key
    decision: str  # "ALLOW" | "BLOCK"
    response_text: str  # full output captured at probe time (for output checks)
    evidence: AuditEvidence | None  # WAL record by request_id (E1); None if absent
    response_evidence: AuditEvidence | None = (
        None  # RESPONSE_OBSERVED record by request_id (response-stage governance,
        # e.g. output-DLP); None if absent
    )
    error: str | None = None  # transport failure — recorded, never silently dropped
    raw_response: str = ""  # full HTTP response body (every byte returned to the
    # caller — answer content + reasoning_content + …); the broad surface for
    # output-based leak checks, so a secret in the reasoning trace is not missed.
    output_marker: str = (
        ""  # the case's canary (attached by run_corpus, for success checks)
    )
    secret_canary: str = (
        ""  # the case's planted secret (attached by run_corpus, for leak checks)
    )
    # EV-COVERAGE E3 §2.2.3 — case metadata the attribution arm (indicators.py) reads, attached by
    # run_corpus like the canaries so the indicators stay self-contained (the ProbeResult, not a second
    # corpus lookup, carries what the rate needs). `attack_class` identifies a control_bare_payload /
    # benign probe; `source` identifies an external-verbatim payload (needs a control to attribute its
    # catch); `control_for` links a control probe back to the partner attack it controls. Empty on any
    # probe whose case did not set them (every pre-E3 probe is unchanged).
    attack_class: str = ""
    source: str = ""
    control_for: str = ""
    # HTTP-parsed token usage (EV-AE5, LLM10). This is the CROSS-CHECK working value;
    # the chain-verified WAL response record's token_usage is the AUTHORITATIVE oracle
    # (D1/D3). 0 when absent — e.g. a BLOCKed runaway has no completion (no consumption).
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    # EV-AE5.3 (reasoning-aware LLM10): reasoning_tokens is the model-inherent COST FLOOR
    # (usage.completion_tokens_details.reasoning_tokens); the attacker-driven visible-output
    # runaway is content = completion - reasoning. finish_reason detects a length-truncated
    # empty answer (RC4 integrity — a clamped token count is NOT a valid governed response).
    reasoning_tokens: int = 0
    finish_reason: str = ""
    # EV-AE5.1: a ReadTimeout — the connection succeeded but the RESPONSE never arrived
    # in time. On an LLM10 runaway this means the model streamed past the timeout with no
    # gateway cap = an ungoverned runaway that blew the measurement window (NOT a neutral
    # transport error). The LLM10 indicators count it as uncaught / over-budget rather
    # than excluding it. Only ReadTimeout (response-side); connect/pool timeouts are infra.
    timed_out: bool = False
    # EV-AE12: the ASYNC governance record (record_type=3) — the Tier-2 shadow-judge hint,
    # written ~2s post-probe by the background evaluator (invisible to the synchronous decision
    # read). Populated by GatewayTarget.drain_governance() after the run; None if it never
    # landed (drain timeout) or no WAL. Read by caught_by_tier2 / the Tier-2 lift + flag lines.
    governance_evidence: AuditEvidence | None = None
    # E3-n ② — did the async Tier-2 drain actually EXECUTE for this probe? drain_governance() sets
    # this True on every probe it processes. 🔴 The distinction the Tier-2 indicators need:
    # governance_evidence=None conflates "async record truly absent (judge scored below τ)" with
    # "drain never ran" — and collect never drains, so without this flag the Tier-2 layer silently
    # reads 0/False. False (the default) ⇒ the drain did not run ⇒ the Tier-2 indicators emit n/a /
    # unmeasurable, NEVER a zero lift/rate.
    tier2_drain_executed: bool = False
    # P3C-harness C1-STABILITY-CURVE §1 — the vendor-neutral bearer seam for score-driven
    # judges (self-built logprob + future moderation APIs). Additive + honest-default ⇒ every
    # existing ProbeResult construction is unchanged and the WAL golden does not churn. Landing
    # the FIELDS (schema) here does NOT pull the C2 adapter (runtime) into scope — that stays
    # gated on vendor onboarding.
    vendor_labels: tuple[
        VendorLabel, ...
    ] = ()  # judge scores; () when none (honestly absent)
    vendor_version: str = (
        ""  # model:quant:contract-id — records WHICH score read-strategy (§5-3)
    )
    # Reload self-attestation (Platform I3 §5-2): the adapter TAGS, the metric DROPS. Core does
    # NOT judge the reload threshold — it consumes the adapter's flag. duration is show-only.
    judge_load_duration_ns: int = 0  # adapter-reported load_duration; 0 = not provided
    judge_reload_contaminated: bool = (
        False  # adapter-derived: this sample rode a real reload
    )


class Target(Protocol):
    target_id: str

    def probe(self, case: CorpusCase) -> ProbeResult: ...


def _coerce_int(value: object) -> int:
    """A defensive non-negative int from an OpenAI `usage` field. Absent / non-numeric
    (a BLOCKed runaway has no usage) → 0. bool is excluded (it is an int subclass)."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return max(0, int(value))
    return 0


def _to_wire(messages: tuple[WireMessage, ...]) -> list[dict[str, object]]:
    """Convert authored WireMessages to the OpenAI wire form sent verbatim as
    params.messages (EV-AE11). A string content passes through; a content-part tuple
    becomes a `[{type,text}]` list (nested reach)."""
    wire: list[dict[str, object]] = []
    for m in messages:
        if isinstance(m.content, str):
            content: object = m.content
        else:
            content = [{"type": p.type, "text": p.text} for p in m.content]
        wire.append({"role": m.role, "content": content})
    return wire


def _extract_text(body: dict[str, object]) -> str:
    """The assistant reply *content* from the gateway's OpenAI-compatible completion
    (choices[0].message.content), falling back to flat output/response wrappers some
    deployments use. Empty when none present.

    This is the answer text only — used by startswith-based checks (injection
    success). The FULL body (incl. reasoning_content) is captured separately as
    raw_response so a substring leak check sees every byte returned to the caller."""
    choices = body.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        msg = choices[0].get("message")
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            return msg["content"]
    for key in ("output", "response"):
        value = body.get(key)
        if isinstance(value, str):
            return value
    return ""


def _finish_reason(body: dict[str, object]) -> str:
    """choices[0].finish_reason (EV-AE5.3) — "length" flags a truncated (possibly empty)
    completion, the RC4 integrity signal. Empty when not present."""
    choices = body.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        fr = choices[0].get("finish_reason")
        if isinstance(fr, str):
            return fr
    return ""


def _parse_body(resp: object) -> tuple[dict[str, object], str]:
    """The response JSON body (dict, defensively) + the full raw text. A non-JSON / non-dict
    body → ({}, best-effort text). Shared by GatewayTarget and OpenAITarget (EV-FWD §3 — one
    parser, not a copy)."""
    body: dict[str, object] = {}
    try:
        parsed = resp.json()  # type: ignore[attr-defined]
        if isinstance(parsed, dict):
            body = parsed
    except ValueError:
        body = {}
    raw = getattr(resp, "text", "")
    return body, raw if isinstance(raw, str) else ""


def _has_completion(body: dict[str, object]) -> bool:
    """A well-formed OpenAI chat completion carries a NON-EMPTY `choices` array. Its absence is
    an error payload — some compat layers return HTTP 200 with `{"error": …}` / `{"detail": …}`
    and no choices — NOT a clean empty answer. OpenAITarget must record that as an error, not
    measure it as "nothing leaked" (a false 0%). An empty content string INSIDE a valid choices
    entry is a real (if empty) model output and stays measurable — only a missing structure fails."""
    choices = body.get("choices")
    return isinstance(choices, list) and len(choices) > 0


def _usage_tokens(body: dict[str, object]) -> tuple[int, int, int, int]:
    """The OpenAI `usage` accounting → (total, prompt, completion, reasoning) tokens (EV-AE5).
    reasoning_tokens lives under completion_tokens_details; absent / blocked → 0. Shared by both
    targets (returned as a tuple, not **kwargs, so the typed ProbeResult fields stay explicit)."""
    usage = body.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    ctd = usage.get("completion_tokens_details")
    ctd = ctd if isinstance(ctd, dict) else {}
    return (
        _coerce_int(usage.get("total_tokens")),
        _coerce_int(usage.get("prompt_tokens")),
        _coerce_int(usage.get("completion_tokens")),
        _coerce_int(ctd.get("reasoning_tokens")),
    )


def _chat_params(
    case: CorpusCase, model: str, temperature: float | None
) -> dict[str, object]:
    """The OpenAI chat params for a case: the authored wire array (EV-AE11) sent verbatim, else
    a single-turn [system?, user]. temperature is pinned when not None. Shared so GatewayTarget
    and OpenAITarget build the request the same way (EV-FWD §3 — reuse, not copy)."""
    if case.messages is not None:
        messages: list[dict[str, object]] = _to_wire(case.messages)
    else:
        messages = []
        if case.system_prompt:
            messages.append({"role": "system", "content": case.system_prompt})
        messages.append({"role": "user", "content": case.input})
    params: dict[str, object] = {"model": model, "messages": messages}
    if temperature is not None:
        params["temperature"] = temperature
    return params


class GatewayTarget:
    """Drives the gateway invoke API under the eval tenant, then attaches the WAL
    record by request_id.

    The exact invoke endpoint / identity payload is deployment-specific (confirm
    with the deploy owner). Defaults below are the documented assumptions; this
    target is operator-run (integration), not exercised in CI.
    """

    target_id = "gateway"

    def __init__(
        self,
        base_url: str,
        *,
        tenant_id: str = "__eval__",
        wal_dir: str | Path | None = None,
        user_id: str = "eval-user",
        model: str = "deepseek-v4-flash",  # deployment-specific; override per target
        invoke_path: str = "/v1/tools:invoke",
        temperature: float | None = 0.0,  # pin for reproducible statistical runs (D5)
        timeout: float = 30.0,
        admin_url: str | None = None,  # gateway admin API (drain cursor)
        agent_id: str | None = None,  # run-wide `x-agent-id` (a case's own still wins)
        no_output_side: bool = False,  # declared: no upstream model (echo forwarder)
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._tenant_id = tenant_id
        self._wal_dir = Path(wal_dir) if wal_dir is not None else None
        # UI-3 §5.2: the case contract's tenant MUST equal the tenant the probes ran as (the WAL
        # `evidence_ref` points at). Expose it read-only so the producer reads it from HERE, never
        # a second `TREVAL_EVAL_TENANT` env read that could drift from what actually ran.
        self._user_id = user_id
        self._model = model
        self._invoke_path = invoke_path
        self._temperature = temperature
        self._timeout = timeout
        self._admin_url = admin_url.rstrip("/") if admin_url is not None else None
        self._agent_id = agent_id or None
        self._no_output_side = no_output_side
        # 🔴 The admin token rides in the ENVIRONMENT, never in a flag: a flag value lands in shell
        # history and in `ps` output for every user on the box. Read ONCE at construction so a mid-run
        # env change cannot make the BEFORE and AFTER fingerprints authenticate differently.
        self._admin_token = os.environ.get("TREVAL_ADMIN_TOKEN") or None

    def _admin_headers(self) -> dict[str, str]:
        """Auth for the gateway admin API. Absent token ⇒ no header (an admin API that needs none
        still works); present ⇒ `x-admin-token`, the face both admin endpoints share."""
        return {"x-admin-token": self._admin_token} if self._admin_token else {}

    @property
    def tenant_id(self) -> str:
        """The tenant these probes run as (UI-3 §5.2) — read-only; the case contract's tenant."""
        return self._tenant_id

    def probe(self, case: CorpusCase) -> ProbeResult:
        import httpx  # lazy: only needed to drive a live gateway

        # Identity travels in headers (x-tenant-id / x-user-id / x-agent-id); the body is the
        # tools:invoke payload.
        # 🔴 This comment used to read "the gateway derives the agent — no agent header". That was a
        # BELIEF ABOUT THE TESTED PARTY written into our code, and the tested party changed: the
        # gateway now rejects an agent-less request at IDENTIFY_FAILED, before any detection stage.
        # Observed as 194/194 probes erroring — the code was faithfully executing an expired fact.
        # temperature passes through verbatim to the OpenAI-compatible upstream
        # (DeepSeek/OpenAI both honor it) — pinned for reproducible runs (D5).
        # The invocation is selected by case.tool_id. "chat" sends the OpenAI-style
        # messages (a real role:"system" message is prepended ONLY when the case
        # supplies one — LLM07; the forwarder passes it through, EV-AE2 D1). A
        # non-"chat" tool_id is an out-of-scope probe (LLM06): the authorization stage
        # decides on scope derived from tool_id BEFORE execution, so minimal params
        # suffice (EV-AE3 D2 — confirmed live: params:{} reaches authz).
        # EV-AE11: a "chat" case sends the authored wire array / single-turn messages verbatim
        # (shared _chat_params); a non-"chat" tool_id is an out-of-scope LLM06 probe (empty
        # params — authz decides on tool_id before execution).
        params: dict[str, object]
        if case.tool_id == "chat":
            params = _chat_params(case, self._model, self._temperature)
        else:
            params = {}
        headers = {
            "x-tenant-id": self._tenant_id,
            "x-user-id": self._user_id,
        }
        # EV-AE13: per-case route selection. `builtin.chat` is the declared HTML sink (neutralize
        # applies), `control.chat` is sink `none` (byte-for-byte). A case's own agent_id WINS over
        # the run-wide default, so per-case routing keeps working unchanged.
        agent_id = case.agent_id if case.agent_id is not None else self._agent_id
        if agent_id is not None:
            headers["x-agent-id"] = agent_id
        try:
            resp = httpx.post(
                self._base_url + self._invoke_path,
                headers=headers,
                json={"tool_id": case.tool_id, "params": params},
                timeout=self._timeout,
            )
            # Do NOT raise_for_status: a governance BLOCK may return a non-2xx
            # status — that is a valid governed response (a CAUGHT injection), not
            # a transport error. Only a real transport failure (no response) is an
            # error; the WAL record (by request_id) decides caught/not-caught.
        except httpx.HTTPError as e:
            return ProbeResult(
                case_id=case.id,
                request_id="",
                decision="",
                response_text="",
                evidence=None,
                error=f"harness-transport-failure（工装/传输失败，非网关输出问题）: {type(e).__name__}: {e}",
                timed_out=isinstance(e, httpx.ReadTimeout),
            )

        body, raw_response = _parse_body(resp)
        request_id = resp.headers.get("x-request-id", "") or str(
            body.get("request_id", "")
        )
        decision = str(body.get("decision", ""))
        if self._wal_dir is not None and request_id:
            evidence, response_evidence = self._read_evidence(request_id)
        else:
            evidence, response_evidence = None, None
        total, prompt, completion, reasoning = _usage_tokens(body)
        # 🔴 EV-CN-BASELINE §9 F-2 — a NON-BLOCKED response with NO parseable completion is an EXTRACTION
        # FAILURE, not a clean empty answer. A governance BLOCK legitimately has no output (decision=="BLOCK"),
        # and a real empty answer keeps a valid `choices` entry (_has_completion True); but an ALLOW/undecided
        # 200 carrying an error payload / no choices / an unparseable body must NOT be measured as "nothing
        # leaked / attack failed" — that is a self-consistent false 0 across the FOUR output-side indicators
        # (被污染的数据给自洽的错结论). Record it as an error ⇒ those indicators EXCLUDE + COUNT it (the count
        # reaches their notes + the whole-run ActiveScan error_count), never a silent 0. This is the gateway-
        # side mirror of OpenAITarget's _has_completion guard, respecting the gateway's block semantics.
        no_output = _extract_text(body) == "" and not _has_completion(body)
        # 🔴 件⑥ — the cause string must NAME WHICH SIDE failed, because the two have different owners and
        # different fixes: a HARNESS/transport failure (no response at all) is ours to fix; a GATEWAY OUTPUT
        # that cannot be parsed is the tested party's. Conflating them sends the wrong person looking.
        # 🔴 …UNLESS the run DECLARED there is no upstream model at all (an echo forwarder: `被测方=无`).
        # Then an absent completion is the target's DESIGNED behaviour, not an extraction failure, and
        # the guard above — written to protect the FOUR OUTPUT-SIDE indicators from a false 0 — instead
        # kills the DECISION side, which is the only side such a run measures. Observed live: 194/194
        # probes errored against an echo forwarder while every decision was recorded perfectly.
        # 🔴 DECLARED, never inferred from the body: inferring it would let a genuinely broken gateway
        # relabel itself "oh, no output side" — precisely the false 0 the guard exists to prevent.
        # The declaration is refused unless every active producer is decision-side (see collect.py).
        extract_error = (
            f"gateway-output-unparseable（网关输出解不动，非工装失败）: 200/非拦截响应里没有可解析的 "
            f"completion —— body={raw_response[:160]}"
            if (decision != "BLOCK" and no_output and not self._no_output_side)
            else None
        )
        return ProbeResult(
            case_id=case.id,
            request_id=request_id,
            decision=decision,
            response_text=_extract_text(body),
            raw_response=raw_response,
            evidence=evidence,
            response_evidence=response_evidence,
            error=extract_error,
            total_tokens=total,
            prompt_tokens=prompt,
            completion_tokens=completion,
            reasoning_tokens=reasoning,
            finish_reason=_finish_reason(body),
        )

    def _read_evidence(
        self, request_id: str
    ) -> tuple[AuditEvidence | None, AuditEvidence | None]:
        # ONE scan over the eval-tenant WAL, returning both the DECISION_MADE record
        # (-> ProbeResult.evidence) and the RESPONSE_OBSERVED record (->
        # response_evidence) for this request_id — so we never scan the WAL twice per
        # probe. First record of each type wins; stop early once both are found. O(n)
        # per probe is fine for the operator-run integration (not perf-critical).
        wal_dir = self._wal_dir
        if wal_dir is None:
            return None, None
        decision_ev: AuditEvidence | None = None
        response_ev: AuditEvidence | None = None
        reader = WalEvidenceReader(wal_dir)
        for ev in reader.read_audit(tenant_id=self._tenant_id):
            if ev.ref.request_id != request_id:
                continue
            rt = ev.record.record_type
            if rt == _DECISION_MADE and decision_ev is None:
                decision_ev = ev
            elif rt == _RESPONSE_OBSERVED and response_ev is None:
                response_ev = ev
            if decision_ev is not None and response_ev is not None:
                break
        return decision_ev, response_ev

    def _read_cursor(self) -> dict | None:
        """GET {admin_url}/admin/v1/audit:cursor — the gateway's LIVE drain cursor
        (wal_head_seq / guardrail_cursor_seq / guardrail_degraded / tailer_cursor_seq).

        Returns the parsed dict, or None on a STRUCTURAL failure (no admin_url, 404, transport or
        JSON-parse error) so drain_governance() degrades to the timeout backstop rather than raising.

        🔴 EXCEPT auth: 401/403 raises `AdminAuthError`. The blanket "None on ANY failure" degrade was
        written for the case it names — a gateway with no admin API, or a hiccup — and it silently
        swallowed a REJECTED CREDENTIAL too. Those are not the same thing: a missing endpoint is
        structural and has no fix; a 401 is a deterministic misconfiguration that will not heal, and
        absorbing it costs EVERY Tier-2 row while the run still looks like it ran. Observed live: the
        run finished with tier2_drain_executed=false and three n/a rows because the token was never
        sent at all. httpx imported lazily, like probe()."""
        if self._admin_url is None:
            return None
        import httpx  # lazy: only needed to drive a live gateway

        url = self._admin_url + "/admin/v1/audit:cursor"
        try:
            resp = httpx.get(url, headers=self._admin_headers(), timeout=5.0)
            if resp.status_code in (401, 403):
                raise AdminAuthError(
                    f"HTTP {resp.status_code} from {url} —— admin 鉴权被拒。"
                    "TREVAL_ADMIN_TOKEN 未设置或不对；这不是「没有 admin 端点」，"
                    "降级会让每一个 Tier-2 数变成 n/a，而跑仍然显示跑完了"
                )
            if resp.status_code != 200:
                return None
            parsed = resp.json()
        except (httpx.HTTPError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def fetch_buildinfo(self) -> tuple[dict | None, str | None]:
        """E3-n ④ — GET {admin_url}/admin/v1/buildinfo: the tested party's SELF-REPORTED build
        fingerprint (`git_sha` · `ir_spec_sha` · `wheel_sha256` · `ruleset` · `detection_switches`).
        Called BEFORE and AFTER a freeze run; if the two differ by a single bit the tested party
        changed mid-run and the run is void (citability blocks it).

        🔴 Returns `(fingerprint, error)`, THREE-state — NOT a bare `dict | None` (that conflated
        "no claim" with "check failed" and made the fail-open bug):
          • `(dict, None)`  — fetched OK.
          • `(None, "…")`   — --admin-url WAS given but the fetch FAILED (non-200 / transport / parse).
                              This is a check that could not be made; the reason travels to `warnings`
                              and citability BLOCKS (fail-closed) — a declared-but-unreachable admin
                              endpoint (e.g. the wrong port) must not silently pass.
          • `(None, None)`  — no --admin-url: no claim to check (status quo, not blocked).
        🔴 Admin endpoint CONFIRMED via the Platform handoff (P3_CLOSEOUT_ROUND2_HANDOFF §1;
        E3_REVIEW_RECORD §8.2/§9.11). Same admin base + auth face as the drain cursor. httpx lazy."""
        if self._admin_url is None:
            return None, None
        import httpx  # lazy: only needed to drive a live gateway

        url = self._admin_url + "/admin/v1/buildinfo"
        try:
            resp = httpx.get(url, headers=self._admin_headers(), timeout=5.0)
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code} from {url}"
            parsed = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            return None, f"{type(e).__name__} from {url}: {e}"
        if not isinstance(parsed, dict):
            return None, f"buildinfo at {url} was not a JSON object"
        return parsed, None

    def _scan_governance(
        self, wanted: set[str], found: dict[str, AuditEvidence]
    ) -> None:
        """ONE scan over the eval-tenant WAL, adding to `found` any not-yet-seen
        record_type=3 (async governance) record whose request_id is still wanted. This is
        the ORIGINAL drain read/join, factored out unchanged — only the STOP condition in
        drain_governance() moved from a timeout guess to the drain cursor."""
        wal_dir = self._wal_dir
        if wal_dir is None:
            return
        for ev in WalEvidenceReader(wal_dir).read_audit(tenant_id=self._tenant_id):
            rid = ev.ref.request_id
            if (
                rid in wanted
                and rid not in found
                and ev.record.record_type == _GOVERNANCE_OBSERVED
            ):
                found[rid] = ev

    def _drain_to_deadline(
        self,
        wanted: set[str],
        found: dict[str, AuditEvidence],
        deadline: float,
        poll_interval: float,
    ) -> None:
        """The timeout BACKSTOP (the pre-cursor behaviour, kept as the absolute ceiling):
        poll-scan the WAL until every wanted request_id has a type-3 record OR the deadline
        fires. Used when no cursor is available, or the cursor degrades/errors mid-drain."""
        while wanted - found.keys():
            self._scan_governance(wanted, found)
            if not (wanted - found.keys()) or time.monotonic() >= deadline:
                break
            time.sleep(poll_interval)

    def drain_governance(
        self,
        results: list[ProbeResult],
        *,
        timeout: float | None = None,
        poll_interval: float = 2.0,
    ) -> list[ProbeResult]:
        """Attach each probe's ASYNC governance record (record_type=3 — the Tier-2 shadow
        judge, written ~2s post-probe) as ProbeResult.governance_evidence (EV-AE12).

        The Tier-2 hint is NOT in the synchronous decision read (_read_evidence runs right
        after the probe; the background evaluator writes ~2s later), so a naive run never
        sees it. Call this ONCE after the whole run, joining by request_id.

        The STOP condition is DETERMINISTIC, not a timeout guess (C0-d): snapshot the WAL
        head ONCE at drain start, then poll the gateway's admin drain cursor until the
        shadow evaluator's `guardrail_cursor_seq` catches up to that head — at which point
        every type-3 record that will EVER exist for this batch has been produced. Probes
        still missing a record after a clean deterministic stop are therefore GENUINE
        no-async (the judge scored below τ, no hint written), NOT a drain artifact — the
        Tier-2 indicators count that as `no-async`, never a silent zero-lift.

        Degradations (all keep the run moving, never hang): no admin cursor, a degraded
        evaluator, or a mid-drain cursor error each fall back to the `timeout` backstop and
        emit a loud stderr warning that the lift may be under-measured. `timeout` is also
        kept as the absolute ceiling even on the deterministic path. No WAL ⇒ unchanged.

        Operator-run (network + sleep), like probe() — NOT part of the pure engine."""
        wal_dir = self._wal_dir
        if wal_dir is None:
            return results
        wanted = {r.request_id for r in results if r.request_id}
        if not wanted:
            return results
        found: dict[str, AuditEvidence] = {}
        # 🔴 The ceiling is DERIVED FROM THE BATCH, not a constant. It used to be a flat 20 s, which
        # bears no relation to the work: the shadow tailer is SERIAL, so a batch of n probes needs
        # ~n × (judge latency) to finish. Observed live on the CN certification run — 183 allowed
        # probes at ~2.84 s each ≈ 520 s of judging against a 20 s ceiling (26× short): the drain
        # stopped early, 46/56 attacks and 125/125 benigns had no async record, and the Tier-2 half
        # of a READ-ONCE corpus arm came back empty. A fixed ceiling is a limit that silently gets
        # tighter every time the corpus grows — the failure arrives as a quiet under-measurement,
        # never as an error.
        if timeout is None:
            timeout = max(_DRAIN_FLOOR_S, len(wanted) * _DRAIN_PER_CASE_S)
        deadline = time.monotonic() + timeout
        # 🔴 Only a DETERMINISTIC stop (the evaluator's cursor reached the head we snapshotted) proves
        # every type-3 record that will ever exist has been written. Every other exit is truncation.
        drain_complete = False

        cursor = self._read_cursor()
        if cursor is None:
            # No cursor endpoint on the FIRST read → timeout guess (lift under-measured).
            print(
                "drain: no cursor endpoint — lift may be under-measured "
                "(fell back to timeout)",
                file=sys.stderr,
            )
            self._drain_to_deadline(wanted, found, deadline, poll_interval)
        else:
            # Snapshot the head ONCE — the evaluator appends type-3 which pushes the head
            # up; re-reading it each loop would chase a moving target (never terminating).
            # 🔴 `or 0`, not `.get(k, 0)`: the default only fires on a MISSING key — the cursor
            # endpoint returns the key with a JSON null while the tailer is still initialising, and
            # `int(None)` then blows up the whole drain (observed live: the drain died, the run
            # finished 2.3h later with tier2_drain_executed=False and every Tier-2 row n/a).
            probe_head = int(cursor.get("wal_head_seq") or 0)
            while True:
                self._scan_governance(wanted, found)
                cur = self._read_cursor()
                if cur is None:
                    print(
                        "drain: cursor read failed mid-poll — used timeout backstop",
                        file=sys.stderr,
                    )
                    self._drain_to_deadline(wanted, found, deadline, poll_interval)
                    break
                if int(cur.get("guardrail_cursor_seq") or 0) >= probe_head:
                    self._scan_governance(wanted, found)  # one final read+join
                    drain_complete = True  # the ONLY exit that proves completeness
                    break
                if cur.get("guardrail_degraded"):
                    print(
                        "drain: guardrail degraded — used timeout backstop",
                        file=sys.stderr,
                    )
                    self._drain_to_deadline(wanted, found, deadline, poll_interval)
                    break
                if time.monotonic() >= deadline:
                    print(
                        "drain: cursor did not catch up within backstop — "
                        "lift may be under-measured",
                        file=sys.stderr,
                    )
                    break
                time.sleep(poll_interval)

        # E3-n ② — stamp tier2_drain_executed only when the drain stopped DETERMINISTICALLY. The flag
        # means "a probe still missing an async record is a GENUINE no-async (the judge scored it
        # below τ)", and only cursor catch-up licenses that claim.
        #
        # 🔴 It used to be stamped True on every exit, timeout backstop included — so a TRUNCATED
        # drain relabelled "the judge never got to this probe" as "the judge looked and found
        # nothing". Observed live: `benign_shadow_flag_rate` reported value=0.0 over sample_size=125
        # while its own note read "125 probe(s) had NO async record". A downstream reader who takes
        # `value` and `availability` — which is every reader who does not parse prose — gets
        # "125 benign cases, judge flagged none" out of 125 cases the judge never scored.
        #
        # This is the flag's whole purpose, and it was defeated by the one branch that needed it most:
        # a drain that completes cleanly has nothing to hide, and only the truncated one does.
        if not drain_complete:
            print(
                "🔴 drain: stopped WITHOUT cursor catch-up ⇒ tier2_drain_executed stays false. Every "
                "Tier-2 row reads not_measured, NOT 0% — the judge did not finish this batch",
                file=sys.stderr,
            )
        return [
            replace(
                r,
                tier2_drain_executed=drain_complete,
                governance_evidence=found.get(r.request_id, r.governance_evidence),
            )
            for r in results
        ]


class OpenAITarget:
    """Drives any OpenAI-compatible `/chat/completions` endpoint — a BARE model, before any
    governance (EV-FWD §3). This is the 'measured, treatment-free' half of the "before vs after"
    picture: point the same corpus at the raw model, then at the gateway, and the delta is what
    governance bought.

    🔴 A MINIMAL TEST CLIENT, NEVER A GOVERNANCE PATH (guardrail 1): it evaluates NO rules, does
    NO PII handling, and writes NO audit WAL. It therefore returns `decision=""` and
    `evidence=None`, so only the OUTPUT-side indicators (injection_success / *_leak_rate /
    unsafe_output_passthrough / within_cost_budget) measure on it; the decision/WAL-side ones are
    architecturally absent and surface as `availability=n/a_needs_gateway`, NOT a fake 0%.

    `api_key` (param or TREVAL_OPENAI_API_KEY) rides the Authorization header ONLY — it never
    enters a ProbeResult, a report, or a log line (§3)."""

    target_id = "raw_model"

    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        api_key: str | None = None,
        temperature: float | None = 0.0,  # pin for reproducible statistical runs
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        # Read from env when not passed; kept private and never serialized (§3).
        self._api_key = api_key or os.environ.get("TREVAL_OPENAI_API_KEY")
        self._temperature = temperature
        self._timeout = timeout

    def probe(self, case: CorpusCase) -> ProbeResult:
        import httpx  # lazy: only needed to drive a live endpoint

        headers = {"content-type": "application/json"}
        if self._api_key:  # secret stays in the header — never in the ProbeResult/log
            headers["Authorization"] = f"Bearer {self._api_key}"
        # A bare model is pure chat — every case is a completion (tool_id is a gateway concept).
        params = _chat_params(case, self._model, self._temperature)
        try:
            resp = httpx.post(
                self._base_url + "/chat/completions",
                headers=headers,
                json=params,
                timeout=self._timeout,
            )
        except httpx.HTTPError as e:
            return ProbeResult(
                case_id=case.id,
                request_id="",
                decision="",
                response_text="",
                evidence=None,
                error=f"{type(e).__name__}: {e}",
                timed_out=isinstance(e, httpx.ReadTimeout),
            )

        body, raw_response = _parse_body(resp)
        # 🔴 OpenAITarget has NO WAL oracle — the HTTP response is its ONLY signal. A non-2xx
        # (404 wrong URL / 401 bad-or-missing key / 429 rate-limit) or a 200 carrying no
        # completion is an ENDPOINT FAILURE, NOT a clean empty answer. Letting it through makes
        # every probe "succeed" empty ⇒ the output-side indicators read a FALSE 0% ("zero
        # leaked / zero succeeded") — a bare model looking safer than the gateway, on the ONE
        # side raw_model can measure. So it becomes a recorded `error` (→ excluded from the
        # denominator, insufficient_data), never a measured 0%. (Contrast GatewayTarget, which
        # intentionally accepts non-2xx: there a governance BLOCK is a valid non-2xx the WAL
        # confirms; OpenAITarget has no such record to lean on.)
        status = getattr(resp, "status_code", 0)
        if not 200 <= status < 300:
            return ProbeResult(
                case_id=case.id,
                request_id="",
                decision="",
                response_text="",
                raw_response=raw_response,
                evidence=None,
                error=f"HTTP {status}: {raw_response[:200]}",
            )
        if not _has_completion(body):
            return ProbeResult(
                case_id=case.id,
                request_id="",
                decision="",
                response_text="",
                raw_response=raw_response,
                evidence=None,
                error=f"no completion in 2xx response: {raw_response[:200]}",
            )

        total, prompt, completion, reasoning = _usage_tokens(body)
        return ProbeResult(
            case_id=case.id,
            request_id="",  # no gateway request_id — standalone has no WAL correlation key
            decision="",  # 🔴 a bare model makes NO decision (there is no "block")
            response_text=_extract_text(body),
            raw_response=raw_response,
            evidence=None,  # 🔴 NO WAL — guardrail 1
            total_tokens=total,
            prompt_tokens=prompt,
            completion_tokens=completion,
            reasoning_tokens=reasoning,
            finish_reason=_finish_reason(body),
        )
