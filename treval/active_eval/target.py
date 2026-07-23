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

import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval.corpus import CorpusCase, WireMessage
from treval.models import AuditEvidence
from treval.readers import WalEvidenceReader

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
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._tenant_id = tenant_id
        self._wal_dir = Path(wal_dir) if wal_dir is not None else None
        self._user_id = user_id
        self._model = model
        self._invoke_path = invoke_path
        self._temperature = temperature
        self._timeout = timeout
        self._admin_url = admin_url.rstrip("/") if admin_url is not None else None

    def probe(self, case: CorpusCase) -> ProbeResult:
        import httpx  # lazy: only needed to drive a live gateway

        # Identity travels in headers (x-tenant-id / x-user-id); the body is the
        # tools:invoke payload. The gateway derives the agent — no agent header.
        # temperature passes through verbatim to the OpenAI-compatible upstream
        # (DeepSeek/OpenAI both honor it) — pinned for reproducible runs (D5).
        # The invocation is selected by case.tool_id. "chat" sends the OpenAI-style
        # messages (a real role:"system" message is prepended ONLY when the case
        # supplies one — LLM07; the forwarder passes it through, EV-AE2 D1). A
        # non-"chat" tool_id is an out-of-scope probe (LLM06): the authorization stage
        # decides on scope derived from tool_id BEFORE execution, so minimal params
        # suffice (EV-AE3 D2 — confirmed live: params:{} reaches authz).
        params: dict[str, object]
        if case.tool_id == "chat":
            if case.messages is not None:
                # EV-AE11: send the authored wire array verbatim (author controls role /
                # index / nesting). `messages` is authoritative — system_prompt/input are
                # NOT prepended (the author places any system turn explicitly).
                params = {"model": self._model, "messages": _to_wire(case.messages)}
            else:
                messages: list[dict[str, str]] = []
                if case.system_prompt:
                    messages.append({"role": "system", "content": case.system_prompt})
                messages.append({"role": "user", "content": case.input})
                params = {"model": self._model, "messages": messages}
            if self._temperature is not None:
                params["temperature"] = self._temperature
        else:
            params = {}
        headers = {
            "x-tenant-id": self._tenant_id,
            "x-user-id": self._user_id,
        }
        # EV-AE13: per-case route selection. Without it the gateway uses its default
        # route; `builtin.chat` is the declared HTML sink (neutralize applies),
        # `control.chat` is sink `none` (byte-for-byte). No header ⇒ unchanged behaviour.
        if case.agent_id is not None:
            headers["x-agent-id"] = case.agent_id
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
                error=f"{type(e).__name__}: {e}",
                timed_out=isinstance(e, httpx.ReadTimeout),
            )

        body = {}
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                body = parsed
        except ValueError:
            body = {}

        raw = getattr(resp, "text", "")
        raw_response = raw if isinstance(raw, str) else ""
        request_id = resp.headers.get("x-request-id", "") or str(
            body.get("request_id", "")
        )
        decision = str(body.get("decision", ""))
        response_text = _extract_text(body)
        usage = body.get("usage")
        usage = usage if isinstance(usage, dict) else {}
        # reasoning_tokens lives in usage.completion_tokens_details.reasoning_tokens (EV-AE5.3)
        ctd = usage.get("completion_tokens_details")
        ctd = ctd if isinstance(ctd, dict) else {}
        if self._wal_dir is not None and request_id:
            evidence, response_evidence = self._read_evidence(request_id)
        else:
            evidence, response_evidence = None, None
        return ProbeResult(
            case_id=case.id,
            request_id=request_id,
            decision=decision,
            response_text=response_text,
            raw_response=raw_response,
            evidence=evidence,
            response_evidence=response_evidence,
            total_tokens=_coerce_int(usage.get("total_tokens")),
            prompt_tokens=_coerce_int(usage.get("prompt_tokens")),
            completion_tokens=_coerce_int(usage.get("completion_tokens")),
            reasoning_tokens=_coerce_int(ctd.get("reasoning_tokens")),
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

        Returns the parsed dict, or None on ANY failure (no admin_url, non-200, transport
        or JSON-parse error) so drain_governance() degrades to the timeout backstop rather
        than raising. httpx imported lazily, like probe()."""
        if self._admin_url is None:
            return None
        import httpx  # lazy: only needed to drive a live gateway

        try:
            resp = httpx.get(self._admin_url + "/admin/v1/audit:cursor", timeout=5.0)
            if resp.status_code != 200:
                return None
            parsed = resp.json()
        except (httpx.HTTPError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None

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
        timeout: float = 20.0,
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
        deadline = time.monotonic() + timeout

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
            probe_head = int(cursor.get("wal_head_seq", 0))
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
                if int(cur.get("guardrail_cursor_seq", 0)) >= probe_head:
                    self._scan_governance(wanted, found)  # one final read+join
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

        if not found:
            return results
        return [
            replace(r, governance_evidence=found[r.request_id])
            if r.request_id in found
            else r
            for r in results
        ]
