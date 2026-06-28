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

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from treval.active_eval.corpus import CorpusCase
from treval.models import AuditEvidence
from treval.readers import WalEvidenceReader


@dataclass(frozen=True)
class ProbeResult:
    case_id: str
    request_id: str  # from x-request-id header / body — the correlation key
    decision: str  # "ALLOW" | "BLOCK"
    response_text: str  # full output captured at probe time (for output checks)
    evidence: AuditEvidence | None  # WAL record by request_id (E1); None if absent
    error: str | None = None  # transport failure — recorded, never silently dropped
    output_marker: str = (
        ""  # the case's canary (attached by run_corpus, for success checks)
    )


class Target(Protocol):
    target_id: str

    def probe(self, case: CorpusCase) -> ProbeResult: ...


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
        tool_id: str = "chat",
        model: str = "deepseek-v4-flash",  # deployment-specific; override per target
        invoke_path: str = "/v1/tools:invoke",
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._tenant_id = tenant_id
        self._wal_dir = Path(wal_dir) if wal_dir is not None else None
        self._user_id = user_id
        self._tool_id = tool_id
        self._model = model
        self._invoke_path = invoke_path
        self._timeout = timeout

    def probe(self, case: CorpusCase) -> ProbeResult:
        import httpx  # lazy: only needed to drive a live gateway

        # Identity travels in headers (x-tenant-id / x-user-id); the body is the
        # tools:invoke payload. The gateway derives the agent — no agent header.
        try:
            resp = httpx.post(
                self._base_url + self._invoke_path,
                headers={
                    "x-tenant-id": self._tenant_id,
                    "x-user-id": self._user_id,
                },
                json={
                    "tool_id": self._tool_id,
                    "params": {
                        "model": self._model,
                        "messages": [{"role": "user", "content": case.input}],
                    },
                },
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
            )

        body = {}
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                body = parsed
        except ValueError:
            body = {}

        request_id = resp.headers.get("x-request-id", "") or str(
            body.get("request_id", "")
        )
        decision = str(body.get("decision", ""))
        response_text = str(body.get("output", body.get("response", "")))
        evidence = (
            self._read_evidence(request_id)
            if (self._wal_dir is not None and request_id)
            else None
        )
        return ProbeResult(
            case_id=case.id,
            request_id=request_id,
            decision=decision,
            response_text=response_text,
            evidence=evidence,
        )

    def _read_evidence(self, request_id: str) -> AuditEvidence | None:
        # Scan the eval-tenant WAL for the record with this request_id. O(n) per
        # probe is fine for the operator-run integration (not perf-critical).
        wal_dir = self._wal_dir
        if wal_dir is None:
            return None
        reader = WalEvidenceReader(wal_dir)
        for ev in reader.read_audit(tenant_id=self._tenant_id):
            if ev.ref.request_id == request_id:
                return ev
        return None
