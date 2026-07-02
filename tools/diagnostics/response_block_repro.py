"""Operator diagnostic — re-run a corpus case N times through the live gateway and
report the response-stage BLOCK rate + match-type attribution.

Surfaced by the `execute.015` pii-block-response false positive (P2-dlp.1). A
response-stage block redacts the content, so the *trigger* is invisible to the eval
in the HTTP response. This reads the chain-verified WAL `response.observed` record's
match-type attribution — `on_tool_response_rules[*].tags["match_types"]` (P2-dlp.1
Part B: type NAMES only, never values) — so we learn WHICH detector fired without
ever seeing the PII.

Use it to (a) measure a benign case's response-block (FP) rate after a rule change,
or (b) attribute any response block by type. Model output is only ~deterministic at
temperature 0, so an intermittent block needs several runs to characterize — hence N.

Operator-run (drives the live gateway); NOT exercised in CI, like tools/eval_report.py.
Reads only the WAL (never the HTTP body) for the block/attribution verdict. No secrets
or detection patterns are embedded here — attribution comes from the gateway.

Usage:
    TREVAL_EVAL_GATEWAY_URL=http://127.0.0.1:8080 TREVAL_EVAL_WAL_DIR=/path/to/wal \\
    TREVAL_EVAL_USER_ID=<provisioned-eval-user> \\
      python tools/diagnostics/response_block_repro.py <corpus_subdir> <case_id> [N]

Example (the execute.015 FP):
    TREVAL_EVAL_USER_ID=jack \\
      python tools/diagnostics/response_block_repro.py llm01_benign benign.hard.execute.015 30
"""

from __future__ import annotations

import os
import sys

from treval.active_eval import GatewayTarget, load_corpus


def main(argv: list[str]) -> int:
    corpus_sub = argv[1] if len(argv) > 1 else "llm01_benign"
    case_id = argv[2] if len(argv) > 2 else "benign.hard.execute.015"
    n = int(argv[3]) if len(argv) > 3 else 10

    gw = os.environ.get("TREVAL_EVAL_GATEWAY_URL", "http://127.0.0.1:8080")
    wal = os.environ.get("TREVAL_EVAL_WAL_DIR", "/home/olvan/wal")
    tenant = os.environ.get("TREVAL_EVAL_TENANT", "__eval__")
    # The eval user MUST be one the gateway provisions for the eval tenant — an
    # unprovisioned user's requests do not correlate to a WAL record (every run comes
    # back "unmeasurable"). Set TREVAL_EVAL_USER_ID to your deployment's eval user.
    user_id = os.environ.get("TREVAL_EVAL_USER_ID", "eval-user")
    target = GatewayTarget(
        gw, wal_dir=wal, tenant_id=tenant, user_id=user_id, temperature=0.0, timeout=120
    )

    corpus = load_corpus(f"corpus/{corpus_sub}")
    case = next((c for c in corpus if c.id == case_id), None)
    if case is None:
        print(f"case {case_id!r} not found in corpus/{corpus_sub}", file=sys.stderr)
        return 2

    print(
        f"case={case_id}  N={n}  gateway={gw}  user={user_id}\ninput={case.input!r}\n"
    )

    blocked = 0
    unmeasurable = 0
    saw_attribution = False
    type_tally: dict[str, int] = {}
    for i in range(n):
        pr = target.probe(
            case
        )  # GatewayTarget attaches evidence + response_evidence (EV-AE8)
        resp_ev = pr.response_evidence
        if pr.error is not None or resp_ev is None:
            unmeasurable += 1  # no response record ⇒ cannot judge this run (excluded)
            reason = pr.error or "no response.observed record"
            print(f"[?????] run{i:02d} unmeasurable: {reason}")
            continue
        resp = resp_ev.record.response
        term = str(resp.final_terminal)
        is_block = "BLOCK" in term
        blocked += is_block
        # match-type attribution from the firing (non-log) response rule(s), P2-dlp.1 Part B.
        firing = []
        for r in resp.on_tool_response_rules:
            if r.matched and list(r.actions_fired) and list(r.actions_fired) != ["log"]:
                mt = dict(r.tags).get("match_types", "")
                if mt:
                    saw_attribution = True
                    for t in mt.split(","):
                        type_tally[t] = type_tally.get(t, 0) + 1
                firing.append(
                    f"{r.rule_id}{list(r.actions_fired)} match_types={mt or '(none)'}"
                )
        marker = "BLOCK" if is_block else "allow"
        print(f"[{marker}] run{i:02d} term={term} {'; '.join(firing) or '-'}")

    measurable = n - unmeasurable
    rate = f"{blocked / measurable:.0%}" if measurable else "n/a"
    print(
        f"\n=> {blocked}/{measurable} BLOCKED ({rate})  |  "
        f"{measurable - blocked}/{measurable} allowed  |  {unmeasurable} unmeasurable"
    )
    if unmeasurable == n:
        print(
            f"   ALL runs unmeasurable — likely the eval user {user_id!r} is not "
            "provisioned for this gateway/tenant. Set TREVAL_EVAL_USER_ID correctly."
        )
    if saw_attribution:
        print(f"   match_types over firing rules: {type_tally}")
    elif blocked:
        print(
            "   (blocks fired but NO match_types tag — P2-dlp.1 Part B attribution is "
            "not live on this gateway build)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
