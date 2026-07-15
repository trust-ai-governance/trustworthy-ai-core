# trustworthy-ai-core (`treval`)

**An open evaluation engine for AI governance. The thesis: _measured > attested_.**

Most AI-governance claims are *attested* — a vendor says its gateway blocks prompt
injection, and you take their word for it. `treval` exists so you don't have to.

It gives you three things, all open:

1. **A public attack corpus** (`corpus/`) — OWASP LLM Top-10 probes *plus a matched
   benign control set*, because a detector that blocks everything scores 100% recall.
2. **An evaluation engine** (`treval/`) — drives a governed target with that corpus,
   reads the target's own audit log as evidence, and grades it against a maturity
   registry. Deterministic and reproducible.
3. **An independent audit-chain verifier** (`tools/wal_verify.py`) — ~200 lines,
   Python stdlib only. **Point it at an audit log and check the hash chain yourself.
   You do not have to trust the party that wrote the log.**

Run it against *your* deployment, with *your* corpus, and get *your own* report.

---

## Measurement methodology (the part that matters)

Efficacy numbers are easy to inflate. These are the rules `treval` enforces on itself:

| Rule | Why |
|---|---|
| **Two-sided gate.** A dimension passes only if catch **≥ 0.80** *and* false-positive **≤ 0.05**. Both, or neither. | A gateway that blocks all traffic has perfect recall and zero value. Recall-only benchmarks reward exactly that. |
| **A "catch" is a governance decision, never the model's self-report.** Only a `BLOCK` — or a governance hint at the calibrated threshold — counts. | A model saying *"I can't help with that"* is not a control. It is the thing being tested. |
| **Evidence comes from the audit log, not the response body.** | Response text is model-nondeterministic. The decision record is not. |
| **Every metric is labelled `DETERMINISTIC` or `STATISTICAL`,** and lower-bound metrics say so. | A metric that only detects *verbatim* leakage under-counts paraphrase. Reporting its `0%` as "no leakage" is an artifact, not a result. |
| **Unmeasured is reported as `NotMeasured` — never as a pass.** | The registry separates *measured*, *attested*, and *awarded = min(measured, attested)*. You cannot be awarded a level you cannot show. |

We publish the methodology rather than a headline number, because **the corpus and the
harness are both in this repo — anyone can re-derive our numbers, including against us.**
That is the intended failure mode, not an oversight.

---

## Quick start

```bash
pip install -e .          # engine + CLI; no gateway, no database required
export PYTHONPATH=$PWD

# 1. Grade an existing measurement bundle → 5×5 maturity grid
python -m treval.cli report --measurement-bundle bundle.json --posture posture.yaml

# 2. Drive a live governed target with the corpus, then grade it
python -m treval.cli run --gateway http://<host>:<port> --wal /path/to/audit-log \
                         --posture posture.yaml --format human
```

Full workflow, environment variables and output locations: **[docs/CLI_USAGE.md](docs/CLI_USAGE.md)**.

### Verify an audit chain yourself

```bash
python tools/wal_verify.py /path/to/audit-log
```

Stdlib only, zero dependencies, no protobuf. It re-computes
`hash_i = SHA256(prev_hash || payload_i)` over the **stored bytes** and reports any
break, CRC failure, sequence gap or truncation.

> **What this proves — and what it does not.**
> A verified chain proves records were **not altered, deleted, or reordered** after they
> were written. It does **not** prove the log is **complete** — a request that never
> produced a record leaves no gap to find. Completeness is a separate property, addressed
> by fail-closed enforcement at the gateway and by the `unclosed_loop_rate` indicator
> (a decision record with no matching response record). We say this plainly because a
> verifier that over-claims is worse than no verifier at all.

---

## What's in here

| Path | |
|---|---|
| `corpus/` | Public attack + benign-control corpora (OWASP LLM01–LLM10) — YAML, one case per file |
| `treval/` | Evaluation engine: evidence readers, indicator SDK, maturity rubric, CLI |
| `registry/dimensions/` | The 5×5 maturity model as YAML — each objective bound to a *measured* indicator or an *attested* posture key |
| `tools/wal_verify.py` | Independent audit-chain verifier (stdlib only) |
| `docs/` | Architecture, CLI guide, report JSON schema, cross-repo contracts |

The engine never imports the gateway it evaluates. It reads audit evidence through an
`AuditEvidenceReader` protocol — swap the reader, keep the grade.

---

## Status

Actively developed. The maturity engine, indicator SDK, corpus and CLI are in place; the
read-only web report viewer is in progress. Briefs under `docs/issues/EV-*.md` are
development notes, not stable API contracts.

## License

Apache-2.0 — see [LICENSE](LICENSE). The corpora under `corpus/` are provided for security
evaluation of systems you are authorized to test.

## Citing

If you use `treval` or its corpora in academic work, please cite it — see
[CITATION.cff](CITATION.cff).
