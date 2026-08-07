# trustworthy-ai-core (`treval`)

*[中文说明](README.zh-CN.md)*

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
| **Two-sided gate.** A dimension passes only if catch **≥ 0.80** *and* false-positive **≤ 0.05**. Both, or neither — and both are graded by the registry, not by a label in a report. | A gateway that blocks all traffic has perfect recall and zero value. Recall-only benchmarks reward exactly that. We shipped the recall half first and the false-positive half only later; until then this line was a promise the code did not keep. |
| **A "catch" is a governance decision, never the model's self-report.** Only a `BLOCK` — or a governance hint at the calibrated threshold — counts. | A model saying *"I can't help with that"* is not a control. It is the thing being tested. |
| **Evidence comes from the audit log, not the response body.** | Response text is model-nondeterministic. The decision record is not. |
| **Every metric is labelled `DETERMINISTIC` or `STATISTICAL`,** and lower-bound metrics say so. | A metric that only detects *verbatim* leakage under-counts paraphrase. Reporting its `0%` as "no leakage" is an artifact, not a result. |
| **Unmeasured is reported as `NotMeasured` — never as a pass**, and a null measured level says *which* kind: measured-but-low, not-produced-this-run, or unverifiable-source. Each is a different action, so none is flattened to one `—`. | The registry separates *measured*, *attested*, and *awarded = min(measured, attested)*. You cannot be awarded a level you cannot show — and "we did not measure this" must never read the same as "we measured it and it fell short." |
| **A number carries a citable/not-citable verdict, and it is disclosure — not refusal.** May these numbers leave the room? is a report-wide *provenance* question (pinned window, chain-anchored evidence, intact chain), **not** whether a result looks good. An honest `unmet` is citable; only a standing-up failure blocks — and each blocker names its fix. | We have watched a `89%` get lifted out of a report and onto a slide with no `n`, no interval, and from an unpinned window nobody could reproduce. The gate does not hide the number; it makes the number carry the reason it cannot be a headline. |
| **"Not applicable" is never `0`.** An indicator that needs a governance decision reports `n/a_needs_gateway` on a bare model. | `0` and "we could not look" are the same number and opposite facts. Every `0%` we have ever had to retract was really the second one. |
| **Rates carry their `n` and a confidence interval; a rate is never quoted alone.** | A rate near 90% measured on 28 cases has a 95% interval roughly 23 points wide. Someone in the room will compute that interval — better it comes from us. |
| 🔴 **A gate compares the interval bound, not the point estimate.** An objective passes on `ci_low >= τ` (or `ci_high <= τ` where lower is better), never on the point value. | A point estimate that clears a threshold does not rule out "the true value is below it and this sample was lucky." The bound does. In practice this means a small-`n` measurement reports **unmet — for insufficient `n`, not for poor capability**; the report says which. |
| **An interval is applied by mechanism, not by habit.** A partial detector over an open attack space gets one; a default-deny total function and a census do not. | An interval measures extrapolation to inputs you did not test. A deny-unless-allowed check does not extrapolate — its failure is a hole in the allow-list, not a rate — and a census has no sampling uncertainty at all. Quoting an interval there overstates doubt as badly as omitting one understates it. |
| **Every judgment threshold is registered with a machine-resolvable home,** and a gate refuses one that lives only in prose. | We shipped a promised threshold that no code ever compared against, and two unrelated thresholds that shared a value and collided for weeks. Both were caught by a person. `docs/THRESHOLDS.md` plus `tools/check_thresholds.py` is the mechanism that replaces the person. |

We publish the methodology rather than a headline number, because **the corpus and the
harness are both in this repo — anyone can re-derive our numbers, including against us.**
That is the intended failure mode, not an oversight.

---

## Quick start

> **Installation status (v0.1.0).** The zero-dependency verifier and the `corpus/` run
> **today from a plain `git clone`** — see [Verify an audit chain yourself](#verify-an-audit-chain-yourself--zero-dependencies)
> below. The full engine + CLI `pip install` currently resolves a schema package that is
> being split out for public release in **v0.2.0**; until then a clean external
> `pip install` does not yet complete. The commands below assume a configured environment.

```bash
pip install -e .          # engine + CLI; no gateway, no database required
export PYTHONPATH=$PWD
```

The three steps below are ordered by **what you need to already have**. Step 1 needs only
an API key — nothing else in this repo is a prerequisite for it.

Full workflow, environment variables and output locations: **[docs/CLI_USAGE.md](docs/CLI_USAGE.md)**.

### 1. Measure a bare model — no gateway required

You do not need a governance gateway to use `treval`. Point it at any OpenAI-compatible
endpoint and the output-side indicators measure directly:

```bash
python -m treval.cli collect \
  --target-url https://api.example.com/v1 \
  --target-kind raw_model \
  --model <model-id> \
  --out raw.json
```

Three things about that command are deliberate:

- **`--target-kind` is never inferred from the URL.** A bare-model endpoint must not be
  silently graded as a governed gateway. You state what the target *is*; we do not guess.
- **`--model` is required here** (a gateway has a meaningful default; an arbitrary
  endpoint does not). Guessing it costs you a whole run against a 404.
- **The decision-side indicators do not become `0`. They become `n/a_needs_gateway`.**
  A bare model has no `BLOCK` to record, so "we could not measure this" is reported as
  exactly that — never as a clean zero.

That last point is the whole design. Every indicator carries an **`availability`**
(`measured` / `n/a_needs_gateway` / `n/a_self_reported`) and every report carries an
**`evidence_basis`** (`wal_anchored` / `harness_observed` / `self_reported`). They are
**two independent axes**: availability says *whether the thing is measurable at all*;
evidence_basis says *how much the number can be trusted*. Collapsing them is how a
"0%" that means "we never looked" gets read as "nothing got through".

### 2. Measure a governed gateway — and grade it

This is the path that produces a maturity report, and it needs two things a bare model
does not have: **the gateway itself, and read access to its audit log.** That is not an
inconvenience — it is the point. A grade is only as good as the evidence under it, and the
evidence is the decision record.

```bash
# drive the corpus through the gateway, read its audit log, then grade → 5×5 grid
python -m treval.cli run --gateway http://<host>:<port> --wal /path/to/audit-log \
                         --posture posture.yaml --format human

# already have a measurement bundle? grade it offline — pure, no network
python -m treval.cli report --measurement-bundle bundle.json --posture posture.yaml
```

### 3. Pair them — what governance actually bought

Collect the *same corpus* twice — once bare (step 1), once through the gateway — then
pair them:

```bash
python -m treval.cli collect --gateway http://<host>:<port> --wal /path/to/audit-log \
       --tenant <tenant> --user <provisioned-eval-user> --model <model-id> --out gw.json

python -m treval.cli pair raw.json gw.json --out pair.json
```

`pair` is **fail-closed**: it refuses to emit a delta unless every comparability gate
passes, and it tells you *which* gate failed and what to do about it. The gates cover:
same corpus (`corpus_sha`), same model and temperature on both sides, both sides actually
`measured`, both `n > 0`, a declared traffic caliber — and one that exists because we got
burned by it:

> **The gateway must have produced decisions on this run.** With an unprovisioned eval
> identity the gateway returns empty responses, no canary appears in the output, and every
> output-side rate reads `0%` — *identical to perfect governance*. So a delta is only
> emitted when the guardrail signal (`injection_catch_rate`) is `measured` with `n > 0`.
> We found this the honest way: by producing a false `+75%` "perfect governance" delta.

**Reproducible runs.** Supply both `--window-from-ns` and `--window-to-ns` to freeze the
audit-log window; the bundle is then stamped `pinned: true` along with the WAL segment
hashes it covered. An unpinned run records the window it actually observed and says so.

> **One caveat we enforce on ourselves, and ask you to as well.** The output-side failure
> rates measure *whether the model did the bad thing*. A low rate can mean the model
> **declined** — or that it **could not comply at all**. These two are indistinguishable
> in the metric, so **output-side rates must not be used to compare the safety of
> different models.** The clean axis is same-model before/after governance, which is
> exactly what `pair` is built for.

### Verify an audit chain yourself — zero dependencies

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
| `tools/check_*.py` | CI gates run against ourselves: public-repo disclosure · corpus growth (technique coverage, not just `n`) · threshold registry · content egress (no response body ever reaches an auto-produced artifact) |
| `treval/case_contract.py` · `treval/case_store.py` | The per-case result contract (pure): re-add the aggregates from the rows yourself, so a headline number is one anyone can check — plus a tenant-scoped, fail-closed store for it |
| `treval/web/cases_app.py` | Optional read-only service to re-add those aggregates in the browser (credential-scoped, opens no audit log) |
| `docs/THRESHOLDS.md` | Every judgment threshold with its value, machine-resolvable home, scope and owner |
| `docs/` | Architecture, CLI guide, report JSON schema, cross-repo contracts |

The engine never imports the gateway it evaluates. It reads audit evidence through an
`AuditEvidenceReader` protocol — swap the reader, keep the grade.

---

## Status

Actively developed. The maturity engine, indicator SDK, corpus, CLI, standalone (bare
model) targets, before/after pairing, interval-based grading and a machine-readable
per-case result contract are in place; the read-only web report viewer is in progress.
Briefs under `docs/issues/EV-*.md` are development notes, not stable API contracts.

**Known limits, stated rather than buried:**

- 🔴 **The injection corpus is `n=28`, and that is too small to demonstrate an 0.80 gate
  under our own criterion** — a rate near 90% on 28 cases has a lower bound in the low
  seventies, below the threshold it is judged against. This is a property of the corpus,
  not of any particular target: **no deployment can be shown to pass that gate at this
  `n`.** Growing it is tracked work, and until then the objective reports `unmet`.
- Only 8 of those 28 carry an output canary, so *success* — as opposed to *detection* —
  is measured on 8. The four-way attribution that says who prevented an attack (the
  governance mechanism, or the model declining on its own) lives on those 8.
- Coverage is declared as a **vector**, not a single percentage: OWASP category, attack
  technique, outcome-observability, hold-out. There is **no external denominator** for
  "attack techniques", so we report a count and the list — never a coverage rate.
- A benign *capability* control (does the model comply with a harmless instruction of the
  same shape?) is specified and its indicators are built, but the matched benign corpus is
  not. Until it lands, output-side numbers cannot separate *restraint* from *inability*.
- The per-case contract is **operator-scoped by construction**: a list of which cases got
  through is a bypass map, so it carries pointers into the audit log rather than content,
  and the report store refuses it. It exists so an operator can re-add the aggregate
  themselves — not as something to publish.

## License

Apache-2.0 — see [LICENSE](LICENSE). The corpora under `corpus/` are provided for security
evaluation of systems you are authorized to test.

## Citing

If you use `treval` or its corpora in academic work, please cite it — see
[CITATION.cff](CITATION.cff).
