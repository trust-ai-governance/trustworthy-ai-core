# `treval` CLI — usage guide (EV-8)

Turn governance evidence into a **maturity report** — *verified* level vs *declared* level, with the
over-claim gap. Entry point: `python -m treval.cli`.

## Mental model (why `bundle.json` "doesn't exist")

There are **two stages**, split on purpose:

```
  collect ──►  bundle.json  ──►  report  ──►  maturity report (json | human | csv)
 (live, may fail)  (the seam)   (pure, deterministic)
```

- **`collect`** drives the live gateway and *writes* a **Measurement bundle** (`bundle.json`).
- **`report`** *reads* that bundle and grades it — no gateway, no clock, byte-deterministic.

So `report --measurement-bundle bundle.json` fails with *"No such file"* until you've **produced**
`bundle.json` first (via `collect`, or by hand for a fixture). That error is expected, not a bug —
you skipped the produce step.

Two-stage on purpose (EV-8 §0②): a collection failure (gateway down, unprovisioned user) never breaks
the grade/render logic, and support can re-render a customer's bundle **offline** without their gateway.

## Quick start

### A. One-shot against a live gateway (`run` = collect ∘ report)
```bash
export TREVAL_EVAL_GATEWAY_URL=http://127.0.0.1:8080
export TREVAL_EVAL_WAL_DIR=/home/olvan/wal
export TREVAL_EVAL_USER=jack          # MUST be a PROVISIONED user (see ⚠ below)
python -m treval.cli run --posture docs/posture.sample.yaml --format human
```

### B. Two steps (collect once, re-render many times)
```bash
python -m treval.cli collect --out bundle.json          # → writes bundle.json (live)
python -m treval.cli report  --measurement-bundle bundle.json \
      --posture docs/posture.sample.yaml --format human  # → renders (offline, repeatable)
```

### C. Offline / support (no gateway — someone hands you a bundle)
```bash
python -m treval.cli report --measurement-bundle their_bundle.json --format json --out report.json
```

## Inputs & outputs (where things go)

| Thing | Where | Notes |
|---|---|---|
| **Registry** (the 5×5 standard) | `registry/dimensions/*.yaml` (repo) | loaded automatically; no flag |
| **Measurement bundle** | `--measurement-bundle <file>` (report) / `--out <file>` (collect, default `bundle.json`) | the seam between the two stages |
| **Posture** (attested facts) | `--posture <file>` | sample: `docs/posture.sample.yaml`; omit → all attested objectives `unmet` |
| **Report output** | stdout, or `--out <file>` | `--out` writes the file; the "wrote …" line goes to stderr |
| **Warnings** | always **stderr** | so `--format json`/`csv` on stdout stays clean/pipeable |

**Formats** (`--format`, default `human`): `json` (the EV-R1 bundle, byte-stable, for the UI/API) ·
`human` (terminal: 5×5 grid → gaps → per-dimension detail → appendix) · `csv` (one row per objective).

**Write to a file** (any format) with `--out` — otherwise it prints to stdout:
```bash
python -m treval.cli report --measurement-bundle bundle.json --format csv --out report.csv
python -m treval.cli run --posture docs/posture.sample.yaml --format csv \
       --out report.csv --bundle-out bundle.json     # run: --out = the report, --bundle-out = the bundle
```
In `run`, `--out` is the **report** destination and `--bundle-out` is the intermediate bundle (they no
longer share one path).

## ⚠ Environment / provisioning (the usual "empty report" cause)

`collect` drives the real gateway; get these right or it silently collects nothing:

| Var / flag | Meaning | Gotcha |
|---|---|---|
| `TREVAL_EVAL_GATEWAY_URL` / `--gateway` | invoke base URL | required for `collect`/`run` |
| `TREVAL_EVAL_WAL_DIR` / `--wal` | WAL mount to read decisions from | the catch signal comes from here |
| `TREVAL_EVAL_USER` / `--user` | eval identity | **MUST be provisioned on the target** — an unprovisioned user makes every probe *unmeasurable*, and you get an empty bundle with the failures only in the warnings. Dev = `jack` |
| `TREVAL_EVAL_TENANT` / `--tenant` | eval tenant | default `__eval__` |
| `TREVAL_EVAL_MODEL` / `--model` | upstream model id | default `deepseek-v4-flash` |

A `collect` run prints `wrote bundle.json: N/2 producer(s) succeeded` to stderr — **check `N`**. `0/2`
means the env is wrong (usually the user isn't provisioned), not that the gateway has no governance.

## Reading the report

Real output (2 active measurements, no posture match):
```
maturity grid  (rows = dimension, cols = L1..L5)
                             L1  L2  L3  L4  L5
efficient_reliability         ·   ·   ·   ·   ·  (NotMeasured)
robustness                    M   M   ·   ·   ·
security_alignment            ·   ·   ·   ·   ·
  legend: A awarded  M measured-only  D declared-only  · none
```
- **A**/green = awarded (verified **and** declared) · **M**/blue = measurement supports, attestation is short ·
  **D**/yellow = declared only (the over-claim zone) · **·**/grey = not reached.
- **`(NotMeasured)`** = the dimension collected **no** measured signal (all `insufficient_data`) — and by
  design attestation **cannot** raise it. That honesty *is* the point.
- Colours show on a TTY; piped/`--out`/`NO_COLOR` → the plain letters above (diff-stable).

**Today's coverage is thin on purpose (EV-8 §1):** only `injection_catch_rate`, `tool_scope_violation_rate`
(active) and `block_rate` (passive, not yet collected) exist — so **robustness + security** carry measured
rows and the other three dimensions read **NotMeasured**. Each future indicator (EV-5/EV-9) lights up more
rows with **zero CLI change**. Note security certifies no level yet because its L3 also needs
`block_rate` (the passive path) — so with active-only it shows a met row in the detail but no grid cell.

## Exit codes
`0` ok (even with warnings) · `2` ambiguous bundle (duplicate aggregate `indicator_id` — a curation bug) ·
`3` I/O or args (bad/missing bundle, registry, or posture file).

## Make a fixture bundle by hand (tests / demos)
```json
{
  "schema_version": 1, "tenant_id": "acme-prod", "window": [0, 0], "mode": "active",
  "measurements": [
    {"indicator_id": "injection_catch_rate", "dimension": "robustness",
     "value": 0.89, "unit": "ratio", "sample_size": 28, "integrity": "verified",
     "evidence_refs": [{"source": "wal:/w/000.wal", "seq": 1, "request_id": "r1"}]}
  ]
}
```
`subject`/`notes`/`integrity`/`evidence_refs` default, so a minimal entry loads. `tenant_id` must match
the `--posture` file's `tenant_id` for attestations to apply.
