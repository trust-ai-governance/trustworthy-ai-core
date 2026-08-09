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
export TREVAL_EVAL_USER=<provisioned-eval-user>          # MUST be a PROVISIONED user (see ⚠ below)
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

### D. Produce a **citable** bundle in one command (EV-CITE)
A citable run needs a **frozen** window (`pinned`): same WAL + same bounds ⇒ same records ⇒ same
number. Two ways, no wasted probes:
```bash
# ① probe ONCE, then pin to the window the passive scan actually covered (window correct by
#    construction; it is still an owned口径 declaration — "口径就是这一跑", not an auto-pin):
python -m treval.cli collect --gateway $GW --wal $WAL --pin-observed-window --out bundle.json

# ② read the WAL and send NO probes at all — re-pin/re-read a passive result without re-paying
#    the whole active side (needs --wal; give bounds, or --pin-observed-window):
python -m treval.cli collect --passive-only --wal $WAL \
      --window-from-ns $FROM --window-to-ns $TO --out bundle.json
```
🔴 `--window-to-ns` **must be in the past** — a window whose upper bound has not passed is *not*
frozen (re-reading the WAL later returns more records, so the number moves), and `collect` **refuses
it at the source**. `--pin-observed-window` is mutually exclusive with `--window-from-ns/--window-to-ns`
(it pins to the scan it would otherwise filter). A **pure-active** run (`--target-kind raw_model`, or a
gateway run with no `--wal`) is anchored by `corpus_sha` + per-probe evidence, **not** a window — its
citability skips the window checks (a re-run draws a new sample regardless).

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

**Citability (件一) — the first line.** `--format human` leads with one verdict: `✅ CITABLE` or `🔴 NOT
CITABLE — <fix>`. It answers *may these numbers leave the room?* — a report-wide **provenance** question
(pinned window · segment hash · chain-anchored evidence · intact integrity chain), **not** whether a result
looks good. 🔴 An honest `unmet` (measured, below the line) is **citable**; only a standing-up failure
blocks. Each blocker names its fix. The delivery bundle carries `citable` / `citable_blockers` (top level)
and a paste-whole `citation_form` per measurement, worded by the indicator's **declared mechanism**
(EV-CIGATE §1.5, three ways — never derived from `ci is None`): a sampled **detector** → `n` + 95%
interval; a default-deny **total function** → *no* interval, "残余在覆盖面，不在抽样" (its residual is a hole
in the allow-list, not a rate); a **census** → `普查 n/n`, no sampling uncertainty. Not-citable → the same
string prefixed `🔴 NOT CITABLE`.

**Two kinds of a null measured level (件二).** A dimension with no certified measured level is **not one
thing** — the report (grid `measured gaps:` section, and the Dashboard) says which, each with a different
action: **below_floor** (测到了、区间下界不到线 → 扩样本，附条件式「还要多少 n」), **blocked_no_data**
(该级某指标本次未产出 → 查那个指标), **evidence_unverified** (有值但来源不可链校验 → 换 WAL 证据源), and
**not_measured** (真的没测 → `无实测信号`). "没测到" and "测了没达标" never read the same again.

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

## Case-level results — re-add the number yourself (UI-3a)

A maturity report says "injection catch rate 89.3%". The **case contract** (`--cases-out`, produced by
the active-eval run) makes that a number anyone can re-add: one row per test case (a *pointer* into the
audit log, never response content), plus the aggregates the rows must sum to.

```bash
# 1) verify a contract re-adds to its own aggregates (self-consistency + tamper check — NOT a proof
#    the numbers are true; it prints, on PASS, exactly what it does and does not cover):
python -m treval.cli cases verify /path/to/cases.json

# 2) ingest it into a tenant-scoped case store (fail-closed: refuses Tier-1 content, a pre-tenant
#    contract, or one whose rows do not re-add). The store is SEPARATE from the report store:
TREVAL_CASE_STORE=~/casestore python -m treval.cli cases store /path/to/cases.json
```

**Browse + re-add in a browser (optional, off by default).** A read-only service (`:8091`) lists a
credential's contracts and re-adds the aggregates on a page — its point is the byte-for-byte download +
the `cases verify` command to re-run in *your* terminal, not the green check on our page.

```bash
# credential → tenant map is a JSON FILE and is REQUIRED (no map ⇒ refuse to start). "*" = admin.
cat > ~/cases-tokens.json <<'EOF'
{"tok-operator": "<your-tenant>", "tok-admin": "*"}
EOF
TREVAL_CASES_TOKENS=~/cases-tokens.json TREVAL_CASE_STORE=~/casestore \
  python -m treval.web.cases        # :8091
```

**Three ways to pass the credential** (never a URL param):
- **a browser** — open `http://127.0.0.1:8091/`; with no credential you get an **access page**, enter the
  token in the 「访问密钥」 field, and a HttpOnly/SameSite=Strict cookie holds it (the 「退出」 link clears it).
  The token is the identity — there is no user, registration or session table;
- `x-treval-token: <token>` — or `Authorization: Bearer <token>` (scripts/API);
- **HTTP Basic** — for a terminal/CI: `curl -u :tok-a http://127.0.0.1:8091/` (username blank, password = the token).

🔴 Do **not** use `?token=` — it lands in browser history, access logs and the `Referer` header, so it is
refused. The tenant is decided by the **credential**, not a `?tenant=` param (a scoped token asking for
another tenant is a 403, never a silent fall-back). **Single-entry is opt-in:** set `TREVAL_CASES_MOUNT=/cases`
when launching the report service (`python -m treval.web`) to mount the case service under it — the
report token never opens `/cases/*` (a mount is a separate app with its own auth). Default: unmounted.

🔴 Case data is a bypass map — tenant-internal, never in outward materials, including screenshots.
