# I3 file-grouped verdict fixture

The multi-file intake shape: one verdict file per group, benign-vs-violating carried by
**file membership** (never a verdict field).

| file | side | cases |
|---|---|---|
| `violating.jsonl` | violating | 1 (`topic_A`) |
| `benign.jsonl` | benign | 2 (`topic_A`, `topic_B`) |
| `benign_meta.jsonl` | benign (joins the benign side) | 1 (`topic_B`) |

**Provenance — what is real and what was re-arranged.** The scores, model/quant, digests,
`load_duration_ns` and `reload_contaminated` values are the **real recorded judge output**
(the same HP2 recording as `../verdicts_smoke.jsonl`), copied verbatim. Only the *layout* was
changed to produce the grouped shape:

* recorded cases were assigned to groups, and renumbered to line numbers **within** each group
  — which is why the same line number appears in more than one file (exactly the collision the
  `{group}:{line}` namespacing has to survive);
* `repeat` was renumbered `0..6` → **`1..7`**, so the fixture also covers repeat numbering that
  does not start at zero. The warmup drop is by position, so the lowest repeat is still dropped;
* `content_class` values are **anonymized placeholders** (`topic_A` / `topic_B`). Real
  content-safety subclass codes are never committed to this repo.

The violating case keeps its real **cold first repeat** (it differs from the warm repeats by
~1e-8). That difference is what makes the warmup drop load-bearing rather than cosmetic, so it
must be preserved: the regression asserts the run is deterministic only *because* that pass is
dropped.
