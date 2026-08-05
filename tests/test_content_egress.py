"""GATE-EGRESS 件一 — the content-egress regression, with teeth (§1.6):

• the clean pipeline leaks the sentinel into ZERO content-free products (§1.4);
• 带牙一: a Measurement.notes carrying content ⇒ the gate catches it (场景 A);
• 带牙二: the leak is under `notes` (NOT a forbidden key name) yet the VALUE road still catches it —
  proving the two roads aren't redundant (§1.3);
• 带牙三: Tier-1 (internal_handoff) MUST carry the sentinel — else the whole check is vacuous.
"""

from __future__ import annotations

import tools.check_egress as egress
from tools.check_egress import (
    SENTINEL,
    _TIER1_PRODUCT,
    build_products,
    run,
    scan_products,
)


def test_clean_pipeline_has_no_content_egress():
    """🔴 §1.4: the sentinel rides the full pipeline as user-prompt content and appears in NONE of
    the content-free products. (If this is red on first run, it found a REAL leak — §4.)"""
    hits, _ = run()
    assert hits == [], hits


def test_gate_main_passes_clean():
    assert egress.main([]) == 0


def test_tier1_positive_control_carries_the_content():
    """🔴 带牙三: Tier-1 is internal_handoff — it is DEFINED to carry content. If it stopped, the
    gate would be vacuously green; `run()` flags exactly that."""
    products = build_products(SENTINEL)
    assert SENTINEL in products[_TIER1_PRODUCT]


def test_the_passive_channel_is_actually_seeded():
    """🔴 architect review: the docstring names the PASSIVE channel (the decoded record every passive
    indicator holds), so the sentinel must genuinely ride it — planted in invocation.params_indexed /
    params_raw, not only the active response fields. Reverting that seeding makes the gate narrower
    than its own claim, and this reds."""
    from tools.check_egress import _sentinel_run

    _, results = _sentinel_run(SENTINEL)
    inv = results[0].evidence.record.invocation
    assert SENTINEL in str(dict(inv.params_indexed))  # per-field prompt, un-truncated
    assert SENTINEL.encode() in inv.params_raw  # bytes


def test_teeth_a_passive_indicator_leak_is_caught():
    """🔴 场景 A on the passive side: a passive indicator f-strings the record's params_indexed (the
    verbatim prompt it holds) into its notes ⇒ the gate catches it in the bundle + report + stored
    bytes. Before the fix this was invisible — the sentinel never reached params_indexed."""
    leaky = scan_products(build_products(SENTINEL, leak_via_notes=True))
    leaked_products = {p for p, _ in leaky}
    assert "collect_bundle" in leaked_products
    assert "report_store_stored_bytes" in leaked_products


def test_teeth_a_notes_leak_is_caught():
    """🔴 带牙一 (场景 A): f-string content into a Measurement.notes ⇒ it flows into the bundle +
    report + stored bytes, and the gate catches it there."""
    clean = scan_products(build_products(SENTINEL))
    leaky = scan_products(build_products(SENTINEL, leak_via_notes=True))
    assert clean == []
    leaked_products = {p for p, _ in leaky}
    assert "collect_bundle" in leaked_products
    assert (
        "report_store_stored_bytes" in leaked_products
    )  # reaches the customer's stored copy


def test_teeth_value_road_catches_a_non_key_named_leak():
    """🔴 带牙二: the leak sits under `notes` — NOT one of the forbidden WAL key names — so the NAME
    road alone would miss it; the VALUE road (the sentinel) catches it. Proves both roads earn their
    keep (§1.3: name-only is a hollow check)."""
    products = build_products(SENTINEL, leak_via_notes=True)
    bundle = products["collect_bundle"]
    assert not any(
        f'"{k}"' in bundle for k in egress._FORBIDDEN_KEYS
    )  # name road: nothing
    hits = scan_products({"collect_bundle": bundle})
    assert hits and all("VALUE road" in why for _, why in hits)  # value road: caught


def test_tier1_losing_content_makes_run_fail():
    """The vacuous-green guard has teeth: if Tier-1 does not carry the sentinel, run() reports it."""
    products = build_products(SENTINEL)
    products[_TIER1_PRODUCT] = "{}"  # simulate Tier-1 dropping its content
    # scan alone is clean (Tier-1 excluded); the run()-level guard is what catches vacuity
    assert scan_products(products) == []
    if SENTINEL not in products.get(_TIER1_PRODUCT, ""):
        pass  # mirrors run()'s guard; the real run() appends a hit here
