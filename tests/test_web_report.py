"""EV-W1/EV-W2 — the read-only report service + the headless render guard.

Web tests skip cleanly without the optional `treval[web]` extra; the render guard skips
without node+jsdom (`npm ci`), and says so loudly rather than passing vacuously.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from treval.report_store import ReportStore, window_key, write_bundle

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests" / "fixtures" / "report" / "valid"
_CHECK_JS = _ROOT / "tests" / "web" / "check_render.js"

pytestmark = pytest.mark.filterwarnings(
    "ignore:Using `httpx` with `starlette.testclient` is deprecated"
)


@pytest.fixture
def store_dir(tmp_path):
    for i, f in enumerate(sorted(_FIXTURES.glob("*.json"))):
        write_bundle(tmp_path, f.read_text(encoding="utf-8"), generated_at_ns=1000 + i)
    return tmp_path


@pytest.fixture
def client(store_dir):
    pytest.importorskip("fastapi", reason="optional treval[web] extra not installed")
    from fastapi.testclient import TestClient

    from treval.web import create_app

    return TestClient(create_app(store_dir=store_dir))


# --------------------------------------------------------------------------- #
# Endpoints (D2)
# --------------------------------------------------------------------------- #


def test_reports_lists_newest_first(client):
    rows = client.get("/reports").json()
    assert len(rows) == 6
    gens = [r["generated_at_ns"] for r in rows]
    assert gens == sorted(gens, reverse=True)
    assert set(rows[0]) == {
        "tenant_id",
        "window",
        "generated_at_ns",
        "registry_fingerprint",
        "file",
    }


def test_report_json_returns_stored_bytes_verbatim(client, store_dir):
    """The bundle's whole value is being the exact artifact the engine produced —
    re-encoding would silently break byte-identity with the customer's copy."""
    entry = ReportStore(store_dir).list()[0]
    file_bytes = (store_dir / entry.file).read_bytes()
    resp = client.get(
        "/report.json",
        params={"tenant": entry.tenant_id, "window": window_key(entry.window)},
    )
    assert resp.status_code == 200
    assert resp.content == file_bytes  # byte-for-byte, not a re-serialization


def test_report_json_defaults_to_newest(client, store_dir):
    entry = ReportStore(store_dir).list()[0]
    assert client.get("/report.json").content == (store_dir / entry.file).read_bytes()


def test_dashboard_and_detail_render(client):
    for path in ("/", "/detail"):
        resp = client.get(path)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
    assert "评级标准指纹" in client.get("/").text
    assert "判定规则与本次结果" in client.get("/detail").text


def test_static_assets_are_cache_busted(client, tmp_path, monkeypatch):
    """Static links must carry a ?v=<hash> that changes with content — else browsers cache a
    stale style.css/*.js and a CSS change silently doesn't take (a ? renders as a square, a
    hidden popover shows flat). StaticFiles sends no Cache-Control, so the URL must version."""
    import re

    from treval.web import app as webapp

    html = client.get("/").text
    links = re.findall(r"/static/\S+?\?v=([0-9a-f]+)", html)
    assert links, "no versioned /static links in the page"
    assert all(v == links[0] for v in links), "all assets share one version token"

    # the token is a content hash: changing a static file changes it
    v1 = webapp._static_version(webapp._STATIC)
    d = tmp_path / "static"
    d.mkdir()
    (d / "a.css").write_text("x", encoding="utf-8")
    va = webapp._static_version(d)
    (d / "a.css").write_text("y", encoding="utf-8")
    vb = webapp._static_version(d)
    assert va != vb, "content hash did not change when a static file changed"
    assert len(v1) == 8


def test_measured_values_carry_their_unit():
    """A bare 60164.0 is a real defect — ms vs µs changes a 60-second p99 into a non-event.
    Every non-ratio value must render its unit (PM finding #1)."""
    from treval.web.view import _format_value

    assert _format_value({"value": 0.8928, "unit": "ratio"}) == "89%"
    assert _format_value({"value": 60164.0, "unit": "ms"}) == "60,164 ms"
    assert (
        _format_value({"value": 3.0, "unit": "count"}) == "3"
    )  # count is dimensionless
    assert _format_value({"value": 1820.0, "unit": "tokens"}) == "1,820 tokens"
    # an unknown unit is still shown, never silently dropped
    assert "widgets" in _format_value({"value": 5.0, "unit": "widgets"})


def test_insufficient_data_shows_no_value_and_no_false_verified():
    """insufficient_data must not also show a value + verified (PM finding #2): the row would
    contradict itself ("0% · verified · insufficient_data"), and "verified" on n=0 is meaningless."""
    import json

    from treval.web.view import objective_rows

    # rich has an insufficient_data objective; build the merged rows and inspect them
    bundle = json.loads(
        (_FIXTURES / "insufficient_data.json").read_text(encoding="utf-8")
    )
    rows = objective_rows(bundle)
    insufficient = [r for r in rows if r["status"] == "insufficient_data"]
    assert insufficient, (
        "fixture should contain at least one insufficient_data objective"
    )
    for r in insufficient:
        assert r["value"] == "", f"{r['id']} shows a value alongside insufficient_data"
    # no row may claim integrity while reporting zero samples
    for r in rows:
        if r["sample_size"] == 0:
            assert r["integrity"] is None, f"{r['id']} claims integrity on an n=0 row"


def test_sample_gate_vs_value_gate_are_distinguished():
    """duration_p99 (rule `sample_size >= 100`) shows a baseline READING; injection_catch_rate
    (rule `value >= 0.80`) shows a JUDGED value. "达标" on the former means "enough samples",
    not "60s latency is fine" — the two must not look the same (PM 60s-p99 blocker)."""
    import json

    from treval.web.view import objective_rows

    bundle = json.loads((_FIXTURES / "rich.json").read_text(encoding="utf-8"))
    by_id = {r["id"]: r for r in objective_rows(bundle)}
    # a value-gated objective
    assert by_id["rob.l2.injection_rule_detection"]["gate"] == "value"
    # sample-gated (baseline) objectives — the value is a reading, not a judged number
    for oid in (
        "rel.l4.slo_latency_baseline",
        "rob.l4.breach_baseline",
        "prv.l4.risk_metrics",
    ):
        assert by_id[oid]["gate"] == "sample", oid
    # attested objectives have no gate
    assert by_id["rob.l2.adversarial_test_ledger"]["gate"] is None


def test_required_sample_parses_the_threshold():
    from treval.web.view import _required_sample

    assert _required_sample("sample_size >= 100") == 100
    assert _required_sample("sample_size>=1") == 1
    assert _required_sample("value >= 0.80") is None
    assert _required_sample(None) is None


def test_radar_labels_stay_inside_the_viewbox():
    """Every axis label must fit the viewBox, with its anchor taken into account.

    Regression: the template hard-coded viewBox="0 0 320 300" while radar.py laid labels out
    on a ring that reached past x=343 — four of the five rendered clipped ("隐私与数..."), and
    nothing caught it because no test looked at label extents. The viewBox now comes from
    radar.py so the two cannot drift; this pins the geometry itself.
    """
    import json

    from treval.web.radar import VIEWBOX_H, VIEWBOX_W, radar_points

    doc = json.loads((_FIXTURES / "rich.json").read_text(encoding="utf-8"))
    titles = {d["id"]: d["title_zh"] for d in doc["registry"]["dimensions"]}
    radar = radar_points(doc["report"], titles)

    char_px = 12.0  # generous per-CJK-glyph width for an 11.5px label
    for a in radar.axes:
        w = len(a.title) * char_px
        if a.label_anchor == "middle":
            x0, x1 = a.label_x - w / 2, a.label_x + w / 2
        elif a.label_anchor == "start":
            x0, x1 = a.label_x, a.label_x + w
        else:
            x0, x1 = a.label_x - w, a.label_x
        assert x0 >= 0, f"{a.title!r} overflows left: x0={x0:.1f}"
        assert x1 <= VIEWBOX_W, (
            f"{a.title!r} overflows right: x1={x1:.1f} > {VIEWBOX_W}"
        )
        # a no-signal axis carries a sub-label ~12px below the title
        assert 0 <= a.label_y - 10 and a.label_y + 14 <= VIEWBOX_H, (
            f"{a.title!r} overflows vertically: y={a.label_y:.1f}"
        )


def test_view_switch_preserves_the_selected_tenant(tmp_path):
    """The Dashboard/详情 nav links must carry the current tenant — scope sits above the view.

    Regression: the links used `{{ qs }}`, which app.py never populated, so they rendered as
    bare "/" and "/detail". Switching view then sent tenant=None and the server fell back to
    the globally-newest report — jumping the user off their chosen tenant onto another one.
    """
    import json
    import re

    from fastapi.testclient import TestClient

    from treval.web import create_app

    src = json.loads((_FIXTURES / "rich.json").read_text(encoding="utf-8"))
    # tenant "zzz" is NOT the globally-newest, so a bare link would fall back to "aaa"
    for tenant, gen in (("aaa", 2000), ("zzz", 1000)):
        doc = json.loads(json.dumps(src))
        doc["report"]["tenant_id"] = tenant
        write_bundle(tmp_path, json.dumps(doc, ensure_ascii=False), generated_at_ns=gen)

    client = TestClient(create_app(store_dir=tmp_path))
    body = client.get("/", params={"tenant": "zzz"}).text

    # the 报告详情 link must keep tenant=zzz
    link = re.search(r'href="(/detail\?[^"]*)"', body)
    assert link, "no /detail nav link found"
    assert "tenant=zzz" in link.group(1), f"view link drops the tenant: {link.group(1)}"

    # and following it actually lands on zzz, not the globally-newest aaa
    follow = client.get(link.group(1))
    assert follow.status_code == 200
    assert "zzz" in follow.text and 'value="aaa" selected' not in follow.text


def test_switching_tenant_does_not_carry_the_old_tenant_window(tmp_path):
    """The tenant selector must submit tenant ALONE — a window belongs to exactly one tenant.

    Regression: tenant and window shared one <form>, so picking a new tenant submitted the
    previous tenant's window and the server 404'd on a scope the UI itself had produced
    (`?tenant=__eval__&window=1784252968666568040-...`, a window that only acme had).
    """
    import json
    import re

    from fastapi.testclient import TestClient

    from treval.web import create_app

    src = json.loads((_FIXTURES / "rich.json").read_text(encoding="utf-8"))
    for tenant, window, gen in (("acme", [111, 222], 2000), ("evalz", [0, 0], 1000)):
        doc = json.loads(json.dumps(src))
        doc["report"]["tenant_id"] = tenant
        doc["report"]["window"] = window
        write_bundle(tmp_path, json.dumps(doc, ensure_ascii=False), generated_at_ns=gen)

    client = TestClient(create_app(store_dir=tmp_path))
    body = client.get("/", params={"tenant": "acme"}).text

    # the tenant <select> must live in a form that carries no window field
    form = re.search(
        r"<form[^>]*>(?:(?!</form>).)*?sel-tenant(?:(?!</form>).)*?</form>", body, re.S
    )
    assert form, "tenant select is not inside its own form"
    assert 'name="window"' not in form.group(0), (
        "tenant form submits a window — switching tenant will 404 with the old tenant's window"
    )

    # and the scope the UI would produce must actually resolve
    assert client.get("/", params={"tenant": "evalz"}).status_code == 200
    # acme's window against evalz is exactly the 404 the old markup generated
    assert (
        client.get("/", params={"tenant": "evalz", "window": "111-222"}).status_code
        == 404
    )


def test_newest_marker_is_per_tenant_not_global(tmp_path):
    """Every tenant's window list marks its OWN newest report.

    Regression: `_selectors` enumerated the global (newest-first) index and filtered by tenant
    inside the comprehension, so `newest` meant "newest across all tenants" — every tenant but
    the globally-newest got no (最新) marker. All six fixtures share one tenant, so nothing
    caught it; multi-tenant is the only case the selector exists for.
    """
    import json

    from fastapi.testclient import TestClient

    from treval.web import create_app

    src = json.loads((_FIXTURES / "rich.json").read_text(encoding="utf-8"))
    for tenant, gen in (("tenant-old", 1000), ("tenant-new", 2000)):
        doc = json.loads(json.dumps(src))
        doc["report"]["tenant_id"] = tenant
        write_bundle(tmp_path, json.dumps(doc, ensure_ascii=False), generated_at_ns=gen)
    client = TestClient(create_app(store_dir=tmp_path))
    assert len(client.get("/reports").json()) == 2, "both tenants must be stored"
    for tenant in ("tenant-old", "tenant-new"):
        body = client.get("/", params={"tenant": tenant}).text
        assert "(最新)" in body, f"{tenant} has no newest-marked window"


def test_unknown_report_is_404_not_a_stack_trace_or_another_tenant(client):
    for params in ({"tenant": "no-such"}, {"window": "1-2"}):
        resp = client.get("/", params=params)
        assert resp.status_code == 404
        assert "Traceback" not in resp.text
    assert client.get("/report.json", params={"tenant": "no-such"}).status_code == 404


def test_api_registry_still_served(client):
    assert client.get("/api/registry").json()["kind"] == "dimension_registry"


# --------------------------------------------------------------------------- #
# Read-only, proven (§7.5)
# --------------------------------------------------------------------------- #


def test_no_mutating_routes_anywhere(client):
    for path in ("/", "/detail", "/reports", "/report.json", "/api/registry"):
        for method in ("post", "put", "delete", "patch"):
            resp = getattr(client, method)(path)
            assert resp.status_code in (404, 405), (
                f"{method.upper()} {path} → {resp.status_code}"
            )


def test_no_evidence_route_exists(client):
    """D3: no /evidence → the service never reads a request body, so it cannot leak PII."""
    from treval.web import create_app  # noqa: F401

    for path in ("/evidence", "/evidence/req-1", "/evidence?indicator=x"):
        assert client.get(path).status_code == 404


def test_app_never_imports_the_active_eval_harness():
    """The service must not be able to run a probe — read-only by construction."""
    code = (
        "import sys; import treval.web.app; "
        "leaked = [m for m in sys.modules if m.startswith('treval.active_eval')]; "
        "assert not leaked, f'web app imported the active-eval harness: {leaked}'"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=_ROOT
    )
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------------------------- #
# Auth (D4)
# --------------------------------------------------------------------------- #


def test_token_when_configured_is_required(store_dir):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from treval.web import create_app

    c = TestClient(create_app(store_dir=store_dir, token="s3cret"))
    assert c.get("/reports").status_code == 401
    assert c.get("/reports", headers={"x-treval-token": "s3cret"}).status_code == 200
    assert (
        c.get("/reports", headers={"authorization": "Bearer s3cret"}).status_code == 200
    )
    assert c.get("/reports", headers={"x-treval-token": "wrong"}).status_code == 401


# --------------------------------------------------------------------------- #
# EV-W2 §8.3 — the headless render guard (NOT optional)
# --------------------------------------------------------------------------- #


def _render_all(tmp_path: Path, out: Path) -> None:
    """Render every fixture's two views to files for the DOM guard.

    All six fixtures deliberately share one (tenant, window) — they are contract examples,
    not a realistic store — so `?tenant=&window=` cannot select among them. Rather than
    invent a selector the contract doesn't have (D2 is tenant+window), give each fixture
    its own store and let the default "newest" resolution pick it.
    """
    from fastapi.testclient import TestClient

    from treval.web import create_app

    out.mkdir(parents=True, exist_ok=True)
    for f in sorted(_FIXTURES.glob("*.json")):
        one = tmp_path / f"store-{f.stem}"
        write_bundle(one, f.read_text(encoding="utf-8"), generated_at_ns=1)
        c = TestClient(create_app(store_dir=one))
        for view, suffix in (("/", "dash"), ("/detail", "detail")):
            resp = c.get(view)
            assert resp.status_code == 200, f"{f.stem} {view} → {resp.status_code}"
            (out / f"{f.stem}.{suffix}.html").write_text(resp.text, encoding="utf-8")


def test_headless_render_guard(client, tmp_path):
    """Load every rendered page in a real DOM: zero JS errors + the key elements exist.

    Three prototype rounds shipped visually broken and ALL THREE passed source review
    (a mismatched quote swallowed a cell; a stray title="…" inside a JS string threw a
    SyntaxError that blanked the page). This is the guard that catches that class.
    """
    if shutil.which("node") is None:
        pytest.skip(
            "node not installed — run `npm ci` to enforce the EV-W2 render guard"
        )
    probe = subprocess.run(
        ["node", "-e", "require('jsdom')"], capture_output=True, cwd=_ROOT
    )
    if probe.returncode != 0:
        pytest.skip(
            "jsdom not installed — run `npm ci` to enforce the EV-W2 render guard"
        )

    pages = tmp_path / "pages"
    _render_all(tmp_path, pages)
    proc = subprocess.run(
        ["node", str(_CHECK_JS), str(pages)],
        capture_output=True,
        text=True,
        cwd=_ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
