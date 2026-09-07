def _data_source(client, **q):
    d = client.get("/report.json", params=q).json()
    prov = d.get("provenance") or (d.get("report") or {}).get("provenance") or {}
    return prov.get("data_source")


def test_bare_root_lands_on_the_synthetic_demo_not_the_newest_run():
    """🔴 RED when: the bare `/` goes back to "newest across all tenants".

    That default landed the most-screenshotted page in the product on whatever ran last — in practice
    an `__eval__` run carrying REAL measured values, on a page a demo script explicitly forbids
    showing numbers on. The wrongness is silent: it renders perfectly, it is just someone else's
    data."""
    from fastapi.testclient import TestClient

    from treval.web.app import create_app

    c = TestClient(create_app())
    assert _data_source(c) == "synthetic_demo"


def test_explicit_tenant_still_wins_over_the_default():
    """RED when: the default starts overriding an explicit `?tenant=` — the selector would become
    decorative, and an operator could not reach their own report at all."""
    from fastapi.testclient import TestClient

    from treval.web.app import create_app

    c = TestClient(create_app())
    assert _data_source(c, tenant="__eval__") == "measured"


def test_absent_default_tenant_falls_back_to_newest_not_404():
    """RED when: a store with no demo report starts 404-ing its landing page. A fresh install must
    still show something; the synthetic report labels itself on the page, so the fallback is visible
    rather than silent."""
    from fastapi.testclient import TestClient

    from treval.web.app import create_app

    assert _data_source(TestClient(create_app(default_tenant="nope"))) == "measured"
    assert _data_source(TestClient(create_app(default_tenant=""))) == "measured"
