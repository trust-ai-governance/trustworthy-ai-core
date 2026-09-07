"""裸 `/` 落在哪一份报告上 —— 路由的默认值，不是数据的默认值。

🔴 本文件第一版三条测试全部调 `create_app()` **不传 store_dir**，于是走 `app.py` 的
生产默认 `"reports/store"` —— **开发机上的真实 store**。而 `reports/` 是 `.gitignore` 的
（`.gitignore:228`）⇒ 本地那里躺着若干份真报告、三条测试全绿；CI 检出的树里那个目录
根本不存在 ⇒ 空 store ⇒ `/report.json` 没有 provenance ⇒ 三条全红。

**它们声称验的是"裸 / 落到合成 demo"这条路由规则，实际验的是"这台机器的 reports/store 里
恰好有一份合成 demo"** —— 在我机器上是一个更容易为真的条件，在 CI 上是一个不可能为真的条件。
⇒ 每条测试自带 store，`create_app` 一律显式传 `store_dir`。

⚠️ `_data_source` 读不到就返回 `None`，把"store 里没有这份报告"和"报告里没有这个字段"
合成了一格 —— 那正是 CI 里那句 `assert None == 'synthetic_demo'` 说不清失败原因的原因。
下面把"store 非空"单独断言一次，让这两件事分开。
"""

from __future__ import annotations

import json

import pytest

from treval.report_store import ReportStore, write_bundle
from treval.web.app import DEFAULT_TENANT


def _bundle(tenant: str, data_source: str, window: tuple[int, int]) -> str:
    """一份最小的 EV-R1 信封 —— 只带本文件断言要读的那几格。"""
    return json.dumps(
        {
            "report": {
                "tenant_id": tenant,
                "window": [window[0], window[1]],
                "measurements": [],
                "provenance": {"data_source": data_source},
            }
        }
    )


@pytest.fixture
def store_dir(tmp_path):
    """一个 demo 报告 + 一个 `__eval__` 报告；`__eval__` 更新，所以"最新"就是它。

    🔴 顺序是判据的一部分：若 demo 是最新的，`test_absent_default_tenant_…` 的
    "回落到最新"就会碰巧命中 demo，那条测试也就测不出回落到底走没走。
    """
    write_bundle(
        tmp_path,
        _bundle(DEFAULT_TENANT, "synthetic_demo", (10, 20)),
        generated_at_ns=10,
    )
    write_bundle(
        tmp_path, _bundle("__eval__", "measured", (30, 40)), generated_at_ns=20
    )
    return tmp_path


@pytest.fixture
def client_for(store_dir):
    from fastapi.testclient import TestClient

    from treval.web.app import create_app

    def _make(**kw):
        return TestClient(create_app(store_dir=store_dir, **kw))

    return _make


def _data_source(client, **q):
    d = client.get("/report.json", params=q).json()
    prov = d.get("provenance") or (d.get("report") or {}).get("provenance") or {}
    return prov.get("data_source")


def test_the_fixture_store_is_the_one_under_test(store_dir):
    """🔴 先把"读的是我建的那个 store"钉死，再谈路由。

    没有这一条，下面三条在一个空 store 上会以 `None != '...'` 的形态失败，
    而那句话说不出失败的是【路由错了】还是【根本没有数据】—— 那正是 CI 上发生的事。
    """
    tenants = {e.tenant_id for e in ReportStore(store_dir).list()}
    assert tenants == {DEFAULT_TENANT, "__eval__"}


def test_bare_root_lands_on_the_synthetic_demo_not_the_newest_run(client_for):
    """🔴 RED when: the bare `/` goes back to "newest across all tenants".

    That default landed the most-screenshotted page in the product on whatever ran last — in practice
    an `__eval__` run carrying REAL measured values, on a page a demo script explicitly forbids
    showing numbers on. The wrongness is silent: it renders perfectly, it is just someone else's
    data."""
    assert _data_source(client_for()) == "synthetic_demo"


def test_explicit_tenant_still_wins_over_the_default(client_for):
    """RED when: the default starts overriding an explicit `?tenant=` — the selector would become
    decorative, and an operator could not reach their own report at all."""
    assert _data_source(client_for(), tenant="__eval__") == "measured"


def test_absent_default_tenant_falls_back_to_newest_not_404(client_for):
    """RED when: a store with no demo report starts 404-ing its landing page. A fresh install must
    still show something; the synthetic report labels itself on the page, so the fallback is visible
    rather than silent."""
    assert _data_source(client_for(default_tenant="nope")) == "measured"
    assert _data_source(client_for(default_tenant="")) == "measured"
