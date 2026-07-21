"""The disclosure gate must actually bite (docs/DISCLOSURE_POLICY.md).

A gate nobody has tried to fool is a gate nobody knows the strength of. Each test below
feeds text that MUST fail and text that MUST pass, because the two failure modes are
symmetric and both fatal: a gate that misses real leaks is useless, and a gate that fires
on legitimate prose gets switched off within a month — leaving everyone believing they are
protected. The second is the one that actually happened to us elsewhere, so it is tested
just as hard as the first.
"""

from __future__ import annotations

from tools.check_doc_disclosure import scan_text


def _categories(text: str) -> set[str]:
    return {hit[2] for hit in scan_text("docs/whatever.md", text)}


def _severities(text: str) -> set[str]:
    return {hit[1] for hit in scan_text("docs/whatever.md", text)}


# --------------------------------------------------------------------------- #
# It must catch each real category — these are the actual strings that leaked.
# --------------------------------------------------------------------------- #


def test_catches_private_source_paths():
    assert "private_source" in _categories(
        "上游查出该字段不是内容派生的 —— `pipeline.py:314` 取的是静态串"
    )


def test_catches_platform_commit_shas():
    # Fake hex on purpose: this file is PUBLIC, so it must not embed a real private SHA
    # to test with — that would re-leak the very thing the gate exists to stop. The gate
    # detects the SHATTER *shape* (private-repo context word + hex), not a hardcoded list.
    assert "platform_commit" in _categories("它落在 Platform 提交 `deadc0de` 里")


def test_a_bare_hex_without_private_context_is_not_flagged():
    """Our OWN public commit SHAs appear in the provenance docs ("git 5b1d104"). A bare hex
    with no private-repo context word must pass, or the gate cries wolf on our own history."""
    assert "platform_commit" not in _categories("语料 git 5b1d104,2026-06-28 起未改")


def test_catches_control_gap_self_disclosure():
    """The worst category: announcing that our own gate does not run."""
    for line in (
        "公开 Core 的 CI 两样都拿不到，挂在这里是空门",
        "配置里 ruleset_version 从未 bump",
        "这个字段 Core 一行都没读",
    ):
        assert "control_gap" in _categories(line), line


def test_catches_named_vendor_next_to_a_negative_judgement():
    assert "vendor_named" in _categories("数美的数据条款通篇未提及留存时长")
    assert "vendor_named" in _categories("HTTPS 未见文档，易盾同病")


def test_catches_internal_layer_and_sku_names():
    assert "internal_name" in _categories("不做词库本体（Platform 的 C-词库层）")


# --------------------------------------------------------------------------- #
# It must NOT fire on legitimate prose. A gate that cries wolf gets disabled,
# and a disabled gate is worse than none because everyone thinks it is running.
# --------------------------------------------------------------------------- #


def test_neutral_vendor_mention_without_a_judgement_passes():
    """Naming a vendor is not the offence; pairing the name with a defect is."""
    assert _categories("两个第三方候选均返回 0–1 连续置信度") == set()
    assert "vendor_named" not in _categories("候选 A 与候选 B 的标签层级都够切片")


def test_our_own_public_source_paths_pass():
    """`treval/` and `tools/` are this repo — referencing them is the whole point."""
    assert _categories("见 `treval/indicators/block_rate.py` 首行的设计原则") == set()
    assert _categories("`tools/eval_report.py` 是主动评测入口") == set()


def test_methodology_language_passes():
    """Our own method IS the asset. Over-redacting it would gut the public repo."""
    for line in (
        "双侧门：只测召回会 ship 出过拦模型",
        "语料必须在任何调优开始之前就冻结",
        "整条链同源会退化成自证",
        "fail-closed：缺记录 ⇒ 记未捕获",
    ):
        assert _categories(line) == set(), line


def test_bare_cross_reference_to_a_private_doc_warns_but_does_not_fail():
    """The pointer is fine; the content is not. Dev briefs legitimately say
    'the contract lives upstream', and failing on that would make the gate unusable."""
    hits = scan_text(
        "docs/issues/EV-AE6.md", "implement from this file + `PLATFORM_ASK_X.md`"
    )
    assert hits, "a private doc reference should still be visible"
    assert _severities("implement from this file + `PLATFORM_ASK_X.md`") == {"warn"}


def test_the_policy_doc_and_the_gate_itself_are_exempt():
    """Both have to quote the forbidden strings in order to explain them."""
    leaky = "空门 / `上游侧` / 数美 未提"
    assert scan_text("docs/DISCLOSURE_POLICY.md", leaky) == []
    assert scan_text("tools/check_doc_disclosure.py", leaky) == []
    assert scan_text("docs/other.md", leaky) != []  # …but nowhere else


# --------------------------------------------------------------------------- #
# The hole that mattered: new files.
# --------------------------------------------------------------------------- #


def test_scan_covers_untracked_files_not_just_tracked_ones():
    """Every incident so far arrived in a NEW document. A gate reading only
    `git ls-files` gives a brand-new file a free pass until it is committed —
    which is exactly too late."""
    import inspect

    from tools import check_doc_disclosure as mod

    src = inspect.getsource(mod._candidate_text_files)
    assert "--others" in src and "--exclude-standard" in src
