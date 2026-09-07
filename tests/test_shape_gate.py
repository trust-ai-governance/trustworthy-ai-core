"""🔴 形状匹配门自己的门 ——「答不出按哪个字段数，就是在按形状数」这条纪律栽过六次。

一条栽过六次的纪律该有一道门；而一道门必须自己被证明有牙，否则它只是又一条纪律。
"""

from __future__ import annotations

from tools.check_shape_match import shape_hit


def test_it_catches_the_one_that_cost_two_arms() -> None:
    """🔴 `"control_" in case_id` —— 在注入臂上剔掉 0 件（一直在跑、一直没生效），
    换个臂又误剔了 6 件良性件。同一个写法，两个相反的失败。

    什么让它红：把 `control_` 从 `_VALUE_PREFIXES` 里拿掉。
    """
    assert shape_hit('    if "control_" in case.id:') is not None
    assert shape_hit('    kept = [c for c in cs if "control_" not in c.id]') is not None
    assert shape_hit('    if fname.startswith("control_"):') is not None


def test_it_does_not_flag_the_only_correct_form() -> None:
    """🔴 正解不许被报出来 —— 一道把正确写法也报红的门，会先被关掉。

    什么让它红：去掉 `_SANCTIONED`。
    """
    assert shape_hit('    if c.attack_class.startswith("control_"):') is None


def test_a_dotted_namespace_prefix_on_a_named_field_is_not_the_defect() -> None:
    """`rule_id.startswith("inj.tier2.")` 是【命名空间】前缀，语义等价于全等收窄。

    栽过的那次是 `"scored" in rule_id` —— 子串，会命中 `unscored`（两个相反的结局并成一格）。
    两者形状像、语义相反，所以显式放行前者。

    什么让它红：把 `rule_id.startswith` 从 `_SANCTIONED` 里拿掉（那时普查那一行会误红）。
    """
    assert shape_hit('        if rid.startswith("inj.tier2."):') is None
    assert shape_hit('    if rule.rule_id.startswith("inj.tier2."):') is None


def test_prose_describing_the_defect_is_not_the_defect(tmp_path) -> None:
    """🔴 第一版不剥注释/文档串，6 处命中里 4 处是**在散文里描述这个错法** ——
    包括这道门自己的模式表。

    **一道门如果主要在报自己的说明书，它会先被人关掉，再才可能拦住什么。**

    什么让它红：去掉 `_prose_lines` 那一步。
    """
    from tools.check_shape_match import _prose_lines

    f = tmp_path / "m.py"
    f.write_text(
        'X = 1\n# 反例：`"control_" in case_id`\nDOC = """\n"control_" in cid\n"""\nY = 2\n',
        encoding="utf-8",
    )
    import tools.check_shape_match as mod

    orig = mod._ROOT
    mod._ROOT = tmp_path
    try:
        prose = _prose_lines("m.py")
    finally:
        mod._ROOT = orig
    assert 2 in prose, "注释行没被认出来"
    assert 3 in prose and 4 in prose, "文档串行没被认出来"
    assert 1 not in prose and 6 not in prose, "真代码行被误当成散文了"


def test_an_unparseable_file_fails_noisy_not_silent(tmp_path) -> None:
    """tokenize 失败 ⇒ 返回空集 ⇒ 该文件所有行都参与匹配。

    🔴 **宁噪不漏**：一个语法坏了的文件如果被整个跳过，它就是一个安静的豁免。
    什么让它红：把 except 那一支改成"跳过整个文件"。
    """
    from tools.check_shape_match import _prose_lines

    import tools.check_shape_match as mod

    f = tmp_path / "bad.py"
    f.write_text('def (:\n  "control_" in x\n', encoding="utf-8")
    orig = mod._ROOT
    mod._ROOT = tmp_path
    try:
        assert _prose_lines("bad.py") == frozenset()
    finally:
        mod._ROOT = orig
