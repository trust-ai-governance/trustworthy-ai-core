"""🔴 分母单位门（PM 裁定③）—— 报数产物必须印出【分母单位】+【会话数】+【消息数】，缺一项不可引。

存在理由，用规则专家自己的话：**他在请求级调参数、却在会话级被判，两个数不可比，而他会以为自己调对了。**

而这一格今天没有门 —— 一个只印「误伤率 4.2%」的产物，读者无从知道那 4.2% 的分母是 40 条会话还是
240 条消息，两者相差六倍。🔴 单位不是排版，它是这个数指的是什么。
"""

from __future__ import annotations

import pytest

from treval.session_unit import (
    SESSION_UNIT,
    SessionUnitError,
    session_denominator_line,
    session_false_block,
)


# --------------------------------------------------------------------------- #
# 判据本身 —— 会话级：一条会话里任何一条消息踩雷 ⇒ 整条记一次误伤
# --------------------------------------------------------------------------- #
def test_any_tripped_message_makes_the_whole_session_one_false_block():
    """🔴 什么让它红：按消息计数（一条会话踩两条就记两次）—— 那是消息级，不是会话级。"""
    # 🔴 恰好【一条】踩雷 —— 这一条是"任何一条"的全部意思，少了它，
    # 把判据改成"两条以上才算"照样绿（一次存活的变异指出来的）。
    assert session_false_block([False, True, False]) is True
    assert session_false_block([False, True, True, False]) is True
    assert session_false_block([True]) is True
    assert session_false_block([False, False]) is False


def test_an_empty_session_is_refused_not_counted_as_clean():
    """🔴 零条消息的会话不是"没踩雷"，是没得判。什么让它红：把空会话当 False 记进分母。"""
    with pytest.raises(SessionUnitError, match="空会话"):
        session_false_block([])


# --------------------------------------------------------------------------- #
# 🔴 门 —— 三项缺一即不可引
# --------------------------------------------------------------------------- #
def test_the_line_carries_all_three():
    """单位 + 会话数 + 消息数，三项都要在同一行上。
    什么让它红：少印任何一项。"""
    line = session_denominator_line(sessions=40, messages=239)
    assert SESSION_UNIT in line
    assert "40" in line and "239" in line


@pytest.mark.parametrize(
    ("sessions", "messages"),
    [(0, 239), (40, 0), (0, 0)],
)
def test_a_zero_count_is_refused(sessions, messages):
    """🔴 零会话或零消息 ⇒ 这批没量过，不许印成一行看起来正常的分母声明。
    什么让它红：把 0 当成一个合法计数印出去。"""
    with pytest.raises(SessionUnitError):
        session_denominator_line(sessions=sessions, messages=messages)


def test_messages_cannot_be_fewer_than_sessions():
    """每条会话至少一条消息 ⇒ 消息数 < 会话数 说明两个数不是同一批件算出来的。
    什么让它红：不校验，于是一个把 A 档会话数配 B 档消息数的产物照样印出来。"""
    with pytest.raises(SessionUnitError, match="不是同一批"):
        session_denominator_line(sessions=40, messages=39)


def test_the_unit_string_names_the_criterion_not_just_the_word():
    """🔴 只印「会话级」三个字不够 —— 读者要能从这一行读出判据是什么。
    什么让它红：把单位缩成一个标签。"""
    assert "任何一条消息" in SESSION_UNIT and "一次" in SESSION_UNIT
