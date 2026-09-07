"""会话级分母单位（PM 裁定③，2026-09-05）—— 标定臂与留出臂必须同单位，且单位要印出来。

🔴 为什么是一道门而不是一句约定，用规则专家自己的话：**他在请求级调参数、却在会话级被判，两个数不
可比，而他会以为自己调对了。** 而一个只印「误伤率 4.2%」的产物，读者无从知道那个分母是 40 条会话还是
240 条消息 —— 两者差六倍。**单位不是排版，它是这个数指的是什么。**

判据（A 档与 B 档逐字相同）：一条会话里**任何一条**消息踩雷 ⇒ **整条**记一次误伤。
"""

from __future__ import annotations

from collections.abc import Iterable

SESSION_UNIT = "分母单位=会话（一条会话里任何一条消息踩雷 ⇒ 整条记一次误伤）"


class SessionUnitError(Exception):
    """分母声明不成立 ⇒ 该批不可引（缺项 / 零计数 / 两个数不是同一批件算出来的）。"""


def session_false_block(tripped: Iterable[bool]) -> bool:
    """一条会话是否记一次误伤：任一条消息踩雷即是。

    🔴 空会话拒绝，不当成"没踩雷"：零条消息不是一个干净的观测，是没得判。把它记成 False 会让分母
    多一条而分子不动，方向偏向"看起来更好" —— 与 no-op 变体同一个形状。"""
    msgs = list(tripped)
    if not msgs:
        raise SessionUnitError("空会话：零条消息不是『没踩雷』，是没得判，不进分母")
    return any(msgs)


def session_denominator_line(*, sessions: int, messages: int) -> str:
    """报数产物里那一行：单位 + 会话数 + 消息数。三项缺一 ⇒ 该批不可引。

    🔴 消息数不是装饰：它是读者判断"这个会话级的数和那个请求级的数差多少"的唯一依据，也是后面那条
    「被扫覆盖率」（B 档有多少消息落在窗口内）挂得上去的地方。"""
    if sessions <= 0 or messages <= 0:
        raise SessionUnitError(
            f"零计数（会话 {sessions} · 消息 {messages}）—— 这批没量过，"
            "不许印成一行看起来正常的分母声明"
        )
    if messages < sessions:
        raise SessionUnitError(
            f"消息 {messages} < 会话 {sessions} —— 每条会话至少一条消息，"
            "两个数不是同一批件算出来的"
        )
    return f"{SESSION_UNIT} · 会话数 {sessions} · 消息数 {messages}"
