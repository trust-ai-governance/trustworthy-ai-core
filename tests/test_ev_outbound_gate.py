"""EV-CN-BENIGN-N180 件⑥/件⑦ — the provenance membership gate and the SENDING-end blind-review gate.
Each test names what reds it AND what it measures."""

from __future__ import annotations


from tools.check_outbound import main, scan_text


def _cats(text: str) -> set[str]:
    return {c for _ln, c, _why, _line in scan_text("m.md", text)}


# --------------------------------------------------------------------------- #
# 件⑦ — WHAT IT MEASURES: whether material about to be SENT would un-blind its reader. 🔴 A leak in a
# message cannot be withdrawn, so receiver-side discipline cannot repair it in principle.
# --------------------------------------------------------------------------- #
def test_jian7_refuses_a_case_id_the_worst_category():
    # 🔴 "which one" lets an author write AROUND the failing case ⇒ the补件 improves while the system does
    # not. What reds it: drop the case_id rule ⇒ the single most damaging fact sails through.
    assert "case_id" in _cats("请重点看 cn.holdout.wfA.01 这条")
    assert "case_id" in _cats("case_id: benign.hard.execute.015")


def test_jian7_refuses_a_measured_value_directional_leak():
    # knowing it currently runs high makes an author write more mildly — the failure the domain side
    # self-reported. What reds it: drop the percentage / k= / k-of-n patterns.
    assert "measured_value" in _cats("当前 FPR 3.5% 左右")
    assert "measured_value" in _cats("we are at k=2 right now")
    assert "measured_value" in _cats("误标 5/86")


def test_jian7_refuses_a_ci_interval_and_a_per_case_verdict():
    # 🔴 ㈣3 —「改数据优于开洞」有且仅有这一格例外：这里的小数【本身就是被测对象】——
    # 这道门测的就是"能不能认出一个 ci_ 小数"，把它改成整数就不再是在测这道门了。
    assert "ci_value" in _cats(
        "ci_high = 0.084"
    )  # disclosure-ok: 构造性测试输入，该小数即被测对象
    assert "per_case_verdict" in _cats("误拦: 这条")
    assert "per_case_verdict" in _cats("blocked: yes")


def test_jian7_lets_ordinary_briefing_material_through():
    # 🔴 a gate that reds on everything gets switched off. A real briefing — family definitions, scenes,
    # counts of what to WRITE — must pass.
    clean = (
        "族 C：音标拼读（呼号、单号、逐字确认姓名）。\n"
        "请写八条，场景铺开，不要写平凡例。\n"
        "作者不看任何跑结果。\n"
    )
    assert scan_text("brief.md", clean) == []


def test_jian7_a_template_placeholder_is_not_a_value():
    # "k={k}" is a FORM, not a leak.
    assert _cats("留出 FPR 全臂 k={k} · 其中 k_C={k_c}") == set()


def test_jian7_an_exemption_requires_a_written_reason():
    # 🔴 a bare marker is not an escape — every exemption is a written decision.
    assert _cats("当前 3.5%  # outbound-ok: 收件人是运营方，非盲评方") == set()
    assert "measured_value" in _cats("当前 3.5%  # outbound-ok:")


def test_jian7_cli_blocks_and_explains(tmp_path, capsys):
    bad = tmp_path / "brief.md"
    bad.write_text("请看 cn.holdout.wfA.01，当前 3.5%\n", encoding="utf-8")
    assert main([str(bad)]) == 1
    err = capsys.readouterr().err
    assert "不得发出" in err and "发出去就收不回来了" in err


def test_jian7_cli_passes_clean_material_and_says_why_the_gate_exists(tmp_path, capsys):
    ok = tmp_path / "brief.md"
    ok.write_text("族 C：音标拼读。请写八条。\n", encoding="utf-8")
    assert main([str(ok)]) == 0
    out = capsys.readouterr().out
    assert "PASS" in out and "不可撤回" in out


# --------------------------------------------------------------------------- #
# 件⑥ — WHAT IT MEASURES: that the hand-maintained provenance roster still describes the SAME set the
# directory-derived corpus_sha pins. Two records of one membership, one automatic and one manual, drift.
# --------------------------------------------------------------------------- #
def test_jian6_drift_is_reported_in_BOTH_directions():
    # 🔴 both matter: an id missing from the roster is a case nobody can attribute; a stale id means the
    # roster attributes a case that is not being measured. What reds it: compare only one direction.
    from tools.check_cn_two_arm import provenance_membership_drift

    missing, stale = provenance_membership_drift(["a", "b", "c"], ["b", "c", "z"])
    assert missing == ["a"] and stale == ["z"]


def test_jian6_equal_membership_is_clean():
    from tools.check_cn_two_arm import provenance_membership_drift

    assert provenance_membership_drift(["a", "b"], ["b", "a"]) == ([], [])


def test_jian6_a_missing_roster_is_not_a_pass():
    # 🔴 未登记 ≠ 已核: no roster file at all must not read as "membership verified".
    from pathlib import Path

    from tools.check_cn_two_arm import _roster_ids

    assert _roster_ids(Path("/nonexistent"), "provenance_calib.json") is None


# --------------------------------------------------------------------------- #
# ㈣2 — the question is "is this a leak FOR THIS RECIPIENT", and the default must fail closed
# --------------------------------------------------------------------------- #
def test_audience_default_is_the_strictest_and_fails_closed():
    # 🔴 the acceptance: a text that is harmless to the party that produced the number and fatal to the
    # author who must stay blind to it MUST red when no audience is given. What reds it: default to a
    # permissive audience ⇒ the caller who forgets the flag — exactly the one forwarding something they
    # did not think about — gets a pass.
    from tools.check_outbound import DEFAULT_AUDIENCE, scan_text

    text = "当前 FPR 3.5%"
    assert DEFAULT_AUDIENCE == "author"
    assert scan_text("m.md", text) != []  # no audience given ⇒ strictest ⇒ red
    assert scan_text("m.md", text, "author") != []
    assert (
        scan_text("m.md", text, "tested_party") == []
    )  # their own number is not news to them


def test_a_case_id_leaks_to_every_audience():
    # our corpus membership is ours regardless of who is reading.
    from tools.check_outbound import AUDIENCES, scan_text

    for a in AUDIENCES:
        assert scan_text("m.md", "见 cn.holdout.wfA.01", a) != [], a


# --------------------------------------------------------------------------- #
# ㈢3 — the gate must have a CALL SITE. 🔴 门存在 ≠ 门被调用.
# --------------------------------------------------------------------------- #
def test_the_outbound_gate_has_a_call_site_on_the_sending_path():
    # 🔴 4th time in this family (declared-but-unenforced / defined-but-uncalled / built-but-unwired).
    # What reds it: remove the scan_text call from send_material ⇒ sending stops being gated while every
    # test here stays green — which is exactly what a gate with no caller looks like.
    import inspect

    from tools import send_material

    assert "scan_text" in inspect.getsource(send_material.gate)


def test_sending_leaky_material_is_refused_not_merely_reported(tmp_path):
    from tools.send_material import main

    bad = tmp_path / "brief.md"
    bad.write_text("请看 cn.holdout.wfA.01\n", encoding="utf-8")
    out = tmp_path / "channel"
    assert main([str(bad), "--to", str(out)]) == 1
    assert not (out / "brief.md").exists()  # 🔴 refused means NOT copied


def test_a_clean_send_reports_in_recipient_terms_with_a_version(tmp_path, capsys):
    # ㈤ — 「我方已发出」是我方动作；对方能否取到、取到哪一版，才是状态。
    from tools.send_material import main

    ok = tmp_path / "spec.md"
    ok.write_text("族 B：谈论管控。请写二十四条。\n", encoding="utf-8")
    out = tmp_path / "channel"
    assert main([str(ok), "--to", str(out), "--audience", "author"]) == 0
    text = capsys.readouterr().out
    assert "对方可取" in text and "版本" in text
    assert "做完不是状态，取到才是" in text
    assert (out / "spec.md").exists()
