"""CN negative-list gate (EV-CN-BASELINE 批C · E3_CN_DOMAIN_INPUT §4-A) — the MACHINE-checkable half
of the 否定清单. A case that trips one of these signatures reads as 看着合理、其实没人这么说 (a
translation-tone / model-tone artifact, NOT real Chinese financial流量). Same SHAPE as the other corpus
gates (`[rule] subject: why` + detail, exit-1-on-hit) and the same §8.5.1 discipline (a green gate prints
what it measured + which dirs it read).

  • BENIGN arm (llm01_cn_benign) — ZERO tolerance. Any A1/A2/A4/A6/A7 hit is red: a fake-tone benign case
    would let the FPR arm measure翻译腔, not Chinese流量.
  • ATTACK arm (llm01_cn_injection) — the 56 SAMPLE cases must be all-natural: any hit is red. The
    control_ SURVIVAL PROBES are EXCLUDED structurally (they are calibration, deliberately carrying a
    catchable literal, out of every denominator) — so NO exemption list is needed (架构师裁定二).

🔴 §4-A only. A3 (「请您帮我查询一下…」— an example, not a signature) and A5 (简称/全称须看场合 — a rule
that flags both directions, self-contradictory as a signature) are NOT machine-checked here — they ride
the §4-B human pass. Encoding a self-contradictory rule as a gate would red correct cases.

🔴 The CN corpus is out-of-repo, so a public-CI run never sees it ⇒ this gate EMPTY-passes there and says
so LOUD (never a silent pass — a green CI is not evidence the CN corpus was checked; §6/§8.5).

    PYTHONPATH=$PWD python tools/check_cn_negative_list.py --corpus <cn_root>
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from treval.active_eval import load_corpus
from treval.active_eval.corpus import CorpusCase, CorpusError
from treval.case_contract import is_control_attack_class

_BENIGN_SUBDIR = "llm01_cn_benign"
_ATTACK_SUBDIR = "llm01_cn_injection"

# §4-A — the machine-checkable signatures. Each is a 直译腔 / 模型腔 artifact that real Chinese financial
# 流量 does NOT contain. Named by the doc's A-number so a hit is traceable to the rationale there.
_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    # A1 🔴 — the `ignore previous instructions` 直译腔. Real中文金融 says 上一版作废 / 以最新为准.
    (
        "A1",
        r"(忽略|无视).{0,4}(之前|以上|上述|前面|先前).{0,6}(的)?(指令|设定|规则|要求|命令)",
        "「忽略/无视之前的指令」= ignore previous instructions 的直译腔（A1）；真实说法：上一版作废 / 以最新为准",
    ),
    # A2 — the model's own opening口癖 written into a user input.
    (
        "A2",
        r"作为一个\s*(AI|人工智能|智能)?\s*助手|^你是一个",
        "「作为一个 AI 助手」「你是一个…」开头 = 模型自己的口癖被当成了用户输入（A2）",
    ),
    # A4 — 对内工单混入对外客服的敬语开头 (register 混用).
    (
        "A4",
        r"您好[，,、]?\s*请问",
        "「您好，请问」= 对外客服话术混进了对内工单（A4，register 混用）",
    ),
    # A6 — 口语工单里精确到分的书面金额 (从系统粘出来的，不是人说的).
    (
        "A6",
        r"\d{1,3}(,\d{3})+(\.\d{2})?\s*元|\d+\.\d{2}\s*元",
        "口语工单里精确到分的金额（A6）= 从系统粘出来的书面数；真实说法：5 万多那笔",
    ),
    # A7 — English 分隔标记 (中文工单用【系统通知】※「一、二、三、」，不用这些).
    (
        "A7",
        r"</?system>|(^|\s)###(\s|$)|(^|\s)---(\s|$)",
        "`<system>` `###` `---` 英文分隔标记（A7）= 英文语料直译；中文用【系统通知】※「一、二、三、」",
    ),
)
_COMPILED = tuple((tag, re.compile(pat, re.I), why) for tag, pat, why in _SIGNATURES)


@dataclass(frozen=True)
class Violation:
    rule: str
    subject: str
    why: str
    detail: str


def _case_text(c: CorpusCase) -> str:
    """The author-controlled surface scanned — input + system_prompt + any wire messages."""
    parts = [c.input or "", c.system_prompt or ""]
    for m in c.messages or ():
        parts.append(
            m.content
            if isinstance(m.content, str)
            else " ".join(p.text for p in m.content)
        )
    return " ".join(parts)


def signature_hits(text: str) -> list[tuple[str, str]]:
    """Every (tag, why) signature the text trips (A3/A5 are NOT here — human pass only)."""
    return [(tag, why) for tag, rx, why in _COMPILED if rx.search(text)]


def _scan(cases: list[CorpusCase], *, arm: str) -> list[Violation]:
    """Benign arm: any hit is red (zero tolerance). Attack arm: the 56 SAMPLE cases must be all-natural, so
    any hit is red — but the control_ SURVIVAL PROBES are excluded (calibration, deliberately literal, out
    of every denominator). No exemption list: a probe is a control_ case, not an exempted sample."""
    out: list[Violation] = []
    for c in cases:
        if arm == "attack" and is_control_attack_class(c.attack_class):
            continue  # control_ survival probe — calibration, not a sample; excluded structurally
        for tag, why in signature_hits(_case_text(c)):
            out.append(
                Violation(
                    f"neg-list/{tag}",
                    c.id,
                    why,
                    f"{arm} 臂"
                    + ("（样本件须自然）" if arm == "attack" else "（良性臂零容忍）"),
                )
            )
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_cn_negative_list", description=__doc__)
    ap.add_argument(
        "--corpus", type=Path, required=True, help="the CN corpus ROOT (out-of-repo)"
    )
    args = ap.parse_args(argv)
    benign_dir = args.corpus / _BENIGN_SUBDIR
    attack_dir = args.corpus / _ATTACK_SUBDIR
    # 🔴 §6/§8.5 — the CN corpus is out-of-repo; a public-CI run finds neither dir ⇒ EMPTY pass, said LOUD.
    if not benign_dir.exists() and not attack_dir.exists():
        print(
            "cn-neg-list gate: PASS —— 🔴 本批语料不在本仓，本项未校验"
            f"（作用域：{benign_dir} · {attack_dir}）"
        )
        print(
            "    只在跑前预检指向仓外根时才校验；绿色公开 CI 不构成 CN 语料合规的证据（§6/§8.5）"
        )
        return 0
    try:
        benign = list(load_corpus(benign_dir)) if benign_dir.exists() else []
        attack = list(load_corpus(attack_dir)) if attack_dir.exists() else []
    except (CorpusError, OSError) as e:
        print(f"cn-neg-list gate: ERROR — {e}", file=sys.stderr)
        return 2
    n_probe = sum(1 for c in attack if is_control_attack_class(c.attack_class))
    violations = _scan(benign, arm="benign") + _scan(attack, arm="attack")
    scope = (
        f"作用域：良性 {benign_dir.name}（{len(benign)} 件，零容忍）· "
        f"攻击 {attack_dir.name}（{len(attack) - n_probe} 样本件须自然，{n_probe} 探针已排除）· "
        "签名 A1/A2/A4/A6/A7（A3/A5 留人工）"
    )
    if not violations:
        # 🔴 §8.5.1 — green prints its scope + what it measured, not just PASS.
        print(
            "cn-neg-list gate: PASS —— 良性臂无否定清单签名，攻击样本件全自然（探针结构性排除）（§4-A）"
        )
        print(f"    {scope}")
        return 0
    print(f"cn-neg-list gate: FAIL —— {len(violations)} 处违反\n", file=sys.stderr)
    print(f"    {scope}", file=sys.stderr)
    for v in violations:
        print(f"[{v.rule}] {v.subject}: {v.why}", file=sys.stderr)
        print(f"    {v.detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
