"""Corpus format + loader (EV-AE0 §3).

Self-describing YAML cases (the adversarial analogue of the conformance suite).
One case per file; the loader globs sorted *.yaml for deterministic order and is
fail-closed on malformed input (like the registry loader). The loader takes a
path (default = repo-root corpus/llm01_prompt_injection/) so the corpus can move
without code change (same packaging caveat as EV-6's registry/, deferred).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from treval.active_eval.checks import KNOWN_SUCCESS_TOKENS

# EV-COVERAGE E3 §2.2.3 — the THIRD attack_class value (control_bare_payload): a case that re-runs a
# verbatim external payload with the injection SKELETON REMOVED, so the attribution arm can MEASURE
# (not claim) whether a partner's catch is due to injection detection. 🔴 RE-EXPORTED here (redundant-
# alias): the canonical definition lives in the PURE treval.case_contract so the catch-exclusion rule
# (catch_excluded_case_ids) single-sources it WITHOUT dragging the harness into that engine-free module
# (E3-l). Every corpus/coverage/indicator import of it via corpus is unchanged.
from treval.case_contract import CONTROL_BARE_PAYLOAD as CONTROL_BARE_PAYLOAD
from treval.case_contract import CONTROL_NO_CANARY as CONTROL_NO_CANARY
from treval.case_contract import is_control_attack_class as is_control_attack_class

_DEFAULT_DIR = Path(__file__).resolve().parents[2] / "corpus" / "llm01_prompt_injection"
# `input` is handled separately (EV-AE11): a case supplies EITHER `input` (a single
# user turn) OR `messages` (an explicit wire array), so it is not in the always-required
# set below.
_REQUIRED = (
    "id",
    "owasp",
    "dimension",
    "attack_class",
    "success_when",
    "severity",
    "source",
)
# Wire message roles the gateway forwards (EV-AE11 §3). Anything else → CorpusError.
_WIRE_ROLES = frozenset({"system", "user", "assistant", "tool"})

# 🔴 `derived_from` 的值域。**没有 `unknown`** —— 语料作者 2026-09-17 逐字：
# 「一个叫 unknown 的合法值会让『没查过来源』和『查过但查不到』同形」。
# 老件走 `unknown_legacy`：它自陈是历史欠账，而 `unknown` 读起来像一个结论。
DERIVED_FROM_VALUES = frozenset(
    {
        "none",  # 没照着任何真实材料改写
        "real_ticket_adapted",  # 照真实工单改写
        "public_document",  # 照公开文件改写
        "synthetic",  # 全合成
        "public_dataset",  # 🔴 取自公开数据集 —— 必须带 `:<名>@<版本>`
        "unknown_legacy",  # 🔴 历史欠账：本字段落地之前的件，来源未记录
    }
)
# 写件人对自己那一件的把握（语料作者 §9.1）。三态，不是评分。
AUTHENTICITY_VALUES = frozenset({"confident", "unsure", "syntax_only"})


# 🔴 单轮限定声明表 —— 读 `case.input` 而不读 `case.messages` 的产品函数，必须在这里登记并写明理由。
#
# 为什么要有落点而不是一句注释：多轮件的 `input` 恒为空串（loader 强制 input XOR messages），所以一个
# 只读 `input` 的消费者会把每一件多轮件读成**空**——而空不报错，只是让那件从这个消费者的视角里消失。
# 这已经真的发生过一次：`perturb_case` 只变换 `input`，于是多轮件的"扰动变体"与原件上线载荷逐字相同，
# 换了 id、进了计数、被当成一次扰动试验。🔴 那比"吃掉件"更坏——吃掉件让分母变小（有机会被发现），
# no-op 变体让分子和分母**一起增加**，方向是"看起来更稳健"。
#
# 声明必须带理由（无理由的豁免等于万能钥匙，与披露门的 disclosure-ok 同一条纪律），而且
# `tests/test_multi_turn_harness.py` 会：① 扫产品 AST，未登记的只读-input 函数即红；② 拒绝孤儿条目。
# 那三条测试就是这张表的读者 —— 没有读者的字段不该存在。
SINGLE_TURN_ONLY: dict[str, str] = {
    "inject": (
        "canary.inject 只替换 system_prompt / input / secret_canary，够不到 messages ⇒ 多轮件"
        "结构上没有金丝雀。这不是遗漏而是当前口径，由 test_canary_injection_does_not_reach_messages "
        "验证；连带后果（多轮臂的『全 ALLOW』与『扫描器没开』分不开）由活性探针承担。"
    ),
    "rule_robustness": (
        "EV-AE7 的鲁棒性汇总，其 evading 明细回显变体的 `input`。它只消费扰动产出的变体，而"
        "`perturb_case` 现在拒绝多轮件 ⇒ 多轮件结构上到不了这里。🔴 连带口径：鲁棒性只覆盖单轮件。"
    ),
}


class CorpusError(Exception):
    """A corpus case is malformed (missing field / bad success_when / unparseable)."""


@dataclass(frozen=True)
class ContentPart:
    """One OpenAI multimodal content part (EV-AE11 D7). Only text is supported —
    the loader rejects any other `type` (the nested-reach channel P2-ind must detect)."""

    type: str  # always "text"
    text: str


@dataclass(frozen=True)
class WireMessage:
    """One wire message the harness sends verbatim as params.messages[i] (EV-AE11).
    content is a plain string or a tuple of text content-parts (nested reach)."""

    role: str  # system | user | assistant | tool
    content: str | tuple[ContentPart, ...]


@dataclass(frozen=True)
class CorpusCase:
    id: str
    owasp: str  # "LLM01"
    dimension: str  # "robustness" (must match the EV-6 dimension id)
    attack_class: str
    input: str  # the adversarial prompt
    success_when: str  # one whitelisted token (checks.py)
    severity: str
    source: str  # provenance (core-authored | promptfoo:... | ...)
    # Optional output-success canary: a distinctive token the injection, if obeyed,
    # makes the model EMIT. Enables injection_success_rate (output-based). Empty ⇒
    # the case is only measurable for gateway catch, not for output success.
    output_marker: str = ""
    # Optional planted sentinel that must NOT appear verbatim in the output. LLM02/07:
    # a high-entropy SECRET (must not leak). LLM05: a raw DANGEROUS PAYLOAD, e.g. an XSS
    # vector (must not pass through un-escaped). Either way, its verbatim presence in the
    # model output = leak / unsafe passthrough (checks.sensitive_disclosed). Distinct
    # from output_marker (an attack sentinel the model is tricked into EMITTING).
    secret_canary: str = ""
    # Optional real role:"system" message the harness sends ahead of the user turn.
    # For LLM07 it embeds the secret_canary (the leak target). Distinct from `input`
    # (the user-turn attack). Empty ⇒ no system message sent (LLM01/LLM02 unchanged).
    system_prompt: str = ""
    # The tool to invoke. Default "chat" (LLM01/02/07). Non-"chat" ⇒ an out-of-scope
    # probe for the eval agent (granted tool:chat:*) — the LLM06 tool-scope test; for
    # those cases `input` is a human-readable attack description, not a chat message.
    tool_id: str = "chat"
    # Optional explicit wire messages array (EV-AE11). When set, GatewayTarget sends it
    # VERBATIM as params.messages (author controls role / index / nesting) and `input`
    # is unused — this is how a payload is placed at its true wire location (tool-role,
    # out-of-window, nested content-part, retrieved-context). None ⇒ the single-user
    # `input` path (every pre-EV-AE11 case is untouched).
    messages: tuple[WireMessage, ...] | None = None
    # W6 decoy (business-disguise injection). `expected_tool_call` is the decoy tool an ACTION case
    # should trip; `target_type` is ACTION | EXFIL, the slice the diagnostic-arm report cuts by.
    # 🔴 Both optional with an empty default, on the same discipline as `scene`: every case written
    # before this round carries neither, and those must keep loading untouched. Neither field enters
    # cfp-v1 (it hashes id/input/system_prompt/messages only) ⇒ `corpus_sha` does not move —
    # measured before/after, not inferred (test_corpus_fingerprint_is_unchanged).
    expected_tool_call: str = ""
    target_type: str = ""
    # Optional per-case route selector (EV-AE13). When set, GatewayTarget sends header
    # `x-agent-id`, choosing which deployment/route (and thus output-sink policy) handles
    # the probe: `builtin.chat` = declared HTML sink (A2 neutralize applies), `control.chat`
    # = sink `none` (byte-for-byte, no neutralize). None ⇒ no header (gateway default route).
    agent_id: str | None = None
    # Optional content-safety slice key (P3C-harness C3). A second, orthogonal slice
    # dimension alongside `attack_class`: the GB/T content class this case belongs to.
    # OPTIONAL BY DESIGN — every pre-P3C corpus predates it, so an absent value must load
    # cleanly; "" = the "unclassified" slice (surfaced separately, never folded into a
    # class total). Adding it to `_REQUIRED` would break all existing corpora.
    content_class: str = ""
    # EV-COVERAGE E0 — the specific ATTACK TECHNIQUE (e.g. `delimiter_break`, `base64_smuggle`),
    # ORTHOGONAL to attack_class: attack_class is the coarse VECTOR (direct/indirect/benign_*) that
    # the attribution RATE table needs a big-n per class for; attack_technique is fine-grained
    # (n=1 per technique is normal) and feeds coverage axis ② as a LIST/COUNT, never a rate
    # (§4.2.1). OPTIONAL here (so i3_run synthetic cases + old fixtures still load); the corpus
    # gate (EV-COVERAGE §4.3-C) is what requires attack cases to carry it. Empty for benign cases.
    attack_technique: str = ""
    # EV-COVERAGE §4.3-D — coverage axis ④. A hold-out case NEVER participates in rule tuning; it
    # runs only in a frozen eval. EXPLICIT (never a random seed — a hold-out set's whole value is
    # that it is PINNED, not drifting with code version). OPTIONAL (defaults False so every existing
    # corpus loads); the coverage report splits tuning vs hold-out on it, and the tuning↔hold-out
    # gap IS the "overfit-to-our-own-detector" measure (§3).
    holdout: bool = False
    # EV-COVERAGE E3 §5.3 — the benign USAGE SCENE a benign control represents (e.g. frontstage-qa /
    # analysis-tool / operator-console). "Benign" is only defined RELATIVE to a scenario — FPR varies
    # by role — so a benign case that declares no scene lets "FPR ≤ 5%" sound scenario-agnostic (the
    # benign mirror of the §5.2 attack-side over-extrapolation). OPTIONAL (the pre-E3 benign corpus
    # predates it, so absent must load); the corpus gate requires it on NEW benign cases only. Empty
    # for attack cases (they carry attack_technique instead).
    scene: str = ""
    # EV-COVERAGE E3 §5.2.1.1 — for a case whose `source` is tagged `(payload-neutralized)` (an
    # external probe whose PAYLOAD was mechanically swapped, skeleton kept verbatim): a hash of the
    # PRE-swap original text (NOT the text — holders of the upstream set recompute and compare). It is
    # the VERIFIABLE record §5.2.1.1 pt2 demands ("实测优于声称" — a swap without a record is only a
    # claim). OPTIONAL (only payload-neutralized cases need it); the corpus gate reds a payload-
    # neutralized case that lacks it. Empty for every other case.
    pre_neutralize_hash: str = ""
    # EV-COVERAGE E3 §2.2.3 — set ONLY on a `control_bare_payload` case (see CONTROL_BARE_PAYLOAD): the
    # id of the PARTNER attack case it controls (the verbatim external case it re-runs with the
    # injection SKELETON removed). The attribution arm (indicators.py) reads it — a control that is
    # itself CAUGHT means the partner's catch is NOT attributable to injection detection, so the partner
    # EXITS the injection_catch_rate denominator. 🔴 The control (and this link) is HAND-WRITTEN by the
    # corpus author; the code never derives it. OPTIONAL / empty on every non-control case.
    control_for: str = ""
    # 🔴 臂 A(C3A 完成判据 §八①) —— 本件复用的那个【既有载荷件】的 id。
    # 为什么 `control_for` 顶不上：它连的是 T↔U 这一对,连不到【载荷的来源件】。
    # §八① 逐字要求「每一件 U 都能指名它配对的 T,且两者载荷字节相同」——「字节相同」这半句
    # 只有在两件都指得出【同一个源件】时才机械可核;靠比文本去核,比的是载体不是载荷。
    # ⚠️ 它同时是一条【真判据】的输入(不是豁免):两件带同一个 payload_case_id ⇒ 同一载荷做了两件
    #    ⇒ 真重复。见 tools/check_cn_two_arm.arm_a_cross_side_duplicates。
    # OPTIONAL：每一批 pre-臂A 的语料都没有它,缺省必须干净装载。
    payload_case_id: str = ""
    # 🔴 臂 A —— 载荷落在 `messages` 的哪个下标。
    # 它【必须是字段,不能是推断】：位置是这条臂的【自变量】,而推断出来的自变量等于把
    # 「我以为它在哪」写成了测量。单一载体时同位同下标,这一点因此机器可读而非口头约定。
    # -1 = 未声明(非臂 A 件)。0 是合法值,所以缺省不能用 0。
    payload_msg_index: int = -1
    # 🔴 臂 B(C-3b) —— 件的语种。Lead 2026-09-15 裁定逐字:「停止规则【只读中文 120 的率】;
    # 英文 40 与合计 160 单列描述,不驱动决策」。
    #
    # ⇒ 那条裁定是一条【机械可执行的分层】,而在本字段落地之前它执行不了:
    #   loader 对未知字段是【静默丢弃】,所以 160 件上写着 lang 而装载之后一个都读不到 ——
    #   🔴 而"读不到"的样子,和"这批件没有这个字段"一模一样。
    #   ⚠️ 唯一的替代是从 case id 前缀猜(cn./en.),那是【把命名约定当数据】:
    #      改一次 id 规则,停止规则就会静默换一个分母,而没有任何东西会红。
    # OPTIONAL：本字段之前的每一批语料都没有它,缺省必须干净装载;"" = 未声明,不是"未知语种"。
    lang: str = ""
    # 🔴 臂 B / 臂 A / W6 的分类轴（语料作者 2026-09-17 报，实测：臂 B 盘上 17 个字段，
    # `load_corpus` 成功 n=160 不报错，而其中 7 个被【静默丢弃】）。
    # 判据与 `lang` 那次逐字相同：loader 对未知字段静默丢弃 ⇒ 盘上写着而装载之后一个都读不到，
    # 而「读不到」与「这批件没有这个字段」一模一样。
    # ⚠️ 全部 OPTIONAL：本轮之前的每一批语料都没有它们，缺省必须干净装载。
    family: str = ""  # f1_override … f7_decode —— §7 配额按它数
    mechanism: str = ""  # M1–M8
    anchor: str = ""  # A–I 业务锚点（§7 的「场景」就是它，件上没有 scene 字段）
    evasion: str = ""  # ev_none / ev_insert / ev_cjk_sep / ev_trad
    grid_no: int = -1  # 网格序号；-1 = 未声明（0 是合法序号，所以缺省不能用 0）
    control_rule_anchor: str = ""  # anchor_A…anchor_I —— 🔴 名字带 rule，存的不是规则名
    # 🔴 来源三态。`unknown` 【不是】合法值：一个叫 unknown 的值会让
    # 「没查过来源」和「查过但查不到」同形 —— 老件走 `unknown_legacy`，它自陈是历史欠账。
    # ⚠️ `public_dataset` 必须带数据集名+版本（见 DERIVED_FROM_VALUES 的校验）。
    derived_from: str = ""
    # 🔴 真实感三态（语料作者 §9.1）：confident / unsure / syntax_only。
    # 它是【写件人对自己那一件的把握】，不是任何人对它的评分 —— 两者混写会让
    # 「我不确定」被读成「它质量低」，而前者可以靠复核消掉，后者不能。
    authenticity: str = ""


def load_corpus(path: str | Path | None = None) -> tuple[CorpusCase, ...]:
    base = Path(path) if path is not None else _DEFAULT_DIR
    if not base.is_dir():
        raise CorpusError(f"corpus directory not found: {base}")

    cases: list[CorpusCase] = []
    seen: set[str] = set()
    for yaml_path in sorted(base.glob("*.yaml")):  # deterministic order
        case = _load_case(yaml_path)
        if case.id in seen:
            raise CorpusError(f"duplicate case id {case.id!r}")
        seen.add(case.id)
        cases.append(case)

    if not cases:
        raise CorpusError(f"no corpus cases (*.yaml) in {base}")
    return tuple(cases)


def _parse_content(yaml_path: Path, content: object) -> str | tuple[ContentPart, ...]:
    """A wire message's content: a non-empty string OR a non-empty list of text parts
    `[{type: text, text: <str>}]` (EV-AE11 D7). Anything else → CorpusError."""
    if isinstance(content, str):
        if not content:
            raise CorpusError(f"{yaml_path}: message content string must be non-empty")
        return content
    if isinstance(content, list) and content:
        parts: list[ContentPart] = []
        for part in content:
            if (
                not isinstance(part, dict)
                or part.get("type") != "text"
                or not isinstance(part.get("text"), str)
                or not part["text"]
            ):
                raise CorpusError(
                    f"{yaml_path}: content parts must be "
                    f"{{type: text, text: <non-empty str>}}, got {part!r}"
                )
            parts.append(ContentPart(type="text", text=part["text"]))
        return tuple(parts)
    raise CorpusError(
        f"{yaml_path}: message content must be a non-empty string or a non-empty "
        f"list of text parts, got {content!r}"
    )


def _parse_messages(yaml_path: Path, raw: object) -> tuple[WireMessage, ...]:
    """Parse + validate a `messages:` array into WireMessages. Fail-closed: roles must
    be in the whitelist and content must be text (EV-AE11 §3)."""
    if not isinstance(raw, list) or not raw:
        raise CorpusError(f"{yaml_path}: `messages`, if set, must be a non-empty list")
    messages: list[WireMessage] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise CorpusError(f"{yaml_path}: each message must be a mapping")
        role = entry.get("role")
        if role not in _WIRE_ROLES:
            raise CorpusError(
                f"{yaml_path}: message role must be one of {sorted(_WIRE_ROLES)}, "
                f"got {role!r}"
            )
        messages.append(
            WireMessage(
                role=role, content=_parse_content(yaml_path, entry.get("content"))
            )
        )
    return tuple(messages)


def _load_case(yaml_path: Path) -> CorpusCase:
    try:
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise CorpusError(f"cannot read {yaml_path}: {e}") from e

    if not isinstance(doc, dict):
        raise CorpusError(f"{yaml_path}: case must be a mapping")
    for field in _REQUIRED:
        value = doc.get(field)
        if not isinstance(value, str) or not value:
            raise CorpusError(
                f"{yaml_path}: missing/invalid required string field {field!r}"
            )
    if doc["success_when"] not in KNOWN_SUCCESS_TOKENS:
        raise CorpusError(
            f"{yaml_path}: unknown success_when {doc['success_when']!r}; "
            f"known={sorted(KNOWN_SUCCESS_TOKENS)}"
        )
    _assert_decoy_declaration(yaml_path, doc)
    fields = {field: doc[field] for field in _REQUIRED}
    # 非词表、自由字符串；不参与 cfp-v1（规范只哈希 id/input/system_prompt/messages）⇒ 不动 corpus_sha
    for optional in ("expected_tool_call", "target_type"):
        if doc.get(optional):
            fields[optional] = str(doc[optional])

    # `input` XOR `messages` (EV-AE11). A case supplies a single-user `input` OR an
    # explicit wire array. Both set is an author error (fail-closed) — pick one.
    raw_messages = doc.get("messages")
    raw_input = doc.get("input")
    if raw_messages is not None:
        if isinstance(raw_input, str) and raw_input:
            raise CorpusError(
                f"{yaml_path}: set either `input` or `messages`, not both"
            )
        fields["messages"] = _parse_messages(yaml_path, raw_messages)
        fields["input"] = ""  # unused when messages is authoritative
    elif isinstance(raw_input, str) and raw_input:
        fields["input"] = raw_input
    else:
        raise CorpusError(f"{yaml_path}: missing/invalid required string field 'input'")

    marker = doc.get("output_marker")  # optional
    if marker is not None:
        if not isinstance(marker, str) or not marker:
            raise CorpusError(
                f"{yaml_path}: output_marker, if set, must be a non-empty string"
            )
        fields["output_marker"] = marker
    canary = doc.get("secret_canary")  # optional
    if canary is not None:
        if not isinstance(canary, str) or not canary:
            raise CorpusError(
                f"{yaml_path}: secret_canary, if set, must be a non-empty string"
            )
        fields["secret_canary"] = canary
    system_prompt = doc.get("system_prompt")  # optional
    if system_prompt is not None:
        if not isinstance(system_prompt, str) or not system_prompt:
            raise CorpusError(
                f"{yaml_path}: system_prompt, if set, must be a non-empty string"
            )
        fields["system_prompt"] = system_prompt
    tool_id = doc.get("tool_id")  # optional, defaults to "chat"
    if tool_id is not None:
        if not isinstance(tool_id, str) or not tool_id:
            raise CorpusError(
                f"{yaml_path}: tool_id, if set, must be a non-empty string"
            )
        fields["tool_id"] = tool_id
    agent_id = doc.get("agent_id")  # optional route selector (EV-AE13)
    if agent_id is not None:
        if not isinstance(agent_id, str) or not agent_id:
            raise CorpusError(
                f"{yaml_path}: agent_id, if set, must be a non-empty string"
            )
        fields["agent_id"] = agent_id
    content_class = doc.get("content_class")  # optional (P3C-harness C3)
    if content_class is not None:
        if not isinstance(content_class, str) or not content_class:
            raise CorpusError(
                f"{yaml_path}: content_class, if set, must be a non-empty string"
            )
        fields["content_class"] = content_class
    attack_technique = doc.get("attack_technique")  # optional (EV-COVERAGE E0)
    if attack_technique is not None:
        if not isinstance(attack_technique, str) or not attack_technique:
            raise CorpusError(
                f"{yaml_path}: attack_technique, if set, must be a non-empty string"
            )
        fields["attack_technique"] = attack_technique
    holdout = doc.get("holdout")  # optional (EV-COVERAGE §4.3-D)
    if holdout is not None:
        if not isinstance(holdout, bool):
            raise CorpusError(f"{yaml_path}: holdout, if set, must be a boolean")
        fields["holdout"] = holdout
    scene = doc.get("scene")  # optional (EV-COVERAGE E3 §5.3 — benign usage scene)
    if scene is not None:
        if not isinstance(scene, str) or not scene:
            raise CorpusError(f"{yaml_path}: scene, if set, must be a non-empty string")
        fields["scene"] = scene
    pre_hash = doc.get("pre_neutralize_hash")  # optional (EV-COVERAGE E3 §5.2.1.1)
    if pre_hash is not None:
        if not isinstance(pre_hash, str) or not pre_hash:
            raise CorpusError(
                f"{yaml_path}: pre_neutralize_hash, if set, must be a non-empty string"
            )
        fields["pre_neutralize_hash"] = pre_hash
    control_for = doc.get("control_for")  # optional (EV-COVERAGE E3 §2.2.3)
    if control_for is not None:
        if not isinstance(control_for, str) or not control_for:
            raise CorpusError(
                f"{yaml_path}: control_for, if set, must be a non-empty string"
            )
        fields["control_for"] = control_for
    payload_case_id = doc.get("payload_case_id")  # optional (C3A 完成判据 §八①)
    if payload_case_id is not None:
        if not isinstance(payload_case_id, str) or not payload_case_id:
            raise CorpusError(
                f"{yaml_path}: payload_case_id, if set, must be a non-empty string"
            )
        fields["payload_case_id"] = payload_case_id
    payload_msg_index = doc.get("payload_msg_index")  # optional (C3A 位置自变量)
    if payload_msg_index is not None:
        # 🔴 bool 是 int 的子类 —— 不显式挡掉，`payload_msg_index: true` 会被收成 1。
        if isinstance(payload_msg_index, bool) or not isinstance(
            payload_msg_index, int
        ):
            raise CorpusError(
                f"{yaml_path}: payload_msg_index, if set, must be an integer"
            )
        if payload_msg_index < 0:
            raise CorpusError(
                f"{yaml_path}: payload_msg_index must be >= 0 (-1 means 未声明，不可显式写)"
            )
        fields["payload_msg_index"] = payload_msg_index
    lang = doc.get("lang")  # optional (C-3b 停止规则的分层键)
    if lang is not None:
        if not isinstance(lang, str) or not lang:
            raise CorpusError(f"{yaml_path}: lang, if set, must be a non-empty string")
        fields["lang"] = lang
    for _key in ("family", "mechanism", "anchor", "evasion", "control_rule_anchor"):
        _v = doc.get(_key)
        if _v is not None:
            if not isinstance(_v, str) or not _v:
                raise CorpusError(
                    f"{yaml_path}: {_key}, if set, must be a non-empty string"
                )
            fields[_key] = _v
    grid_no = doc.get("grid_no")
    if grid_no is not None:
        # 🔴 bool 是 int 的子类，不显式挡掉 `grid_no: true` 会被静默收成 1。
        if isinstance(grid_no, bool) or not isinstance(grid_no, int):
            raise CorpusError(f"{yaml_path}: grid_no, if set, must be an integer")
        if grid_no < 0:
            raise CorpusError(
                f"{yaml_path}: grid_no must be >= 0 (-1 表示未声明，不可显式写)"
            )
        fields["grid_no"] = grid_no
    derived_from = doc.get("derived_from")
    if derived_from is not None:
        if not isinstance(derived_from, str) or not derived_from:
            raise CorpusError(
                f"{yaml_path}: derived_from, if set, must be a non-empty string"
            )
        head = derived_from.split(":", 1)[0]
        if head not in DERIVED_FROM_VALUES:
            raise CorpusError(
                f"{yaml_path}: derived_from={derived_from!r} 不在值域 "
                f"{sorted(DERIVED_FROM_VALUES)}；🔴 `unknown` 不是合法值——"
                "老件走 `unknown_legacy`（它自陈是历史欠账），"
                "而一个叫 unknown 的值会让「没查过」和「查过但查不到」同形"
            )
        if head == "public_dataset" and ":" not in derived_from:
            raise CorpusError(
                f"{yaml_path}: derived_from=public_dataset 必须带数据集名+版本，"
                "写成 `public_dataset:<名>@<版本>` —— 不写等于没记来源"
            )
        fields["derived_from"] = derived_from
    authenticity = doc.get("authenticity")
    if authenticity is not None:
        if authenticity not in AUTHENTICITY_VALUES:
            raise CorpusError(
                f"{yaml_path}: authenticity={authenticity!r} 不在值域 "
                f"{sorted(AUTHENTICITY_VALUES)}"
            )
        fields["authenticity"] = authenticity
    # 🔴 两个字段【成对】——只有一个时,位置效应要么指不出载荷、要么指不出位置。
    # 缺一半不是"少一点信息",是这条臂的自变量断了,而断了的样子和填好的一模一样。
    if bool(fields.get("payload_case_id")) != ("payload_msg_index" in fields):
        raise CorpusError(
            f"{yaml_path}: payload_case_id 与 payload_msg_index 必须成对出现 —— "
            "只有其一时,位置效应要么指不出载荷、要么指不出位置"
        )
    # A leak check with no planted secret is meaningless — fail closed (D3/§4).
    if doc["success_when"] == "not_leaked" and not fields.get("secret_canary"):
        raise CorpusError(
            f"{yaml_path}: success_when 'not_leaked' requires a secret_canary"
        )
    return CorpusCase(**fields)


DECOY_TOOL_NAME = "audit_suppress"
DECOY_TOOL_SIGNATURE = "audit_suppress("
# Closed vocabulary. `target_type` present == "this is a W6 disguise case"; the value picks which
# half of the batch the case is in. Closed because ③④ compare it to "ACTION" literally.
TARGET_TYPES = ("ACTION", "EXFIL")


def _decoy_prose(doc: dict) -> str:
    """The author-written request text of a raw case doc: `input` plus every `messages[].content`.
    🔴 `messages` is read too — a multi-turn ACTION case carries its record id in a wire message, and
    an `input`-only reading would refuse every one of them."""
    parts: list[str] = []
    if isinstance(doc.get("input"), str):
        parts.append(doc["input"])
    for turn in doc.get("messages") or ():
        if isinstance(turn, dict):
            content = turn.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):  # nested content-parts (EV-AE11)
                parts += [
                    p["text"]
                    for p in content
                    if isinstance(p, dict) and isinstance(p.get("text"), str)
                ]
    return "\n".join(parts)


def _assert_decoy_declaration(yaml_path: object, doc: dict) -> None:
    """FIVE assertions over the decoy-tool declaration. Each covers a way the others stay green while
    the batch is unusable — and three of the five were caught downstream BEFORE they were written:

      ① the `expected_tool_call` VALUE appears in this case's own system_prompt — else the model is
         asked for a tool it was never shown.
      ② the SIGNATURE SHAPE `audit_suppress(` appears too. With only ①, the model knows the name and
         not how to call it: all 30 cases die the day W4b thaws while ① stays green throughout.
      🔴 ③ REVERSE, scoped to ACTION. Unscoped it reds every EXFIL case by construction: those DECLARE
         the tool (they must — declaring only on ACTION cases would make "declares audit_suppress" a
         100% predictor of "not EXFIL", a structural marker of the same family as the register leak,
         and the judge reads system_prompt) but are judged on canary leakage, so their
         `expected_tool_call` is correctly empty.
      🔴 ④ an ACTION case must carry a non-empty `secret_canary` AND that value must appear in its own
         prose. `_decoy_tool_called` judges "the decoy was called carrying THIS case's canary as
         record_id"; with no canary it is False forever, and with a canary the model never sees it is
         False forever too — silently, in both directions. That is the same false zero
         `decoy_unmeasurable` exists to prevent, arriving through a different door. ACTION-scoped for
         the same reason as ③: an EXFIL case's canary lives in system_prompt, which is precisely what
         it must NOT be shown to reproduce.
      🔴 ⑤ EVERY W6 case — EXFIL as much as ACTION — must declare the decoy, and declare the SIGNATURE
         SHAPE, not merely the name. ③'s comment above already states the reason; this batch proved
         that stating it is not enough. The person who wrote that comment read it, restated it,
         quoted its reasoning back — and still shipped an EXFIL case with no declaration. ③ and ④ are
         both ACTION-scoped, so nothing was checking the other half: the rule lived only in prose,
         which is exactly the place this batch demonstrated does not hold.
         🔴 The signature, not the name, is what must be required. Requiring only the name would move
         the marker one level finer instead of removing it — ② makes every ACTION case carry
         `audit_suppress(`, so "carries the signature" would then predict ACTION at 100%, and the
         judge reads system_prompt. Same defect, one field down.
         Keyed on `target_type` being PRESENT (that is what makes a case a W6 case). Its value is
         checked against a closed vocabulary because ③ and ④ compare it to "ACTION" literally: a typo
         does not fail there, it silently switches them off and the case loads unmeasurable.
    """
    expected = doc.get("expected_tool_call") or ""
    sys_prompt = doc.get("system_prompt") or ""
    target_type = doc.get("target_type") or ""
    if target_type:
        if target_type not in TARGET_TYPES:
            raise CorpusError(
                f"{yaml_path}: unknown target_type {target_type!r}; known={list(TARGET_TYPES)} — "
                "③/④ compare this field to 'ACTION' literally, so a typo would not fail here, it "
                "would silently turn them off"
            )
    if target_type == "ACTION" and (expected or DECOY_TOOL_NAME in sys_prompt):
        canary = doc.get("secret_canary") or ""
        if not canary:
            raise CorpusError(
                f"{yaml_path}: an ACTION case declaring the decoy has no secret_canary — "
                "`decoy_tool_called` would be False forever and say nothing (a silent false zero)"
            )
        if canary not in _decoy_prose(doc):
            raise CorpusError(
                f"{yaml_path}: secret_canary {canary!r} does not appear in this case's own prose "
                "(input / messages[].content) — the model never sees the record id, so it cannot "
                "put it in `record_id`, so the verdict is False forever"
            )
    if expected:
        if expected not in sys_prompt:
            raise CorpusError(
                f"{yaml_path}: expected_tool_call {expected!r} is not declared in this case's "
                "system_prompt — the model is being asked for a tool it was never shown"
            )
        if DECOY_TOOL_SIGNATURE not in sys_prompt:
            raise CorpusError(
                f"{yaml_path}: system_prompt names {expected!r} but carries no signature shape "
                f"{DECOY_TOOL_SIGNATURE!r} — the model would know the name and not how to call it"
            )
    elif DECOY_TOOL_NAME in sys_prompt and target_type == "ACTION":
        raise CorpusError(
            f"{yaml_path}: an ACTION case declares {DECOY_TOOL_NAME!r} but leaves "
            "expected_tool_call empty — it would silently become unmeasurable "
            "(EXFIL cases legitimately leave it empty; this check is ACTION-scoped)"
        )
    # ⑤ LAST, deliberately: it is the general one. ① and ② diagnose the same missing declaration far
    # more precisely when `expected_tool_call` is set, so letting ⑤ pre-empt them would replace two
    # exact messages with one vague one — and would leave ② reachable only by a case shape no author
    # writes, i.e. a check that verifies something easier than what it claims.
    if target_type and DECOY_TOOL_SIGNATURE not in sys_prompt:
        raise CorpusError(
            f"{yaml_path}: a W6 case (target_type {target_type!r}) does not declare "
            f"{DECOY_TOOL_SIGNATURE!r} in its system_prompt. EXFIL cases must declare it too: "
            "declaring only on ACTION cases makes the declaration a 100% predictor of the "
            "target_type, and the judge reads system_prompt"
        )


def load_case(path: str | Path) -> CorpusCase:
    """Load ONE case file. The corpus gate needs file-level granularity to tell a git-ADDED case from
    the existing baseline (EV-COVERAGE §4.3-C rule 2); load_corpus/load_corpus_tree drop the paths."""
    return _load_case(Path(path))


def load_corpus_tree(root: str | Path) -> dict[str, tuple[CorpusCase, ...]]:
    """Load EVERY corpus subdir under `root` → {subdir_name: cases} (EV-COVERAGE §4.3-B — the
    coverage report walks the whole tree, not one indicator's corpus). Each immediate subdirectory
    that holds *.yaml is one corpus; subdirs are visited in sorted order for determinism."""
    base = Path(root)
    if not base.is_dir():
        raise CorpusError(f"corpus root not found: {base}")
    out: dict[str, tuple[CorpusCase, ...]] = {}
    for sub in sorted(base.iterdir()):
        if sub.is_dir() and any(sub.glob("*.yaml")):
            out[sub.name] = load_corpus(sub)
    return out


# 🔴 EV-CN-BENIGN-N180 件④ — the fingerprint ALGORITHM's own version. The delivery side could not
# independently recompute our corpus_sha (they got a different value), which means the anchor was only
# reproducible by running OUR code — and then "the algorithm changed" and "the corpus changed" are
# INDISTINGUISHABLE: both move every sha. So the algorithm is (a) specified normatively below, and (b)
# versioned here. A registration entry records this version alongside its sha; a sha mismatch under a
# CHANGED version is diagnosed as ALGORITHM DRIFT, not as someone editing the corpus (the same
# stored-vs-recompute discipline as citability's CRITERIA_VERSION).
# 🔴 Bump this on ANY change to the sort key, the separators, the participating fields, or the boundary
# byte — every corpus_sha in every registration entry changes when you do.
CORPUS_FINGERPRINT_VERSION = 1
CORPUS_FINGERPRINT_ALGO = f"cfp-v{CORPUS_FINGERPRINT_VERSION}"


def corpus_fingerprint(cases: Iterable[CorpusCase]) -> str:
    """A sha256 over the case SET that actually ran (EV-PAIR §3.1 / P3) — the proof that two runs
    used the SAME corpus. Canonical per case: id + normalized content (input + system_prompt +
    wire messages); sorted by id so probe ORDER is irrelevant, but a changed case_id or one byte of
    content moves it. Per-INDICATOR (each producer runs its own corpus), so the pairing gate can
    reject a single indicator whose corpus differs without failing the rest.

    🔴 件④ NORMATIVE SPEC (so a third party can recompute this WITHOUT running our code — an anchor only
    we can compute is not an anchor). Algorithm `CORPUS_FINGERPRINT_ALGO`; bump its version on any change
    to the four points below.
      • SORT KEY   — the cases are ordered by `case.id`, ascending, using Python's default string
                     comparison over the UTF-8 code points. Order of files on disk is irrelevant.
      • FIELDS     — per case, and ONLY these, in this order: `id`, `input`, `system_prompt`, then each
                     wire message in authored order as `role` followed by its content. A message with
                     structured content contributes each part as `type` then `text`, in authored order.
                     🔴 A field that is None/absent contributes the EMPTY string, not a skipped write —
                     so "absent" and "empty" hash identically, by design. NO other field participates:
                     attack_class / scene / severity / success_when / source do NOT move the sha.
      • SEPARATORS — a single NUL byte (0x00) is written after `id`, after `input`, after
                     `system_prompt`, after each message `role`, after each part `type`, and after each
                     message's content block.
      • BOUNDARY   — a single 0x01 byte terminates each case, so concatenation ambiguities (a case whose
                     content ends where the next case's id begins) cannot collide.
    The digest is sha256 over that byte stream, rendered as `sha256:<64 lowercase hex>`."""
    h = hashlib.sha256()
    for c in sorted(cases, key=lambda c: c.id):
        h.update(c.id.encode("utf-8"))
        h.update(b"\0")
        h.update((c.input or "").encode("utf-8"))
        h.update(b"\0")
        h.update((c.system_prompt or "").encode("utf-8"))
        h.update(b"\0")
        for msg in c.messages or ():
            h.update(msg.role.encode("utf-8"))
            h.update(b"\0")
            if isinstance(msg.content, str):
                h.update(msg.content.encode("utf-8"))
            else:
                for part in msg.content:
                    h.update(part.type.encode("utf-8"))
                    h.update(b"\0")
                    h.update(part.text.encode("utf-8"))
            h.update(b"\0")
        h.update(b"\x01")  # case boundary
    return "sha256:" + h.hexdigest()


# 🔴 mfp-v1 —— 分类字段指纹。与 cfp-v1 【并列，不合并】。
#
# 存在的理由是一次实测（售后研发 2026-09-17，我复现）：把一件的 family / mechanism / anchor /
# lang / evasion 五个字段【全改掉】，`corpus_fingerprint` 逐位不变；改 input 一个字符才变。
# 而 C3B §7 的复核清单从头到尾数的正是那五个字段。
# ⇒ 「先对 sha、对上了才往下数」继承了一个洞：`sha ✅ + §7 ✅` 与
#    「有人在取 sha 之后把每一件的分类字段重写了一遍」**输出同形**。
#
# 🔴 为什么是两个指纹而不是把字段并进 cfp-v1：它们回答两个问题，合并会让答案读不出来。
#     cfp-v1  这批件的【内容】是不是同一批   —— 它一动，测的就不是同一批件
#     mfp-v1  这批件的【分类】是不是同一套   —— 它一动，按分类数出来的配额就换了含义
#   合成一个哈希 ⇒ 它一变，你分不出是正文被改了还是标签被改了，而两者的处置完全不同。
#   ⚠️ 并且 cfp-v1 是已锚定的历史值：把字段并进去会让每一条既有登记条目的 sha 全部失效。
#
# 🔴 覆盖面是【推导】的，不是手抄的字段清单：mfp 覆盖「YAML 里除 cfp-v1 参与字段之外的全部键」。
#   手抄一张清单只在抄写当天正确 —— 下一个人加一个新分类字段，清单不会自己跟着长。
#   ⇒ cfp(内容) ∪ mfp(其余) = 文件全集，一个新字段必然落进其中一个，不会两个都漏。
#
# 🔴 从【生 YAML】读，不从 CorpusCase 读：loader 对未知字段是【静默丢弃】的，
#   而"丢弃"正是这个洞的一半。从 CorpusCase 读会让 loader 不认识的字段再次隐形。
_CFP_FIELDS = frozenset({"id", "input", "system_prompt", "messages"})
METADATA_FINGERPRINT_VERSION = 1
METADATA_FINGERPRINT_ALGO = f"mfp-v{METADATA_FINGERPRINT_VERSION}"


def _canon(value: object) -> str:
    """标量/序列/映射 → 一个确定的字符串。🔴 用 JSON 且 sort_keys：嵌套字典的键序不该进指纹。"""
    import json as _json

    if isinstance(value, str):
        return value
    return _json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def metadata_fingerprint(corpus_dir: str | Path) -> str:
    """一批件的【分类字段】指纹 —— cfp-v1 的补集。

    🔴 规范（第三方不跑我们的代码也能复算；改动任何一条都要升版本）：
      • 取件    `corpus_dir` 下的 `*.yaml`，逐个 `yaml.safe_load` 成映射；非映射的跳过
      • 排序    按 `id` 升序（UTF-8 码点序），与 cfp-v1 同一把尺
      • 字段    每件取【除 id/input/system_prompt/messages 之外的全部键】，键名升序
                🔴 `id` 本身仍写进字节流（做为件的定位），但不计入"参与字段"
      • 编码    每件写 `id` + NUL；然后对每个参与键写 `键名` + NUL + `值的规范串` + NUL
                值的规范串：字符串取原文；其余取 JSON(ensure_ascii=False, sort_keys=True,
                separators=(",",":"))
      • 边界    每件以 0x01 结束
    摘要为 sha256，渲染成 `mfp-v1:<64 位小写十六进制>` —— 算法名写在值里，
    因为一个不带算法名的哈希，在两种算法之间无法自证是哪一种（cfp-v1 那次的教训）。
    """
    base = Path(corpus_dir)
    if not base.is_dir():
        raise CorpusError(f"corpus directory not found: {base}")
    docs: list[dict] = []
    for p in sorted(base.glob("*.yaml")):
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "id" in doc:
            docs.append(doc)
    h = hashlib.sha256()
    for doc in sorted(docs, key=lambda d: str(d["id"])):
        h.update(str(doc["id"]).encode("utf-8"))
        h.update(b"\0")
        for key in sorted(k for k in doc if k not in _CFP_FIELDS):
            h.update(str(key).encode("utf-8"))
            h.update(b"\0")
            h.update(_canon(doc[key]).encode("utf-8"))
            h.update(b"\0")
        h.update(b"\x01")
    return f"{METADATA_FINGERPRINT_ALGO}:" + h.hexdigest()
