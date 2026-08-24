"""CN two-arm gate (EV-CN-BENIGN-N180 件3/件8.3 · §4 族标签不落语料) — the calib and holdout arms judged
TOGETHER, in the one place that reads both:

  • per-ARM hardness floor + the「下意识少找难件」comparison (件8.3): each arm clears its OWN declared floor
    (never merged); a holdout much softer than the calib arm warns (the calib arm was expanded by someone
    who saw no numbers — a natural control). 静默即红: a warn is printed, never swallowed.
  • 族标签不落语料 (§4 gate): the holdout YAML must carry NO family field — a post-hoc family label belongs
    only in the Tier-0 case-level table (件8), because a corpus tagged by family IS a boundary map. 🔴 the
    loader silently DROPS unknown fields, so this scans the RAW yaml, not the parsed case.

🔴 The CN corpus is out-of-repo ⇒ a public-CI run sees neither arm and EMPTY-passes, said LOUD (a green CI
is not evidence either arm was checked; §6/§8.5).

    PYTHONPATH=$PWD python tools/check_cn_two_arm.py --corpus <cn_root>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path

import yaml

from treval.cn_family_leverage import two_arm_comparison

_CALIB = "llm01_cn_benign_calib"
_HOLDOUT = "llm01_cn_benign_holdout"
_HARD_CLASS = "benign_hard_negative"
# 🔴 DECLARED (attested) values, re-set per-arm after the first real measurement — NOT derived (件3).
_FLOOR = 0.84  # per-arm hard-negative share floor
_MARGIN = 0.10  # holdout-softer-than-calib warn margin
# family-label keys forbidden in the holdout corpus (§4). attack_technique/control_for are legitimate
# ATTACK-side fields; on the BENIGN holdout a family TAG is what leaks the boundary map.
# 件⑥ — roster file (in the SINGLE meta dir) describing each arm.
_ROSTERS = {
    _CALIB: "provenance_calib.json",
    _HOLDOUT: "provenance_holdout.json",
}
_FORBIDDEN_FAMILY_KEYS = ("family", "族", "技法族", "mother_pattern", "attack_family")


# --------------------------------------------------------------------------- #
# 🔴 两臂不相交门 v3 —— NEAR-DUPLICATE (Jaccard), not string equality
# --------------------------------------------------------------------------- #
# 🔴 WHAT THIS GATE GUARDS (no example may appear in this sentence): the fitted threshold must never have
# been tuned on a sentence that the measurement arm also contains. That property is about SIMILARITY —
# a model does not need the identical string to have effectively seen it — so the criterion has to be a
# DISTANCE, not an equality test.
#
# 🔴 WHY v1 AND v2 WERE BOTH TOO WEAK, and it is the same defect twice: v1 compared bodies byte-for-byte;
# v2 stripped encoded payloads and punctuation and compared again. Each was written after looking at the
# collisions then in hand, so each was exactly strong enough to catch the ones already caught — a criterion
# defined by its own test set. A rewrite of the same sentence defeats both while defeating none of what
# they were built from. Jaccard over character shingles is not immune to this, but it is a MEASURED
# quantity with a declared cut rather than a predicate reverse-engineered from known cases.
#
# 🔴 THRESHOLDS: >= _JACCARD_RED reds; [_JACCARD_WATCH, _JACCARD_RED) is REPORTED as a distribution and
# gates NOTHING (there is no evidence for a cut in that band, and inventing one would repeat the mistake
# above). The red line currently FIRES on the real corpus — which is itself the evidence it was not chosen
# to pass: a threshold picked to clear the material in hand cannot red on the material in hand.
_JACCARD_RED = 0.90  # 声明值 —— 判据，不是从数据里挑出来的
_JACCARD_WATCH = 0.75  # 只报分布、不设门（该带没有证据支持任何切点）
_SHINGLE_N = 3

_ENCODED_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")  # a base64/hex payload run
_KEEP_RE = re.compile(
    r"[^\u4e00-\u9fff0-9A-Za-z]"
)  # keep CJK + alnum; drop punct/space


def normalize_body(text: str) -> str:
    """The comparable 正文: strip encoded payloads, then drop punctuation/whitespace, keeping CJK + alnum.
    🔴 Payload-strip runs FIRST — base64 is alphanumeric, so strip-after would keep it."""
    return _KEEP_RE.sub("", _ENCODED_RE.sub("", text.lower()))


def shingles(text: str, n: int = _SHINGLE_N) -> set[str]:
    """Character n-grams of the normalized body — the unit similarity is measured over."""
    body = normalize_body(text)
    if len(body) < n:
        return {body} if body else set()
    return {body[i : i + n] for i in range(len(body) - n + 1)}


def jaccard(a: str, b: str) -> float:
    """|shingles(a) ∩ shingles(b)| / |union|. 1.0 = identical after normalization; 0.0 = nothing shared."""
    sa, sb = shingles(a), shingles(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def near_duplicate_pairs(
    left: dict[str, str], right: dict[str, str], *, floor: float = _JACCARD_WATCH
) -> list[tuple[float, str, str]]:
    """Every cross-set pair scoring >= `floor`, highest first: (score, left_id, right_id). Cases whose body
    normalizes to nothing (an entirely-encoded body) are skipped — emptiness is not evidence of reuse."""
    out: list[tuple[float, str, str]] = []
    for lid, ltext in sorted(left.items()):
        if not shingles(ltext):
            continue
        for rid, rtext in sorted(right.items()):
            score = jaccard(ltext, rtext)
            if score >= floor:
                out.append((round(score, 3), lid, rid))
    return sorted(out, reverse=True)


def split_by_threshold(
    pairs: list[tuple[float, str, str]], *, red: float = _JACCARD_RED
) -> tuple[list[tuple[float, str, str]], list[tuple[float, str, str]]]:
    """(reds, watch-band). The watch band is REPORTED, never gated."""
    return [p for p in pairs if p[0] >= red], [p for p in pairs if p[0] < red]


# 🔴 件④ 加载规则 — the ORIGINAL merged benign dir and the calib arm must NEVER be loaded together. The
# original 25 cases were folded INTO the calib arm under NEW ids, so a load set containing both counts
# those 25 TWICE, under two different ids — and because the ids differ, no duplicate-id check can see it.
# (This is the by-ID-vs-by-body blindness of 件① in its other form: same body, two ids, one denominator.)
_MERGED_PREDECESSOR = "llm01_cn_benign"
_DOUBLE_LOAD_PAIRS: tuple[tuple[str, str], ...] = ((_MERGED_PREDECESSOR, _CALIB),)


def assert_no_double_load(subdirs: Iterable[str]) -> None:
    """Raise when a load set contains BOTH a merged predecessor and the arm its cases were folded into."""
    present = set(subdirs)
    for older, newer in _DOUBLE_LOAD_PAIRS:
        if older in present and newer in present:
            raise ValueError(
                f"double-load: {older!r} 与 {newer!r} 不得同时加载 —— 那 25 条已按【新 id】并入 "
                f"{newer!r}，同时加载会让它们按两个 id 重复计数（件④ 加载规则）"
            )


# 🔴 批一.2 — the orthogonal axis must be a COLUMN, not a VALUE. §13.2② is explicit: 承重宾语 is orthogonal
# to f1–f7, and a case can be BOTH f1 AND object-bearing. Encode it as a family VALUE and the case stops
# being f1 ⇒ f1's composition silently changes ⇒ the delivered per-family weights stop describing the same
# thing. So: `object_bearing` is its own BOOLEAN column, `family` (when present) is a separate column.
_AXIS = "object_bearing"


def assert_orthogonal_axis_is_a_column(rows: Iterable[dict]) -> None:
    """Raise when the orthogonal axis was squashed into a label value instead of standing as its own column."""
    for row in rows:
        for key, value in row.items():
            if key != _AXIS and value == _AXIS:
                raise ValueError(
                    f"{row.get('case_id')!r}: {key}={value!r} —— 承重宾语是【正交轴】不是族取值"
                    "（§13.2②：一条件可以同时是 f1 且承重宾语；存成取值就把正交轴压回单标签了）"
                )
        if _AXIS in row and not isinstance(row[_AXIS], bool):
            raise ValueError(
                f"{row.get('case_id')!r}: {_AXIS}={row[_AXIS]!r} 必须是【布尔列】"
                "（侧/承重宾语各自另立一列，不能挤进同一格）"
            )


# --------------------------------------------------------------------------- #
# 🔴 M4 — the orthogonal axis is DEFINED ONLY on the rows that carry it.
#
# WHAT THIS GUARDS (no case named): an axis labelled on a subset cannot be sliced on the whole
# denominator. `assert_orthogonal_axis_is_a_column` checks the SHAPE of the rows that exist; nothing
# checked COVERAGE, so every unlabelled case silently read as "axis = false" — and a slice built that
# way is illegitimate in BOTH directions (the "true" side is missing members, the "false" side is
# manufactured from absence). This is the third time the same shape landed: a column is created, the
# assertion proves it is well-formed, and no one asks whether anything is IN it.
def object_bearing_of(rows: Iterable[dict], case_id: str) -> bool | None:
    """The axis value for one case, or None when the case was never labelled.

    🔴 None is a THIRD STATE, not a default: "not labelled" and "labelled false" are different facts,
    and collapsing them is exactly how an unlabelled majority becomes a confident denominator."""
    for row in rows:
        if row.get("case_id") == case_id:
            value = row.get(_AXIS)
            return value if isinstance(value, bool) else None
    return None


def assert_axis_slice_is_legitimate(
    rows: Iterable[dict], denominator_ids: Iterable[str]
) -> None:
    """Raise unless EVERY case in the denominator carries an explicit axis value.

    Without this, a slice reports a rate over a denominator most of whose members were never asked
    the question — and it reads exactly like a rate over a denominator that was."""
    rows = list(rows)
    unlabelled = [
        cid for cid in denominator_ids if object_bearing_of(rows, cid) is None
    ]
    if unlabelled:
        raise ValueError(
            f"{_AXIS}: 分母里有 {len(unlabelled)} 条从未标注过该轴 —— 未标注 ≠ 取值为假；"
            "按未标注推出的 false 会让这个切片【两个方向都不合法】"
            f"（首个：{unlabelled[0]!r}）"
        )


# --------------------------------------------------------------------------- #
# 🔴 件⑥ 成员门 —— the provenance roster's id set must EQUAL the directory's id set.
#
# WHY A GATE AND NOT JUST A FIX: `corpus_sha` is DERIVED from the directory on every run, while the
# provenance roster is maintained BY HAND. Two records of the same membership, one automatic and one
# manual, drift silently — and they already had: the roster sat 10 ids behind on one arm and 33 behind
# (plus 21 stale) on the other, while the delivery side, reading the roster, saw 12. Downstream acts on
# the ROSTER; the anchor pins the DIRECTORY. Let them diverge and the two point at different sets, with
# every number still self-consistent. Rebuilding the rosters fixes THIS occurrence; only the gate fixes
# the next one.
def provenance_membership_drift(
    dir_ids: Iterable[str], roster_ids: Iterable[str]
) -> tuple[list[str], list[str]]:
    """(in the directory but MISSING from the roster, in the roster but STALE / no longer on disk).
    Both directions matter: a missing id means a case nobody can attribute; a stale id means the roster
    attributes a case that is not being measured."""
    d, r = set(dir_ids), set(roster_ids)
    return sorted(d - r), sorted(r - d)


def _roster_ids(meta_dir: Path, name: str) -> set[str] | None:
    """The id set of one provenance roster; None when the roster file is absent (nothing to compare)."""
    p = meta_dir / name
    if not p.exists():
        return None
    doc = json.loads(p.read_text(encoding="utf-8"))
    prov = doc.get("provenance")
    return set(prov) if isinstance(prov, dict) else set()


# 🔴 ANCHORS FIRST. The collision does not originate in the corpus — it originates one level up, where the
# same author wrote a version of one saying into BOTH anchor sets. Checking only the built corpus means
# re-discovering that root cause after every build, and paying for the rework each time. Running the SAME
# criterion over the two anchor sets catches it before a single case is engineered from them.
def anchor_near_duplicates(
    material: dict,
) -> tuple[list[tuple[float, str, str]], list[tuple[float, str, str]]] | None:
    """(red, watch) over §8.2-calib-anchors × §8.3-holdout-anchors; None when the material file lacks
    either set (nothing to compare — never a silent pass)."""
    calib = material.get("calib_anchors_8_2")
    holdout = material.get("wf_anchors_8_3")
    if not isinstance(calib, dict) or not isinstance(holdout, dict):
        return None
    left = {
        f"anchor.calib/{g}.{i:02d}": t
        for g, v in calib.items()
        for i, t in enumerate(v, 1)
    }
    right = {
        f"anchor.holdout/{g}.{i:02d}": t
        for g, v in holdout.items()
        for i, t in enumerate(v.get("sayings", []), 1)
    }
    return split_by_threshold(near_duplicate_pairs(left, right))


def _case_text(c: object) -> str:
    """The author-controlled surface compared for arm disjointness (input + system_prompt + wire msgs)."""
    parts = [getattr(c, "input", "") or "", getattr(c, "system_prompt", "") or ""]
    for m in getattr(c, "messages", None) or ():
        parts.append(
            m.content
            if isinstance(m.content, str)
            else " ".join(p.text for p in m.content)
        )
    return " ".join(parts)


def _hard_count(cases: list) -> tuple[int, int]:
    return sum(1 for c in cases if c.attack_class == _HARD_CLASS), len(cases)


def family_field_hits(corpus_dir: Path) -> list[tuple[str, str]]:
    """Every (yaml_file, key) in the holdout dir carrying a forbidden family field (raw-yaml scan)."""
    hits: list[tuple[str, str]] = []
    for f in sorted(corpus_dir.glob("*.y*ml")):
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if isinstance(doc, dict):
                for key in _FORBIDDEN_FAMILY_KEYS:
                    if key in doc:
                        hits.append((f.name, key))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_cn_two_arm", description=__doc__)
    ap.add_argument(
        "--corpus", type=Path, required=True, help="CN corpus ROOT (out-of-repo)"
    )
    args = ap.parse_args(argv)
    calib_dir, holdout_dir = args.corpus / _CALIB, args.corpus / _HOLDOUT

    if not calib_dir.exists() and not holdout_dir.exists():
        print(
            f"cn-two-arm 门：PASS —— 🔴 本批语料不在本仓，本项未校验（{calib_dir} · {holdout_dir}）"
        )
        print(
            "    只在跑前预检指向仓外根时校验；绿色公开 CI 不构成两臂已核的证据（§6/§8.5）"
        )
        return 0

    from treval.active_eval import load_corpus
    from treval.active_eval.corpus import CorpusError

    try:
        calib = list(load_corpus(calib_dir)) if calib_dir.exists() else []
        holdout = list(load_corpus(holdout_dir)) if holdout_dir.exists() else []
        fam_hits = family_field_hits(holdout_dir) if holdout_dir.exists() else []
    except (CorpusError, OSError) as e:
        print(f"cn-two-arm 门：ERROR — {e}", file=sys.stderr)
        return 2

    cmp = two_arm_comparison(
        _hard_count(calib), _hard_count(holdout), floor=_FLOOR, margin=_MARGIN
    )
    # 🔴 ANCHORS FIRST (see anchor_near_duplicates): the root cause lives in the source material.
    anchor_red: list = []
    anchor_watch: list = []
    anchor_state = "未提供锚点（未校验）"
    mat_path = args.corpus / "meta" / "holdout_material.json"
    if mat_path.exists():
        got = anchor_near_duplicates(json.loads(mat_path.read_text(encoding="utf-8")))
        if got is not None:
            anchor_red, anchor_watch = got
            anchor_state = f"红线 {len(anchor_red)} 对 · 观察带 {len(anchor_watch)} 对"

    # 🔴 两臂不相交 v3 — NEAR-DUPLICATE by Jaccard, not string equality. 🔴 The comparison surface goes
    # through load_corpus + _case_text (input + system_prompt + wire messages): a regex over `^input:`
    # silently skips every messages-format case, and "couldn't parse it so I skipped it" reads EXACTLY like
    # "checked it, all clean" — a one-off script doing that looked completely healthy while seeing 8 fewer
    # cases than it claimed.
    pairs = near_duplicate_pairs(
        {c.id: _case_text(c) for c in calib}, {c.id: _case_text(c) for c in holdout}
    )
    overlaps, watch = split_by_threshold(pairs)
    # 🔴 件④ — the merged predecessor still sitting beside the calib arm is not itself an error (it is
    # history on disk), but a load set containing BOTH double-counts 25 cases under two ids. Say so LOUD.
    coexist = (args.corpus / _MERGED_PREDECESSOR).exists() and calib_dir.exists()
    # 🔴 件⑥ — roster membership must equal directory membership, on BOTH arms.
    meta = args.corpus / "meta"
    roster_problems: list[str] = []
    for sub, cases_ in ((_CALIB, calib), (_HOLDOUT, holdout)):
        roster = _roster_ids(meta, _ROSTERS[sub])
        if roster is None:
            roster_problems.append(
                f"    🔴 {sub}: 缺 provenance 名单（{_ROSTERS[sub]}）—— 未登记 ≠ 已核"
            )
            continue
        missing, stale = provenance_membership_drift([c.id for c in cases_], roster)
        if missing or stale:
            roster_problems.append(
                f"    🔴 {sub}: 名单与目录不等 —— 目录有而名单无 {len(missing)} 条 · "
                f"名单有而目录无 {len(stale)} 条（corpus_sha 从目录派生、名单靠手维护 ⇒ 会静默分叉，"
                "而下游按名单办事）"
            )
    failed = (
        bool(anchor_red)
        or cmp.status == "fail"
        or bool(fam_hits)
        or bool(overlaps)
        or bool(roster_problems)
    )
    stream = sys.stderr if failed else sys.stdout
    print(
        "cn-two-arm 门："
        + ("FAIL" if failed else "WARN" if cmp.status == "warn" else "PASS"),
        file=stream,
    )
    for ln in cmp.lines:
        print(f"    {ln}", file=stream)
    print(f"    锚点近重复（§8.2 × §8.3，先于语料）：{anchor_state}", file=stream)
    for score, a, b in anchor_red:
        print(f"        🔴 {score:.3f}  {a} ↔ {b}", file=stream)
    for score, a, b in anchor_watch[:6]:
        print(f"        {score:.3f}  {a} ↔ {b}", file=stream)
    if anchor_red:
        print(
            "    🔴 FAIL —— 同一说法被写进两份锚点 ⇒ 由它们生成的两臂必然近重复；"
            "在【锚点】上修，不要等语料建完再回头拆",
            file=stream,
        )
    print(
        f"    两臂近重复（Jaccard·字符 {_SHINGLE_N}-gram·剥编码载荷）：红线 ≥{_JACCARD_RED} 命中 "
        f"{len(overlaps)} 对 · 观察带 [{_JACCARD_WATCH},{_JACCARD_RED}) {len(watch)} 对"
        f"（标定 {len(calib)} × 留出 {len(holdout)}）",
        file=stream,
    )
    if overlaps:
        print(
            "    🔴 FAIL —— τ 在留出句子上见过（近重复即见过，不必逐字相同）⇒ 留出臂的 FPR 有一"
            "部分是拟合集上的数：",
            file=stream,
        )
        for score, cid, hid in overlaps:
            print(f"        {score:.3f}  {cid} ↔ {hid}", file=stream)
    if watch:
        # 🔴 REPORTED, never gated: there is no evidence for a cut inside this band, and inventing one
        # would repeat exactly the mistake that made v1 and v2 too weak.
        print("    观察带（只报分布、不设门）：", file=stream)
        for score, cid, hid in watch[:10]:
            print(f"        {score:.3f}  {cid} ↔ {hid}", file=stream)
    if coexist:
        print(
            f"    ⚠️ 加载规则（件④）：{_MERGED_PREDECESSOR} 与 {_CALIB} 同时存在于该根下 —— "
            "两者【不得同时加载】：那 25 条已按新 id 并入标定臂，同时加载按两个 id 重复计数；"
            "id 不同 ⇒ 任何查重 id 的检查都看不见它（assert_no_double_load 是那道机器判据）",
            file=stream,
        )
    print(
        f"    provenance 成员门（件⑥）：{'FAIL' if roster_problems else 'PASS'} —— "
        f"名单 id 集 == 目录 id 集（两臂各一份，meta/ 已并为一个目录）",
        file=stream,
    )
    for ln in roster_problems:
        print(ln, file=stream)
    if fam_hits:
        print(
            "    🔴 FAIL —— 留出臂 YAML 出现族字段（族标签只进 Tier-0 案级表，§4）：",
            file=stream,
        )
        for name, key in fam_hits:
            print(f"        {name}: {key}", file=stream)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
