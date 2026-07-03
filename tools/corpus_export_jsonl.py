"""Export the labelled LLM01 corpus as JSONL for Platform's P2-b judge τ-sweep (OPERATOR).

One object per line: {"id", "prompt", "label"} with label ∈ {injection, benign}.
Label is derived from attack_class (benign_* → benign, else injection) — no new schema,
just the prompts + labels the corpus already carries. Covers the injection set
(llm01_prompt_injection + llm01_wire_indirect) and the benign set (llm01_benign +
llm01_indirect_benign), so τ calibrates against the real attack/benign distribution —
including the lexical residuals {007,008,014} and the benign discussion cases {008,009}.

Multi-turn cases (wire / indirect-benign) are serialized as `role: content` lines so the
judge sees the same role framing the gateway does (the framing is exactly what separates a
user *discussing* injection from one *issuing* it). Deterministic: sorted by id.

Usage:
  python tools/corpus_export_jsonl.py                       # → reports/llm01_labelled.jsonl
  python tools/corpus_export_jsonl.py --out /path/to.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_CORPUS = _ROOT / "corpus"
_DIRS = (
    "llm01_prompt_injection",
    "llm01_wire_indirect",
    "llm01_benign",
    "llm01_indirect_benign",
)


def _content_text(content: Any) -> str:
    """Flatten a message `content` (str | list-of-content-parts) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    return str(content)


def _prompt(case: dict[str, Any]) -> str:
    """Faithful prompt text: single-turn `input`, else serialized `role: content`."""
    if "input" in case:
        return str(case["input"])
    return "\n".join(
        f"{m.get('role', '?')}: {_content_text(m.get('content'))}"
        for m in case.get("messages", [])
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="export labelled LLM01 set as JSONL")
    parser.add_argument(
        "--out", default=str(_ROOT / "reports" / "llm01_labelled.jsonl")
    )
    args = parser.parse_args()

    rows: list[dict[str, str]] = []
    for subdir in _DIRS:
        for path in sorted((_CORPUS / subdir).glob("*.yaml")):
            case = yaml.safe_load(path.read_text(encoding="utf-8"))
            attack_class = str(case.get("attack_class", ""))
            rows.append(
                {
                    "id": str(case["id"]),
                    "prompt": _prompt(case),
                    "label": "benign"
                    if attack_class.startswith("benign")
                    else "injection",
                }
            )
    rows.sort(key=lambda r: r["id"])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8",
    )

    n_inj = sum(1 for r in rows if r["label"] == "injection")
    print(
        f"wrote {out}: {len(rows)} cases ({n_inj} injection, {len(rows) - n_inj} benign)"
    )
    # Confirm the cases the τ-sweep specifically needs are present.
    need = {
        "llm01.direct.translate_then_leak.007",
        "llm01.direct.base64_smuggle.008",
        "llm01.direct.language_switch_override.014",
        "benign.indirect.user_summarize_injection_article.008",
        "benign.indirect.user_asks_what_is_injection.009",
    }
    have = {r["id"] for r in rows}
    missing = need - have
    print(
        "required residual/discussion cases:",
        "ALL PRESENT" if not missing else f"MISSING {missing}",
    )


if __name__ == "__main__":
    main()
