"""Corpus format + loader (EV-AE0 §3).

Self-describing YAML cases (the adversarial analogue of the conformance suite).
One case per file; the loader globs sorted *.yaml for deterministic order and is
fail-closed on malformed input (like the registry loader). The loader takes a
path (default = repo-root corpus/llm01_prompt_injection/) so the corpus can move
without code change (same packaging caveat as EV-6's registry/, deferred).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from treval.active_eval.checks import KNOWN_SUCCESS_TOKENS

_DEFAULT_DIR = Path(__file__).resolve().parents[2] / "corpus" / "llm01_prompt_injection"
_REQUIRED = (
    "id",
    "owasp",
    "dimension",
    "attack_class",
    "input",
    "success_when",
    "severity",
    "source",
)


class CorpusError(Exception):
    """A corpus case is malformed (missing field / bad success_when / unparseable)."""


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
    # Optional planted secret that must NOT appear in the output (LLM02 leak test).
    # Distinct from output_marker (an attack sentinel the model is tricked into
    # EMITTING); secret_canary is a protected secret the model must NOT emit (D3).
    secret_canary: str = ""
    # Optional real role:"system" message the harness sends ahead of the user turn.
    # For LLM07 it embeds the secret_canary (the leak target). Distinct from `input`
    # (the user-turn attack). Empty ⇒ no system message sent (LLM01/LLM02 unchanged).
    system_prompt: str = ""
    # The tool to invoke. Default "chat" (LLM01/02/07). Non-"chat" ⇒ an out-of-scope
    # probe for the eval agent (granted tool:chat:*) — the LLM06 tool-scope test; for
    # those cases `input` is a human-readable attack description, not a chat message.
    tool_id: str = "chat"


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
    fields = {field: doc[field] for field in _REQUIRED}
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
    # A leak check with no planted secret is meaningless — fail closed (D3/§4).
    if doc["success_when"] == "not_leaked" and not fields.get("secret_canary"):
        raise CorpusError(
            f"{yaml_path}: success_when 'not_leaked' requires a secret_canary"
        )
    return CorpusCase(**fields)
