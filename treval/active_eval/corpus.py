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
    fields = {field: doc[field] for field in _REQUIRED}

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
    # A leak check with no planted secret is meaningless — fail closed (D3/§4).
    if doc["success_when"] == "not_leaked" and not fields.get("secret_canary"):
        raise CorpusError(
            f"{yaml_path}: success_when 'not_leaked' requires a secret_canary"
        )
    return CorpusCase(**fields)


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
