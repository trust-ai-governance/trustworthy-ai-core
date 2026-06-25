"""Tests for treval.posture.PostureFileReader (EV-3)."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator

import pytest

from treval import PostureFileError, PostureFileReader, PostureProvider
from treval.models import EvidenceRef, PostureEvidence

_YAML = """\
tenant_id: default
attestations:
  - key: security.sso_mfa_enabled
    value: "true"
    attested_by: jane@corp.example
    attested_at_ns: 1782000000000000000
  - key: reliability.iac_provisioned
    value: "true"
    attested_by: ops-team
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# 1. Happy path
# --------------------------------------------------------------------------- #


def test_reads_yaml(tmp_path):
    ev = list(PostureFileReader(_write(tmp_path, "posture.yaml", _YAML)).collect())

    assert len(ev) == 2
    assert all(isinstance(e, PostureEvidence) for e in ev)
    assert ev[0].key == "security.sso_mfa_enabled"
    assert ev[0].value == "true"
    assert ev[0].attested_by == "jane@corp.example"
    assert ev[0].attested_at_ns == 1782000000000000000
    assert ev[0].tenant_id == "default"
    assert ev[0].ref.source.startswith("attest:")
    # attested_at_ns defaults to 0 when omitted.
    assert ev[1].attested_at_ns == 0
    assert ev[1].attested_by == "ops-team"


# --------------------------------------------------------------------------- #
# 2. JSON parses to the identical evidence (same loader path)
# --------------------------------------------------------------------------- #


def test_json_matches_yaml(tmp_path):
    doc = {
        "tenant_id": "default",
        "attestations": [
            {
                "key": "security.sso_mfa_enabled",
                "value": "true",
                "attested_by": "jane@corp.example",
                "attested_at_ns": 1782000000000000000,
            },
            {
                "key": "reliability.iac_provisioned",
                "value": "true",
                "attested_by": "ops-team",
            },
        ],
    }
    yaml_ev = list(PostureFileReader(_write(tmp_path, "p.yaml", _YAML)).collect())
    json_ev = list(
        PostureFileReader(_write(tmp_path, "p.json", json.dumps(doc))).collect()
    )

    # EvidenceRef.source differs only by path; compare the attested content.
    def content(e):
        return (e.tenant_id, e.key, e.value, e.attested_by, e.attested_at_ns)

    assert [content(e) for e in json_ev] == [content(e) for e in yaml_ev]


# --------------------------------------------------------------------------- #
# 3. Fail-closed + tenant filter
# --------------------------------------------------------------------------- #


def test_missing_required_field_raises(tmp_path):
    bad = """\
tenant_id: default
attestations:
  - key: security.sso_mfa_enabled
    value: "true"
"""  # no attested_by
    with pytest.raises(PostureFileError, match="attested_by"):
        list(PostureFileReader(_write(tmp_path, "bad.yaml", bad)).collect())


def test_missing_tenant_id_raises(tmp_path):
    with pytest.raises(PostureFileError, match="tenant_id"):
        list(
            PostureFileReader(
                _write(tmp_path, "bad.yaml", "attestations: []")
            ).collect()
        )


def test_attestations_not_a_list_raises(tmp_path):
    with pytest.raises(PostureFileError, match="attestations"):
        list(PostureFileReader(_write(tmp_path, "bad.yaml", "tenant_id: x")).collect())


def test_unparseable_file_raises(tmp_path):
    with pytest.raises(PostureFileError):
        list(PostureFileReader(_write(tmp_path, "bad.yaml", "key: : :")).collect())


def test_doc_not_a_mapping_raises(tmp_path):
    with pytest.raises(PostureFileError, match="mapping"):
        list(PostureFileReader(_write(tmp_path, "bad.yaml", "- a\n- b")).collect())


def test_attestation_not_a_mapping_raises(tmp_path):
    bad = "tenant_id: default\nattestations:\n  - just-a-string\n"
    with pytest.raises(PostureFileError, match="must be a mapping"):
        list(PostureFileReader(_write(tmp_path, "bad.yaml", bad)).collect())


def test_unquoted_non_string_value_raises(tmp_path):
    # YAML auto-types `value: true` to a bool; the model wants str -> fail closed.
    bad = """\
tenant_id: default
attestations:
  - key: security.sso_mfa_enabled
    value: true
    attested_by: jane@corp.example
"""
    with pytest.raises(PostureFileError, match="must be a string"):
        list(PostureFileReader(_write(tmp_path, "bad.yaml", bad)).collect())


def test_non_integer_attested_at_ns_raises(tmp_path):
    # bool is an int subclass in Python; it must NOT slip through.
    bad = """\
tenant_id: default
attestations:
  - key: security.sso_mfa_enabled
    value: "true"
    attested_by: jane@corp.example
    attested_at_ns: true
"""
    with pytest.raises(PostureFileError, match="attested_at_ns"):
        list(PostureFileReader(_write(tmp_path, "bad.yaml", bad)).collect())


def test_nonexistent_file_raises(tmp_path):
    with pytest.raises(PostureFileError):
        list(PostureFileReader(tmp_path / "nope.yaml").collect())


def test_tenant_filter(tmp_path):
    p = PostureFileReader(_write(tmp_path, "posture.yaml", _YAML))
    assert len(list(p.collect(tenant_id="default"))) == 2
    assert list(p.collect(tenant_id="other")) == []


# --------------------------------------------------------------------------- #
# 4. Seam proof: a test-local provider satisfies the Protocol + same downstream
# --------------------------------------------------------------------------- #


class _MemoryProvider:
    provider_id = "memory"

    def __init__(self, items: list[PostureEvidence]) -> None:
        self._items = items

    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]:
        for e in self._items:
            if tenant_id is None or e.tenant_id == tenant_id:
                yield e


def test_custom_provider_satisfies_protocol(tmp_path):
    item = PostureEvidence(
        ref=EvidenceRef(source="memory:test"),
        tenant_id="default",
        key="security.sso_mfa_enabled",
        value="true",
        attested_by="unit-test",
        attested_at_ns=0,
    )
    # Static: assignable to the Protocol type. Runtime: same downstream shape.
    provider: PostureProvider = _MemoryProvider([item])
    file_provider: PostureProvider = PostureFileReader(
        _write(tmp_path, "posture.yaml", _YAML)
    )
    assert list(provider.collect(tenant_id="default")) == [item]
    assert all(isinstance(e, PostureEvidence) for e in file_provider.collect())


# --------------------------------------------------------------------------- #
# 5. The attested-only safety invariant (§5)
# --------------------------------------------------------------------------- #


def test_posture_evidence_has_no_measured_field():
    names = {f.name for f in dataclasses.fields(PostureEvidence)}
    assert names == {
        "ref",
        "tenant_id",
        "key",
        "value",
        "attested_by",
        "attested_at_ns",
    }
    # No field a provider could use to inject a measured signal.
    assert not (names & {"integrity", "sample_size", "unit", "dimension"})
