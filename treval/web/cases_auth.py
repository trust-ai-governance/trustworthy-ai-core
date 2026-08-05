"""UI-3 §3.3 — the case service's credential-scope logic: the ONE piece of authorization code in
this ticket, kept in its own module so it unit-tests without HTTP (§11).

🔴 The load-bearing decision (§3): the tenant is derived from the CREDENTIAL, never chosen by a
`?tenant=` query param. Core has no identity system and must not grow one (EV-W1 D4) — so this is
NOT a login: no users, sessions, passwords, or role inheritance. It is Core's existing shared-secret
model PLUS a scope, which turns `?tenant=` from a SELECTOR into a BOUNDARY (what P2-2 requires).

The map is `{token: tenant}`; a value of `"*"` is admin (sees every tenant) — 🔴 and `*` must be an
EXPLICIT row, never a default. No map ⇒ refuse to start (fail-closed): "no token = allow" (the report
service's loopback posture) is WRONG for a bypass map.
"""

from __future__ import annotations

import json
from pathlib import Path

ADMIN = "*"


class CasesAuthError(Exception):
    """The token map is missing or malformed — refuse to start (fail-closed, §4 table)."""


class Forbidden(Exception):
    """A scoped credential asked for a tenant outside its scope — 403 (§3.3). 🔴 NOT a silent
    fall-back to the credential's own tenant: a silent fall-back makes an over-reach look like it
    succeeded (the "0% and can't-see look the same" family)."""


def load_token_map(source: str | Path) -> dict[str, str]:
    """Load `{token: tenant}` from a JSON FILE PATH (§3.3). 🔴 A file, never an inline env value —
    an inline token lands in the process table and shell history. Fail-closed on any problem, naming
    the file and the offending row so a misconfig is legible, never a silent open door."""
    path = Path(source)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise CasesAuthError(f"cannot read token map {path}: {e}") from e
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CasesAuthError(f"token map {path} is not valid JSON: {e}") from e
    if not isinstance(doc, dict) or not doc:
        raise CasesAuthError(
            f"token map {path} must be a non-empty object {{token: tenant}}"
        )
    out: dict[str, str] = {}
    for token, tenant in doc.items():
        if not isinstance(token, str) or not token:
            raise CasesAuthError(f"token map {path}: a token key is empty/non-string")
        if not isinstance(tenant, str) or not tenant:
            raise CasesAuthError(
                f"token map {path}: token {token!r} maps to {tenant!r}, must be a non-empty tenant "
                f"string (or {ADMIN!r} for admin)"
            )
        out[token] = tenant
    return out


def scope_for_token(token_map: dict[str, str], supplied: str | None) -> str | None:
    """The scope tenant for a supplied credential: a tenant id, `"*"` (admin), or None if the token
    is unknown (→ 401). An empty/absent token is never admitted."""
    if not supplied:
        return None
    return token_map.get(supplied)


def is_admin(scope: str) -> bool:
    return scope == ADMIN


def can_see_tenant(scope: str, tenant: str) -> bool:
    """Whether a credential may see a record owned by `tenant`. 🔴 Used AFTER a key lookup: an
    unguessable content key is not authorization, so the record's tenant is still checked, and a
    mismatch is a 404 (not 403 — to an unauthorized viewer we do not even confirm existence, §4)."""
    return scope == ADMIN or scope == tenant


def resolve_query_tenant(scope: str, requested: str | None) -> str | None:
    """§3.3 — turn `?tenant=` into a BOUNDARY. Returns the tenant to filter by, or None meaning
    "no single tenant selected" (admin listing across tenants). Raises Forbidden when a scoped
    credential asks for someone else's tenant.

      • admin (`*`)        → `requested` is an authorized SELECTOR (None = all tenants);
      • scoped to tenant T → None or T is fine (idempotent) and yields T; anything else ⇒ 403.
    """
    if scope == ADMIN:
        return requested
    if requested is None or requested == scope:
        return scope
    raise Forbidden(
        f"credential scoped to {scope!r} may not request tenant {requested!r} (§3.3) — this is 403, "
        "NOT a silent fall-back to your own tenant"
    )
