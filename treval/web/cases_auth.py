"""UI-3 §3.3 / UI-3-AUTH — the case service's credential logic: the ONE piece of authorization code
in this ticket, kept in its own module so it unit-tests without HTTP (§11).

🔴 The load-bearing decision (§3): the tenant is derived from the CREDENTIAL, never chosen by a
`?tenant=` query param. Core has no identity system and must not grow one (EV-W1 D4) — so this is
NOT a login: no users, sessions, passwords, or role inheritance. It is Core's existing shared-secret
model PLUS a scope, which turns `?tenant=` from a SELECTOR into a BOUNDARY (what P2-2 requires).

UI-3-AUTH upgrades the map from `{token: tenant}` to `{token: {label, scope, expires_at, note?}}`:
every key now carries an IDENTITY (`label`, shown on the page — 🔴 NEVER the key itself), a SCOPE
(`"*"` = admin, an EXPLICIT row, never a default) and an EXPIRY (§3.1 — there are no permanent keys).
🔴 Old str→tenant rows are STILL accepted (normalized to a legacy TokenInfo that never expires) with a
startup WARN — a fail-closed upgrade would be routed around by "revert to the old version" (§2.1).
Expiry auto-takes-effect because the scope is re-queried PER REQUEST (`scope_for_token`) and the map
is re-read when the file changes (`TokenMap`, §3.3) — with NO session store (§1.1).

No map ⇒ refuse to start (fail-closed): "no token = allow" (the report service's loopback posture)
is WRONG for a bypass map.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ADMIN = "*"

_log = logging.getLogger(__name__)

# §5 件D — repeated failures from one source wait a little longer each time (NOT a ban; a ban needs
# state). The step is small and capped so it can never wedge the process.
_FAIL_DELAY_STEP = 0.02
_FAIL_DELAY_MAX = 1.0


class CasesAuthError(Exception):
    """The token map is missing or malformed — refuse to start (fail-closed, §4 table)."""


class Forbidden(Exception):
    """A scoped credential asked for a tenant outside its scope — 403 (§3.3). 🔴 NOT a silent
    fall-back to the credential's own tenant: a silent fall-back makes an over-reach look like it
    succeeded (the "0% and can't-see look the same" family)."""


@dataclass(frozen=True)
class TokenInfo:
    """One key's metadata (§2.1). `label` is the page identity (globally unique, non-empty) — 🔴 NEVER
    the key itself. `scope` is a tenant id or `"*"` (admin). `expires_at` is a UTC instant, or None for
    a LEGACY str→tenant row (which never expires, §2.1 carve-out). `note` is an optional ops memo."""

    label: str
    scope: str
    expires_at: datetime | None
    note: str | None = None
    legacy: bool = False


def _parse_utc(raw: str) -> datetime:
    """Parse an ISO-8601 instant to an aware UTC datetime (accepts a trailing `Z`). Fail-closed."""
    s = raw.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise CasesAuthError(
            f"expires_at {raw!r} is not a parseable UTC instant: {e}"
        ) from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_token_map(source: str | Path) -> dict[str, TokenInfo]:
    """Load `{token: TokenInfo}` from a JSON FILE PATH (§2.1/§3.3). 🔴 A file, never an inline env
    value — an inline token lands in the process table and shell history. Fail-closed on any problem
    with the NEW object format, naming the offending row by LABEL or index — 🔴 never by its token (a
    token in an error message is a key leaked to the logs, §5). Old str→tenant rows are accepted
    (normalized, legacy) with a single WARN — never fail-closed (§2.1)."""
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
            f"token map {path} must be a non-empty object {{token: {{label, scope, expires_at}}}}"
        )
    out: dict[str, TokenInfo] = {}
    labels: dict[
        str, int
    ] = {}  # new-format label → row index, for global uniqueness (§2.1)
    legacy_tenants: list[str] = []
    for i, (token, value) in enumerate(doc.items()):
        where = f"token map {path} row #{i}"
        if not isinstance(token, str) or not token:
            raise CasesAuthError(f"{where}: a token key is empty/non-string")
        if isinstance(value, str):
            # 🔴 §2.1 back-compat: old str→tenant. Non-empty tenant required (as before); normalized to
            # a legacy row (label = tenant, never expires). WARN, do NOT fail-closed.
            if not value:
                raise CasesAuthError(f"{where}: maps to an empty tenant string")
            out[token] = TokenInfo(
                label=value, scope=value, expires_at=None, legacy=True
            )
            legacy_tenants.append(value)
            continue
        if not isinstance(value, dict):
            raise CasesAuthError(
                f"{where}: must map to a tenant string (legacy) or an object "
                "{label, scope, expires_at, note?}"
            )
        label = value.get("label")
        if not isinstance(label, str) or not label:
            raise CasesAuthError(f"{where}: 'label' must be a non-empty string")
        scope = value.get("scope")
        if not isinstance(scope, str) or not scope:
            raise CasesAuthError(
                f"{where} (label {label!r}): 'scope' must be a non-empty tenant id (or {ADMIN!r})"
            )
        raw_exp = value.get("expires_at")
        if not isinstance(raw_exp, str) or not raw_exp:
            raise CasesAuthError(
                f"{where} (label {label!r}): 'expires_at' is required — there are no permanent keys "
                "(§3.1); use a far-future date, never null"
            )
        expires_at = _parse_utc(raw_exp)
        if label in labels:
            raise CasesAuthError(
                f"{where}: label {label!r} is not globally unique (also row #{labels[label]})"
            )
        labels[label] = i
        note = value.get("note")
        out[token] = TokenInfo(
            label=label,
            scope=scope,
            expires_at=expires_at,
            note=note if isinstance(note, str) and note else None,
            legacy=False,
        )
    if legacy_tenants:
        _log.warning(
            "token map %s: %d legacy str→tenant row(s) accepted for tenant(s) %s — these NEVER expire; "
            "upgrade to the object format {label, scope, expires_at} (§2.1)",
            path,
            len(legacy_tenants),
            ", ".join(sorted(set(legacy_tenants))),
        )
    return out


def scope_for_token(
    token_map: dict[str, TokenInfo],
    supplied: str | None,
    *,
    now: datetime | None = None,
) -> str | None:
    """The scope tenant for a supplied credential: a tenant id, `"*"` (admin), or None if the token is
    unknown OR EXPIRED. 🔴 An expired object-format key resolves EXACTLY like an unknown one, so §5
    stays un-enumerable: "exists but expired" and "never existed" are indistinguishable here. An
    empty/absent token is never admitted. `now` defaults to the current UTC instant (injectable for
    tests); legacy rows (expires_at is None) never expire."""
    if not supplied:
        return None
    info = token_map.get(supplied)
    if info is None:
        return None
    if info.expires_at is not None:
        moment = now if now is not None else datetime.now(timezone.utc)
        if moment >= info.expires_at:
            return None
    return info.scope


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


def failure_delay_seconds(consecutive_failures: int) -> float:
    """§5 件D — the incrementing delay for repeated failures from ONE source (NOT a ban). Every failed
    attempt already waits one step, so a single probe is never faster than a slow success path;
    capped so it can never wedge the process. Constant across failure KIND (unknown/expired/revoked/
    malformed all wait the same) — that is what keeps §5 un-enumerable."""
    n = consecutive_failures if consecutive_failures > 0 else 1
    delay = n * _FAIL_DELAY_STEP
    return delay if delay < _FAIL_DELAY_MAX else _FAIL_DELAY_MAX


def _stat_sig(path: Path) -> tuple[int, int] | None:
    """(mtime_ns, size) — the cheap change signature used for hot reload (§3.3). None if the file
    can't be stat'd (deleted/unreadable) ⇒ the caller keeps its last-good map."""
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


class TokenMap:
    """The token map with §3.3 hot reload: re-read the file when its (mtime, size) changes — at most
    ONE `stat` per `current()` call, NO cache layer. 🔴 On a re-read FAILURE (corrupt / JSON error)
    keep the LAST-GOOD map and log ERROR — never clear (that locks everyone out), never fall open
    (that lets everyone in). Loaded once at construction (fail-closed at startup)."""

    def __init__(self, source: str | Path) -> None:
        self._path = Path(source)
        self._map = load_token_map(self._path)  # fail-closed at startup
        self._sig = _stat_sig(self._path)

    def current(self) -> dict[str, TokenInfo]:
        sig = _stat_sig(self._path)
        if sig is not None and sig != self._sig:
            # take the new signature even on failure, so a persistently-bad file is not re-logged
            # (and re-read) on every request; a later fix changes the mtime and we retry.
            self._sig = sig
            try:
                self._map = load_token_map(self._path)
            except CasesAuthError as e:
                _log.error(
                    "token map %s failed to reload (%s) — keeping the LAST-GOOD map: NOT clearing "
                    "(would lock everyone out), NOT falling open (would let everyone in), §3.3",
                    self._path,
                    e,
                )
        return self._map
