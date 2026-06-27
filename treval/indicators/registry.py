"""IndicatorRegistry — id → Indicator, with dimension lookup (EV-4 §3.2).

No I/O, no global state. `ids()` is the bridge to EV-6: pass it to
`registry.validate_against(reg, indicator_ids=sdk.ids())` so every control
objective's `indicator_id` resolves to a registered indicator.
"""

from __future__ import annotations

from treval.protocols import Indicator


class IndicatorRegistry:
    def __init__(self) -> None:
        # dict preserves insertion (registration) order — the stable order for
        # all() / by_dimension(), so output never depends on hashing.
        self._by_id: dict[str, Indicator] = {}

    def register(self, indicator: Indicator) -> None:
        iid = indicator.indicator_id
        if iid in self._by_id:
            raise ValueError(f"duplicate indicator_id {iid!r}")
        self._by_id[iid] = indicator

    def get(self, indicator_id: str) -> Indicator:
        return self._by_id[indicator_id]  # KeyError if absent

    def by_dimension(self, dimension: str) -> tuple[Indicator, ...]:
        return tuple(ind for ind in self._by_id.values() if ind.dimension == dimension)

    def all(self) -> tuple[Indicator, ...]:
        return tuple(self._by_id.values())

    def ids(self) -> frozenset[str]:
        return frozenset(self._by_id)
