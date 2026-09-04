"""Target model: describes what to scan and how to mutate a single parameter."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Target:
    """A single HTTP endpoint with injectable parameters.

    params are the baseline values. A detector picks one parameter to mutate
    and calls ``mutate`` to build the full parameter set with an injected value.
    """

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def testable_params(self) -> list[str]:
        return list(self.params.keys())

    def mutate(self, param: str, value: str) -> dict[str, str]:
        """Return a copy of params with ``param`` replaced by ``value``."""
        merged = dict(self.params)
        merged[param] = value
        return merged

    def is_get(self) -> bool:
        return self.method.upper() == "GET"
