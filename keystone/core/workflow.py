"""Small state-machine helper for record lifecycles (policies, incidents, audits...)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .rbac import require


class InvalidTransition(ValueError):
    pass


@dataclass(frozen=True)
class Workflow:
    name: str
    # from_state -> {to_state: permission required}
    transitions: dict[str, dict[str, str]]
    initial: str
    terminal: frozenset[str] = field(default_factory=frozenset)

    @property
    def states(self) -> list[str]:
        seen: list[str] = []
        for src, dests in self.transitions.items():
            for s in (src, *dests):
                if s not in seen:
                    seen.append(s)
        return seen

    def allowed(self, current: str) -> list[str]:
        return list(self.transitions.get(current, {}))

    def check(self, current: str, target: str, actor) -> None:
        dests = self.transitions.get(current, {})
        if target not in dests:
            raise InvalidTransition(f"{self.name}: cannot move from {current!r} to {target!r}. Allowed: {', '.join(dests) or 'none'}.")
        require(actor, dests[target])

    def apply(self, obj, target: str, actor, attr: str = "status") -> None:
        self.check(getattr(obj, attr), target, actor)
        setattr(obj, attr, target)
