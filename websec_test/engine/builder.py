"""CheckSpec dataclass and CheckTreeBuilder."""
from dataclasses import dataclass, field
from typing import Callable

from ..results.models import Severity
from .nodes import NodeStatus, Sequence, Parallel
from .adapters import CheckAdapter, DiscoverAction


@dataclass
class CheckSpec:
    """Describes a single security check that can be wrapped as a CheckAdapter."""
    name: str
    fn: Callable
    severity: Severity
    depends_on: list[str] | None = None
    module_name: str = ""


class CheckTreeBuilder:
    """Builds check-level Behavior Trees from a list of CheckSpecs."""

    @staticmethod
    def build_module(module_name: str, discover_fn, checks: list[CheckSpec]) -> Sequence:
        """Build a check-level tree: DiscoverAction → grouped CheckAdapters."""
        discover_node = DiscoverAction(f"{module_name}_discover", discover_fn)

        # Build CheckAdapter nodes
        check_nodes = {
            spec.name: CheckAdapter(spec.name, spec.fn, module_name)
            for spec in checks
        }

        # Group by dependency
        groups = CheckTreeBuilder._group_by_dependency(checks, check_nodes)

        if len(groups) == 1:
            check_group = Parallel(
                f"{module_name}_checks",
                children=groups[0],
                min_success=0,
            )
        else:
            check_group = Sequence(f"{module_name}_checks", children=[
                Parallel(
                    f"{module_name}_group_{i}",
                    children=group,
                    min_success=0,
                )
                for i, group in enumerate(groups)
            ])

        return Sequence(module_name, children=[discover_node, check_group])

    @staticmethod
    def _group_by_dependency(specs, check_nodes):
        """Topological sort: group independent checks together.

        Returns list of lists: [group0, group1, ...]
        group0 = no deps
        group1 = depends only on group0
        etc.

        Within each group, checks are ordered by their original
        position in ``specs`` for deterministic execution order.
        """
        # Track original spec order for deterministic sorting
        spec_order = {s.name: i for i, s in enumerate(specs)}
        spec_map = {s.name: s for s in specs}
        remaining = set(spec_map.keys())
        groups = []
        while remaining:
            # Pick specs whose deps are all already grouped
            current_group = []
            for name in list(remaining):
                spec = spec_map[name]
                deps = spec.depends_on or []
                # A check is ready if all its deps are NOT in remaining anymore
                if not any(d in remaining for d in deps):
                    current_group.append(name)
            if not current_group:
                # Break circular or unresolvable deps by putting remaining all in one group
                current_group = list(remaining)
            # Sort by original spec order for deterministic execution
            current_group.sort(key=lambda n: spec_order.get(n, 0))
            group_nodes = [check_nodes[name] for name in current_group]
            groups.append(group_nodes)
            for name in current_group:
                remaining.discard(name)
        return groups
