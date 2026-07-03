import inspect
from .nodes import Sequence, Selector, Parallel
from .decorators import Retry
from .adapters import CheckAdapter


class CheckTreeBuilder:
    @staticmethod
    def build(module_instance, module_name, endpoints):
        checks = inspect.getmembers(module_instance, predicate=inspect.ismethod)
        check_fns = {name: fn for name, fn in checks if name.startswith("check_")}
        selector_groups = getattr(module_instance, "SELECTOR_GROUPS", {})
        endpoint_sequences = []
        for ep in endpoints:
            ep_path = getattr(ep, "url", None) or getattr(ep, "path", None) or str(ep)
            ep_children = []
            grouped_checks = set()
            if selector_groups:
                for group_name, check_names in selector_groups.items():
                    group_children = []
                    for cn in check_names:
                        if cn in check_fns:
                            adapter = CheckAdapter(f"{module_name}:{cn}", check_fns[cn], ep)
                            group_children.append(Retry(f"{module_name}:{cn}:retry", adapter, max_retries=1))
                            grouped_checks.add(cn)
                    if group_children:
                        ep_children.append(Selector(f"{module_name}:{group_name}", children=group_children))
            for cn, cf in check_fns.items():
                if cn not in grouped_checks:
                    adapter = CheckAdapter(f"{module_name}:{cn}", cf, ep)
                    ep_children.append(Retry(f"{module_name}:{cn}:retry", adapter, max_retries=1))
            endpoint_sequences.append(Parallel(ep_path, children=ep_children))
        return Parallel(module_name, children=endpoint_sequences)
