# Task 2: CheckAdapter + CheckTreeBuilder + Tests

Add CheckAdapter leaf node and CheckTreeBuilder that builds check-level trees from module classes.

## Files to modify
- websec_test/engine/adapters.py: add CheckAdapter class (keep existing ModuleAdapter)
- CREATE websec_test/engine/builder.py: CheckTreeBuilder
- websec_test/engine/__init__.py: export CheckAdapter, CheckTreeBuilder
- tests/test_bt_adapters.py: add CheckAdapter tests (keep existing ModuleAdapter tests)
- CREATE tests/test_bt_builder.py: CheckTreeBuilder tests

## New interfaces to produce
- CheckAdapter(name, check_fn, endpoint) extends Action
  - do_tick: check_fn(client, target, endpoint) -> TestResult
  - SUCCESS if TestStatus in (PASS, INFO), FAILURE otherwise
  - adds result to blackboard

- CheckTreeBuilder
  - build(module_instance, module_name, endpoints) -> Sequence
  - Scans module for check_* methods using inspect.getmembers(module_instance, inspect.ismethod)
  - Supports SELECTOR_GROUPS dict on module (optional)
  - Wraps each CheckAdapter in Retry(max_retries=1)
  - Returns Sequence(module_name, children=[Sequence(endpoint_path, endpoint_children)])

## Existing interfaces to consume
- Action from websec_test.engine.leaves
- Sequence, Selector from websec_test.engine.nodes
- Retry from websec_test.engine.decorators
- TestResult, TestStatus from websec_test.results.models
