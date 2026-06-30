# Task 1: Core BT Nodes + Decorators + Tests

Add Selector, Parallel (sequential), Condition nodes. Add Decorator base + Retry, Timeout (daemon thread, no leak), Invert. Update engine/__init__.py exports. Create test files.

## Key constraint
- Decorator must implement tick() that delegates to child (Node.tick is abstract)
- Timeout: use daemon thread + threading.Event, NOT threading.Timer (leaks on hang)

## Files to modify
- websec_test/engine/nodes.py: add Selector, Parallel classes (after existing Sequence)
- websec_test/engine/leaves.py: add Condition class
- CREATE websec_test/engine/decorators.py: Decorator, Retry, Timeout, Invert
- websec_test/engine/__init__.py: add new exports
- CREATE tests/test_bt_nodes.py: test Selector, Parallel, Condition
- CREATE tests/test_bt_decorators.py: test Retry, Timeout, Invert

## Existing interfaces to consume
- Node (ABC), NodeStatus(Enum), Blackboard from websec_test.engine.nodes
- Action (ABC) from websec_test.engine.leaves
- Sequence from websec_test.engine.nodes

## New interfaces to produce
- Selector(name, children) : Node — OR node, short-circuits on SUCCESS
- Parallel(name, children, min_success=1) : Node — runs all, SUCCESS if >= min_success
- Condition(name, fn) : Action — fn(blackboard) -> bool
- Decorator(name, child) : Node — base, tick delegates to child
- Retry(name, child, max_retries=1, delay=0) : Decorator — retries on FAILURE
- Timeout(name, child, timeout=30) : Decorator — daemon thread + threading.Event
- Invert(name, child) : Decorator — flips SUCCESS/FAILURE
