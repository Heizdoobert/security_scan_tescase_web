---
name: ponytail-audit
description: >
  Whole-repo over-engineering audit. Scan for bloated abstractions,
  unnecessary dependencies, duplicate code, premature generalization, and
  dead scaffolding. Return a ranked list of what to delete or collapse first.
---

# Ponytail Audit

Audit the repo for code that should not exist.

## Find

- Dead code
- Duplicate helpers
- One-off abstractions
- Custom wrappers around standard features
- Dependencies used for tiny tasks
- Config or framework layers with no real payoff

## Prioritize

Rank by:

1. Easy delete with zero behavior change
2. Large simplification with small test impact
3. Unclear value, but likely overbuilt

## Output

For each item:

`path: what is overbuilt. what to do instead.`

Keep it short. No essays.
