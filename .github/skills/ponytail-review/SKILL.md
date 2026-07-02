---
name: ponytail-review
description: >
  Review code for over-engineering. Use when a change feels bloated,
  abstracted too early, or contains unnecessary dependencies, layers,
  factories, helpers, or scaffolding. Output should be terse, actionable,
  and point to the simplest possible fix.
---

# Ponytail Review

Review code like a lazy senior developer. Find slop. Kill slop.

## What to look for

- Unneeded abstraction with one implementation
- Custom code replacing stdlib or native feature
- New dependency for a few lines
- Premature config, hooks, factories, managers, services
- Duplicate logic that should be one shared helper
- Scaffolding for future work that is not real yet

## Output format

Use terse findings. Prefer one line per issue.

Pattern:
`L42: yagni: factory, one product. Inline.`

Then, if needed, one short fix line.

## Rules

- Do not rewrite the whole file.
- Do not suggest more structure than needed.
- If code can be deleted, prefer delete.
- If stdlib or existing code already covers it, say so.
- If risk is low and change is only style, skip it.
