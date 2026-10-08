# xgrep Code Graph Commands

## Building the Graph

```bash
xgrep graph build <directory>
```

The graph is auto-cached to `.xgrep/graph.json`. It rebuilds automatically when source files change. You can also skip this step -- queries auto-build on first use.

## Finding Callers

Find all functions that call a given function:

```bash
xgrep graph callers <function-name>
xgrep graph callers --json <function-name>
```

**Use case**: Trace backwards from a dangerous sink to find all entry points.

## Finding Callees

Find all functions called by a given function:

```bash
xgrep graph callees <function-name>
xgrep graph callees --json <function-name>
```

**Use case**: Understand what a function does and what it depends on.

## Finding Call Paths

Find all call paths between two functions:

```bash
xgrep graph paths <source-func> <dest-func>
xgrep graph paths --json <source-func> <dest-func>
```

**Use case**: Trace dataflow from an entry point to a dangerous sink. Check every function along the path for sanitization.

## Function Context

Show a function with its N-hop neighborhood and inlined source code:

```bash
xgrep graph context <function-name> --depth 2
```

Produces a markdown document with:
- The focus function's full source code
- All callers and callees within N hops
- Their source code inlined
- Call relationships listed

**This is the most useful single command** -- topology and code in one shot.

Use `--depth 1` for focused context, `--depth 2` for broader investigation.

## Reachable Functions

Find all functions reachable from a starting function:

```bash
xgrep graph reachable <function-name>
xgrep graph reachable --json <function-name>
```

**Use case**: Map the blast radius of a data source -- everywhere sensitive data can flow.

## Function Name Resolution

- **Partial matches**: `EvalRule` matches `EvalRule`, `EvalRuleWithContext`, etc.
- **Exact matches**: Use the full node ID: `pkg/core/eval.go::EvalRule`
- **Cross-file references**: Edges starting with `?::` are unresolved

## Edge Confidence Levels

| Confidence | Meaning |
|-----------|---------|
| `certain` | Direct function call |
| `inferred` | Method call on a known type |
| `uncertain` | Dynamic dispatch, interface call |

## JSON Output Format

### Callers/Callees

```json
[
  {
    "source": "handleRequest",
    "target": "pkg/db/query.go::executeQuery",
    "confidence": "certain",
    "location": {"file": "app/handler.go", "start_line": 15}
  }
]
```

### Paths

```json
[
  ["app/handler.go::handleRequest", "app/db.go::buildQuery", "app/db.go::execute"]
]
```
