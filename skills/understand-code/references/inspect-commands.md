# xgrep inspect Commands

## overview

High-level codebase summary.

```bash
xgrep inspect overview --json .
```

Returns:
- `languages`: [{name, files, symbols}] sorted by file count
- `packages`: [{path, public_symbols, total_symbols, functions, types}] sorted by symbol count
- `entry_points`: functions named "main" or "Main"
- `key_types`: classes/interfaces with the most methods
- `total_nodes`, `total_edges`, `exported_functions`

## symbol

Search for symbols by name.

```bash
xgrep inspect symbol "Query" --json
xgrep inspect symbol "Query" --kind function --json
```

Tries exact match first, then prefix, then substring (case-insensitive). Filter by kind: `function`, `method`, `class`, `interface`, `variable`, `field`, `constant`.

Returns: array of CodeNode objects with id, name, kind, location, visibility, type_annotation, doc_comment.

## search

Fast trigram-indexed text search (powered by Zoekt).

```bash
xgrep inspect search "pattern" --json
xgrep inspect search "func\s+\w+" --regex --json
xgrep inspect search "TODO" --lang go --json
xgrep inspect search "handler" --file-pattern "*.ts" --json
```

Flags:
- `--regex` / `-e`: treat query as regex
- `--case-sensitive` / `-s`: case-sensitive matching
- `--lang` / `-l`: filter by language
- `--file-pattern`: filter by file glob
- `--limit`: max file matches (default 100)
- `--context` / `-C`: context lines before/after

Returns: `{results: [{file, line, content, language}], total_files, total_matches, duration}`

## definition

Find the symbol at a specific source position.

```bash
xgrep inspect definition --file pkg/core/eval.go --line 42 --json
xgrep inspect definition --file pkg/core/eval.go --line 42 --col 15 --json
```

Returns the innermost symbol at that position with full metadata.

## references

Find all usages of a symbol.

```bash
xgrep inspect references "EvalRule" --json
```

Returns per matching symbol: callers (call edges in), callees (call edges out), and reference edges.

## implementations

Find types implementing an interface.

```bash
xgrep inspect implementations "LangExtractor" --json
```

Returns array of implementing types with locations.

## outline

List all symbols in a file, sorted by line number.

```bash
xgrep inspect outline pkg/graph/model.go --json
```

Returns array of CodeNode objects: functions, methods, classes, variables, fields, constants — with visibility and type annotations. Nested symbols are indented via parentID.

## impact

Assess blast radius of changing a symbol.

```bash
xgrep inspect impact "EvalRule" --json
```

Returns:
- `symbol`: the target symbol
- `direct_callers`: functions that directly call this
- `direct_callees`: functions this directly calls
- `transitive_callers`: all functions that transitively depend on this
- `affected_files`: files containing transitive callers
- `risk_score`: 0.0-1.0
- `risk_level`: "low", "medium", "high"

## deps

Show call dependencies (upstream and downstream).

```bash
xgrep inspect deps "EvalRule" --json
xgrep inspect deps "EvalRule" --depth 3 --json
```

Returns:
- `symbol`: the target symbol
- `callees`: direct callees (distance=1)
- `downstream`: transitive callees (distance=2+)
- `callers`: direct callers (distance=1)
- `upstream`: transitive callers (distance=2+)

Each entry includes the node and its distance from the target.
