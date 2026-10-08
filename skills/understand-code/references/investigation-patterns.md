# Investigation Patterns

Common patterns for using xgrep inspect to answer code questions.

## "What does this codebase do?"

```bash
xgrep inspect overview --json .
```

Read the languages, packages, entry points, and key types. Follow up with `outline` on the most important packages.

## "Where is X defined?"

```bash
# By symbol name
xgrep inspect symbol "ClassName" --json

# By text pattern (if symbol search misses)
xgrep inspect search "class ClassName" --json

# At a specific position (e.g., from an error message)
xgrep inspect definition --file path.go --line 42 --json
```

## "Who calls this function?"

```bash
# Direct + transitive callers
xgrep inspect references "FunctionName" --json

# Full upstream dependency chain with distances
xgrep inspect deps "FunctionName" --json
```

## "What does this function call?"

```bash
# Direct + transitive callees
xgrep inspect deps "FunctionName" --json

# With limited depth (avoid explosion)
xgrep inspect deps "FunctionName" --depth 2 --json
```

## "What implements this interface?"

```bash
xgrep inspect implementations "InterfaceName" --json
```

## "What's in this file?"

```bash
xgrep inspect outline path/to/file.go --json
```

Use before reading the full file — know what's there without scrolling.

## "Is it safe to change this function?"

```bash
# Check blast radius
xgrep inspect impact "FunctionName" --json
```

Look at:
- `risk_score` / `risk_level`: overall risk
- `direct_callers`: who calls this directly
- `transitive_callers`: full upstream chain
- `affected_files`: how many files would need review

## "How does data flow from A to B?"

```bash
# Find call paths
xgrep graph paths "SourceFunction" "SinkFunction"

# Get context with source code
xgrep graph context "FunctionName" --depth 3
```

## "Find all TODOs / FIXMEs / security annotations"

```bash
xgrep inspect search "TODO|FIXME|HACK|XXX" --regex --json
xgrep inspect search "nosec|nolint" --regex --json
```

## "What functions handle HTTP requests?"

```bash
xgrep inspect search "func.*Handler" --regex --lang go --json
xgrep inspect symbol "Handler" --kind function --json
```

## "Show me the public API of a package"

```bash
# All symbols in a directory
xgrep inspect overview pkg/graph --json

# Detailed outline of a specific file
xgrep inspect outline pkg/graph/graph.go --json
```

Filter the JSON for `visibility: "exported"` to see only the public API.
