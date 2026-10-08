---
name: understand-code
description: Understand an unfamiliar codebase before you change it — map structure, find definitions/callers, trace call chains, and assess a change's blast radius with xgrep's AST code graph.
argument-hint: "<question about the code, or specific investigation task>"
allowed-tools: Bash Read Glob Grep
---

# Understand code with xgrep inspect

**Task:** $ARGUMENTS

Use `xgrep inspect` commands to answer the question or complete the investigation. All commands support `--json` for structured output. The graph and search index are built automatically on first use and cached incrementally.

## Workflow

Choose the appropriate phase based on the task:

### Phase 1: Orient (if unfamiliar with the codebase)

```bash
xgrep inspect overview --json .
```

Parse the JSON to understand: languages, packages (sorted by symbol count), entry points, key types (sorted by method count). This replaces 15-20 manual ls/grep/read calls.

### Phase 2: Locate (find relevant code)

```bash
# Structured symbol search — try this first
xgrep inspect symbol "TargetName" --json
xgrep inspect symbol "TargetName" --kind function --json

# Fast text search — when symbol search doesn't match
xgrep inspect search "pattern" --json
xgrep inspect search "pattern" --lang go --json
xgrep inspect search "func.*Handler" --regex --json
```

### Phase 3: Navigate (understand relationships)

```bash
# Go to definition at a specific position
xgrep inspect definition --file path/to/file.go --line 42 --json

# Find all callers and callees
xgrep inspect references "SymbolName" --json

# Find interface implementations
xgrep inspect implementations "InterfaceName" --json

# List all symbols in a file (outline view)
xgrep inspect outline path/to/file.go --json
```

### Phase 4: Assess (before making changes)

```bash
# What breaks if I change this? (blast radius)
xgrep inspect impact "FunctionName" --json

# What does this function call / what calls it? (transitively)
xgrep inspect deps "FunctionName" --json
xgrep inspect deps "FunctionName" --depth 3 --json
```

### Phase 5: Deep dive (call chain analysis)

```bash
# N-hop neighborhood with inlined source code
xgrep graph context "FunctionName" --depth 2

# Find call paths between two functions
xgrep graph paths "EntryPoint" "DangerousSink"
```

## Guidelines

- Always use `--json` when you need to process results programmatically
- Use `inspect symbol` before `inspect search` — structured results are more precise
- Use `inspect impact` before modifying any exported function — check the blast radius
- Use `inspect deps` to understand what a function depends on before refactoring
- Use `inspect outline` to understand a file before reading it line by line
- The graph and search index are cached in `.xgrep/` — incremental rebuilds are fast (~0.3s)
