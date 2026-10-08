# understand-code

A skill for understanding an unfamiliar codebase before you change it, using xgrep's AST-powered code intelligence.

## What it does

Provides structured code navigation that replaces dozens of grep/read calls with single commands:

- **Orient**: Codebase overview (languages, packages, entry points, key types)
- **Locate**: Symbol search + Zoekt-powered text search
- **Navigate**: Go-to-definition, find references, find implementations, file outline
- **Assess**: Impact analysis (blast radius), call dependency graph

## Usage

```
/understand-code what does this codebase do?
/understand-code where is EvalRule defined and who calls it?
/understand-code is it safe to rename CodeGraph.Build?
/understand-code show me the public API of pkg/graph
```

## Requirements

- `xgrep` CLI installed and on PATH
- Works with any codebase xgrep supports (30+ languages via tree-sitter)
