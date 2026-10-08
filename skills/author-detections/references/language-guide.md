# Language Guide

## Language Capabilities

### Tree-sitter Languages (Full AST Matching)

These languages support all xgrep features: AST patterns, metavariables, taint analysis, type inference, and autofix.

| Language | Extensions | FQ Names | Type Inference | Special Features |
|----------|-----------|----------|----------------|------------------|
| Python | `.py`, `.pyi` | Yes | Yes | Decorator matching, f-string interpolation, fq_naming |
| Go | `.go` | Yes | Yes | Func body expansion, error return patterns |
| Java | `.java` | Yes | Yes | Annotation matching, generic types |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | Yes | Yes | Template literal interpolation |
| TypeScript | `.ts` | Yes | Yes | Type annotations, generics |
| TSX | `.tsx` | - | Yes | JSX element matching |
| Ruby | `.rb` | - | Partial | Block syntax, symbol matching |
| PHP | `.php` | - | - | Namespace resolution |
| C | `.c`, `.h` | - | - | Preprocessor-aware |
| C++ | `.cc`, `.cpp`, `.cxx`, `.hpp` | - | - | Template matching |
| C# | `.cs` | - | - | Attribute matching |
| Rust | `.rs` | - | - | Lifetime/ownership patterns |
| Kotlin | `.kt`, `.kts` | - | - | Null-safety operators |
| Scala | `.scala`, `.sc` | - | - | Case class patterns |
| Bash | `.sh`, `.bash`, `.zsh` | - | - | Command substitution |
| Lua | `.lua` | - | - | - |
| Julia | `.jl` | - | - | - |
| OCaml | `.ml`, `.mli` | - | - | Pattern matching syntax |
| HTML | `.html`, `.htm`, `.vue` | - | - | Tag-aware matching |
| JSON | `.json` | - | - | Key-value patterns |
| YAML | `.yaml`, `.yml` | - | - | Key-value patterns |
| XML | `.xml` | - | - | Tag-aware matching |
| HCL | `.tf`, `.hcl` | - | - | Block patterns |

### Regex-Only Languages

These languages support `pattern-regex`, basic `pattern`, and all regex-tier matching. AST-specific features (structural matching, typed metavariables) are unavailable.

Dockerfile, Swift, R, Dart, Solidity, Clojure, Elixir, Erlang, Scheme, Lisp, Groovy, JSP

### Generic Mode

`languages: [generic]` uses regex matching only. Avoid when targeting a specific language.

## Porting Idiom Maps

### SQL Injection

| Language | Dangerous Pattern | Safe Alternative |
|----------|------------------|-----------------|
| Python | `cursor.execute("SELECT " + user)` | `cursor.execute("SELECT ?", (user,))` |
| Go | `db.Query("SELECT " + user)` | `db.Query("SELECT ?", user)` |
| Java | `stmt.executeQuery("SELECT " + user)` | `pstmt = conn.prepareStatement("SELECT ?")` |
| JavaScript | `pool.query("SELECT " + user)` | `pool.query("SELECT $1", [user])` |
| Ruby | `conn.exec("SELECT " + user)` | `conn.exec_params("SELECT $1", [user])` |
| PHP | `$pdo->query("SELECT " . $user)` | `$pdo->prepare("SELECT ?")->execute([$user])` |
| C# | `cmd.CommandText = "SELECT " + user` | `cmd.Parameters.AddWithValue("@p", user)` |

### Command Injection

| Language | Dangerous Pattern | Safe Alternative |
|----------|------------------|-----------------|
| Python | `os.system(cmd)`, `subprocess.run(cmd, shell=True)` | `subprocess.run([prog, arg])` |
| Go | `exec.Command("sh", "-c", cmd).Run()` | `exec.Command(prog, arg).Run()` |
| Java | `Runtime.getRuntime().exec(cmd)` | `ProcessBuilder(list).start()` |
| JavaScript | `child_process.exec(cmd)` | `child_process.execFile(prog, [arg])` |
| Ruby | `` `#{cmd}` ``, `system(cmd)` | `system(prog, arg)` |
| PHP | `exec($cmd)`, `system($cmd)` | `escapeshellarg($arg)` |

### XSS / HTML Injection

| Language | Dangerous Pattern | Safe Alternative |
|----------|------------------|-----------------|
| Python | `render_template_string(user)` | `render_template("t.html", data=user)` |
| Go | `template.HTML(user)` | `template.Execute(w, data)` (auto-escaped) |
| Java | `response.getWriter().println(user)` | Use OWASP encoder or template engine |
| JavaScript | `res.send(user)`, `innerHTML = user` | `textContent = user`, template with escaping |
| Ruby | `raw(user)` in ERB | `<%= user %>` (auto-escaped in Rails) |
| PHP | `echo $user` | `echo htmlspecialchars($user)` |

### Path Traversal

| Language | Dangerous Pattern | Safe Alternative |
|----------|------------------|-----------------|
| Python | `open(user_path)` | `os.path.realpath()` + prefix check |
| Go | `os.Open(userPath)` | `filepath.Clean()` + prefix check |
| Java | `new FileInputStream(userPath)` | `Paths.get(base).resolve(user).normalize()` + check |
| JavaScript | `fs.readFile(userPath)` | `path.resolve()` + prefix check |
| Ruby | `File.read(user_path)` | `File.expand_path` + prefix check |

### Hardcoded Secrets

Pattern is similar across languages -- look for string assignments to variables named `password`, `secret`, `token`, `api_key`, etc. with high-entropy values.

```yaml
# Works across many languages
patterns:
  - pattern: $VAR = "..."
  - metavariable-regex:
      metavariable: $VAR
      regex: "(?i)(password|passwd|secret|token|api_key)"
```

## Language-Specific Notes

### Python
- **Decorators**: Match with `@decorator` patterns inside `pattern-inside`
- **f-strings**: xgrep matches interpolated expressions inside f-strings
- **FQ names**: `os.system` matches even if imported as `from os import system`

### Go
- **Error returns**: Go functions often return `(result, error)`. Consider whether error-checking patterns matter for your rule.
- **Goroutines**: `go func()` launches concurrent execution; taint may flow through goroutines
- **Struct literals**: Match with `Type{field: $VAL}`

### Java
- **Annotations**: Match with `@Annotation` patterns
- **Generics**: `List<String>` can be matched; use `$TYPE` for generic type params
- **Checked exceptions**: Try-catch blocks may wrap dangerous calls

### JavaScript/TypeScript
- **Template literals**: `` `SELECT ${user}` `` is matched by xgrep's string interpolation support
- **Async/await**: `await dangerous(input)` -- the `await` wrapper doesn't affect pattern matching
- **TSX**: Use `tsx` language, not `typescript`, for `.tsx` files

### Ruby
- **Blocks**: `do...end` and `{...}` blocks are matched
- **Symbols**: `:symbol` syntax is language-specific
- **Rails conventions**: `params[:key]` is a common source in Rails apps
