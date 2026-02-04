# edgecheck

**Python Edge Case Detector** — find missing error handling and boundary checks that AI coding agents commonly miss.

Zero dependencies. Single file. Python 3.9+.

> *"AI excels at drafting features but falters on logic, security, and edge cases — making errors 75% more common in logic alone."*
> — [Addy Osmani, Code Review in the Age of AI](https://addyo.substack.com/p/code-review-in-the-age-of-ai) (2026)

## Why?

AI-generated Python code consistently misses edge cases. [45% contains security flaws](https://www.veracode.com/blog/ai-generated-code-security-risks/), [logic errors appear at 1.75× the rate](https://dl.acm.org/doi/10.1145/3716848) of human-written code, and [XSS vulnerabilities at 2.74×](https://dl.acm.org/doi/10.1145/3716848). The "happy path" works, but the unhappy paths crash.

edgecheck catches the patterns that slip through:
- `Optional` parameters used without `None` checks
- Division by variables without zero guards
- `dict[key]` access without `.get()` or `try/except`
- HTTP requests without timeouts
- `json.loads()` without error handling
- `str.split()[n]` without length verification
- And 14 more rules

## Quick Start

```bash
# Scan a single file
python3 edgecheck.py app.py

# Scan a directory
python3 edgecheck.py src/

# CI mode (exit 1 on error/warning findings)
python3 edgecheck.py src/ --check

# JSON output
python3 edgecheck.py src/ --json

# Verbose with fix suggestions
python3 edgecheck.py src/ -v
```

## Rules

| ID | Rule | Severity | What it catches |
|----|------|----------|-----------------|
| EC01 | Unchecked Optional Parameter | warning | `Optional[T]` param used without `if x is None` |
| EC02 | Division Without Zero Guard | error | `a / b` where `b` is a variable, no zero check |
| EC03 | Unguarded Dict Key Access | warning | `d[key]` without `.get()`, `in`, or `try/except` |
| EC04 | next() Without Default | warning | `next(iter)` — raises `StopIteration` if empty |
| EC05 | Missing Network Timeout | error | `requests.get(url)` without `timeout=` |
| EC06 | Unchecked Subprocess | warning | `subprocess.run()` without `check=True` |
| EC07 | Bare int/float Conversion | warning | `int(x)` without `try/except ValueError` |
| EC08 | if/elif Without else | info | 3+ branch chain without default handler |
| EC09 | Unguarded List Index | warning | `lst[idx]` by variable without bounds check |
| EC10 | Unguarded Unpacking | warning | `a, b, c = expr` without length verification |
| EC11 | Unchecked .pop() | info | `.pop()` on possibly empty collection |
| EC12 | File Open Without Guard | info | `open(path)` for reading without existence/try |
| EC13 | Regex With Variable Pattern | warning | `re.compile(user_input)` without `try/except` |
| EC14 | Inconsistent Returns | warning | Function mixes value returns with bare returns |
| EC15 | Long Attribute Chain | warning | `a.b.c.d` — intermediate values may be `None` |
| EC16 | Subscript of Return Value | warning | `func()[0]` — return may be None/empty |
| EC17 | str.split() Index | error | `s.split(x)[n]` — may fail on unexpected input |
| EC19 | Unguarded json.loads | warning | `json.loads()` without `try/except` |
| EC20 | Direct os.environ Access | warning | `os.environ['KEY']` — use `.get()` instead |

## Example

```bash
$ python3 edgecheck.py examples/bad_edges.py -v

examples/bad_edges.py  F (0/100)
  error    22:11  [EC02] Division by variable 'count' without zero check
                  ... / count
  error    45:15  [EC05] requests.get() without timeout — may hang indefinitely
                  requests.get(...)  # add timeout=N
  error   114:11  [EC17] .split()[1] — may fail on empty/unexpected string
                  s.split(sep)[n]  # check len(parts) first
  warning  12:10  [EC01] Parameter 'name' is Optional but never checked for None
                  def greet(..., name: Optional[...], ...)
  warning  31:11  [EC03] Dict access users[username] may raise KeyError
                  users[username]
  warning  63:11  [EC07] int(age_str) without try/except — may raise ValueError
                  int(age_str)  # wrap in try/except ValueError
  ...

  Files: 1  Findings: 27  error: 6  warning: 21
  Average: F (0/100)
```

## Usage

```
edgecheck [path] [-s SEVERITY] [--check] [--json] [-v] [--ignore RULES]

  path                File, directory, or '-' for stdin
  -s, --severity      Minimum: error, warning, info
  --check             CI mode: exit 1 on error/warning findings
  --json              JSON output
  -v, --verbose       Show fix context for each finding
  --ignore            Comma-separated rule IDs to skip (e.g., EC08,EC11)
  --rules             List all rules
```

## CI Integration

```yaml
# GitHub Actions
- name: Edge Case Check
  run: python3 edgecheck.py src/ --check --severity warning
```

## How It Works

Pure AST-based analysis using Python's built-in `ast` module:
- Parses type annotations to detect `Optional` parameters
- Tracks try/except scope to avoid false positives on guarded code
- Detects zero-checks in preceding `if` statements
- Skips constant values (only flags variable-based risks)
- Identifies import aliases for network libraries

No execution. No network. No dependencies.

## License

MIT
