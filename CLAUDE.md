# CLAUDE.md

Development guidelines for Swiss Knife Web Security Scanner - a Go-based CLI security tool.

## Project Context

This is a web security scanner that uses context-aware and behavior-based detection. It integrates external tools (SQLMap, Nuclei, ffuf) and follows OWASP frameworks (WSTG, Web Top 10, API Top 10, ASVS).

## Quick Reference

```bash
# Build and test
make build              # Build binary
make test               # Run tests
make lint               # Run linter
make check              # All checks before commit

# Run scanner with binary cli
skws scan --target https://example.com 
```

## Test-Driven Development (TDD)

This project strictly follows TDD. No production code without tests first.

### TDD Workflow (Red-Green-Refactor)

1. **RED** - Write a failing test that defines expected behavior
2. **GREEN** - Write minimal code to make the test pass
3. **REFACTOR** - Clean up code while keeping tests green
4. **REPEAT** - Continue for next requirement

### TDD Rules

- Never write production code without a failing test
- Write only enough test to fail (compilation failure counts)
- Write only enough code to pass the failing test
- Refactor only when all tests are green
- Each test should test one thing only

### Testing Pyramid

| Level | Coverage | Location | Purpose |
|-------|----------|----------|---------|
| Unit | 99%+ | `*_test.go` beside code | Test individual functions |
| Integration | Key paths | `tests/integration/` | Test component interactions |
| E2E | Critical flows | `tests/e2e/` | Test full scan workflows |

### Test Requirements

- **Unit tests**: Table-driven, mock external dependencies
- **Integration tests**: Test tool wrappers with real binaries
- **E2E tests**: Test complete scan against test targets
- **Security-critical** (`internal/detection/`): 100% coverage required
- **All tests**: Must pass with race detector (`-race` flag)

### Test Commands

```bash
make test               # Run all unit tests
make test-cover         # Run with coverage report
make test-race          # Run with race detector
make test-integration   # Run integration tests
make test-e2e           # Run e2e tests
```

---

## Code Quality Control

### Quality Gates (CI/CD)

All PRs must pass these gates before merge:

| Gate | Tool | Threshold |
|------|------|-----------|
| Format | `go fmt`, `gofumpt` | No changes needed |
| Lint | `golangci-lint` | Zero warnings |
| Vet | `go vet` | Zero issues |
| Security | `gosec` | Zero high/critical |
| Tests | `go test` | All pass |
| Coverage | `go test -cover` | >= 80% |
| Race | `go test -race` | No races detected |

### Code Review Checklist

Before approving any PR, verify:

- [ ] Tests written first (TDD followed)
- [ ] All tests pass including race detector
- [ ] Coverage meets threshold
- [ ] No linter warnings
- [ ] Error handling is explicit
- [ ] Context passed for cancellable operations
- [ ] No hardcoded credentials or secrets
- [ ] Doc comments on all exports

### Complexity Limits

| Metric | Limit | Tool |
|--------|-------|------|
| Function length | 50 lines | `golangci-lint` |
| Cyclomatic complexity | 15 | `gocyclo` |
| Cognitive complexity | 20 | `gocognit` |
| File length | 500 lines | Manual review |
| Nesting depth | 4 levels | `nestif` |

### Error Handling

- Always handle errors explicitly - never use `_` to ignore
- Wrap errors with context: `fmt.Errorf("context: %w", err)`
- Return errors, don't panic
- Create custom error types for domain-specific errors

### Documentation

- All exported functions, types, constants must have doc comments
- Doc comments start with the element name
- Package-level documentation in `doc.go`

---

## Formatting & Linting

- Run `go fmt` and `golangci-lint` before every commit
- All linter warnings must be resolved
- Use `gofumpt` for stricter formatting (optional)
- Configuration in `.golangci.yml`

## Style Guidelines

### Naming Conventions
| Element | Style | Example |
|---------|-------|---------|
| Package | lowercase, single word | `detection`, `scanner` |
| Interface | PascalCase, `-er` suffix | `Scanner`, `Detector` |
| Struct | PascalCase | `Finding`, `ScanConfig` |
| Exported func | PascalCase | `Scan()`, `Execute()` |
| Unexported func | camelCase | `parseOutput()`, `validate()` |
| Variable | camelCase | `targetURL`, `maxRetries` |
| Constant | PascalCase or UPPER_SNAKE | `DefaultTimeout`, `MAX_RETRIES` |
| File | snake_case | `sql_injection.go` |

### Import Order
1. Standard library
2. External packages
3. Internal packages

(Separate groups with blank lines)

### Code Patterns
- Use early returns to reduce nesting
- Prefer composition over inheritance
- Keep functions focused on single responsibility
- Use `context.Context` as first parameter for cancellable operations

## Concurrency Rules

- Always pass `context.Context` for HTTP requests, external tools, long operations
- Use `sync.Mutex` for shared state
- Use channels for goroutine communication
- Always handle goroutine cleanup with `sync.WaitGroup`
- Never leak goroutines

## Git Conventions

### Commit Format
```
<type>(<scope>): <description>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`

Examples:
- `feat(detection): add time-based SQL injection`
- `fix(tools): handle SQLMap timeout`
- `test(wstg): add WSTG-INPV-05 cases`

### Branch Naming
- `feature/` - new features
- `fix/` - bug fixes
- `refactor/` - code refactoring

### Forbidden
- Never commit credentials or API keys
- Never mention AI tools in commits
- Never commit vendor/ unless configured

## Security Rules

This is a security tool. Follow these strictly:

1. **Validate all inputs** - Never trust user input
2. **No hardcoded credentials** - Use environment variables
3. **Respect scope** - Never scan outside defined targets
4. **Rate limiting** - Respect target server limits
5. **Redact logs** - Never log sensitive data

## Project Structure

```
cmd/scanner/         # Entry point only, minimal logic
internal/
  core/              # Core types and interfaces
  detection/         # Vulnerability detection (high coverage required)
  owasp/             # OWASP framework implementations
  tools/             # External tool integrations
  headless/          # Browser automation
  scanner/           # Scan flow orchestration
  reporting/         # Output generation
configs/             # Configuration files
data/                # Payloads, wordlists, fingerprints
tests/               # Integration and E2E tests
```

## External Tool Integration

- All tools must implement the `Tool` interface
- Always check tool availability before use
- Parse output to normalized `Finding` format
- Handle timeouts and errors gracefully

## Before Committing

Always update gitignore and code quality and code audit review first

```bash
go fmt ./...
go vet ./...
golangci-lint run
go test -race ./...
```

Or simply: `make check`
