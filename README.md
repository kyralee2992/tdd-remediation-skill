# @lhi/tdd-audit

Anti-Gravity Skill for TDD Remediation. Patches security vulnerabilities by applying a Test-Driven Remediation (Red-Green-Refactor) protocol — you prove the hole exists, apply the fix, and prove it's closed.

## What happens on install

Running the installer does five things immediately:

1. **Scans your codebase** for common vulnerability patterns (SQL injection, IDOR, XSS, command injection, path traversal, broken auth) and prints findings to stdout
2. **Scaffolds `__tests__/security/`** with a framework-matched boilerplate exploit test
3. **Adds `test:security`** to your `package.json` scripts (Node.js projects)
4. **Creates `.github/workflows/security-tests.yml`** so the CI gate exists from day one
5. **Installs the `/tdd-audit` workflow shortcode** for your agent

## Installation

Install globally so the skill is available across all your projects:

```bash
npx @lhi/tdd-audit
```

Or clone and run directly:

```bash
node index.js
```

### Flags

| Flag | Description |
|---|---|
| `--local` | Install skill files to the current project directory instead of `~` |
| `--claude` | Use `.claude/` instead of `.agents/` as the skill directory |
| `--with-hooks` | Install a pre-commit hook that blocks commits if security tests fail |
| `--skip-scan` | Skip the automatic vulnerability scan on install |
| `--scan-only` | Run the vulnerability scan without installing anything |

**Install to a Claude Code project with pre-commit protection:**
```bash
npx @lhi/tdd-audit --local --claude --with-hooks
```

### Framework Detection

The installer automatically detects your project's test framework and scaffolds the right boilerplate:

| Detected | Boilerplate | `test:security` command |
|---|---|---|
| `jest` / `supertest` | `sample.exploit.test.js` | `jest --testPathPattern=__tests__/security` |
| `vitest` | `sample.exploit.test.vitest.js` | `vitest run __tests__/security` |
| `mocha` | `sample.exploit.test.js` | `mocha '__tests__/security/**/*.spec.js'` |
| `pytest.ini` / `pyproject.toml` | `sample.exploit.test.pytest.py` | `pytest tests/security/ -v` |
| `go.mod` | `sample.exploit.test.go` | `go test ./security/... -v` |

## Usage

Once installed, trigger the autonomous audit in your agent:

```text
/tdd-audit
```

The agent will:
1. Scan the codebase and present a severity-ranked findings report (CRITICAL / HIGH / MEDIUM / LOW)
2. Wait for your confirmation before making any changes
3. For each confirmed vulnerability, apply the full Red-Green-Refactor loop:
   - **Red** — write an exploit test that fails, proving the vulnerability exists
   - **Green** — apply the targeted patch, making the test pass
   - **Refactor** — run the full suite to confirm no regressions
4. Deliver a final Remediation Summary table

The agent works one vulnerability at a time and does not advance until the current one is fully proven closed.

## Running security tests manually

```bash
# Node.js
npm run test:security

# Python
pytest tests/security/ -v

# Go
go test ./security/... -v
```

## CI/CD

The installer creates `.github/workflows/security-tests.yml` for your stack. It runs on every pull request targeting `main` — any exploit test that regresses will block the merge.

To add this gate to an existing CI pipeline manually:

```yaml
- name: Run security exploit tests
  run: npm run test:security   # or pytest tests/security/, or go test ./security/...
```

## Pre-commit Hook

The `--with-hooks` flag appends a security gate to `.git/hooks/pre-commit`. Commits are blocked if any exploit test fails:

```
❌ Security tests failed. Commit blocked.
```

The hook is non-destructive — it appends to any existing hook content rather than overwriting it.

## License

MIT
