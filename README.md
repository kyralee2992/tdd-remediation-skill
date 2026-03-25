# @lhi/tdd-audit

> **v1.8.3** — Security skill installer for **Claude Code, Gemini CLI, Cursor, Codex, and OpenCode**. Patches vulnerabilities using a Red-Green-Refactor exploit-test protocol — you prove the hole exists, apply the fix, and prove it's closed.

## What happens on install

Running the installer does five things immediately:

1. **Scans your codebase** for 34 vulnerability patterns across OWASP Top 10, mobile, agentic AI, and prompt/skill files — prints a severity-ranked findings report to stdout
2. **Scaffolds `__tests__/security/`** with a framework-matched boilerplate exploit test
3. **Adds `test:security`** to your `package.json` scripts (Node.js projects)
4. **Creates `.github/workflows/security-tests.yml`** so the CI gate exists from day one
5. **Installs the `/tdd-audit` skill** for your AI coding agent

## Installation

```bash
npx @lhi/tdd-audit
```

Or clone and run directly:

```bash
node index.js
```

### Platform-specific flags

| Platform | Command |
|---|---|
| Claude Code | `npx @lhi/tdd-audit --local --claude` |
| Gemini CLI / Codex / OpenCode | `npx @lhi/tdd-audit --local` |
| With pre-commit hook | add `--with-hooks` |
| Scan only (no install) | `npx @lhi/tdd-audit --scan` |

### All flags

| Flag | Description |
|---|---|
| `--local` | Install skill files into the current project instead of `~` |
| `--claude` | Use `.claude/` instead of `.agents/` as the skill directory |
| `--with-hooks` | Install a pre-commit hook that blocks commits if security tests fail |
| `--skip-scan` | Skip the automatic vulnerability scan on install |
| `--scan` / `--scan-only` | Run the vulnerability scan without installing anything |

### Framework detection

The installer automatically detects your project's test framework and scaffolds the right boilerplate:

| Detected | Boilerplate | `test:security` command |
|---|---|---|
| `jest` / `supertest` | `sample.exploit.test.js` | `jest --testPathPatterns=__tests__/security` |
| `vitest` | `sample.exploit.test.vitest.js` | `vitest run __tests__/security` |
| `mocha` | `sample.exploit.test.js` | `mocha '__tests__/security/**/*.spec.js'` |
| `pytest.ini` / `pyproject.toml` | `sample.exploit.test.pytest.py` | `pytest tests/security/ -v` |
| `go.mod` | `sample.exploit.test.go` | `go test ./security/... -v` |
| `pubspec.yaml` | `sample_exploit_test.dart` | `flutter test test/security/` |

## Usage

Once installed, trigger the autonomous audit in your agent:

```text
/tdd-audit
```

The agent will:

1. Detect your tech stack and scope the scan to relevant patterns only
2. Scan the codebase and present a severity-ranked findings report (CRITICAL / HIGH / MEDIUM / LOW)
3. **Wait for your confirmation** before making any changes
4. For each confirmed vulnerability, apply the full Red-Green-Refactor loop:
   - **Red** — write an exploit test that fails, proving the vulnerability exists
   - **Green** — apply the targeted patch, making the test pass
   - **Refactor** — run the full suite to confirm no regressions
5. Apply proactive hardening controls (security headers, rate limiting, `npm audit`, secret history scan)
6. Deliver a final Remediation Summary table

The agent works one vulnerability at a time and does not advance until the current one is fully proven closed.

Pass `--scan` in your prompt to get the Audit Report only, without any code changes.

## Vulnerability scanner

The built-in scanner catches **34 patterns** across OWASP Top 10, mobile, agentic AI, and prompt/skill files:

| Category | Patterns |
|---|---|
| Injection | SQL Injection, Command Injection, NoSQL Injection, Template Injection |
| Broken Auth | JWT Alg None, Broken Auth, Timing-Unsafe Comparison, Hardcoded Secret, Secret Fallback |
| XSS / Output | XSS, eval() Injection, Open Redirect |
| Crypto | Weak Crypto (MD5/SHA1), Insecure Random, TLS Bypass |
| Server-side | SSRF, Path Traversal, XXE, Insecure Deserialization |
| Assignment | Mass Assignment, Prototype Pollution |
| Mobile | Sensitive Storage, WebView JS Bridge, Deep Link Injection, Android Debuggable |
| Config / Infra | CORS Wildcard, Cleartext Traffic, Config Secrets, ReDoS |
| Agentic / Prompt | Deprecated CSRF Package (`csurf`), Unpinned npx MCP Server, Cleartext URL in Prompt |

### Scanner behaviour

- **Test files are flagged but labelled** — findings in `__tests__/`, `tests/`, `spec/`, or `*.test.*` files are shown with a `[test file]` badge. Patterns that mark `skipInTests: true` (e.g. Hardcoded Secret, Sensitive Log, Cleartext Traffic) are further tagged `likelyFalsePositive` and separated at the bottom of the report.
- **Prompt/skill files get their own scan** — `.md` files inside `prompts/`, `skills/`, `.claude/`, `workflows/`, plus `CLAUDE.md` and `SKILL.md`, are scanned for prompt-specific anti-patterns. Matches inside backtick code spans are suppressed to avoid noise from documentation examples.
- **`audit_status: safe` exemption** — any prompt file with `audit_status: safe` in its YAML frontmatter is skipped and listed separately so you can verify exemptions are intentional.
- **Binary and oversized files skipped** — files larger than 512 KB or containing null bytes are skipped to prevent OOM.
- **Symlinks skipped** — symlinks are never followed, preventing directory-escape on M-series Macs and shared filesystems.

## Running security tests

```bash
# Node.js
npm run test:security

# Python
pytest tests/security/ -v

# Go
go test ./security/... -v

# Flutter
flutter test test/security/
```

## CI/CD

The installer creates framework-matched workflow files under `.github/workflows/`. Both `security-tests.yml` and `ci.yml` include:

- SHA-pinned `uses:` references on every action (supply chain hardening)
- `npm audit --audit-level=high` (or equivalent) to catch vulnerable dependencies
- The security exploit test suite on every push and pull request

To add the security gate to an existing pipeline manually:

```yaml
- name: Dependency audit
  run: npm audit --audit-level=high

- name: Run security exploit tests
  run: npm run test:security   # or pytest tests/security/, flutter test test/security/
```

## Pre-commit hook

The `--with-hooks` flag appends a security gate to `.git/hooks/pre-commit`. Commits are blocked if any exploit test fails:

```
❌ Security tests failed. Commit blocked.
```

The hook is non-destructive — it appends to existing hook content rather than overwriting it.

## Agentic AI security (ASI01–ASI10)

When the project contains AI agent code, MCP configurations, or `CLAUDE.md` files, the scanner also checks for agentic-specific vulnerabilities:

| ID | Vulnerability | Risk |
|---|---|---|
| ASI01 | Prompt injection via tool output | Malicious content in web/file reads hijacks agent behaviour |
| ASI02 | CLAUDE.md / instructions file injection | Attacker-controlled system prompts override agent identity |
| ASI03 | MCP server supply chain (unpinned `npx`) | Compromised package version exfiltrates secrets |
| ASI04 | Excessive tool permissions | Agent can write files or run shell when only read is needed |
| ASI05 | Secrets in tool call arguments | Tokens/passwords logged by external tools |
| ASI06 | Unvalidated agent action execution | Agent runs irreversible actions without user confirmation |
| ASI07 | Insecure direct agent communication | Sub-agent messages trusted without verification |
| ASI08 | GitHub Actions command injection | `github.event.*` interpolated directly into `run:` steps |
| ASI09 | Unpinned GitHub Actions (supply chain) | Mutable `@v4` / `@main` tags can be hijacked |
| ASI10 | Secrets in workflow environment | Secrets printed to logs or embedded in curl URLs |

See [`docs/agentic-ai-security.md`](docs/agentic-ai-security.md) for grep patterns, examples, and fixes.

## Documentation

| File | Contents |
|---|---|
| [`docs/scanner.md`](docs/scanner.md) | How the scanner works — architecture, detection logic, false-positive handling |
| [`docs/vulnerability-patterns.md`](docs/vulnerability-patterns.md) | All 34 patterns with descriptions, grep signatures, and fix pointers |
| [`docs/tdd-protocol.md`](docs/tdd-protocol.md) | The Red-Green-Refactor protocol in full, with framework templates |
| [`docs/agentic-ai-security.md`](docs/agentic-ai-security.md) | ASI01–ASI10 agentic AI vulnerability reference |
| [`docs/hardening.md`](docs/hardening.md) | Phase 4 proactive hardening controls |
| [`docs/ci-cd.md`](docs/ci-cd.md) | CI/CD integration guide for all supported stacks |

## License

MIT
