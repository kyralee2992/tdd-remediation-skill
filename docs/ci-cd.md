# CI/CD Integration Guide

`@lhi/tdd-audit` installs framework-matched GitHub Actions workflow templates on first run. This document covers what ships, how to add the gate to an existing pipeline, and what each template does.

---

## What the installer creates

| File | When created |
|---|---|
| `.github/workflows/security-tests.yml` | Always (if it doesn't already exist) |
| `.github/workflows/ci.yml` | Always (if it doesn't already exist) |

Both files are only written if they don't already exist — the installer never overwrites your existing CI configuration.

---

## Installed workflow templates

All templates ship with:
- Every `uses:` pinned to a full 40-character commit SHA (supply chain hardening, ASI09)
- A dependency audit step (`npm audit --audit-level=high`, `pip-audit`, or `govulncheck`)
- The security exploit test suite run on every push and pull request

### Node.js (jest / vitest / mocha)

**`.github/workflows/security-tests.yml`**
```yaml
name: Security Tests
on:
  push:    { branches: [main, master] }
  pull_request: { branches: [main, master] }
jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
        with: { node-version: '20', cache: 'npm' }
      - run: npm ci
      - run: npm audit --audit-level=high
      - run: npm run test:security
```

**`.github/workflows/ci.yml`**
Runs the full test suite on Node.js 18 / 20 / 22, uploads coverage as an artifact.

### Python

**`security-tests.python.yml`** — runs `pytest tests/security/ -v` on Python 3.12
**`ci.python.yml`** — matrix across Python 3.10 / 3.11 / 3.12, runs `ruff` lint and `pytest --cov`

### Go

**`security-tests.go.yml`** — runs `go test ./security/... -v` on Go 1.22
**`ci.go.yml`** — matrix across Go 1.21 / 1.22 / 1.23, runs `staticcheck` and `go test ./...` with coverage

### Flutter / Dart

**`security-tests.flutter.yml`** — runs `flutter test test/security/` with `subosito/flutter-action` (SHA-pinned)
**`ci.flutter.yml`** — runs `dart analyze`, `dart format`, `flutter test --coverage`

---

## Adding to an existing pipeline

Minimum addition — add these two steps to your existing workflow after `npm ci` (or language equivalent):

```yaml
- name: Dependency audit
  run: npm audit --audit-level=high

- name: Security exploit tests
  run: npm run test:security
```

For Python:
```yaml
- name: Dependency audit
  run: pip install pip-audit && pip-audit

- name: Security exploit tests
  run: pytest tests/security/ -v
```

For Go:
```yaml
- name: Dependency audit
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...

- name: Security exploit tests
  run: go test ./security/... -v
```

---

## Pre-commit hook (optional)

Install with `--with-hooks`:

```bash
npx @lhi/tdd-audit --with-hooks
```

This appends to `.git/hooks/pre-commit`:

```sh
# tdd-remediation: security gate
npm run test:security --silent
if [ $? -ne 0 ]; then
  printf "\n\033[0;31m❌ Security tests failed. Commit blocked.\033[0m\n"
  exit 1
fi
```

The hook is non-destructive — it appends to existing hook content and does not overwrite it. If the project is not a git repository, the hook installation is skipped with a warning.

---

## Supply chain hardening in workflows

All installed workflows pin action refs to full commit SHAs. If you add new actions manually, use SHA refs:

```yaml
# Find the SHA for any action tag:
# 1. Go to github.com/actions/checkout/releases
# 2. Click the tag → copy the full commit SHA from the URL or git log

- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
```

To audit your existing workflows for unpinned refs:

```bash
grep -rn "uses:.*@v\|uses:.*@main\|uses:.*@master" .github/workflows/
```

The security test `sec-05-unpinned-action-in-docs.test.js` enforces that documentation examples in this repo stay SHA-pinned as well.

---

## Preventing secrets from leaking in CI

Always pass secrets as environment variables — never interpolate them inline:

```yaml
# Vulnerable — secret appears in the Actions log as part of the URL
- run: curl https://api.example.com?token=${{ secrets.API_TOKEN }}

# Safe
- name: Call API
  env:
    API_TOKEN: ${{ secrets.API_TOKEN }}
  run: curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com
```

Similarly, never interpolate `github.event.*` values directly into `run:` steps (see [ASI08](agentic-ai-security.md#asi08--github-actions-command-injection)):

```yaml
# Vulnerable — PR title with shell metacharacters is injected
- run: echo "PR: ${{ github.event.pull_request.title }}"

# Safe
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR: $PR_TITLE"
```
