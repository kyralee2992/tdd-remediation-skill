---
name: TDD Remediation Protocol
description: A comprehensive toolkit for applying Red-Green-Refactor to fix security vulnerabilities.
---

# TDD Remediation Protocol

Applying Test-Driven Development (TDD) to code that has already been generated requires Test-Driven Remediation. You must prove the security hole exists by writing a test that exploits it, apply the fix, and then prove the hole is closed.

## Autonomous Audit Mode
If the user asks you to "Run the TDD Remediation Auto-Audit" or asks you to implement this on your own:
1. **Explore**: Proactively use `Glob`, `Grep`, and `Read` to scan the repository. Focus on `controllers/`, `routes/`, `api/`, `middleware/`, and database files. Search for anti-patterns: unparameterized SQL queries, missing ownership checks, unsafe HTML rendering, and command injection sinks. Full search patterns are in [auto-audit.md](./prompts/auto-audit.md).
2. **Plan**: Present a structured list of vulnerabilities (grouped by severity: CRITICAL / HIGH / MEDIUM / LOW) and get confirmation before making any changes.
3. **Self-Implement**: For *each* confirmed vulnerability, autonomously execute the complete 3-phase protocol:
   - **[Phase 1 (Red)](./prompts/red-phase.md)**: Write the exploit test ensuring it fails.
   - **[Phase 2 (Green)](./prompts/green-phase.md)**: Write the security patch ensuring the test passes.
   - **[Phase 3 (Refactor)](./prompts/refactor-phase.md)**: Run the full test suite and ensure no business logic broke.
Move methodically through vulnerabilities one by one, CRITICAL-first. Do not advance until the current vulnerability is fully remediated.

---

## Manual Mode
If addressing a single vulnerability manually, invoke the context from the appropriate sub-prompt:
1. **[Red Phase](./prompts/red-phase.md)**: Writing the exploit test.
2. **[Green Phase](./prompts/green-phase.md)**: Writing the patch.
3. **[Refactor Phase](./prompts/refactor-phase.md)**: Ensuring no regressions.

A boilerplate test has been added to the project at `__tests__/security/sample.exploit.test.js`.

---
## CI/CD Integration Guide

To ensure vulnerabilities do not re-enter the main branch, add a strict security testing step to your CI pipeline (e.g., GitHub Actions, GitLab CI).

**Example GitHub Actions Workflow (`.github/workflows/security-tests.yml`)**
```yaml
name: Security Tests
on: [pull_request]
jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: npm ci
      - name: Run Security Exploit Tests
        run: npm run test:security
```
