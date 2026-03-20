---
name: TDD Remediation Protocol
description: A comprehensive toolkit for applying Red-Green-Refactor to fix security vulnerabilities.
---

# TDD Remediation Protocol

Applying Test-Driven Development (TDD) to code that has already been generated requires Test-Driven Remediation. You must prove the security hole exists by writing a test that exploits it, apply the fix, and then prove the hole is closed.

## Autonomous Audit Mode
If the user asks you to "Run the TDD Remediation Auto-Audit" or asks you to implement this on your own:
1. **Explore**: Proactively use your tools (like `grep_search`, `view_file`, and `list_dir`) to scan the user's repository. Focus on `controllers/`, `routes/`, `api/`, and database files. Search for anti-patterns: missing authorization checks, unparameterized SQL queries, and lack of sanitization.
2. **Plan**: Identify the active vulnerabilities and outline them to the user.
3. **Self-Implement**: For *each* vulnerability found, autonomously execute the complete 3-phase protocol:
   - **[Phase 1 (Red)](./prompts/red-phase.md)**: Write the exploit test ensuring it fails.
   - **[Phase 2 (Green)](./prompts/green-phase.md)**: Write the security patch ensuring the test passes.
   - **[Phase 3 (Refactor)](./prompts/refactor-phase.md)**: Clean the code and ensure no business logic broke.
Move methodically through the vulnerabilities one by one.

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
