---
description: Run the complete TDD Remediation Autonomous Audit
---
Please use the TDD Remediation Protocol Auto-Audit skill (located in the `skills/tdd-remediation` folder) to secure this repository.

Follow the full Auto-Audit protocol from `auto-audit.md`:

1. **Explore** the codebase using Glob, Grep, and Read. Focus on controllers, routes, middleware, and database layers. Search for the vulnerability patterns defined in Phase 0 of the auto-audit prompt.
2. **Present** a structured Audit Report, grouped by severity (CRITICAL / HIGH / MEDIUM / LOW), and wait for my confirmation before making any changes.
3. **Remediate** each confirmed vulnerability one at a time, top-down by severity, applying the full Red-Green-Refactor loop:
   - Write the exploit test (Red — must fail)
   - Apply the patch (Green — test must pass)
   - Run the full suite (Refactor — no regressions)
4. **Harden** the codebase proactively after all vulnerabilities are patched:
   - Security headers (Helmet / CSP)
   - Rate limiting on auth routes
   - Dependency vulnerability audit (npm audit / pip-audit / govulncheck)
   - Secret history scan (gitleaks / trufflehog)
   - Production error handling (no stack traces)
   - CSRF protection and secure cookie flags
5. **Report** a final Remediation Summary table when all issues are addressed.

Do not skip steps. Do not advance to the next vulnerability until the current one is fully proven closed by a passing test.
