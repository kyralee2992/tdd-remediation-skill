---
name: refactor-phase
description: "Refactor Phase: run the full test suite after patching to confirm no regressions, then clean up."
risk: low
source: personal
date_added: "2024-01-01"
audited_by: lcanady
last_audited: "2026-03-22"
audit_status: safe
---

# TDD Remediation: Regression & Refactor (Refactor Phase)

Security fixes can be heavy-handed and break legitimate functionality. The perimeter is now secure — confirm nothing else broke, then clean up.

## Action
Run the **full** test suite: security tests + all pre-existing functional/integration tests.

## Protocol

### Step 1: Verify the Green baseline
```bash
npm test          # or pytest, go test ./..., etc.
```
All tests must be green. If any pre-existing functional test now fails, **stop and revert the security patch.** A security fix that breaks functionality is a failed fix — return to Phase 2 with a narrower approach.

### Step 2: Check for regressions by category
Go through this checklist before closing the vulnerability:

```
GATE:BASE     happy-path | safe-errors:no-stacktraces | no-auth-bypass | perf-ok | no-secrets
GATE:REACT    no-dangerouslySetInnerHTML(DOMPurify) | next-middleware-matcher-correct | env-clean
GATE:RN       asyncStorage→secureStore | offline-token-refresh-works | deep-link-params-sanitized
GATE:SSRF     allowlist:internal-IPs-blocked | open-redirect:relative-only | nosql-sanitized | mass-assign:allowlist | proto-pollution:stripped | passwords:bcrypt|argon2 | rate-limit:auth-routes | helmet:before-routes
GATE:FLUTTER  flutter_secure_storage:in-pubspec | no-SharedPreferences-sensitive | no-badCertificateCallback | ios-entitlements-ok
```

### Step 3: Clean the patch
- Remove any debugging `console.log` or `print` statements added during patching
- Extract reusable security logic into middleware or utility functions if it appears in more than one place
- Add a brief comment only if the security rationale is non-obvious (e.g., `// Scope query to owner to prevent IDOR`)

### Step 4: Lock it in
- Ensure the exploit test in `__tests__/security/` has a clear, descriptive name
- Confirm the test file will be picked up by your CI security test job
- If applicable, add the CVE reference or ticket ID as a comment in the test

## Goal
A fully passing test suite (security tests + functional tests) with clean, reviewable code. The vulnerability is provably closed and provably non-regressive.

---

## When to revert and retry

Revert the patch (git checkout -- <file>) and return to Phase 2 if:
- A functional test fails after applying the security fix
- The fix introduces a new 401/403 for a legitimate user flow
- Performance degrades measurably under load (e.g., O(n) queries replacing O(1))

When you retry, describe the constraint to the AI: *"The previous fix broke X — find a narrower approach that still closes the vulnerability."*
