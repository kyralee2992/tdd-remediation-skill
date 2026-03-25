# TDD Remediation Protocol

Security patching without tests is guesswork. The Red-Green-Refactor loop turns every vulnerability into a provable, reproducible closure: you prove the hole exists, you close it, and you prove it is closed.

---

## The three phases

```
RED   → write the exploit test   → it MUST fail   (vulnerability confirmed)
GREEN → apply the patch          → test MUST pass  (vulnerability closed)
REFACTOR → run the full suite    → all MUST pass   (no regressions)
```

**Do not move to the next vulnerability until the current one completes all three phases.**

---

## Phase 1 — Red (Exploit)

Write a test that actively attempts the breach. The test must fail on the **security assertion**, not just crash the app.

```javascript
// Wrong Red: test fails because the app throws 500
expect(res.status).toBe(403); // ← fails because app returned 500

// Correct Red: test fails because the vulnerability is open
expect(res.status).toBe(403); // ← fails because app returned 200 with data
```

Place the test in your security test directory (`__tests__/security/`, `tests/security/`, or `test/security/`) so it is picked up by the `test:security` CI job.

### Framework templates

**Jest / Supertest (Node.js)**
```javascript
const request = require('supertest');
const app = require('../../app');

describe('[VulnType] — Red Phase', () => {
  it('SHOULD block [exploit description]', async () => {
    const res = await request(app)
      .post('/api/vulnerable-endpoint')
      .send({ input: '<exploit payload>' });

    expect(res.status).toBe(403); // currently 200 — MUST fail (Red)
    expect(res.body.data).not.toContain('<exploit payload>');
  });
});
```

**PyTest (Python)**
```python
def test_exploit_blocked(client, attacker_token):
    response = client.post(
        '/api/vulnerable-endpoint',
        json={'input': '<exploit payload>'},
        headers={'Authorization': f'Bearer {attacker_token}'}
    )
    assert response.status_code == 403  # currently 200 — RED
```

**Vitest + Testing Library (React / Next.js)**
```typescript
test('SHOULD NOT store auth token in localStorage', async () => {
  render(<LoginForm />);
  fireEvent.submit(screen.getByRole('form'));
  await waitFor(() => {
    expect(localStorage.getItem('token')).toBeNull(); // currently set — RED
  });
});
```

**flutter_test (Flutter)**
```dart
test('SHOULD NOT store auth token in SharedPreferences', () async {
  SharedPreferences.setMockInitialValues({});
  await simulateLogin(username: 'user', password: 'password');
  final prefs = await SharedPreferences.getInstance();
  expect(prefs.getString('token'), isNull); // currently stored — RED
});
```

See [`prompts/red-phase.md`](../prompts/red-phase.md) for vulnerability-specific exploit strategies.

---

## Phase 2 — Green (Patch)

Apply the **minimum code change** that makes the exploit test pass. A targeted fix is safer than a rewrite.

1. Identify the root cause — a 500 error is not a security fix
2. Apply the narrowest patch that closes the vulnerability
3. Run `npm run test:security` — the exploit test must now pass
4. If the test still fails, the patch is incomplete — do not advance

See [`prompts/green-phase.md`](../prompts/green-phase.md) for vulnerability-specific patch strategies with before/after code examples covering:

- IDOR / tenant isolation
- XSS and `dangerouslySetInnerHTML`
- SQL injection (parameterized queries)
- Command injection (argument arrays)
- Path traversal (resolve + bounds check)
- Broken auth (JWT middleware)
- Next.js API route auth
- React Native / Expo sensitive storage migration
- Flutter sensitive storage migration
- SSRF (URL allowlist)
- Open redirect (relative-only)
- NoSQL injection (operator sanitization)
- Mass assignment (field allowlisting)
- Prototype pollution (key sanitization)
- Weak crypto (bcrypt/argon2)
- Missing rate limiting
- Missing security headers (Helmet)
- TLS bypass removal

---

## Phase 3 — Refactor (Regression)

Run the **full** test suite — security tests plus all pre-existing functional and integration tests.

```bash
npm test          # Node.js
pytest            # Python
go test ./...     # Go
flutter test      # Flutter
```

**If any pre-existing test now fails, stop and revert.** Return to Phase 2 with a narrower approach. A security fix that breaks functionality is a failed fix.

### Regression checklist

- [ ] Happy-path flows still work — legitimate users can access their own resources
- [ ] Error messages are safe — no stack traces or internal paths in error responses
- [ ] Auth bypass not introduced — the fix doesn't open a new unprotected code path
- [ ] No secrets committed — patch doesn't hardcode keys or tokens
- [ ] No debug logging left — remove any `console.log` added during patching

See [`prompts/refactor-phase.md`](../prompts/refactor-phase.md) for the full framework-specific regression checklist.

---

## Phase 4 — Hardening (Proactive)

After all vulnerabilities are remediated, apply defence-in-depth controls that make future vulnerabilities harder to introduce. See [`docs/hardening.md`](hardening.md) for the full guide.

Summary of controls:
- **Security headers** — `helmet()` applied before all routes; explicit CSP
- **CSRF protection** — `csrf-csrf` double-submit pattern (not deprecated `csurf`)
- **Rate limiting** — `express-rate-limit` on auth routes
- **Dependency audit** — `npm audit --audit-level=high` in CI
- **Secret history scan** — `gitleaks` / `trufflehog` to catch committed secrets
- **Error handling** — generic 500 messages in production, no stack traces
- **SRI** — subresource integrity hashes on third-party CDN assets
- **GitHub Actions pinning** — every `uses:` locked to a full commit SHA

---

## When to revert and retry

Revert the patch (`git checkout -- <file>`) and return to Phase 2 if:

- A functional test fails after applying the security fix
- The fix introduces a new 401/403 for a legitimate user flow
- Performance degrades measurably (e.g., O(n) queries replacing O(1))

When you retry, describe the constraint: *"The previous fix broke X — find a narrower approach that still closes the vulnerability."*

---

## Remediation Summary format

After all vulnerabilities are addressed, the agent outputs a table:

```
## Remediation Summary

| Vulnerability | File | Status | Test File | Fix Applied |
|---|---|---|---|---|
| SQLi | src/routes/users.js:34 | ✅ Fixed | __tests__/security/sqli-users.test.js | Parameterized query |
| IDOR | src/controllers/docs.js:87 | ✅ Fixed | __tests__/security/idor-docs.test.js | Ownership check added |
```
