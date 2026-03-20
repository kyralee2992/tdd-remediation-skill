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

- [ ] **Happy-path flows still work** — legitimate users can still access their own resources
- [ ] **Error messages are safe** — no stack traces, internal paths, or sensitive data leaked in error responses
- [ ] **Auth bypass not introduced** — the fix doesn't create a new unprotected code path
- [ ] **Performance acceptable** — the patch doesn't add unbounded DB queries or blocking I/O
- [ ] **No secrets in code** — patch doesn't hardcode keys, tokens, or credentials

**React / Next.js additions:**
- [ ] **`dangerouslySetInnerHTML` removed or wrapped** — confirm DOMPurify is imported and called before all remaining usages
- [ ] **Next.js middleware matcher is correct** — `/api/:path*` or tighter; public routes (health checks, webhooks) still reachable
- [ ] **`app.json` / `.env.local` clean** — no API keys or secrets committed; `*.env` is in `.gitignore`

**React Native / Expo additions:**
- [ ] **`AsyncStorage` fully migrated** — no remaining `setItem('token', ...)` calls; `expo-secure-store` in `package.json`
- [ ] **Offline token refresh still works** — `SecureStore.getItemAsync` is called in the right lifecycle (not before `SecureStore.isAvailableAsync()` on web)
- [ ] **Deep link params validated** — any `route.params` passed to API calls are sanitized or type-checked

**Flutter additions:**
- [ ] **`flutter_secure_storage` in `pubspec.yaml`** — dependency present and `flutter pub get` ran
- [ ] **No remaining `SharedPreferences` calls for sensitive keys** — grep for `prefs.getString('token')`, `prefs.setString('password', ...)`
- [ ] **TLS `badCertificateCallback` fully removed** — grep the entire `lib/` directory for `badCertificateCallback`
- [ ] **iOS entitlements updated if needed** — `flutter_secure_storage` requires Keychain Sharing capability on iOS

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
