# TDD Remediation: Proactive Hardening (Phase 4)

Once all known vulnerabilities are remediated, Phase 4 goes beyond patching holes to building layers of defense that make future vulnerabilities harder to introduce and easier to catch.

This phase is **additive and non-breaking** — apply each control independently, confirm the test suite remains green after each.

---

## 4a. Security Headers (Helmet)

If `helmet` is not already installed:

```bash
npm install helmet
```

Apply as the **first** middleware in your Express/Fastify app:

```javascript
const helmet = require('helmet');
app.use(helmet()); // sets X-Content-Type-Options, X-Frame-Options, HSTS, and more
```

For Next.js, add headers in `next.config.js`:

```javascript
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'X-XSS-Protection', value: '1; mode=block' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
];

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};
```

**Verify:** `curl -I https://localhost:3000/` — confirm headers are present.

---

## 4b. Content Security Policy (CSP)

A strict CSP is the most effective mitigation against XSS — even if a sanitization step is bypassed.

```javascript
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],            // no 'unsafe-inline' — use nonces for inline scripts
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],       // equivalent to X-Frame-Options: DENY
      upgradeInsecureRequests: [],
    },
  })
);
```

**Test:** Use `https://csp-evaluator.withgoogle.com/` to score your policy.

---

## 4c. CSRF Protection

For any app that uses cookie-based sessions (not pure JWT/Authorization header flows):

```javascript
// Express — csurf (or csrf for ESM)
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);
app.get('/form', (req, res) => res.render('form', { csrfToken: req.csrfToken() }));

// In the HTML form:
// <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
```

For single-page apps using `fetch`, use the double-submit cookie pattern or a same-site cookie with `SameSite=Strict`.

```javascript
// SameSite cookies (simple and effective for modern browsers)
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
});
```

---

## 4d. Rate Limiting Audit

Verify these route categories all have rate limiting applied:

| Route type | Recommended limit |
|---|---|
| `/login`, `/register`, `/forgot-password` | 10 requests / 15 min / IP |
| `/api/` general endpoints | 100 requests / 1 min / IP |
| File upload endpoints | 5 requests / 1 min / IP |
| Password reset confirmation | 5 requests / 15 min / IP |

```bash
# Quick check — grep for unprotected POST routes
grep -rn "app\.post\|router\.post" src/ --include="*.js" | grep -v "limiter\|rateLimit"
```

---

## 4e. Dependency Vulnerability Audit

Run your ecosystem's audit tool and fix HIGH/CRITICAL findings:

```bash
# Node.js
npm audit --audit-level=high
npm audit fix  # auto-fix where safe

# Python
pip install pip-audit
pip-audit

# Go
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Ruby
gem install bundler-audit
bundle audit check --update

# Dart / Flutter
flutter pub outdated
dart pub deps  # review transitive deps
```

Add dependency audits to CI so new vulnerabilities are caught on every PR:

```yaml
# .github/workflows/security-tests.yml (add this step)
- name: Dependency Audit
  run: npm audit --audit-level=high
```

---

## 4f. Secrets in Git History

Scan for secrets that were committed and then removed — they still exist in git history.

```bash
# Using trufflehog (recommended)
npx trufflehog git file://. --only-verified

# Using gitleaks
brew install gitleaks   # or download from github.com/gitleaks/gitleaks
gitleaks detect --source . -v
```

If secrets are found in history:
1. **Rotate the secret immediately** — treat it as compromised.
2. Use `git filter-repo` (not `filter-branch`) to rewrite history.
3. Force-push and notify all team members to re-clone.

Add a pre-commit hook to prevent future secret commits:

```bash
# .git/hooks/pre-commit (or use the --with-hooks flag when installing tdd-audit)
npx gitleaks protect --staged -v
```

---

## 4g. Error Handling Hardening

Production error responses must never reveal stack traces, file paths, or internal state.

```javascript
// Express — production error handler (place last, after all routes)
app.use((err, req, res, next) => {
  const isDev = process.env.NODE_ENV !== 'production';
  console.error(err); // log internally — never expose to client
  res.status(err.status || 500).json({
    error: isDev ? err.message : 'Internal server error',
    ...(isDev && { stack: err.stack }),
  });
});
```

```python
# FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    # Log internally
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
```

---

## 4h. Subresource Integrity (SRI)

For any third-party scripts or stylesheets loaded via CDN, add integrity hashes to prevent supply-chain injection:

```html
<!-- Generate hash: openssl dgst -sha384 -binary script.js | openssl base64 -A -->
<script
  src="https://cdn.example.com/lib.min.js"
  integrity="sha384-<hash>"
  crossorigin="anonymous"
></script>
```

**Tool:** https://www.srihash.org/ generates the integrity attribute from any public URL.

---

## 4i. Hardening Verification Checklist

After Phase 4, confirm all of the following:

- [ ] `helmet()` applied before all routes; `X-Content-Type-Options: nosniff` in every response
- [ ] CSP header present; validated with csp-evaluator
- [ ] CSRF protection on all state-mutating routes (or SameSite=Strict cookies)
- [ ] Rate limiting on auth routes (429 returned after threshold — covered by red-phase test)
- [ ] `npm audit` / `pip-audit` / `govulncheck` shows 0 HIGH/CRITICAL issues
- [ ] `gitleaks` or `trufflehog` shows no verified secrets in history
- [ ] Production error handler returns generic messages; no stack traces in 5xx responses
- [ ] SRI hashes on all third-party CDN resources
- [ ] `*.env` files in `.gitignore`; no `.env` committed to git
- [ ] All cookies use `httpOnly: true`, `secure: true`, `sameSite: 'strict'` or `'lax'`
