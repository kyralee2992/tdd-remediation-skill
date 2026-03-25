# Phase 4 — Proactive Hardening

Phase 4 runs after all known vulnerabilities are patched. It applies defence-in-depth controls that make future vulnerabilities harder to introduce and easier to catch.

Apply each control independently. Confirm the test suite stays green after each.

---

## 4a. Security headers (Helmet)

```bash
npm install helmet
```

Apply as the **first** middleware, before any routes:

```javascript
const helmet = require('helmet');
app.use(helmet());
```

For **Next.js**, add to `next.config.js`:

```javascript
const securityHeaders = [
  { key: 'X-Content-Type-Options',    value: 'nosniff' },
  { key: 'X-Frame-Options',           value: 'SAMEORIGIN' },
  { key: 'X-XSS-Protection',          value: '1; mode=block' },
  { key: 'Referrer-Policy',           value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy',        value: 'camera=(), microphone=(), geolocation=()' },
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

```javascript
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc:             ["'self'"],
      scriptSrc:              ["'self'"],       // no 'unsafe-inline' — use nonces
      styleSrc:               ["'self'", "'unsafe-inline'"],
      imgSrc:                 ["'self'", 'data:', 'https:'],
      connectSrc:             ["'self'"],
      fontSrc:                ["'self'"],
      objectSrc:              ["'none'"],
      frameAncestors:         ["'none'"],       // equivalent to X-Frame-Options: DENY
      upgradeInsecureRequests: [],
    },
  })
);
```

Validate your policy at `https://csp-evaluator.withgoogle.com/`.

---

## 4c. CSRF protection

For cookie-based sessions (not pure JWT / Authorization header flows):

```javascript
// csrf-csrf (csurf is deprecated since March 2023)
const { doubleCsrf } = require('csrf-csrf');

const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret:     () => process.env.CSRF_SECRET,
  cookieName:    '__Host-psifi.x-csrf-token',
  cookieOptions: { sameSite: 'strict', secure: true },
});

app.use(doubleCsrfProtection);
app.get('/form', (req, res) => res.render('form', { csrfToken: generateToken(req, res) }));
```

For SPAs using `fetch`, set `SameSite=Strict` on the session cookie:

```javascript
res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });
```

---

## 4d. Rate limiting

| Route type | Recommended limit |
|---|---|
| `/login`, `/register`, `/forgot-password` | 10 requests / 15 min / IP |
| `/api/` general endpoints | 100 requests / 1 min / IP |
| File upload endpoints | 5 requests / 1 min / IP |
| Password reset confirmation | 5 requests / 15 min / IP |

```javascript
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000,      max: 100 });

app.use('/api/', apiLimiter);
app.post('/api/auth/login',    authLimiter, loginHandler);
app.post('/api/auth/register', authLimiter, registerHandler);
```

Quick grep to find unprotected POST routes:

```bash
grep -rn "app\.post\|router\.post" src/ --include="*.js" | grep -v "limiter\|rateLimit"
```

---

## 4e. Dependency vulnerability audit

```bash
# Node.js
npm audit --audit-level=high
npm audit fix   # auto-fix where safe

# Python
pip install pip-audit && pip-audit

# Go
go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...

# Flutter / Dart
flutter pub outdated
```

The live `ci.yml` and `security-tests.yml` workflows both run `npm audit --audit-level=high` on every push and pull request (added in v1.8.0).

---

## 4f. Secret history scan

```bash
# trufflehog (recommended)
npx trufflehog git file://. --only-verified

# gitleaks
brew install gitleaks
gitleaks detect --source . -v
```

If secrets are found in history:
1. Rotate the secret immediately — treat it as compromised
2. Use `git filter-repo` to rewrite history
3. Force-push and have all team members re-clone

Prevent future secret commits via pre-commit hook:

```bash
npx gitleaks protect --staged -v
# or use: npx @lhi/tdd-audit --with-hooks
```

---

## 4g. Production error handling

```javascript
// Express — place last, after all routes
app.use((err, req, res, next) => {
  const isDev = process.env.NODE_ENV !== 'production';
  console.error(err);  // log internally — never expose to client
  res.status(err.status || 500).json({
    error: isDev ? err.message : 'Internal server error',
    ...(isDev && { stack: err.stack }),
  });
});
```

```python
# FastAPI
@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
```

---

## 4h. Subresource Integrity (SRI)

For third-party scripts or stylesheets loaded via CDN:

```html
<script
  src="https://cdn.example.com/lib.min.js"
  integrity="sha384-<hash>"
  crossorigin="anonymous"
></script>
```

Generate integrity hashes at `https://www.srihash.org/`.

---

## 4i. GitHub Actions supply chain hardening

Pin every `uses:` to a full commit SHA:

```yaml
# Vulnerable — mutable tag
- uses: actions/checkout@v4

# Safe — SHA-locked, tag as comment
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
```

Grep for unpinned actions:

```bash
grep -rn "uses:.*@v\|uses:.*@main\|uses:.*@master" .github/workflows/
```

Workflow inputs that inject into `run:` steps:

```yaml
# Vulnerable
run: echo "${{ github.event.pull_request.title }}"

# Safe
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "$PR_TITLE"
```

---

## 4j. Agentic AI controls

- `CLAUDE.md` under version control; reviewed on every commit; no user-supplied content
- MCP servers pinned to exact versions or local installs (see [ASI03](agentic-ai-security.md#asi03--mcp-server-supply-chain-risk))
- Agent tool permissions scoped to minimum required; no `bash` when only `read` is needed
- Tool outputs sanitized before injecting into prompt context (see [ASI01](agentic-ai-security.md#asi01--prompt-injection-via-tool-output))

---

## Hardening verification checklist

- [ ] `helmet()` applied before all routes; `X-Content-Type-Options: nosniff` in every response
- [ ] CSP header present; validated with csp-evaluator
- [ ] CSRF protection on all state-mutating routes (or `SameSite=Strict` cookies)
- [ ] Rate limiting on auth routes — 429 returned after threshold
- [ ] `npm audit` / `pip-audit` / `govulncheck` shows 0 HIGH/CRITICAL findings
- [ ] `gitleaks` / `trufflehog` shows no verified secrets in history
- [ ] Production error handler returns generic messages; no stack traces in 5xx responses
- [ ] SRI hashes on all third-party CDN resources
- [ ] `*.env` in `.gitignore`; no `.env` committed to git
- [ ] All cookies: `httpOnly: true`, `secure: true`, `sameSite: 'strict'` or `'lax'`
- [ ] All GitHub Actions `uses:` pinned to full commit SHAs
- [ ] No `github.event.*` interpolated directly into `run:` steps
- [ ] No secrets inline in workflow `run:` commands or URLs
- [ ] `CLAUDE.md` in version control and reviewed; no user-supplied content
- [ ] MCP servers pinned to exact versions or local installs
- [ ] Agent tool permissions scoped to minimum required
