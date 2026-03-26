---
name: hardening-phase
description: "Hardening Phase: add security headers, rate limiting, secret scanning, SHA-pinned Actions, and agentic AI controls after all vulnerabilities are patched."
risk: low
source: personal
date_added: "2024-01-01"
audited_by: lcanady
last_audited: "2026-03-22"
audit_status: safe
---

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
// Express — csrf-csrf (csurf is deprecated since March 2023)
const { doubleCsrf } = require('csrf-csrf');

const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: '__Host-psifi.x-csrf-token',
  cookieOptions: { sameSite: 'strict', secure: true },
});

app.use(doubleCsrfProtection);
app.get('/form', (req, res) => res.render('form', { csrfToken: generateToken(req, res) }));

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

## 4i. GitHub Actions Supply Chain Hardening

Unpinned GitHub Actions are a supply chain vector — a compromised tag or branch can exfiltrate your `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`, or other secrets.

**Grep for unpinned actions:**
```bash
grep -rn "uses:.*@v\|uses:.*@main\|uses:.*@master" .github/workflows/
```

**Pin every `uses:` to a full commit SHA:**
```yaml
# Before (vulnerable)
- uses: actions/checkout@v4
- uses: actions/setup-node@v4

# After (safe — SHA locked, tag as comment)
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
```

**Also audit workflow inputs for injection (ASI08):**
```yaml
# Vulnerable — direct interpolation into run step
run: echo "${{ github.event.pull_request.title }}"

# Safe — use env var to break interpolation chain
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "$PR_TITLE"
```

**Secrets in workflows** — never inline secrets into `run:` commands:
```yaml
# Vulnerable — secret in URL leaks to logs
run: curl https://api.example.com?key=${{ secrets.API_KEY }}

# Safe — pass via env var
env:
  API_KEY: ${{ secrets.API_KEY }}
run: curl -H "Authorization: $API_KEY" https://api.example.com
```

---

## 4j. Agentic AI Security Hardening

If this project contains AI agent code, MCP configurations, or CLAUDE.md files, apply these additional controls:

**CLAUDE.md / Instructions file hygiene:**
- Ensure `CLAUDE.md` is under version control and reviewed on every commit
- Never include any user-supplied content in `CLAUDE.md`
- Scope `CLAUDE.md` permissions to the minimum needed for the project

**MCP server pinning:**
```json
// settings.json — pin to exact version, prefer local install over npx
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": ["/usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"]
    }
  }
}
```

**Tool permission scope:**
- Never grant `bash` tool access when only `read` is needed
- Review `allowedTools` lists and remove any tool not required for the task
- For automated CI agents, use a dedicated low-privilege service account

**Prompt injection defense:**
- Sanitize all tool outputs before injecting into prompt context
- Treat content from web fetches, file reads, and search results as untrusted
- Never have the agent execute commands derived directly from tool output content

---

## 4l. Coverage Gate (≥ 95%)

After hardening is complete, measure test coverage and drive it to **≥ 95% line and branch coverage** before closing the audit.

```bash
# Node.js / Jest
npx jest --coverage --coverageReporters=text

# Python
pytest --cov=. --cov-report=term-missing

# Go
go test ./... -coverprofile=coverage.out && go tool cover -func=coverage.out
```

1. Run the coverage report and note every uncovered line or branch.
2. For each gap: write a failing test (Red), make it pass (Green), re-run coverage.
3. Repeat until line **and** branch coverage both reach ≥ 95%.
4. Files that are intentionally excluded (generated code, migration stubs) must be listed in the coverage config with a reason.

Do **not** write trivially-true tests to inflate numbers — every test must assert real behavior.

---

## 4m. Badge README

Once coverage is ≥ 95%, add (or update) a coverage badge in `README.md`. If no `README.md` exists, create a minimal one.

The badge must appear at the **top of the file**, before any other content:

```markdown
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)
```

**Colour tiers:**

| Coverage | Colour |
|---|---|
| ≥ 90% | `brightgreen` |
| 75–89% | `yellow` |
| < 75% | `red` |

Adjust the percentage to match the actual measured value (e.g., `97%25` for 97%). Do not overwrite other existing badges — add the coverage badge as the first badge on the line.

---

## 4n. SECURITY.md

Check whether a `SECURITY.md` exists at the repo root. **Do not overwrite an existing file.**

If absent, create one following the GitHub Security Advisory format:

```markdown
# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| latest | ✅ |
| < latest | ❌ |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately via:
- **GitHub**: Use [GitHub's private vulnerability reporting](../../security/advisories/new)
- **Email**: security@example.com *(replace with project contact)*

Expect acknowledgement within **48 hours** and a patch or mitigation plan within **14 days** for verified HIGH/CRITICAL issues. Reporters are credited in release notes unless anonymity is requested.

## Security Hardening

This repository is maintained with the following controls:

- HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Rate limiting on all state-mutating and authentication routes
- Dependencies audited on every CI run (`npm audit --audit-level=high`)
- No secrets committed to git history (verified with gitleaks / trufflehog)
- ≥ 95% test coverage enforced via CI coverage gate
- Vulnerabilities remediated using a Red-Green-Refactor exploit-test protocol
```

Replace placeholder email and version table with the project's real information.

---

## 4k. Hardening Verification Checklist

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
- [ ] All GitHub Actions `uses:` pinned to full commit SHAs
- [ ] No `github.event.*` interpolated directly into `run:` steps
- [ ] No secrets inline in workflow `run:` commands or URLs
- [ ] `CLAUDE.md` in version control and reviewed; no user-supplied content
- [ ] MCP servers pinned to exact versions or local installs
- [ ] Agent tool permissions scoped to minimum required
- [ ] Test coverage ≥ 95% line and branch (4l)
- [ ] `README.md` has a coverage badge at the top reflecting the actual % (4m)
- [ ] `SECURITY.md` exists at repo root with a private vulnerability reporting contact (4n)
