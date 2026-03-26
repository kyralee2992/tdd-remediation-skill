# Security Policy

## Supported Versions

| Version | Security fixes |
|---------|---------------|
| 1.x (current) | ✅ Supported |
| < 1.0 | ❌ Unsupported |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via [GitHub private vulnerability reporting](https://github.com/kyralee2992/tdd-remediation-skill/security/advisories/new) or by emailing the maintainer directly (see `author` in `package.json`).

**Expected response time:** within 5 business days.

**What to include in your report:**
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code or a failing test if available)
- The version(s) affected

**What to expect after reporting:**
- Acknowledgement within 5 business days
- A fix or mitigation will be prepared and released as a patch version
- You will be credited in the release notes (unless you prefer anonymity)

## Security Hardening

The following protections are applied and verified by automated security tests (`npm run test:security`):

| Control | Implementation | Test |
|---------|---------------|------|
| Timing-safe authentication | HMAC + `crypto.timingSafeEqual` — prevents timing-oracle attacks on Bearer tokens | SEC-17 |
| Rate limiting | 60 requests/minute per IP; respects `trustProxy` for `X-Forwarded-For` | SEC-14, SEC-16 |
| Security headers | `Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` on every response | SEC-20 |
| Path traversal guard | `POST /scan` and `POST /audit` paths are resolved and validated to be within `cwd` | SEC-15, SEC-23 |
| SSRF protection | `webhook` URLs accepted only over `https://` to non-private, non-localhost hosts | SEC-26 |
| SSRF protection (provider baseUrl) | LLM provider `baseUrl` overrides validated — HTTPS required for non-localhost origins | SEC-19, SEC-24 |
| Prompt injection sanitization | Finding snippets and fields sanitized (null bytes stripped, newlines collapsed) before embedding in AI prompts | SEC-18, SEC-21 |
| Request body size limit | Fastify `bodyLimit: 512 KB`; legacy HTTP server enforces the same limit | SEC-03 |
| Binary / oversized file skip | Scanner skips files > 512 KB and non-text binary files to prevent OOM | SEC-02, SEC-03 |
| Dependency audit | `npm audit` runs in CI; no known vulnerabilities at time of release | SEC-07, SEC-09 |
| AI-key redaction | API keys are HMAC'd before appearing in error messages | SEC-21 |
| Job store bounds | In-memory job store capped at `MAX_JOBS` with TTL eviction to prevent unbounded memory growth | SEC-13 |
