# REST API

`tdd-audit serve` turns the scanner into an authenticated HTTP API. Use it to integrate vulnerability scanning into dashboards, CI pipelines, bots, or any tooling that speaks JSON.

---

## Start the server

```bash
# Minimal
npx @lhi/tdd-audit serve --port 3000 --api-key YOUR_SECRET

# With config file (recommended)
npx @lhi/tdd-audit init                    # scaffold .tdd-audit.json
npx @lhi/tdd-audit serve                   # reads config automatically

# Point to a config anywhere
npx @lhi/tdd-audit serve --config ~/configs/prod.json
```

**`.tdd-audit.json` server options:**

```json
{
  "port":         3000,
  "serverApiKey": "YOUR_SECRET",
  "output":       "json",
  "trustProxy":   false
}
```

If `--api-key` / `serverApiKey` is omitted the server starts unauthenticated with a warning. Always set one in production.

---

## Security

### Authentication

All endpoints except `GET /health` require:

```
Authorization: Bearer YOUR_SECRET
```

Missing or wrong key → `401 Unauthorized`.

Tokens are compared using **HMAC + `crypto.timingSafeEqual`** to prevent timing-oracle attacks.

### Rate limiting

All endpoints are rate-limited to **60 requests / IP / minute** (default). Exceeding the limit returns `429 Too Many Requests`.

By default the rate limiter keys on the **socket IP**, not `X-Forwarded-For`, to prevent header-spoofing bypasses. Enable proxy-forwarded IPs only if you are behind a trusted reverse proxy:

```json
{ "trustProxy": true }
```

### Path validation

`POST /scan` validates that the requested path is inside the server's working directory (normalised with a trailing separator to prevent sibling-directory prefix bypasses). Paths outside cwd return `400`.

### Security headers

Every response includes:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

---

## Endpoints

### `GET /health`

No auth required. Returns server status and version.

```json
{ "status": "ok", "version": "1.9.0" }
```

---

### `POST /scan`

Scan a local path and return structured findings.

**Request**
```json
{
  "path":   ".",
  "format": "json"
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `path` | string | cwd | Absolute or relative path to scan. Must be inside server cwd. |
| `format` | `"json"` \| `"sarif"` | `"json"` | Output format |

**Response — JSON**
```json
{
  "version":             "1.9.0",
  "summary":             { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 1, "LOW": 0 },
  "findings":            [ ... ],
  "likelyFalsePositives": [ ... ],
  "exempted":            [],
  "scannedAt":           "2026-03-25T12:00:00.000Z",
  "duration":            42
}
```

**Response — SARIF**

Returns a SARIF 2.1.0 object ready to upload to GitHub code scanning.

**Errors**

| Status | Reason |
|---|---|
| 400 | Path traversal attempt, sibling-directory bypass, oversized body (> 512 KB), or invalid JSON |
| 401 | Missing or invalid API key |
| 429 | Rate limit exceeded |

---

### `POST /remediate`

Queue an AI-powered remediation job. Returns immediately with a `jobId`; poll `/jobs/:id` for results.

The server stores up to **1 000 jobs** in memory (TTL: 1 hour). Oldest jobs are evicted when the cap is reached.

**Request**
```json
{
  "findings": [ ... ],
  "provider": "openai",
  "apiKey":   "sk-...",
  "model":    "gpt-4o",
  "baseUrl":  "https://api.groq.com/openai/v1",
  "severity": "HIGH"
}
```

| Field | Required | Description |
|---|---|---|
| `findings` | yes | Array of finding objects from `POST /scan` |
| `provider` | yes | `anthropic` \| `openai` \| `gemini` \| `ollama` |
| `apiKey` | yes | Provider API key |
| `model` | no | Defaults per provider (see [AI Remediation](ai-remediation.md)) |
| `baseUrl` | no | Override base URL for any OpenAI-compatible service |
| `severity` | no | Minimum severity to fix. Default: `LOW` (fix all) |

**Response**
```json
{ "jobId": "job_1_1711363200000" }
```

---

### `GET /jobs/:id`

Poll for remediation job status.

**Response — pending / running**
```json
{ "id": "job_1_...", "status": "pending", "createdAt": "..." }
```

**Response — done**
```json
{
  "id":          "job_1_...",
  "status":      "done",
  "createdAt":   "...",
  "startedAt":   "...",
  "completedAt": "...",
  "results": [
    {
      "finding":        { ... },
      "status":         "remediated",
      "exploitTest":    { "filename": "__tests__/security/xss.test.js", "content": "..." },
      "patch":          { "filename": "src/app.js", "diff": "..." },
      "refactorChecks": ["npm test", "npm run test:security"]
    }
  ]
}
```

---

## Examples

### curl

```bash
# Start server
npx @lhi/tdd-audit serve --port 3000 --api-key mysecret &

# Scan current directory
curl -s -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"path": "."}' | jq '.summary'

# SARIF output for GitHub upload
curl -s -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"path": ".", "format": "sarif"}' > results.sarif
```

### Node.js

```javascript
const res = await fetch('http://localhost:3000/scan', {
  method:  'POST',
  headers: {
    'Authorization': 'Bearer mysecret',
    'Content-Type':  'application/json',
  },
  body: JSON.stringify({ path: '/path/to/project' }),
});
const { findings, summary } = await res.json();
console.log(`CRITICAL: ${summary.CRITICAL}  HIGH: ${summary.HIGH}`);
```
