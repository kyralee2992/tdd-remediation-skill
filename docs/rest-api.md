# REST API

`tdd-audit serve` turns the scanner into an authenticated HTTP API built on **Fastify**. Use it to integrate vulnerability scanning and AI remediation into dashboards, CI pipelines, bots, or any tooling that speaks JSON.

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

If `--api-key` / `serverApiKey` is omitted the server starts unauthenticated with a stderr warning. Always set one in production.

---

## Security

### Authentication

All endpoints except `GET /health` require:

```
Authorization: Bearer YOUR_SECRET
```

Missing or wrong key → `401 Unauthorized`.

Tokens are compared using **HMAC + `crypto.timingSafeEqual`** to prevent timing-oracle attacks (both values are HMAC-normalised before comparison so lengths are always equal).

### Rate limiting

All endpoints are rate-limited to **60 requests / IP / minute**. Exceeding the limit returns `429 Too Many Requests`.

By default the rate limiter keys on the **socket IP**, not `X-Forwarded-For`, to prevent header-spoofing bypasses. Enable proxy-forwarded IPs only when you are behind a trusted reverse proxy:

```json
{ "trustProxy": true }
```

### Path validation

`POST /scan` and `POST /audit` validate that the requested path is inside the server's working directory. The check is normalised with a trailing path separator to prevent sibling-directory prefix bypasses (e.g. `/app-evil` cannot escape via `/app`). Paths outside cwd return `400`.

### Security headers

Every response includes:

```
Content-Security-Policy: default-src 'none'
X-Content-Type-Options:  nosniff
X-Frame-Options:         DENY
```

---

## Endpoints

### `GET /health`

No auth required. Returns server status and version.

```json
{ "status": "ok", "version": "1.13.0" }
```

---

### `POST /scan`

Scan a local path and return structured findings synchronously.

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
  "version":              "1.13.0",
  "summary":              { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 1, "LOW": 0 },
  "findings":             [ ... ],
  "likelyFalsePositives": [ ... ],
  "exempted":             [],
  "scannedAt":            "2026-03-25T12:00:00.000Z",
  "duration":             42
}
```

**Response — SARIF**

Returns a SARIF 2.1.0 object ready to upload to GitHub code scanning.

**Errors**

| Status | Reason |
|---|---|
| 400 | Path traversal attempt, oversized body (> 512 KB), or invalid JSON |
| 401 | Missing or invalid API key |
| 429 | Rate limit exceeded |

---

### `POST /remediate`

Queue an AI-powered remediation job for a **provided findings list**. Returns immediately with a `jobId`; poll `GET /jobs/:id` (or stream `GET /jobs/:id/stream`) for results.

Use `POST /audit` instead if you want the server to run the scan itself.

**Request**
```json
{
  "findings": [ ... ],
  "provider": "anthropic",
  "apiKey":   "sk-ant-...",
  "model":    "claude-opus-4-6",
  "baseUrl":  null,
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

**Response — 202 Accepted**
```json
{ "jobId": "job_1_1711363200000" }
```

Job lifecycle: `pending → running → done | error`

---

### `POST /audit`

Full automated pipeline: **scan + AI remediation in one shot**. No interaction needed. Returns immediately with a `jobId`.

If no `provider`/`apiKey` are supplied, the server runs the scan only (no remediation) and the job transitions to `done` with just the `findings` array.

**Request**
```json
{
  "path":     ".",
  "provider": "anthropic",
  "apiKey":   "sk-ant-...",
  "model":    "claude-opus-4-6",
  "baseUrl":  null,
  "webhook":  "https://your-server.example.com/webhook"
}
```

| Field | Required | Description |
|---|---|---|
| `path` | no | Path to scan. Defaults to cwd. Must be inside server cwd. |
| `provider` | no | If supplied with `apiKey`, AI remediation runs after the scan |
| `apiKey` | no | Provider API key |
| `model` | no | Defaults per provider |
| `baseUrl` | no | Override base URL for OpenAI-compatible providers |
| `webhook` | no | URL to POST the final job payload to when complete (fire-and-forget) |

**Response — 202 Accepted**

```
HTTP/1.1 202 Accepted
Location: /jobs/job_1_1711363200000
Retry-After: 2
```
```json
{ "jobId": "job_1_1711363200000" }
```

Job lifecycle: `pending → scanning → scanned → remediating → done | error`

Poll `GET /jobs/:id` or stream `GET /jobs/:id/stream` for progress.

**Job object during remediation**
```json
{
  "id":        "job_1_...",
  "status":    "remediating",
  "total":     8,
  "completed": 3,
  "current":   "SQL Injection"
}
```

**Job object when done**
```json
{
  "id":          "job_1_...",
  "status":      "done",
  "createdAt":   "...",
  "startedAt":   "...",
  "completedAt": "...",
  "findings":    [ ... ],
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

### `GET /jobs/:id`

Poll for job status. Works for jobs created by both `POST /remediate` and `POST /audit`.

**Response — pending / scanning**
```json
{ "id": "job_1_...", "status": "scanning", "createdAt": "..." }
```

**Response — remediating (with progress)**
```json
{
  "id":        "job_1_...",
  "status":    "remediating",
  "total":     8,
  "completed": 3,
  "current":   "SQL Injection"
}
```

**Response — done**
```json
{
  "id":          "job_1_...",
  "status":      "done",
  "createdAt":   "...",
  "startedAt":   "...",
  "completedAt": "...",
  "results":     [ ... ]
}
```

**Response — error**
```json
{ "id": "job_1_...", "status": "error", "error": "Provider returned 401: ..." }
```

The job store keeps up to **1 000 jobs** in memory (TTL: 1 hour). Oldest jobs are evicted when the cap is reached.

---

### `GET /jobs/:id/stream`

Real-time job progress via **Server-Sent Events (SSE)**. The server pushes an event each time the job state changes, and closes the connection when the job reaches `done` or `error`.

```bash
curl -N http://localhost:3000/jobs/job_1_.../stream \
  -H "Authorization: Bearer YOUR_SECRET"
```

**Event format**
```
data: {"id":"job_1_...","status":"scanning","createdAt":"..."}

data: {"id":"job_1_...","status":"scanned","findings":[...]}

data: {"id":"job_1_...","status":"remediating","total":8,"completed":1,"current":"SQL Injection"}

data: {"id":"job_1_...","status":"done","completedAt":"...","results":[...]}
```

The connection is closed automatically after the terminal state (`done` / `error`). If you connect to an already-completed job, the server pushes the current state and closes immediately.

**Node.js example using EventSource**
```javascript
const es = new EventSource(
  'http://localhost:3000/jobs/job_1_.../stream',
  { headers: { Authorization: 'Bearer YOUR_SECRET' } }
);
es.onmessage = (e) => {
  const job = JSON.parse(e.data);
  if (job.status === 'done') { console.log(job.results); es.close(); }
  if (job.status === 'error') { console.error(job.error); es.close(); }
};
```

---

## Full workflow examples

### curl — scan only

```bash
npx @lhi/tdd-audit serve --port 3000 --api-key mysecret &

curl -s -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"path": "."}' | jq '.summary'
```

### curl — full pipeline with polling

```bash
# Kick off audit
JOB=$(curl -s -X POST http://localhost:3000/audit \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{
    "path":     ".",
    "provider": "anthropic",
    "apiKey":   "sk-ant-..."
  }' | jq -r '.jobId')

# Poll until done
while true; do
  STATUS=$(curl -s http://localhost:3000/jobs/$JOB \
    -H "Authorization: Bearer mysecret" | jq -r '.status')
  echo "Status: $STATUS"
  [ "$STATUS" = "done" ] || [ "$STATUS" = "error" ] && break
  sleep 2
done
```

### curl — SARIF output for GitHub code scanning

```bash
curl -s -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"path": ".", "format": "sarif"}' > results.sarif
```

### Node.js — scan

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
