# REST API

`tdd-audit serve` exposes an authenticated HTTP API built on **Fastify**. Use it to integrate AI-powered security audits into dashboards, CI pipelines, bots, or any tooling that speaks JSON.

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

`POST /audit` and `POST /audit/ai` validate that the requested path is inside the server's working directory. The check is normalised with a trailing path separator to prevent sibling-directory prefix bypasses (e.g. `/app-evil` cannot escape via `/app`). Paths outside cwd return `400`.

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
{ "status": "ok", "version": "1.17.0" }
```

---

### `POST /audit/ai`

**The primary endpoint.** Runs a full agentic LLM audit using tool calls (`read_file`, `list_files`, `search_in_files`, `write_file`). Returns immediately with a `jobId`; poll `GET /jobs/:id` or stream `GET /jobs/:id/stream` for results.

Provider and API key can be supplied in the request body or pre-configured in `.tdd-audit.json`.

**Request**
```json
{
  "path":     ".",
  "provider": "anthropic",
  "apiKey":   "sk-ant-...",
  "model":    "claude-opus-4-6",
  "baseUrl":  null,
  "depth":    "tier-2"
}
```

| Field | Required | Default | Description |
|---|---|---|---|
| `path` | no | cwd | Path to audit. Must be inside server cwd. |
| `provider` | yes* | cfg | `anthropic` \| `openai` \| `gemini` \| `ollama` |
| `apiKey` | yes* | cfg | Provider API key |
| `model` | no | provider default | Model override |
| `baseUrl` | no | — | Base URL for OpenAI-compatible services |
| `depth` | no | `tier-1` | Output depth tier (see below) |
| `scanOnly` | no | — | Override depth-derived scan mode |
| `allowWrites` | no | `false` | Override depth-derived write permission |
| `findings` | no | — | Pre-identified findings array (triggers targeted-apply mode when `depth=tier-4`) |

*Required unless configured in `.tdd-audit.json`.

**Response — 202 Accepted**

```
HTTP/1.1 202 Accepted
Location: /jobs/job_1_...
Retry-After: 5
```
```json
{ "jobId": "job_1_1711363200000" }
```

**Job result envelope** (available via `GET /jobs/:id` after completion)

```json
{
  "version":             "1.16.0",
  "provider":            "anthropic",
  "model":               "claude-opus-4-6",
  "depth":               "tier-2",
  "mode":                "scan-only",
  "stack":               "Node.js / Express",
  "summary":             { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 1 },
  "patchesApplied":      0,
  "findings":            [ ... ],
  "likelyFalsePositives": [ ... ],
  "remediation":         [],
  "scannedAt":           "2026-03-26T12:00:00.000Z"
}
```

`patchesApplied` is the billable unit for `tier-4`: the count of `remediation` entries where `status === "fixed"`.

---

### Depth tiers

| Tier | Mode | Finding fields added | `allowWrites` |
|---|---|---|---|
| `tier-1` | scan-only | `name`, `severity`, `file`, `line`, `snippet` | no |
| `tier-2` | scan-only | + `risk`, `effort`, `cwe`, `owasp`, `references` | no |
| `tier-3` | full audit | + `patch` (copy-ready), `testSnippet` | no |
| `tier-4` | full audit | LLM calls `write_file`; `remediation` array tracks each patch | yes |

---

### Targeted apply (tier-4 + findings)

When `depth=tier-4` and a `findings` array is supplied, the LLM skips the scan phase entirely and applies only the patches you specify. Use this to apply a single finding from a previous tier-3 report:

```json
{
  "provider": "anthropic",
  "apiKey":   "sk-ant-...",
  "depth":    "tier-4",
  "findings": [
    {
      "name":    "SQL Injection",
      "file":    "src/db.js",
      "line":    42,
      "patch":   "const stmt = db.prepare('SELECT * FROM users WHERE id = ?');\nstmt.run(id);"
    }
  ]
}
```

The job mode will be reported as `targeted-apply/tier-4(1)`. Only the listed findings are touched — no full re-scan.

---

### `POST /remediate`

Queue an AI-powered remediation job for a **provided findings list**. Returns immediately with a `jobId`.

Use `POST /audit/ai` for a fully agentic audit instead.

**Request**
```json
{
  "findings": [ ... ],
  "provider": "anthropic",
  "apiKey":   "sk-ant-...",
  "model":    "claude-opus-4-6",
  "baseUrl":  null
}
```

| Field | Required | Description |
|---|---|---|
| `findings` | yes | Array of finding objects |
| `provider` | yes | `anthropic` \| `openai` \| `gemini` \| `ollama` |
| `apiKey` | yes | Provider API key |
| `model` | no | Defaults per provider |
| `baseUrl` | no | Override base URL for OpenAI-compatible services |

**Response — 202 Accepted**
```json
{ "jobId": "job_1_1711363200000" }
```

---

### `POST /audit`

Static scan + AI remediation pipeline in one shot. Runs `quickScan` then passes findings to the remediator. If no `provider`/`apiKey` are supplied, runs the scan only.

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
| `path` | no | Path to scan. Defaults to cwd. |
| `provider` | no | If supplied with `apiKey`, AI remediation runs after the scan |
| `apiKey` | no | Provider API key |
| `model` | no | Defaults per provider |
| `baseUrl` | no | Override base URL for OpenAI-compatible providers |
| `webhook` | no | URL to POST the final job payload to when complete (fire-and-forget) |

**Response — 202 Accepted**

```
HTTP/1.1 202 Accepted
Location: /jobs/job_1_...
Retry-After: 2
```

Job lifecycle: `pending → scanning → scanned → remediating → done | error`

---

### `GET /jobs/:id`

Poll for job status. Works for jobs created by `POST /audit/ai`, `POST /remediate`, and `POST /audit`.

**Response — pending / running**
```json
{ "id": "job_1_...", "status": "running", "depth": "tier-2", "createdAt": "..." }
```

**Response — done**
```json
{
  "id":          "job_1_...",
  "status":      "done",
  "createdAt":   "...",
  "startedAt":   "...",
  "completedAt": "...",
  "result": { ... }
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
data: {"id":"job_1_...","status":"running","depth":"tier-2","log":"🔍 Exploring..."}

data: {"id":"job_1_...","status":"done","completedAt":"...","result":{...}}
```

The connection closes automatically after the terminal state. Connecting to an already-completed job pushes the current state and closes immediately.

**Node.js example**
```javascript
const es = new EventSource(
  'http://localhost:3000/jobs/job_1_.../stream',
  { headers: { Authorization: 'Bearer YOUR_SECRET' } }
);
es.onmessage = (e) => {
  const job = JSON.parse(e.data);
  if (job.status === 'done') { console.log(job.result); es.close(); }
  if (job.status === 'error') { console.error(job.error); es.close(); }
};
```

---

## Full workflow examples

### curl — tier-2 audit with polling

```bash
npx @lhi/tdd-audit serve --port 3000 --api-key mysecret &

# Start the audit
JOB=$(curl -s -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "anthropic",
    "apiKey":   "sk-ant-...",
    "depth":    "tier-2"
  }' | jq -r '.jobId')

# Poll until done
while true; do
  STATUS=$(curl -s http://localhost:3000/jobs/$JOB \
    -H "Authorization: Bearer mysecret" | jq -r '.status')
  echo "Status: $STATUS"
  [ "$STATUS" = "done" ] || [ "$STATUS" = "error" ] && break
  sleep 3
done

# Print findings summary
curl -s http://localhost:3000/jobs/$JOB \
  -H "Authorization: Bearer mysecret" | jq '.result.summary'
```

### curl — tier-3 report then targeted apply

```bash
# Step 1: get copy-ready patches (no writes)
JOB=$(curl -s -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"provider":"anthropic","apiKey":"sk-ant-...","depth":"tier-3"}' \
  | jq -r '.jobId')

# (wait for done)

# Step 2: apply one specific patch
FINDING=$(curl -s http://localhost:3000/jobs/$JOB \
  -H "Authorization: Bearer mysecret" \
  | jq '.result.findings[0]')

curl -s -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d "{
    \"provider\": \"anthropic\",
    \"apiKey\":   \"sk-ant-...\",
    \"depth\":    \"tier-4\",
    \"findings\": [$FINDING]
  }" | jq '.jobId'
```

### curl — SARIF output for GitHub code scanning

```bash
JOB=$(curl -s -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"provider":"anthropic","apiKey":"sk-ant-...","depth":"tier-2","format":"sarif"}' \
  | jq -r '.jobId')

# (wait for done)

curl -s http://localhost:3000/jobs/$JOB \
  -H "Authorization: Bearer mysecret" | jq '.result' > results.sarif
```
