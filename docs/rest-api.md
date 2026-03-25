# REST API

`tdd-audit serve` turns the scanner into an authenticated HTTP API. Use it to integrate vulnerability scanning into dashboards, CI pipelines, bots, or any tooling that speaks JSON.

---

## Start the server

```bash
npx @lhi/tdd-audit serve --port 3000 --api-key YOUR_SECRET
```

Or via config file (`.tdd-audit.json` in your project root):

```json
{
  "port": 3000,
  "serverApiKey": "YOUR_SECRET",
  "output": "json"
}
```

If `--api-key` / `serverApiKey` is omitted the server starts unauthenticated with a warning. Always set one in production.

---

## Authentication

All endpoints except `GET /health` require:

```
Authorization: Bearer YOUR_SECRET
```

Missing or wrong key → `401 Unauthorized`.

---

## Endpoints

### `GET /health`

No auth required.

```json
{ "status": "ok", "version": "1.9.0" }
```

---

### `POST /scan`

Scan a local path and return structured findings.

**Request**
```json
{
  "path": ".",
  "format": "json"
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `path` | string | cwd | Absolute or relative path to scan. Must be inside cwd. |
| `format` | `"json"` \| `"sarif"` | `"json"` | Output format |

**Response — JSON format**
```json
{
  "version": "1.9.0",
  "summary": { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 1, "LOW": 0 },
  "findings": [ ... ],
  "likelyFalsePositives": [ ... ],
  "exempted": [],
  "scannedAt": "2026-03-25T12:00:00.000Z",
  "duration": 42
}
```

**Response — SARIF format**

Returns a SARIF 2.1.0 object ready to upload to GitHub code scanning.

**Errors**
| Status | Reason |
|---|---|
| 400 | Missing path, path traversal attempt, or invalid JSON body |
| 401 | Missing or invalid API key |

---

### `POST /remediate`

Queue an AI-powered remediation job. Returns immediately with a `jobId`; poll `/jobs/:id` for results.

**Request**
```json
{
  "findings": [ ... ],
  "provider": "anthropic",
  "apiKey": "sk-ant-...",
  "model": "claude-opus-4-6",
  "severity": "HIGH"
}
```

| Field | Required | Description |
|---|---|---|
| `findings` | yes | Array of finding objects from `POST /scan` |
| `provider` | yes | `anthropic` \| `openai` \| `gemini` \| `ollama` |
| `apiKey` | yes | Provider API key |
| `model` | no | Defaults per provider (see [AI Remediation](ai-remediation.md)) |
| `severity` | no | Minimum severity to fix. Default: `LOW` (fix all) |

**Response**
```json
{ "jobId": "job_1_1711363200000" }
```

---

### `GET /jobs/:id`

Poll for remediation job status.

**Response — pending**
```json
{ "id": "job_1_...", "status": "pending", "createdAt": "..." }
```

**Response — done**
```json
{
  "id": "job_1_...",
  "status": "done",
  "createdAt": "...",
  "startedAt": "...",
  "completedAt": "...",
  "results": [
    {
      "finding": { ... },
      "status": "remediated",
      "exploitTest": { "filename": "__tests__/security/xss.test.js", "content": "..." },
      "patch": { "filename": "src/app.js", "diff": "..." },
      "refactorChecks": ["npm test", "npm run test:security"]
    }
  ]
}
```

---

## Example: scan from curl

```bash
# Start server
npx @lhi/tdd-audit serve --port 3000 --api-key mysecret &

# Scan current directory
curl -s -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"path": "."}' | jq '.summary'

# Get SARIF for GitHub upload
curl -s -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"path": ".", "format": "sarif"}' > results.sarif
```

---

## Example: scan from Node.js

```javascript
const res = await fetch('http://localhost:3000/scan', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer mysecret',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ path: '/path/to/project' }),
});
const { findings, summary } = await res.json();
console.log(`CRITICAL: ${summary.CRITICAL}  HIGH: ${summary.HIGH}`);
```
