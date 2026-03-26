# AI Remediation

`tdd-audit --ai` runs a fully agentic LLM audit: the model explores your codebase with tool calls, identifies vulnerabilities, and (depending on the depth tier) provides copy-ready patches or applies them directly. No agent shell required.

---

## Depth tiers

| Tier | What you get | Writes files? | Billing unit |
|---|---|---|---|
| `tier-1` | Scan report: name, severity, file, line, snippet | no | per report |
| `tier-2` | + risk, effort, CWE, OWASP category, references | no | per report |
| `tier-3` | + copy-ready `patch` and `testSnippet` per finding | no | per report |
| `tier-4` | LLM applies patches via `write_file`; `patchesApplied` count in envelope | yes | per applied patch |

```bash
# Fast scan report
npx @lhi/tdd-audit --ai --depth tier-1 --format json

# Rich report with CWE/OWASP — review and decide what to fix
npx @lhi/tdd-audit --ai --depth tier-2 --format json

# Patch included in every finding — copy and apply yourself
npx @lhi/tdd-audit --ai --depth tier-3 --format json

# Let the LLM write the fixes
npx @lhi/tdd-audit --ai --depth tier-4
```

---

## Config file (recommended)

Scaffold once, run anywhere:

```bash
npx @lhi/tdd-audit init
```

Edit `.tdd-audit.json`:

```json
{
  "provider":   "openai",
  "model":      "gpt-4o",
  "apiKeyEnv":  "OPENAI_API_KEY"
}
```

`apiKeyEnv` names the environment variable to read the key from — no key ever touches disk. Then just:

```bash
npx @lhi/tdd-audit --ai --depth tier-2 --format json
```

Point to a config at any path:

```bash
npx @lhi/tdd-audit --ai --config ~/configs/my-audit.json --depth tier-3
```

---

## CLI flags

```bash
# Anthropic
npx @lhi/tdd-audit --ai \
  --provider anthropic \
  --api-key $ANTHROPIC_API_KEY \
  --depth tier-2

# OpenAI
npx @lhi/tdd-audit --ai \
  --provider openai \
  --api-key $OPENAI_API_KEY \
  --model gpt-4o-mini \
  --depth tier-1
```

---

## OpenAI-compatible services

Any service that exposes the OpenAI chat completions API works via `--base-url`.
The API key is sent in the `Authorization: Bearer` header — never in the URL.

```bash
# Groq (fast inference)
npx @lhi/tdd-audit --ai \
  --provider openai \
  --base-url https://api.groq.com/openai/v1 \
  --model llama-3.3-70b-versatile \
  --api-key $GROQ_API_KEY

# OpenRouter (access 200+ models)
npx @lhi/tdd-audit --ai \
  --provider openai \
  --base-url https://openrouter.ai/api/v1 \
  --model meta-llama/llama-3.3-70b-instruct \
  --api-key $OPENROUTER_API_KEY

# Together AI
npx @lhi/tdd-audit --ai \
  --provider openai \
  --base-url https://api.together.xyz/v1 \
  --model mistralai/Mixtral-8x7B-Instruct-v0.1 \
  --api-key $TOGETHER_API_KEY

# LM Studio / vLLM / llama.cpp (fully local)
npx @lhi/tdd-audit --ai \
  --provider openai \
  --base-url http://localhost:1234/v1 \
  --model local-model
  # no --api-key needed for local servers
```

In `.tdd-audit.json`:

```json
{
  "provider":  "openai",
  "baseUrl":   "https://api.groq.com/openai/v1",
  "model":     "llama-3.3-70b-versatile",
  "apiKeyEnv": "GROQ_API_KEY"
}
```

---

## Supported providers

| Provider | `--provider` | Default model | Key env var | Notes |
|---|---|---|---|---|
| Anthropic | `anthropic` | `claude-opus-4-6` | `ANTHROPIC_API_KEY` | |
| OpenAI | `openai` | `gpt-4o` | `OPENAI_API_KEY` | Supports `--base-url` |
| Google Gemini | `gemini` | `gemini-2.0-flash` | `GEMINI_API_KEY` | Key sent via `x-goog-api-key` header |
| Ollama (local) | `ollama` | `llama3` | — | No key required |
| Any OpenAI-compat | `openai` | — | varies | Set `--base-url` |

---

## REST API usage

```bash
# Start the server
npx @lhi/tdd-audit serve --port 3000 --api-key $SERVER_KEY

# Launch a tier-2 audit job
JOB=$(curl -s -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer $SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"provider\": \"openai\",
    \"apiKey\":   \"$GROQ_API_KEY\",
    \"baseUrl\":  \"https://api.groq.com/openai/v1\",
    \"model\":    \"llama-3.3-70b-versatile\",
    \"depth\":    \"tier-2\"
  }" | jq -r '.jobId')

# Poll until done
while true; do
  STATUS=$(curl -s http://localhost:3000/jobs/$JOB \
    -H "Authorization: Bearer $SERVER_KEY" | jq -r '.status')
  [ "$STATUS" = "done" ] || [ "$STATUS" = "error" ] && break
  sleep 3
done

# Print summary
curl -s http://localhost:3000/jobs/$JOB \
  -H "Authorization: Bearer $SERVER_KEY" | jq '.result.summary'
```

### Targeted apply (tier-4)

Take a single finding from a tier-3 report and apply its patch without re-scanning:

```bash
# Get the first finding from a previous tier-3 job
FINDING=$(curl -s http://localhost:3000/jobs/$TIER3_JOB_ID \
  -H "Authorization: Bearer $SERVER_KEY" \
  | jq '.result.findings[0]')

# Apply only that patch
curl -s -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer $SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"provider\": \"anthropic\",
    \"apiKey\":   \"$ANTHROPIC_API_KEY\",
    \"depth\":    \"tier-4\",
    \"findings\": [$FINDING]
  }" | jq '.jobId'
```

See [REST API](rest-api.md) for the full endpoint reference.

---

## Output envelope

All structured output (`--format json` or via REST API) returns the same envelope shape regardless of tier:

```json
{
  "version":             "1.17.0",
  "provider":            "anthropic",
  "model":               "claude-opus-4-6",
  "depth":               "tier-3",
  "mode":                "full",
  "stack":               "Node.js / Express",
  "summary":             { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0 },
  "patchesApplied":      0,
  "findings": [
    {
      "name":        "SQL Injection",
      "severity":    "HIGH",
      "file":        "src/db.js",
      "line":        42,
      "snippet":     "db.query(userInput)",
      "risk":        "Full database read/write via UNION injection",
      "effort":      "low",
      "cwe":         "CWE-89",
      "patch":       "const stmt = db.prepare('SELECT ...');\nstmt.run(id);",
      "testSnippet": "test('prevents injection', () => { ... });"
    }
  ],
  "likelyFalsePositives": [],
  "remediation":          [],
  "scannedAt":            "2026-03-26T12:00:00.000Z"
}
```

`patchesApplied` is always `0` for tiers 1–3 (no files written). For tier-4 it counts `remediation` entries where `status === "fixed"` — the billable unit.

---

## Ollama (fully local / air-gapped)

```bash
# Pull a code model
ollama pull codellama
ollama serve

# Run tdd-audit against it
npx @lhi/tdd-audit --ai \
  --provider ollama \
  --model codellama \
  --depth tier-1
```

No API key required. Ollama must be running on `http://localhost:11434`.

Ollama does not support the tool-use API, so the audit runs in single-shot mode: the project files are bundled into the prompt rather than explored interactively with tool calls. For best results, use `tier-1` or `tier-2` with Ollama.
