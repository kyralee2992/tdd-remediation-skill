# AI Remediation

Pass a provider and API key to have tdd-audit autonomously generate exploit tests, patches, and regression checks for each finding — no agent required.

---

## CLI usage

```bash
# Scan and auto-fix all CRITICAL findings via Anthropic
npx @lhi/tdd-audit --scan --fix critical \
  --provider anthropic \
  --api-key $ANTHROPIC_API_KEY

# Fix everything, use a specific model
npx @lhi/tdd-audit --scan --fix all \
  --provider openai \
  --model gpt-4o \
  --api-key $OPENAI_API_KEY \
  --json
```

## REST API usage

```bash
# 1. Scan and get findings
FINDINGS=$(curl -s -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer $SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"path": "."}' | jq '.findings')

# 2. Submit remediation job
JOB=$(curl -s -X POST http://localhost:3000/remediate \
  -H "Authorization: Bearer $SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"findings\": $FINDINGS, \"provider\": \"anthropic\", \"apiKey\": \"$ANTHROPIC_API_KEY\", \"severity\": \"HIGH\"}")

JOB_ID=$(echo $JOB | jq -r '.jobId')

# 3. Poll for results
curl -s "http://localhost:3000/jobs/$JOB_ID" \
  -H "Authorization: Bearer $SERVER_KEY" | jq '.status'
```

---

## Supported providers

| Provider | `--provider` | Default model | Key env var |
|---|---|---|---|
| Anthropic | `anthropic` | `claude-opus-4-6` | `ANTHROPIC_API_KEY` |
| OpenAI | `openai` | `gpt-4o` | `OPENAI_API_KEY` |
| Google Gemini | `gemini` | `gemini-2.0-flash` | `GEMINI_API_KEY` |
| Ollama (local) | `ollama` | `llama3` | — |

---

## Config file

```json
{
  "provider": "anthropic",
  "model": "claude-opus-4-6",
  "apiKeyEnv": "ANTHROPIC_API_KEY"
}
```

`apiKeyEnv` lets you name the environment variable to read the key from, so no key is ever written to disk.

---

## What the model returns

For each finding the remediator sends a structured prompt and expects back:

```json
{
  "exploitTest": {
    "filename": "__tests__/security/xss-comments.test.js",
    "content": "..."
  },
  "patch": {
    "filename": "src/routes/comments.js",
    "diff": "--- a/src/routes/comments.js\n+++ ..."
  },
  "refactorChecks": ["npm test", "npm run test:security"]
}
```

The result is returned as-is from the API — review and apply patches manually or pipe into your own automation.

---

## Ollama (fully local / air-gapped)

```bash
# Start Ollama with a code model
ollama pull codellama
ollama serve

# Run tdd-audit against it
npx @lhi/tdd-audit --scan --fix high \
  --provider ollama \
  --model codellama
```

No API key required. Ollama must be running on `http://localhost:11434`.
