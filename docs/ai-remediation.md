# AI Remediation

Pass a provider and API key to have tdd-audit autonomously generate exploit tests, patches, and regression checks for each finding — no agent required.

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
npx @lhi/tdd-audit serve
```

Point to a config at any path:

```bash
npx @lhi/tdd-audit serve --config ~/configs/my-audit.json
```

---

## CLI flags

```bash
# Anthropic
npx @lhi/tdd-audit serve \
  --provider anthropic \
  --api-key $ANTHROPIC_API_KEY

# OpenAI
npx @lhi/tdd-audit serve \
  --provider openai \
  --api-key $OPENAI_API_KEY \
  --model gpt-4o-mini
```

---

## OpenAI-compatible services

Any service that exposes the OpenAI chat completions API works via `--base-url`.
The API key is sent in the `Authorization: Bearer` header — never in the URL.

```bash
# Groq (fast inference)
npx @lhi/tdd-audit serve \
  --provider openai \
  --base-url https://api.groq.com/openai/v1 \
  --model llama-3.3-70b-versatile \
  --api-key $GROQ_API_KEY

# OpenRouter (access 200+ models)
npx @lhi/tdd-audit serve \
  --provider openai \
  --base-url https://openrouter.ai/api/v1 \
  --model meta-llama/llama-3.3-70b-instruct \
  --api-key $OPENROUTER_API_KEY

# Together AI
npx @lhi/tdd-audit serve \
  --provider openai \
  --base-url https://api.together.xyz/v1 \
  --model mistralai/Mixtral-8x7B-Instruct-v0.1 \
  --api-key $TOGETHER_API_KEY

# LM Studio / vLLM / llama.cpp (fully local)
npx @lhi/tdd-audit serve \
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
# 1. Scan and get findings
FINDINGS=$(curl -s -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer $SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"path": "."}' | jq '.findings')

# 2. Submit remediation job (using Groq via --base-url)
JOB=$(curl -s -X POST http://localhost:3000/remediate \
  -H "Authorization: Bearer $SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"findings\": $FINDINGS,
    \"provider\": \"openai\",
    \"apiKey\": \"$GROQ_API_KEY\",
    \"baseUrl\": \"https://api.groq.com/openai/v1\",
    \"model\": \"llama-3.3-70b-versatile\",
    \"severity\": \"HIGH\"
  }")

JOB_ID=$(echo $JOB | jq -r '.jobId')

# 3. Poll for results
curl -s "http://localhost:3000/jobs/$JOB_ID" \
  -H "Authorization: Bearer $SERVER_KEY" | jq '.status'
```

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
# Pull a code model
ollama pull codellama
ollama serve

# Run tdd-audit against it
npx @lhi/tdd-audit serve \
  --provider ollama \
  --model codellama
```

No API key required. Ollama must be running on `http://localhost:11434`.
