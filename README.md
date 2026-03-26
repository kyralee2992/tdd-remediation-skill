# @lhi/tdd-audit
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)
[![tdd-audit](https://img.shields.io/badge/tdd--audit-passing-brightgreen)](https://www.npmjs.com/package/@lhi/tdd-audit) <!-- tdd-audit-badge -->

> **v1.17.0** — AI-powered security audit skill for **Claude Code, Gemini CLI, Cursor, Codex, and OpenCode**. Four output depth tiers let you choose between a fast scan report, a rich findings report, copy-ready patches, or fully automated patch application — all backed by an agentic LLM with tool use.

## Install

```bash
npx @lhi/tdd-audit
```

On first run the installer:

1. Scaffolds `__tests__/security/` with a framework-matched exploit test boilerplate
2. Adds `test:security` to `package.json`
3. Creates `.github/workflows/security-tests.yml` with SHA-pinned actions and `npm audit`
4. Installs the `/tdd-audit` skill for your AI agent

### Flags

| Flag | Description |
|---|---|
| `--local` | Install into the current project instead of `~` |
| `--claude` | Use `.claude/` instead of `.agents/` |
| `--with-hooks` | Add a pre-commit hook that blocks commits on failing security tests |
| `--skip-scan` | Skip the vulnerability scan on install |
| `--config <path>` | Load config from an explicit file path |

### Platform

| Platform | Command |
|---|---|
| Claude Code | `npx @lhi/tdd-audit --local --claude` |
| Gemini CLI / Codex / OpenCode | `npx @lhi/tdd-audit --local` |

## AI Audit (`--ai`)

```bash
npx @lhi/tdd-audit --ai \
  --provider anthropic \
  --api-key $ANTHROPIC_API_KEY \
  --depth tier-2 \
  --format json
```

The `--ai` flag triggers a full agentic audit: the LLM explores your codebase using `read_file`, `list_files`, and `search_in_files` tool calls, then produces a structured findings report shaped by `--depth`.

### Depth tiers

| Tier | Mode | Output | Billing unit |
|---|---|---|---|
| `tier-1` | scan-only | `name`, `severity`, `file`, `line`, `snippet` | per report |
| `tier-2` | scan-only | + `risk`, `effort`, `cwe`, `owasp`, `references` | per report |
| `tier-3` | full audit, read-only | + `patch` (copy-ready), `testSnippet` | per report |
| `tier-4` | full audit, writes enabled | LLM applies patches via `write_file`; `patchesApplied` in envelope | per applied patch |

```bash
# Minimal scan report
npx @lhi/tdd-audit --ai --depth tier-1 --format json

# Rich report with CWE/OWASP/references — no changes made
npx @lhi/tdd-audit --ai --depth tier-2 --format json

# Copy-ready patches in every finding — apply manually
npx @lhi/tdd-audit --ai --depth tier-3 --format json

# Let the LLM apply the patches for you
npx @lhi/tdd-audit --ai --depth tier-4 --allow-writes

# Targeted apply: apply one specific patch from a prior tier-3 report
# (via REST API — see docs/rest-api.md)
```

### AI flags

| Flag | Description |
|---|---|
| `--ai` | Enable LLM agentic audit |
| `--depth tier-1\|tier-2\|tier-3\|tier-4` | Output depth tier (default: `tier-1`) |
| `--allow-writes` | Permit the LLM to write files (auto-enabled for `tier-4`) |
| `--provider <name>` | `anthropic` \| `openai` \| `gemini` \| `ollama` |
| `--api-key <key>` | Provider API key |
| `--model <name>` | Model override (e.g. `claude-opus-4-6`, `gpt-4o`) |
| `--base-url <url>` | Base URL for any OpenAI-compatible service |
| `--format json\|sarif` | Structured output format (default: streaming text) |
| `--verbose` | Print tool call details to stderr |

## Config file

Scaffold a starter config with a single command:

```bash
npx @lhi/tdd-audit init
# or at a custom path:
npx @lhi/tdd-audit init ~/configs/my-audit.json
```

`.tdd-audit.json` — all CLI flags settable here, loaded automatically from your project root:

```json
{
  "provider":          "openai",
  "model":             "gpt-4o",
  "apiKeyEnv":         "OPENAI_API_KEY",
  "baseUrl":           null,
  "output":            "json",
  "severityThreshold": "LOW",
  "port":              3000,
  "serverApiKey":      null,
  "trustProxy":        false,
  "ignore":            ["node_modules", "dist", "build", "coverage"]
}
```

Point to a config anywhere with `--config`:

```bash
npx @lhi/tdd-audit serve --config ~/configs/prod-audit.json
```

## REST API

```bash
# Start the API server
npx @lhi/tdd-audit serve --port 3000 --api-key YOUR_SECRET

# AI audit — returns jobId immediately
curl -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"provider": "anthropic", "apiKey": "sk-ant-...", "depth": "tier-2"}' \
  | jq '.jobId'

# Poll job status
curl http://localhost:3000/jobs/<jobId>

# Or stream real-time LLM output via SSE
curl -N http://localhost:3000/jobs/<jobId>/stream

# Targeted apply: re-apply a specific patch from a tier-3 report
curl -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "anthropic",
    "apiKey": "sk-ant-...",
    "depth": "tier-4",
    "findings": [{ "name": "SQL Injection", "file": "src/db.js", "line": 10, "patch": "..." }]
  }'

# Use any OpenAI-compatible service (Groq, OpenRouter, Together AI, etc.)
npx @lhi/tdd-audit serve \
  --provider openai \
  --base-url https://api.groq.com/openai/v1 \
  --api-key $GROQ_API_KEY \
  --model llama-3.3-70b-versatile
```

Supported providers: `anthropic` · `openai` · `gemini` · `ollama` (local) · **any OpenAI-compatible endpoint via `--base-url`**

### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | No | Version + liveness check |
| `POST` | `/audit/ai` | Yes | Agentic LLM audit with depth tiers; returns `jobId` |
| `POST` | `/remediate` | Yes | AI-fix a provided findings list; returns `jobId` |
| `POST` | `/audit` | Yes | Static scan + AI remediation pipeline; returns `jobId` |
| `GET` | `/jobs/:id` | Yes | Poll job status |
| `GET` | `/jobs/:id/stream` | Yes | SSE stream — real-time job progress |

## Agent skill

```text
/tdd-audit
```

The agent detects your stack, presents a CRITICAL → LOW findings report, waits for confirmation, then works through each vulnerability one at a time using Red-Green-Refactor (prove the hole exists, apply the fix, prove it's closed). Enforces ≥ 95% test coverage, README badge, and SECURITY.md on every audit.

## Testing

791 tests across unit, E2E, and security suites:

```bash
npm test                  # full suite
npm run test:unit         # unit tests with coverage (95.6% branch coverage)
npm run test:security     # security regression tests only
npm run test:e2e          # end-to-end REST API tests
```

Security tests cover prompt injection, path traversal, rate limiting, timing-safe auth, job store bounds, SARIF schema, and more. See [__tests__/security/](__tests__/security/) for all regression tests.

## Documentation

| | |
|---|---|
| [REST API](docs/rest-api.md) | Endpoints, auth, rate limiting, depth tiers, targeted apply |
| [AI Remediation](docs/ai-remediation.md) | Provider setup, `--base-url` for compatible APIs, config file |
| [Vulnerability Patterns](docs/vulnerability-patterns.md) | All 57 patterns — descriptions, grep signatures, fix pointers |
| [TDD Protocol](docs/tdd-protocol.md) | Red-Green-Refactor in full, with framework templates for all 6 stacks |
| [Agentic AI Security](docs/agentic-ai-security.md) | ASI01–ASI10 — prompt injection, MCP supply chain, Actions injection |
| [Hardening](docs/hardening.md) | Phase 4 controls — Helmet, CSP, CSRF, rate limiting, gitleaks, SRI |
| [CI/CD](docs/ci-cd.md) | Workflow templates, existing pipeline integration, secret leak prevention |

## License

MIT
