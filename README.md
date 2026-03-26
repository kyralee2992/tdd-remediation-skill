# @lhi/tdd-audit

> **v1.12.0** — Security skill installer for **Claude Code, Gemini CLI, Cursor, Codex, and OpenCode**. Patches vulnerabilities using a Red-Green-Refactor exploit-test protocol — prove the hole exists, apply the fix, prove it's closed.

## Install

```bash
npx @lhi/tdd-audit
```

On first run the installer:

1. Scans your codebase for **57 vulnerability patterns** across 6 scanner modules and prints a severity-ranked report
2. Scaffolds `__tests__/security/` with a framework-matched exploit test boilerplate
3. Adds `test:security` to `package.json`
4. Creates `.github/workflows/security-tests.yml` with SHA-pinned actions and `npm audit`
5. Installs the `/tdd-audit` skill for your AI agent

### Flags

| Flag | Description |
|---|---|
| `--local` | Install into the current project instead of `~` |
| `--claude` | Use `.claude/` instead of `.agents/` |
| `--with-hooks` | Add a pre-commit hook that blocks commits on failing security tests |
| `--skip-scan` | Skip the vulnerability scan on install |
| `--scan` / `--scan-only` | Scan only — no install, no code changes |
| `--json` | Output findings as JSON |
| `--format sarif` | Output findings as SARIF 2.1.0 (GitHub code scanning) |
| `--config <path>` | Load config from an explicit file path |

### Platform

| Platform | Command |
|---|---|
| Claude Code | `npx @lhi/tdd-audit --local --claude` |
| Gemini CLI / Codex / OpenCode | `npx @lhi/tdd-audit --local` |

## Usage

```text
/tdd-audit
```

The agent detects your stack, presents a CRITICAL → LOW findings report, waits for confirmation, then works through each vulnerability one at a time using Red-Green-Refactor. Pass `--scan` for a report-only run with no code changes.

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
  "output":            "text",
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

## REST API + AI remediation

```bash
# Start the API server
npx @lhi/tdd-audit serve --port 3000 --api-key YOUR_SECRET

# Scan any path → JSON
curl -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer YOUR_SECRET" \
  -d '{"path": "."}' | jq '.summary'

# Use any OpenAI-compatible service (Groq, OpenRouter, Together AI, etc.)
npx @lhi/tdd-audit serve \
  --provider openai \
  --base-url https://api.groq.com/openai/v1 \
  --api-key $GROQ_API_KEY \
  --model llama-3.3-70b-versatile
```

Supported providers: `anthropic` · `openai` · `gemini` · `ollama` (local) · **any OpenAI-compatible endpoint via `--base-url`**

## Output formats

```bash
npx @lhi/tdd-audit --scan --json          # structured JSON
npx @lhi/tdd-audit --scan --format sarif  # GitHub code scanning (inline PR annotations)
npx @lhi/tdd-audit --scan                 # human-readable text (default)
```

## Testing

463 tests across unit, E2E, and security suites:

```bash
npm test                  # full suite
npm run test:unit         # unit tests with coverage (91.6% branch coverage)
npm run test:security     # security regression tests only
npm run test:e2e          # end-to-end REST API tests
```

Security tests cover prompt injection, path traversal, rate limiting, timing-safe auth, job store bounds, SARIF schema, and more. See [__tests__/security/](__tests__/security/) for all 22 regression tests.

## Documentation

| | |
|---|---|
| [REST API](docs/rest-api.md) | Endpoints, auth, rate limiting, trust-proxy, request/response schema |
| [AI Remediation](docs/ai-remediation.md) | Provider setup, `--base-url` for compatible APIs, config file |
| [Scanner](docs/scanner.md) | Architecture, detection logic, false-positive handling |
| [Vulnerability Patterns](docs/vulnerability-patterns.md) | All 34 patterns — descriptions, grep signatures, fix pointers |
| [TDD Protocol](docs/tdd-protocol.md) | Red-Green-Refactor in full, with framework templates for all 6 stacks |
| [Agentic AI Security](docs/agentic-ai-security.md) | ASI01–ASI10 — prompt injection, MCP supply chain, Actions injection |
| [Hardening](docs/hardening.md) | Phase 4 controls — Helmet, CSP, CSRF, rate limiting, gitleaks, SRI |
| [CI/CD](docs/ci-cd.md) | Workflow templates, existing pipeline integration, secret leak prevention |

## License

MIT
