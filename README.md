# @lhi/tdd-audit

> **v1.9.0** — Security skill installer for **Claude Code, Gemini CLI, Cursor, Codex, and OpenCode**. Patches vulnerabilities using a Red-Green-Refactor exploit-test protocol — prove the hole exists, apply the fix, prove it's closed.

## Install

```bash
npx @lhi/tdd-audit
```

On first run the installer:

1. Scans your codebase for **34 vulnerability patterns** and prints a severity-ranked report
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

## REST API + AI remediation

```bash
# Start the API server
npx @lhi/tdd-audit serve --port 3000 --api-key YOUR_SECRET

# Scan any path → JSON
curl -X POST http://localhost:3000/scan \
  -H "Authorization: Bearer YOUR_SECRET" \
  -d '{"path": "."}' | jq '.summary'

# Auto-fix with any AI provider
npx @lhi/tdd-audit --scan --fix critical \
  --provider anthropic --api-key $ANTHROPIC_API_KEY --json
```

Supported providers: `anthropic` · `openai` · `gemini` · `ollama` (local)

## Output formats

```bash
npx @lhi/tdd-audit --scan --json          # structured JSON
npx @lhi/tdd-audit --scan --format sarif  # GitHub code scanning (inline PR annotations)
npx @lhi/tdd-audit --scan                 # human-readable text (default)
```

## Config file

`.tdd-audit.json` in your project root — all CLI flags can be set here:

```json
{
  "port": 3000,
  "output": "json",
  "provider": "anthropic",
  "apiKeyEnv": "ANTHROPIC_API_KEY",
  "severityThreshold": "HIGH"
}
```

## Documentation

| | |
|---|---|
| [REST API](docs/rest-api.md) | Endpoints, auth, request/response schema, curl examples |
| [AI Remediation](docs/ai-remediation.md) | Provider setup, CLI flags, Ollama local mode |
| [Scanner](docs/scanner.md) | Architecture, detection logic, false-positive handling |
| [Vulnerability Patterns](docs/vulnerability-patterns.md) | All 34 patterns — descriptions, grep signatures, fix pointers |
| [TDD Protocol](docs/tdd-protocol.md) | Red-Green-Refactor in full, with framework templates for all 6 stacks |
| [Agentic AI Security](docs/agentic-ai-security.md) | ASI01–ASI10 — prompt injection, MCP supply chain, Actions injection |
| [Hardening](docs/hardening.md) | Phase 4 controls — Helmet, CSP, CSRF, rate limiting, gitleaks, SRI |
| [CI/CD](docs/ci-cd.md) | Workflow templates, existing pipeline integration, secret leak prevention |

## License

MIT
