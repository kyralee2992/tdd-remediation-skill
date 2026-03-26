# @lhi/tdd-audit
![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)
[![tdd-audit](https://img.shields.io/badge/tdd--audit-passing-brightgreen)](https://www.npmjs.com/package/@lhi/tdd-audit) <!-- tdd-audit-badge -->

> **Your AI-generated code is probably vulnerable right now.** SQL injection. Hardcoded secrets. Prompt injection backdoors. The same assistant that built your feature in 30 minutes didn't think twice about security. `tdd-audit` finds the holes, proves they're real, and closes them — every fix backed by a failing test before and a passing test after.

## One command. Proven secure.

```bash
npx @lhi/tdd-audit --local --claude
```

That's it. In seconds you get:

- A severity-ranked findings report (CRITICAL → LOW) with the exact file and line
- Exploit tests that **prove the vulnerability is real** — not theoretical
- Patches that close each hole, verified by a passing test suite
- ≥ 95% test coverage enforced, a README security badge, and a `SECURITY.md` ready for auditors

No security expertise required. No config needed to start.

---

## Why this exists

Vibecoders move fast. AI assistants hallucinate security. The result: apps with SQL injection in the ORM layer, JWT algorithm confusion, hardcoded API keys one `git log` away from leaking, and LLM prompt injection that hands your backend to anyone who knows the trick.

PMs and security officers feel it too — "is this thing actually secure?" has no good answer when there are no tests proving it.

`tdd-audit` gives you the answer. Every vulnerability is proven closed by a test, not just patched and hoped for the best.

---

## Install

```bash
# Claude Code (recommended)
npx @lhi/tdd-audit --local --claude

# Gemini CLI / Codex / OpenCode / Cursor
npx @lhi/tdd-audit --local
```

On first run the installer:

1. Scaffolds `__tests__/security/` with framework-matched exploit test boilerplate
2. Adds `test:security` to `package.json`
3. Creates `.github/workflows/security-tests.yml` — SHA-pinned actions, `npm audit` on every PR
4. Installs the `/tdd-audit` skill in your AI agent

Then open your agent and type `/tdd-audit`. It handles the rest.

### Install flags

| Flag | What it does |
|---|---|
| `--local` | Install into the current project (recommended) |
| `--claude` | Use `.claude/` for Claude Code |
| `--with-hooks` | Block commits that break security tests |
| `--skip-scan` | Skip the initial vulnerability scan |
| `--config <path>` | Load config from a specific path |

---

## What gets caught

100+ patterns across Node.js, Python, Go, React, React Native, Flutter, and Expo — including the AI-specific vulnerabilities that most scanners miss entirely:

**Standard OWASP holes** — SQL/NoSQL/Command injection · Path traversal · Broken auth · XSS · IDOR · Mass assignment · SSRF · Open redirect · XXE · Insecure deserialization · Prototype pollution · Weak crypto · Hardcoded secrets · TLS bypass

**AI / LLM-specific** (the ones that will actually get you hacked in 2025) — LLM prompt injection · Eval of model output · LangChain ShellTool / ExecChain · Unbounded agent loops · MCP credential leakage · GitHub Actions expression injection · Hardcoded provider keys (OpenAI, Anthropic, Gemini, Cohere, Mistral, HuggingFace) · Missing `max_tokens` · Dynamic require from user input · VM sandbox escape · Electron `nodeIntegration: true`

**Vibecoding anti-patterns** — `localStorage` token storage · `Math.random()` for session IDs · `process.env.SECRET || "hardcoded-fallback"` · Silent exception swallowing · Insecure WebSocket URLs

---

## How it works

The full `/tdd-audit` skill run follows Red-Green-Refactor for every finding:

1. **Detect** — scans your stack, scopes patterns to what's actually relevant
2. **Report** — presents a CRITICAL → LOW findings table with plain-language risk and effort estimate. Waits for your sign-off before touching anything
3. **Red** — writes an exploit test that **fails** (proves the hole is real)
4. **Green** — applies the patch (test now passes)
5. **Refactor** — runs the full suite (zero regressions)
6. **Harden** — security headers, rate limiting, `npm audit`, secret scan, production error handling
7. **Coverage gate** — pushes test coverage to ≥ 95% line and branch
8. **Badge + SECURITY.md** — updates your README badge, creates `SECURITY.md` in GitHub Security Advisory format

Nothing is marked done until a test proves it.

---

## For PMs and security officers

You need evidence, not promises. `tdd-audit` produces:

- **Exploit tests** — a failing test per vulnerability, committed to source, proves the hole existed
- **Passing tests** — the fix is proven by the test suite, not just code review
- **`--format report`** — a markdown compliance report with findings table, fix evidence, patch commits, and coverage gate result; ready to attach to SOC 2, ISO 27001, or vendor security questionnaire
- **`--sbom`** — CycloneDX Software Bill of Materials (required for US federal contracts under EO 14028)
- **`SECURITY.md`** — GitHub Security Advisory format with your security contact, supported versions, and hardening summary
- **Webhook + Slack notifications** — findings summary delivered to your security channel on every scan

Configure your security contact in `.tdd-audit.json`:

```json
{
  "security_name":  "Alice Smith",
  "security_email": "security@yourorg.com"
}
```

Both fields are optional — use one, both, or neither. When set, they appear in SECURITY.md, the compliance report, and webhook payloads.

---

## AI Audit (`--ai`)

Let the LLM explore and report on your codebase directly:

```bash
npx @lhi/tdd-audit --ai \
  --provider anthropic \
  --api-key $ANTHROPIC_API_KEY \
  --depth tier-2 \
  --format json
```

### Depth tiers

| Tier | Mode | What you get | Billing unit |
|---|---|---|---|
| `tier-1` | Scan only | File, line, severity, snippet | per report |
| `tier-2` | Scan only | + risk explanation, effort estimate, CWE, OWASP, references | per report |
| `tier-3` | Full audit, read-only | + copy-ready patches and test snippets — you apply manually | per report |
| `tier-4` | Full audit, writes | LLM applies every patch via `write_file` | per applied patch |

```bash
# Fast scan — just the findings
npx @lhi/tdd-audit --ai --depth tier-1 --format json

# Full report with context, no changes made
npx @lhi/tdd-audit --ai --depth tier-2 --format json

# Copy-ready patches — apply yourself
npx @lhi/tdd-audit --ai --depth tier-3 --format json

# Let the LLM fix everything
npx @lhi/tdd-audit --ai --depth tier-4 --allow-writes
```

### AI flags

| Flag | Description |
|---|---|
| `--ai` | Enable LLM agentic audit |
| `--depth tier-1\|2\|3\|4` | Output depth tier (default: `tier-1`) |
| `--allow-writes` | Permit the LLM to write files (auto-enabled for `tier-4`) |
| `--provider <name>` | `anthropic` \| `openai` \| `gemini` \| `ollama` |
| `--api-key <key>` | Provider API key |
| `--model <name>` | Model override (e.g. `claude-opus-4-6`, `gpt-4o`) |
| `--base-url <url>` | Any OpenAI-compatible service |
| `--format json\|sarif\|report` | Structured output format |
| `--verbose` | Print tool call details to stderr |

---

## CI integration

### PR gate — block merges on new findings

```yaml
- run: npx @lhi/tdd-audit@latest --pr --threshold HIGH
```

Exits non-zero if any finding meets or exceeds the threshold. Sub-second — no AI, no agents, pure static scan. Wire into branch protection rules to stop vulnerable code from merging.

### Org-wide posture scan

```bash
npx @lhi/tdd-audit@latest --org my-github-org --format report
```

Scans every repo in the org, produces a cross-org summary and a compliance report. Fires your webhook/Slack with the aggregate payload.

---

## Config file

```bash
npx @lhi/tdd-audit init                      # scaffold .tdd-audit.json
npx @lhi/tdd-audit init --provider anthropic  # with Anthropic defaults
```

`.tdd-audit.json` — everything settable here, CLI flags always win:

```json
{
  "provider":          "anthropic",
  "model":             "claude-opus-4-6",
  "apiKeyEnv":         "ANTHROPIC_API_KEY",
  "severityThreshold": "HIGH",
  "ignore":            ["node_modules", "dist", "coverage"],

  "security_name":     "Alice Smith",
  "security_email":    "security@yourorg.com",

  "webhook_url":       "https://hooks.yourorg.com/security",
  "slack_webhook":     "https://hooks.slack.com/services/...",
  "slack_channel":     "#security-alerts",

  "severity_overrides": {
    "CORS Wildcard": "CRITICAL"
  }
}
```

Full schema → [docs/configuration.md](docs/configuration.md)

---

## REST API

```bash
npx @lhi/tdd-audit serve --port 3000 --api-key YOUR_SECRET
```

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | No | Liveness check |
| `POST` | `/audit/ai` | Yes | LLM audit with depth tiers; returns `jobId` |
| `POST` | `/scan` | Yes | Static scan; returns findings immediately |
| `POST` | `/remediate` | Yes | AI-fix a provided findings list; returns `jobId` |
| `GET` | `/jobs/:id` | Yes | Poll job status |
| `GET` | `/jobs/:id/stream` | Yes | SSE — stream live LLM output |

```bash
# Start an AI audit
curl -X POST http://localhost:3000/audit/ai \
  -H "Authorization: Bearer YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"provider": "anthropic", "apiKey": "sk-ant-...", "depth": "tier-2"}'

# Stream results live
curl -N http://localhost:3000/jobs/<jobId>/stream
```

Supported providers: `anthropic` · `openai` · `gemini` · `ollama` · **any OpenAI-compatible endpoint via `--base-url`**

---

## Testing

```bash
npm test                  # full suite (841 tests)
npm run test:unit         # unit tests with coverage
npm run test:security     # security regression tests only
npm run test:e2e          # end-to-end REST API tests
```

Security tests cover: prompt injection · path traversal · SSRF via webhook and baseUrl · rate limiting · timing-safe auth · XFF bypass · job store bounds · SARIF schema · AI key redaction · coverage skip detection · and more. Every past vulnerability is a permanent regression test.

---

## Documentation

| | |
|---|---|
| [Configuration](docs/configuration.md) | Full schema — all fields, CLI equivalents, payload schemas |
| [REST API](docs/rest-api.md) | Endpoints, auth, rate limiting, depth tiers, targeted apply |
| [AI Remediation](docs/ai-remediation.md) | Provider setup, `--base-url` for compatible APIs |
| [Vulnerability Patterns](docs/vulnerability-patterns.md) | All 100+ patterns — descriptions, grep signatures, fix pointers |
| [TDD Protocol](docs/tdd-protocol.md) | Red-Green-Refactor in full, with framework templates for all 6 stacks |
| [Agentic AI Security](docs/agentic-ai-security.md) | ASI01–ASI10 — prompt injection, MCP supply chain, Actions injection |
| [Hardening](docs/hardening.md) | Phase 4 controls — Helmet, CSP, CSRF, rate limiting, gitleaks, SRI |
| [CI/CD](docs/ci-cd.md) | Workflow templates, existing pipeline integration, secret leak prevention |

---

## License

MIT
