# Configuration Reference

All `tdd-audit` behaviour is controlled by `.tdd-audit.json` at your repo root. CLI flags override file config; file config overrides built-in defaults.

Generate a starter file:
```bash
npx @lhi/tdd-audit@latest init
npx @lhi/tdd-audit@latest init --provider anthropic
```

---

## Full schema

```jsonc
{
  // ── Core ──────────────────────────────────────────────────────────────────
  "output":            "text",      // "text" | "json" | "sarif" | "report"
  "severityThreshold": "LOW",       // minimum severity to include: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  "ignore":            [],          // path prefixes to skip: ["node_modules", "dist"]
  "port":              3000,        // port for `tdd-audit serve`
  "serverApiKey":      null,        // required on REST API calls; falls back to TDD_AUDIT_API_KEY env var

  // ── AI provider ───────────────────────────────────────────────────────────
  "provider":  "anthropic",         // "anthropic" | "openai" | "gemini" | "ollama"
  "model":     "claude-opus-4-6",
  "apiKeyEnv": "ANTHROPIC_API_KEY", // env var to read the key from
  "baseUrl":   null,                // override for OpenAI-compatible providers

  // ── Branding ──────────────────────────────────────────────────────────────
  // For wrapper/rebranded distributions. See docs/extensibility.md.
  "org":          "Daily Caller",
  "project":      "my-project",
  "badge_label":       "dc-audit",                   // replaces "tdd-audit" in the shields.io badge
  "tdd_site":          "https://security.example.com", // replaces npm link in badge + SARIF
  "security_name":     "Alice Smith",                   // name of the security contact — stamped into SECURITY.md, compliance reports, and webhook payloads
  "security_email":    "security@example.com",           // email for the vulnerability reporting address in SECURITY.md and payloads

  // ── Policy as code ────────────────────────────────────────────────────────
  // Override the default severity for any named pattern.
  // Useful when a pattern's default severity doesn't match your org's risk model.
  "severity_overrides": {
    "CORS Wildcard":   "CRITICAL",  // default: MEDIUM
    "Sensitive Log":   "HIGH",      // default: MEDIUM
    "Cleartext Traffic": "HIGH"     // default: MEDIUM
  },

  // ── Notifications ─────────────────────────────────────────────────────────
  // Fired when a scan completes. Both can be set simultaneously.
  "webhook_url":   "https://hooks.example.com/tdd-audit",
  // POST body: { project, timestamp, summary: { critical, high, medium, low }, findings: [...] }

  "slack_webhook": "https://hooks.slack.com/services/...",
  "slack_channel": "#security",     // optional override; uses webhook default if absent

  // ── Workflow integration ───────────────────────────────────────────────────
  "open_pr":      true,   // open a GitHub PR per finding instead of committing directly
  "github_token": null,   // falls back to GITHUB_TOKEN env var
  "github_repo":  null,   // "owner/repo" — auto-detected from git remote if null

  // ── CI / scheduled modes ──────────────────────────────────────────────────
  "pr_mode":   false,     // lightweight static scan only — fast, designed for PR gates
  "org_scan":  null,      // "my-github-org" — scan all repos in the org
  "schedule":  null,      // cron expression for external schedulers: "0 2 * * *"

  // ── Output additions ──────────────────────────────────────────────────────
  "sbom":   false,    // generate CycloneDX SBOM alongside the audit
  "report": false,    // generate human-readable compliance report (markdown)
  "watch":  false,    // re-scan affected files on save (watch mode)

  // ── Secret rotation ───────────────────────────────────────────────────────
  "rotate_secrets": false,  // when a hardcoded key is detected, prompt to rotate via provider API

  // ── Extensibility ─────────────────────────────────────────────────────────
  // See docs/extensibility.md for full documentation.
  "pattern_repos":    [],
  "extra_skill_dirs": [],
  "extra_repos":      [],
  "mcp_services":     [],
  "extra_domains":    []
}
```

---

## CLI flag equivalents

| Config key | CLI flag |
|---|---|
| `output: "json"` | `--json` or `--format json` |
| `output: "sarif"` | `--format sarif` |
| `output: "report"` | `--format report` |
| `pr_mode: true` | `--pr` |
| `org_scan: "myorg"` | `--org myorg` |
| `open_pr: true` | `--open-pr` |
| `sbom: true` | `--sbom` |
| `watch: true` | `--watch` |
| `report: true` | `--report` |
| `rotate_secrets: true` | `--rotate-secrets` |
| `provider: "openai"` | `--provider openai` |
| `model: "gpt-4o"` | `--model gpt-4o` |
| `severityThreshold: "HIGH"` | `--threshold HIGH` |

CLI flags always win over file config.

---

## Policy as code

`severity_overrides` lets you redefine what severity means for your org without forking the scanner. The key is the exact pattern name from the [vulnerability patterns reference](./vulnerability-patterns.md).

```json
"severity_overrides": {
  "CORS Wildcard": "CRITICAL"
}
```

This is applied before findings are reported, before notifications fire, and before PR gates are evaluated. A pattern overridden to `CRITICAL` will block a PR merge just like any built-in CRITICAL.

---

## Notifications

Both `webhook_url` and `slack_webhook` fire after every scan (CLI, `--ai`, and `POST /scan`).

**Webhook payload:**
```json
{
  "project":   "my-project",
  "org":       "My Org",
  "timestamp": "2026-03-26T12:00:00Z",
  "duration_ms": 4200,
  "summary":   { "critical": 1, "high": 3, "medium": 2, "low": 0 },
  "findings":  [ ... ]
}
```

**Slack message format:**
```
🔴 tdd-audit — my-project
1 critical · 3 high · 2 medium
Run /caller-audit to remediate.
```

---

## PR mode (`--pr`)

Designed for CI PR gates. Runs only the static scanner — no AI agents, no RAG, no fixes. Completes in under a second.

```yaml
- run: npx @lhi/tdd-audit@latest --pr --threshold HIGH
```

Exits non-zero if any finding meets or exceeds `severityThreshold`. Wire into your branch protection rules to block merges automatically.

Use `severity_overrides` to tune what counts as a blocker for your stack.

---

## Auto-fix PR (`--open-pr`)

Instead of committing fixes directly to the working branch, opens a GitHub PR per finding. Each PR contains:
- The exploit test (Red)
- The patch (Green)
- A description linking to the vulnerability pattern

Requires `GITHUB_TOKEN` in the environment or `github_token` in config.

---

## Watch mode (`--watch`)

```bash
npx @lhi/tdd-audit@latest --watch
```

Re-runs the static scanner on any modified file on save. Reports new findings immediately in the terminal. Does not run agents or apply fixes — use `/caller-audit` for that.

---

## SBOM (`--sbom`)

Generates a [CycloneDX](https://cyclonedx.org/) Software Bill of Materials in JSON format alongside the audit report. Output to `sbom.json` in the project root.

Required for US federal contracts (EO 14028), increasingly required in enterprise vendor questionnaires.

---

## Compliance report (`--format report` / `--report`)

Generates a markdown report suitable for attaching to a SOC 2 audit, ISO 27001 evidence package, or vendor security questionnaire. Includes:

- Findings summary table (severity, location, status)
- Fix evidence (exploit test name, patch commit, suite result)
- Coverage gate result
- Hardening controls applied
- SBOM reference (if generated)
- Timestamp and auditor (org/project from config)

---

## Org scan (`--org`)

```bash
npx @lhi/tdd-audit@latest --org my-github-org --format report
```

Discovers all repos in a GitHub org, runs `--pr` mode on each, and produces a cross-org summary:

```
my-github-org security posture — 2026-03-26

✅ repo-a     0 critical · 0 high
⚠️  repo-b     0 critical · 2 high
🔴 repo-c     1 critical · 4 high

3 repos scanned · 1 critical · 6 high total
```

Fires `webhook_url` and `slack_webhook` with the aggregate payload if configured.

---

## Secret rotation (`--rotate-secrets`)

When a hardcoded API key is detected, prompts to rotate it via the provider's API. Supported providers:

| Secret type | Rotation method |
|---|---|
| OpenAI key (`sk-...`) | OpenAI API — revoke + generate new key |
| Anthropic key (`sk-ant-...`) | Anthropic console link + clipboard |
| GitHub token | GitHub API — revoke token |
| Supabase service key | Supabase API — regenerate |

After rotation, updates the relevant `.env` file and removes the hardcoded value from source. The old key is invalidated whether you commit the change or not.
