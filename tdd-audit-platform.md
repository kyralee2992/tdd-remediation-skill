# tdd-audit → Platform

## Goal
Evolve the CLI into a programmable security platform: JSON/SARIF output, REST API server, provider-agnostic AI remediation, and GitHub PR integration — all backward-compatible with the existing CLI.

---

## Architecture

```
index.js               CLI entry point (extended, not replaced)
lib/
  scanner.js           existing — untouched
  reporter.js          NEW — toJson() + toSarif() formatters
  config.js            NEW — .tdd-audit.json loader + flag merger
  server.js            NEW — Express REST API
  remediator.js        NEW — provider-agnostic AI client
  github.js            NEW — SARIF upload + PR review comments
```

**Design constraints:**
- Zero new runtime deps for CLI/scan-only path (scanner stays dep-free)
- `express` added only when `serve` mode is active
- AI providers called via `fetch()` — no SDKs, one adapter pattern
- In-memory job store (Map) — no Redis, no external deps
- All new modules get unit + security tests before shipping

---

## Tasks

- [ ] **1. `lib/reporter.js`** — `toJson(findings)` + `toSarif(findings, projectDir)` + `toText(findings)`
  → Verify: `npm test` passes, SARIF output validates against schema

- [ ] **2. `--json` + `--format sarif` flags** — wire into `index.js` scan-only path, keep `--scan` working
  → Verify: `node index.js --scan --json` outputs valid JSON; `--format sarif` outputs SARIF

- [ ] **3. `lib/config.js`** — loads `.tdd-audit.json` from cwd, merges with CLI flags (flags win)
  → Verify: config file sets `output: json`, CLI `--format sarif` overrides it

- [ ] **4. `lib/server.js`** — Express REST API:
  - `GET  /health` → `{ status, version }`
  - `POST /scan`   → `{ path, options }` → `{ findings, summary, duration }`
  - `POST /remediate` → `{ findings, provider, apiKey, model }` → `{ jobId }`
  - `GET  /jobs/:id`  → `{ status, results, diff }`
  → Verify: supertest suite covers all endpoints, auth header required on /scan + /remediate

- [ ] **5. `tdd-audit serve`** — add `serve` subcommand to `index.js`, `--port`, `--api-key`
  → Verify: `node index.js serve --port 3001` starts, `curl /health` returns 200 JSON

- [ ] **6. `lib/remediator.js`** — provider adapter pattern:
  - `callProvider(provider, apiKey, model, prompt)` → diff string
  - Providers: `anthropic`, `openai`, `gemini`, `ollama`
  - `--fix critical|high|all` CLI flag triggers remediator + Red-Green-Refactor loop
  → Verify: mock provider test confirms prompt construction + patch application

- [ ] **7. `lib/github.js`** — GitHub integration:
  - `postSarif(repo, token, sarif)` → uploads to GitHub code scanning
  - `postReviewComments(repo, pr, token, findings)` → inline PR annotations
  - `--github-pr`, `--repo`, `--token` CLI flags
  → Verify: mocked Octokit calls assert correct payloads

- [ ] **8. Security tests for REST API** — `__tests__/security/sec-10-server-auth.test.js`:
  - Missing auth → 401
  - Malformed path in POST /scan → 400 (no path traversal)
  - Oversized body → 413
  → Verify: all three assertions pass

- [ ] **9. Docs + README** — update `docs/` with REST API reference, provider setup, GitHub integration guide
  → Verify: all six docs files updated, README badge bumped

- [ ] **10. Version, tag, publish** — bump to 1.9.0 (minor — new features), tag, push
  → Verify: `npm audit` clean, 153+ tests green, publish workflow succeeds

---

## Done When
- [ ] `node index.js --scan --json` returns structured JSON findings
- [ ] `node index.js serve` starts an authenticated REST API on configurable port
- [ ] `POST /scan` returns JSON findings for any local path
- [ ] `POST /remediate` with a valid provider + API key autonomously patches and returns a diff
- [ ] `--format sarif` output uploads cleanly to GitHub code scanning
- [ ] All existing 153 tests still green + new tests added
- [ ] `npm audit` exits 0

---

## Build Order (critical path)

```
reporter.js (1)
    └─ --json/--format flags (2)
    └─ config.js (3)
            └─ server.js (4)
                    └─ tdd-audit serve (5)
                    └─ security tests (8)
            └─ remediator.js (6)
            └─ github.js (7)
                    └─ docs (9)
                            └─ version + publish (10)
```

Tasks 6 and 7 are parallel after task 3. Tasks 8 and 9 are parallel after task 5.
