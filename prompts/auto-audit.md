---
name: auto-audit
description: "Auto-Audit mode: discover, report, and remediate vulnerabilities using Red-Green-Refactor."
risk: low
source: personal
date_added: "2024-01-01"
audited_by: lcanady
last_audited: "2026-03-22"
audit_status: safe
---

# TDD Remediation: Auto-Audit Mode

When invoked in Auto-Audit mode, proactively secure the user's entire repository without waiting for explicit files to be provided.

## Phase 0: Discovery

### 0a. Explore the Architecture
Use `Glob` and `Read` to understand the project structure. Focus on:

**Backend / API**
- `controllers/`, `routes/`, `api/`, `handlers/` — request entry points
- `services/`, `models/`, `db/`, `repositories/` — data access
- `middleware/`, `utils/`, `helpers/`, `lib/` — shared utilities
- Config files: `*.env`, `config.js`, `settings.py` — secrets and security settings

**React / Next.js**
- `pages/api/`, `app/api/` — Next.js API routes (check for missing auth)
- `components/`, `app/`, `pages/` — UI components (check for `dangerouslySetInnerHTML`, `eval`)
- `hooks/`, `context/`, `store/` — state management (check for sensitive data leakage)

**React Native / Expo**
- `screens/`, `navigation/`, `app/` — screen components (check `route.params` usage)
- `services/`, `api/`, `utils/` — API calls (check TLS config, token storage)
- `app.json`, `app.config.js` — Expo config (check for embedded keys)

**Flutter / Dart**
- `lib/screens/`, `lib/pages/`, `lib/views/` — UI layer
- `lib/services/`, `lib/api/`, `lib/repositories/` — data layer (check HTTP client config)
- `lib/utils/`, `lib/helpers/` — shared utilities
- `pubspec.yaml` — dependency audit

### 0b. Search for Anti-Patterns
Use `Grep` with the following patterns to surface candidates. Read the matched files to confirm before reporting.

**SQL Injection**
```
`SELECT.*\$\{          # template literal SQL (JS/TS)
"SELECT.*" \+          # string concatenation SQL (Java/Python/JS)
execute\(f"           # f-string SQL (Python)
cursor\.execute\(.*%  # %-formatted SQL (Python)
raw\(                 # Django raw() queries
\.query\(`            # tagged template DB calls
```

**IDOR / Missing Ownership Checks**
```
findById\(req\.       # lookup directly from request params without user scope
params\.id            # request param used in a DB lookup
req\.body\.userId     # trusting client-supplied user ID
findOne\(\{.*id:.*req # DB findOne keyed only to request param
```

**XSS / Unsafe Rendering**
```
innerHTML\s*=         # direct DOM write
dangerouslySetInnerHTML  # React unsafe HTML
\.write\(             # document.write
res\.send\(.*req\.    # reflecting request data directly into response
render_template_string  # Flask dynamic template with user input
```

**Command Injection**
```
exec\(.*req\.         # exec with request data
execSync\(.*req\.     # execSync with request data
shell=True            # Python subprocess with shell=True
child_process         # review all child_process usages
```

**Path Traversal**
```
readFile.*req\.       # file read from request param
sendFile.*req\.       # file send from request param
join.*req\.params     # path.join with user input
open\(.*request\.     # Python file open with request data
```

**Broken Authentication**
```
jwt\.decode\(         # JWT decoded but not verified
verify.*false         # verification disabled
secret.*=.*['"]      # hardcoded secrets
Bearer.*hardcoded    # hardcoded tokens
```

**Missing Rate Limiting**
```
router\.(post|put|delete)  # mutation routes (check for rate-limit middleware)
app\.post\(           # POST handlers (check for rate-limit middleware)
```

**Sensitive Storage (React / React Native / Expo)**
```
AsyncStorage\.setItem.*token    # token stored in unencrypted AsyncStorage
localStorage\.setItem.*token    # token stored in localStorage (XSS-accessible)
AsyncStorage\.setItem.*password # password stored in plain AsyncStorage
SecureStore vs AsyncStorage     # confirm sensitive values use expo-secure-store
```

**TLS / Certificate Bypass**
```
rejectUnauthorized.*false       # Node.js TLS verification disabled
badCertificateCallback.*true    # Dart/Flutter TLS bypass
NODE_TLS_REJECT_UNAUTHORIZED=0  # env-level TLS disable
```

**Hardcoded Secrets (vibecoded apps)**
```
API_KEY\s*=\s*['"][A-Za-z0-9]{20,}   # hardcoded API key in source
PRIVATE_KEY\s*=\s*['"]               # private key in source
SECRET_KEY\s*=\s*['"]                # secret embedded in code
process\.env\.\w+\s*\|\|\s*['"]      # env var with hardcoded fallback
```

**Next.js API Route Auth**
```
export.*async.*handler             # Next.js API route — check for missing auth guard
export default.*req.*res           # pages/api handler — verify authentication
getServerSideProps.*params         # SSR with params — check for injection
```

**React Native / Expo Navigation Injection**
```
route\.params\.\w+.*query          # route param passed to DB/API query
route\.params\.\w+.*fetch          # route param used in fetch URL
navigation\.navigate.*params       # user-controlled navigation params
```

**Flutter / Dart**
```
http\.get\(                         # raw http call — check for TLS config
http\.post\(                        # raw http call — check for TLS config
SharedPreferences.*setString.*token # token in unencrypted SharedPreferences
Platform\.environment\[            # env access in Flutter — check for secrets
```

**SSRF (Server-Side Request Forgery)**
```
fetch\(.*req\.(query|body|params)   # fetch with user-controlled URL
axios\.(get|post)\(.*req\.body      # axios with user-controlled target
got\(.*req\.(query|params)          # got with user-controlled URL
```

**Open Redirect**
```
res\.redirect\(.*req\.(query|body)  # redirecting to user-supplied URL
window\.location.*=.*params\.       # client-side redirect from route params
router\.push\(.*searchParams        # Next.js/RN push with user param
```

**NoSQL Injection**
```
\.find\(\s*req\.(body|query)        # MongoDB find with raw request object
\.findOne\(\s*req\.(body|query)     # MongoDB findOne with raw request object
\$where.*:                          # $where operator (executes JS in Mongo)
```

**Mass Assignment**
```
new.*Model\(.*req\.body             # passing full req.body to constructor
\.create\(.*req\.body               # ORM create with unsanitized body
\.update.*req\.body                 # ORM update with unsanitized body
```

**Prototype Pollution**
```
_\.merge\(.*req\.(body|query)       # lodash merge with user input
deepmerge\(.*req\.(body|query)      # deepmerge with user input
Object\.assign\(\{\}.*req\.body     # Object.assign from user input
```

**Weak Cryptography**
```
createHash\(['"]md5['"]             # MD5 for anything security-related
createHash\(['"]sha1['"]            # SHA1 for anything security-related
md5\(.*password                     # MD5-hashed password
sha1\(.*password                    # SHA1-hashed password
```

**Missing Security Headers / Rate Limiting**
```
app\.(use|listen)                   # check: is helmet() present before routes?
router\.(post|put|delete)           # mutation routes — check for rateLimit middleware
app\.post\('/login                  # login route — must have rate limit
app\.post\('/register               # register route — must have rate limit
```

**CORS Misconfiguration**
```
cors\(\{.*origin.*\*                # wildcard CORS origin
Access-Control-Allow-Origin.*\*     # wildcard CORS header
```

**Template Injection**
```
res\.render\(.*req\.(params|query)  # user-controlled template name
ejs\.render\(.*req\.body            # ejs render with user input
pug\.render\(.*req\.body            # pug render with user input
```

**Cleartext Traffic / XXE**
```
baseURL.*=.*['"]http://(?!localhost) # non-HTTPS API base URL
noent.*:.*true                      # XML entity expansion enabled
resolve_entities.*True              # Python lxml entity expansion
```

**Dependency Audit**
```
# Run manually — not grep-based:
# npm audit --audit-level=high
# pip-audit
# govulncheck ./...
# bundle audit
```

### 0c. Present Findings
Before touching any code, output a structured **Audit Report** with this format:

```
## Audit Findings

### CRITICAL
- [ ] [SQLi] `src/routes/users.js:34` — raw template literal in SELECT query
- [ ] [IDOR] `src/controllers/docs.js:87` — findById(req.params.id) with no ownership check

### HIGH
- [ ] [XSS] `src/api/comments.js:52` — req.body.content reflected via res.send()
- [ ] [CmdInj] `src/utils/export.js:19` — exec() called with req.body.filename

### MEDIUM
- [ ] [PathTraversal] `src/routes/files.js:41` — path.join with req.params.name, no bounds check
- [ ] [BrokenAuth] `src/middleware/auth.js:12` — JWT decoded without signature verification

### LOW / INFORMATIONAL
- [ ] [RateLimit] `src/routes/auth.js` — /login endpoint has no rate limiting
```

Ask the user to confirm the list before beginning remediation. If they say "fix all" or "proceed", work through them top-down (CRITICAL first).

---

## Phase 1–3: Remediation Engine

For **each** confirmed vulnerability, rigorously apply the RED-GREEN-REFACTOR protocol in order:

1. **[RED](./red-phase.md)**: Write the exploit test in the project's security test directory (e.g., `tests/security/`, `__tests__/security/`, `test/security/` — wherever the installer scaffolded the boilerplate) and run it to prove the vulnerability exists (test must fail).
2. **[GREEN](./green-phase.md)**: Apply the targeted patch. Run the exploit test — it must now pass.
3. **[REFACTOR](./refactor-phase.md)**: Run the full test suite. All tests must be green before moving on.

**Do not move to the next vulnerability until the current one is fully remediated and all tests pass.**

After all vulnerabilities are addressed, output a final **Remediation Summary**:

```
## Remediation Summary

| Vulnerability | File | Status | Test File |
|---|---|---|---|
| SQLi | src/routes/users.js:34 | ✅ Fixed | __tests__/security/sqli-users.test.js |
| IDOR | src/controllers/docs.js:87 | ✅ Fixed | __tests__/security/idor-docs.test.js |
| XSS  | src/api/comments.js:52  | ✅ Fixed | __tests__/security/xss-comments.test.js |
```

---

## Agentic AI Security (ASI01–ASI10)

When the project contains AI agent code, MCP configurations, CLAUDE.md files, or tool-calling patterns, also scan for agentic-specific vulnerabilities. These can be harder to spot than traditional web vulns but carry severe consequences (data exfiltration via tool abuse, agent hijacking, supply chain via MCP).

### ASI01 — Prompt Injection via Tool Output
**What**: Malicious text in tool results (web scrapes, file reads, search results) that instructs the agent to perform unauthorized actions.
**Grep for**:
```
fetch\(.*then.*res\.text         # agent reading raw web content into prompt
readFile.*utf8.*then             # file content fed directly to model
tool_result.*content             # MCP tool output injected into context
```
**Fix**: Sanitize tool outputs before injecting into prompt context. Never trust tool result content as instructions.

### ASI02 — CLAUDE.md / Instructions File Injection
**What**: Attacker-controlled files (CLAUDE.md, .cursorrules, system prompts) that override the agent's behavior or extract secrets.
**Grep for**:
```
CLAUDE\.md                       # ensure project CLAUDE.md doesn't accept untrusted input
\.cursorrules                    # check cursor rules file for malicious overrides
system_prompt.*file              # system prompt loaded from a file path
```
**Fix**: CLAUDE.md must be under version control and reviewed on every commit. Never load system prompts from user-supplied paths.

### ASI03 — MCP Server Supply Chain Risk
**What**: MCP servers installed via `npx` or un-pinned package references that can execute arbitrary code in the agent's context.
**Grep for**:
```
mcpServers                       # review all MCP server configurations
npx.*mcp                         # npx-executed MCP servers (not pinned)
"command".*"npx"                 # dynamic npx MCP invocations
```
**Fix**: Pin all MCP server packages to exact versions. Prefer locally-installed servers over npx. Review server source before installation.

### ASI04 — Excessive Tool Permissions
**What**: Agent granted filesystem write, shell exec, or network send permissions when the task only requires read access.
**Grep for**:
```
allow.*Write.*true               # broad write permissions granted
bash.*permission.*allow          # shell execution permitted
tools.*\["bash"                  # bash tool included in agent tool list
```
**Fix**: Apply principle of least privilege. Grant only the minimum tool permissions required for the task.

### ASI05 — Sensitive Data in Tool Calls
**What**: Agent passes secrets, PII, or auth tokens to external tools (web search, APIs) where they may be logged or leaked.
**Grep for**:
```
tool_call.*password              # password in tool argument
tool_call.*token                 # token passed to external tool
messages.*secret                 # secret embedded in model messages
```
**Fix**: Scrub secrets from all tool arguments. Use environment variables rather than embedding secrets in prompts.

### ASI06 — Unvalidated Agent Action Execution
**What**: Agent executes shell commands, file writes, or API calls without confirming with the user when the action has significant side effects.
**Grep for**:
```
exec.*tool_result                # shell exec driven by tool output
writeFile.*agent                 # agent writing files autonomously
http\.post.*tool_call            # agent making POST requests without confirmation
```
**Fix**: For irreversible or high-blast-radius actions, the agent must confirm with the user before executing.

### ASI07 — Insecure Direct Agent Communication
**What**: Agent-to-agent messages that trust the calling agent's identity without verification, enabling privilege escalation.
**Grep for**:
```
agent_message.*role.*user        # sub-agent message injected as user role
from_agent.*trust                # inter-agent trust without verification
orchestrator.*execute            # orchestrator passing actions directly
```
**Fix**: Treat messages from sub-agents with the same skepticism as user input. Validate before acting.

### ASI08 — GitHub Actions Command Injection
**What**: User-controlled input (PR title, branch name, issue body) injected into GitHub Actions `run:` steps via `${{ github.event.* }}`.
**Grep for** (in `.github/workflows/*.yml`):
```
\$\{\{ github\.event\.pull_request\.title
\$\{\{ github\.event\.issue\.body
\$\{\{ github\.head_ref
\$\{\{ github\.event\.comment\.body
run:.*\$\{\{                     # inline expression in shell step
```
**Fix**: Never interpolate `github.event.*` directly into `run:` steps. Use intermediate env vars:
```yaml
env:
  TITLE: ${{ github.event.pull_request.title }}
run: echo "$TITLE"               # safe — expanded by shell, not by Actions interpolation
```

### ASI09 — Unpinned GitHub Actions (Supply Chain)
**What**: Using `@v4` or `@main` action refs instead of full commit SHAs. A compromised action tag can exfiltrate secrets or inject malicious code.
**Grep for** (in `.github/workflows/*.yml`):
```
uses:.*@v\d                      # mutable version tag
uses:.*@main                     # mutable branch ref
uses:.*@master                   # mutable branch ref
```
**Fix**: Pin every `uses:` to a full commit SHA with a comment:
```yaml
uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
```

### ASI10 — Secrets in Workflow Environment
**What**: Secrets printed to logs, passed as positional arguments, or embedded in URLs in CI workflows.
**Grep for** (in `.github/workflows/*.yml`):
```
echo.*secrets\.                  # secret echoed to log
run:.*\$\{\{ secrets\.           # secret interpolated inline into run step
curl.*\$\{\{ secrets\.           # secret in curl URL (leaks in logs)
```
**Fix**: Always pass secrets as environment variables, never inline:
```yaml
env:
  TOKEN: ${{ secrets.NPM_TOKEN }}
run: npm publish
```
