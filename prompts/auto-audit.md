# TDD Remediation: Auto-Audit Mode

When invoked in Auto-Audit mode, proactively secure the user's entire repository without waiting for explicit files to be provided.

## Phase 0: Discovery

### 0a. Explore the Architecture
Use `Glob` and `Read` to understand the project structure. Focus on:
- `controllers/`, `routes/`, `api/`, `handlers/` — request entry points
- `services/`, `models/`, `db/`, `repositories/` — data access
- `middleware/`, `utils/`, `helpers/`, `lib/` — shared utilities
- Config files: `*.env`, `config.js`, `settings.py` — secrets and security settings

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

1. **[RED](./red-phase.md)**: Write the exploit test in `__tests__/security/` and run it to prove the vulnerability exists (test must fail).
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
