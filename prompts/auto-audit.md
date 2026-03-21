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
