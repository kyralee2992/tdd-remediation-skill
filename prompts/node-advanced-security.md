# Node.js Advanced Security Companion — Detection & Repair Guide

This guide covers Node.js/Express attack surfaces beyond the OWASP Top 10 basics.
Apply these patterns during the Explore and Audit phases.

---

## 1. Timing Oracle Attack (Non-Constant-Time String Comparison)

**What it is:** Using `===` or `==` to compare tokens, passwords, or HMACs allows an attacker
to infer the correct value one byte at a time by measuring response latency.

**Detection — look for:**
- `token === req.headers.authorization`
- `secret == providedKey`
- `apiKey === process.env.API_KEY`
- Any `===` comparison where one operand is from `req.*` and the other is a secret

**Repair:**
```javascript
const crypto = require('crypto');
function timingSafeEqual(a, b) {
  const ha = crypto.createHmac('sha256', 'cmp').update(String(a)).digest();
  const hb = crypto.createHmac('sha256', 'cmp').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
if (!timingSafeEqual(req.headers.authorization, `Bearer ${process.env.API_KEY}`)) {
  return res.status(401).json({ error: 'Unauthorized' });
}
```

**Test snippet:**
```javascript
test('responds in constant time for wrong vs missing token', async () => {
  const t1 = Date.now(); await request(app).get('/api').set('Authorization', 'Bearer wrong'); const d1 = Date.now() - t1;
  const t2 = Date.now(); await request(app).get('/api').set('Authorization', `Bearer ${'x'.repeat(100)}`); const d2 = Date.now() - t2;
  expect(Math.abs(d1 - d2)).toBeLessThan(50); // within 50 ms
});
```

---

## 2. Host Header Injection

**What it is:** `req.headers.host` (or `req.hostname`) is used to construct password-reset
links, email confirmation URLs, or redirects. An attacker supplies a forged `Host:` header,
redirecting victims to an attacker-controlled domain.

**Detection — look for:**
- `req.headers['host']`, `req.hostname`, `req.get('host')`
- Used in string concatenation building a URL for email, redirect, or link

**Repair:** Use a hard-coded trusted base URL from config — never trust `Host:` header:
```javascript
const BASE_URL = process.env.BASE_URL; // e.g. 'https://app.example.com'
if (!BASE_URL) throw new Error('BASE_URL env var required');
const resetLink = `${BASE_URL}/reset?token=${token}`;
```

---

## 3. Headless Browser SSRF (Puppeteer / Playwright / wkhtmltopdf)

**What it is:** A headless browser is instructed to navigate to a URL derived from user input.
The browser runs server-side, so it can access internal services, cloud metadata endpoints
(`169.254.169.254`), or local network resources.

**Detection — look for:**
- `page.goto(req.query.url)`, `page.navigate(req.body.url)`
- `wkhtmltopdf(userUrl, ...)`, `page.goto(url)` where `url` comes from request

**Repair:**
```javascript
const { URL } = require('url');
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const BLOCKED_HOSTS = /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/;

function assertSafeUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('Invalid URL'); }
  if (!ALLOWED_PROTOCOLS.has(u.protocol)) throw new Error(`Protocol not allowed: ${u.protocol}`);
  if (BLOCKED_HOSTS.test(u.hostname)) throw new Error(`Blocked host: ${u.hostname}`);
}
```

---

## 4. Body Parser DoS (No Size Limit)

**What it is:** `express.json()` or `bodyParser.json()` with no `limit` option will buffer
arbitrarily large payloads into memory, enabling a DoS attack with a single large request.

**Detection — look for:**
- `express.json()` — no argument
- `express.urlencoded()` — no argument
- `bodyParser.json()` — no `limit:` property in the options object

**Repair:**
```javascript
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
```

---

## 5. vm2 Deprecated — Sandbox Escape

**What it is:** The `vm2` library has been publicly abandoned with unfixed sandbox-escape CVEs
(CVE-2023-29017, CVE-2023-32314). Any code using `require('vm2')` is vulnerable to full host
compromise from untrusted code execution.

**Detection — look for:**
- `require('vm2')` or `import ... from 'vm2'`

**Repair:** Replace with `isolated-vm` for true V8 isolate sandboxing, or Node's built-in
`vm.runInNewContext` with a frozen context for limited use cases:
```javascript
// Replace vm2 with isolated-vm
const ivm = require('isolated-vm');
const isolate = new ivm.Isolate({ memoryLimit: 32 });
const context = isolate.createContextSync();
const result = isolate.compileScriptSync(untrustedCode).runSync(context);
```

---

## 6. Template Engine Raw / Unescaped Output

**What it is:** Template engines provide escape bypasses for trusted HTML content. When these
are used with user-controlled values, they create reflected XSS vulnerabilities.

**Detection — look for:**
- **Pug:** `!{userValue}` (raw unescaped output)
- **EJS:** `<%-` tag (unescaped)
- **Handlebars:** `{{{userValue}}}` (triple-stache)
- **Dust.js:** `{userValue|s}` (safe/unescaped filter)
- **Vue SSR / v-html:** `v-html="userValue"` (server-rendered)

**Repair:** Use the escaped variants:
```
Pug:        #{userValue}       not  !{userValue}
EJS:        <%= userValue %>   not  <%- userValue %>
Handlebars: {{userValue}}      not  {{{userValue}}}
```

---

## 7. postMessage Missing Origin Validation

**What it is:** A `message` event listener on `window` does not check `event.origin`, allowing
any page (including attacker-controlled iframes) to send arbitrary messages.

**Detection — look for:**
- `addEventListener('message', handler)` where `handler` does not reference `event.origin`

**Repair:**
```javascript
const ALLOWED_ORIGINS = new Set(['https://app.example.com', 'https://admin.example.com']);
window.addEventListener('message', (event) => {
  if (!ALLOWED_ORIGINS.has(event.origin)) return; // reject unknown origins
  handleMessage(event.data);
});
```

---

## 8. Dynamic import() with User Input

**What it is:** `import()` or `require()` with a path derived from user input enables path
traversal to load arbitrary modules, including `child_process`, `fs`, or native addons.

**Detection — look for:**
- `import(req.query.module)`, `import(userPath)`, `require(req.body.plugin)`
- `` import(`./plugins/${req.params.name}`) ``

**Repair:** Use a static allowlist:
```javascript
const ALLOWED_PLUGINS = new Map([
  ['csv',  () => import('./plugins/csv-parser.js')],
  ['json', () => import('./plugins/json-parser.js')],
]);
const loader = ALLOWED_PLUGINS.get(req.params.format);
if (!loader) return res.status(400).json({ error: 'Unknown format' });
const plugin = await loader();
```

---

## 9. JWT — No Revocation Mechanism

**What it is:** JWTs with long-lived `expiresIn` values (days/hours) and no server-side
revocation mechanism cannot be invalidated after issuance. Stolen tokens remain valid until
natural expiry.

**Detection — look for:**
- `jwt.sign({ ... }, secret, { expiresIn: '7d' })` with no token blocklist or session store
- No middleware that checks a revocation list before trusting a valid JWT

**Repair options:**
1. **Short TTL + refresh tokens:** Issue 15-minute access tokens, longer refresh tokens stored server-side.
2. **JTI blocklist:** Store `jti` claims of revoked tokens in Redis with matching TTL:
```javascript
async function revokeToken(token) {
  const { jti, exp } = jwt.decode(token);
  const ttl = exp - Math.floor(Date.now() / 1000);
  await redis.set(`revoked:${jti}`, '1', 'EX', ttl);
}
async function isRevoked(jti) {
  return !!(await redis.get(`revoked:${jti}`));
}
```

---

## 10. X-Powered-By Header Exposes Framework Fingerprint

**What it is:** Express sets `X-Powered-By: Express` by default, advertising the framework
version to attackers for targeted exploit selection.

**Detection — look for:**
- `express()` app initialisation with no subsequent `app.disable('x-powered-by')`
- Absence of `helmet()` middleware (which removes this header)

**Repair:**
```javascript
const helmet = require('helmet');
app.use(helmet());           // removes X-Powered-By and sets 11 security headers
// or manually:
app.disable('x-powered-by');
```

---

## 11. Logger Data Leakage

**What it is:** User-supplied input is passed directly to `console.log`, `logger.info`,
`winston.debug`, etc., causing PII, tokens, or secrets to be written to log files or
shipped to centralised logging systems.

**Detection — look for:**
- `console.log(req.body)`, `logger.info(req.headers)`, `logger.debug(user)`
- Logging full request objects that include `authorization`, `password`, `token`

**Repair:** Sanitise log payloads — log an allowlist of safe fields only:
```javascript
function safeLogRequest(req) {
  return { method: req.method, path: req.path, ip: req.ip, userId: req.user?.id };
}
logger.info('Request received', safeLogRequest(req));
```

---

## 12. GraphQL Introspection Enabled in Production

**What it is:** GraphQL introspection allows any client to enumerate the entire schema,
exposing internal types, field names, and resolver structure — a reconnaissance goldmine.

**Detection — look for:**
- `introspection: true` in ApolloServer config
- No `NODE_ENV` guard around introspection
- Missing depth/complexity limiting plugins

**Repair:**
```javascript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  plugins: [
    ApolloServerPluginLandingPageDisabled(), // prod: disable playground
    createDepthLimitPlugin(7),
    createComplexityPlugin({ maxComplexity: 1000 }),
  ],
});
```

---

## 13. Prototype Pollution via Bracket Notation

**What it is:** `obj[userKey] = userValue` where `userKey` comes from user input allows
setting `__proto__`, `constructor`, or `prototype` properties, poisoning the Object
prototype for all objects in the process and potentially enabling privilege escalation.

**Detection — look for:**
- `obj[req.body.key] = req.body.value`
- `config[userKey]` without key validation
- `_.merge(target, req.body)` without `_.cloneDeep` or `Object.create(null)` base

**Repair:**
```javascript
function safeMerge(target, source) {
  const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
  for (const [k, v] of Object.entries(source)) {
    if (BLOCKED.has(k)) continue;
    target[k] = v;
  }
}
// Or use Object.create(null) as base to avoid prototype chain entirely
const safeObj = Object.assign(Object.create(null), userInput);
```

---

## 14. Silent Exception Swallow

**What it is:** `catch` blocks that contain only a comment or are completely empty silently
discard errors, hiding security-relevant failures (auth errors, validation failures,
crypto exceptions) and making incident investigation impossible.

**Detection — look for:**
- `catch (e) { }` — empty catch
- `catch (e) { // ignore }` — comment-only catch
- `catch (err) { return; }` — silent return

**Repair:** Always log and re-throw or return a safe error:
```javascript
try {
  await riskyOperation();
} catch (err) {
  logger.error({ err, userId: req.user?.id }, 'Operation failed');
  return res.status(500).json({ error: 'Internal error' });
}
```

---

## 15. Sequelize / Knex TLS Disabled on Database Connection

**What it is:** `dialectOptions: { ssl: false }` or `ssl: { rejectUnauthorized: false }`
disables certificate validation on the database connection, exposing credentials to
man-in-the-middle attacks.

**Detection — look for:**
- `ssl: false` inside `dialectOptions`
- `ssl: { rejectUnauthorized: false }` in Sequelize/pg/mysql2 config
- `knex({ client: 'pg', connection: { ssl: false } })`

**Repair:**
```javascript
new Sequelize(DATABASE_URL, {
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: true,
      ca: fs.readFileSync('./certs/ca.pem'),
    },
  },
});
```

---

## 16. Insecure WebSocket URL (ws:// in Production)

**What it is:** Connecting to `ws://` (unencrypted WebSocket) transmits data in plaintext,
enabling credential theft and message injection on any network path.

**Detection — look for:**
- `new WebSocket('ws://')` — hardcoded insecure URL (not localhost)
- `io.connect('ws://')` (Socket.IO)

**Repair:** Always use `wss://` in production:
```javascript
const ws = new WebSocket(
  process.env.NODE_ENV === 'production'
    ? 'wss://api.example.com/ws'
    : 'ws://localhost:3001'
);
```

---

## Severity Reference

| Pattern | CWE | Severity |
|---|---|---|
| Headless browser SSRF | CWE-918 | CRITICAL |
| vm2 deprecated (sandbox escape) | CWE-693 | CRITICAL |
| Host header injection | CWE-601 | HIGH |
| Body parser DoS | CWE-400 | HIGH |
| Template engine raw output (XSS) | CWE-79 | HIGH |
| Dynamic import with user input | CWE-706 | HIGH |
| JWT no revocation | CWE-613 | HIGH |
| GraphQL introspection in prod | CWE-200 | HIGH |
| Prototype pollution | CWE-1321 | HIGH |
| Sequelize TLS disabled | CWE-295 | HIGH |
| Timing oracle (non-constant compare) | CWE-208 | MEDIUM |
| postMessage no origin check | CWE-346 | MEDIUM |
| X-Powered-By exposed | CWE-200 | MEDIUM |
| Logger data leakage | CWE-532 | MEDIUM |
| Silent exception swallow | CWE-390 | MEDIUM |
| Insecure WebSocket URL | CWE-311 | MEDIUM |
