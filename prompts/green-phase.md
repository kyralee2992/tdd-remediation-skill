# TDD Remediation: The Patch (Green Phase)

Once the failing exploit test is committed, write the minimum code required to make it pass. Do not over-engineer — a targeted fix is safer than a rewrite.

## Action
Apply a security patch to the relevant routes, middleware, database layer, or sanitization utilities. Run the test suite. The exploit test from Phase 1 (Red) must now pass.

## Protocol
1. Identify the **root cause** — not just the symptom. A 500 error is not a security fix.
2. Apply the narrowest patch that closes the vulnerability.
3. Run the full test suite. The exploit test must pass AND all pre-existing tests must remain green.
4. If the test still fails, your patch is incomplete — do not move on.

## Goal
Prove definitively that the specific vulnerability is closed without relying on manual testing, guessing, or superficial UI changes.

---

## Vulnerability-Specific Patch Strategies

### IDOR (Insecure Direct Object Reference) / Tenant Isolation

**Root cause:** Resource lookups that use a user-supplied ID without verifying ownership.

**Fix:** Scope every database query to the authenticated user's ID or tenant ID. Never trust the client.

```javascript
// BEFORE (vulnerable)
const record = await db.records.findById(req.params.id);

// AFTER (patched)
const record = await db.records.findOne({
  id: req.params.id,
  userId: req.user.id, // enforce ownership at query level
});
if (!record) return res.status(403).json({ error: 'Forbidden' });
```

```python
# BEFORE (vulnerable)
record = db.query(Record).filter(Record.id == record_id).first()

# AFTER (patched)
record = db.query(Record).filter(
    Record.id == record_id,
    Record.user_id == current_user.id  # enforce ownership
).first()
if not record:
    raise HTTPException(status_code=403, detail="Forbidden")
```

**Libraries:** Built-in ORM scoping; no extra library needed.

---

### XSS (Cross-Site Scripting)

**Root cause:** User input is reflected into HTML, JS, or DOM without encoding or sanitization.

**Fix options (choose the appropriate layer):**
- **Storage:** Sanitize on write using a safe library.
- **Rendering:** Escape on output; never use `innerHTML` with user data.
- **API responses:** Set `Content-Type: application/json` strictly; never reflect raw input.

```javascript
// BEFORE (vulnerable — Express)
res.send(`<p>Hello ${req.query.name}</p>`);

// AFTER — Option A: escape on output
const escapeHtml = require('escape-html');
res.send(`<p>Hello ${escapeHtml(req.query.name)}</p>`);

// AFTER — Option B: sanitize rich HTML (for WYSIWYG content)
const DOMPurify = require('isomorphic-dompurify');
const clean = DOMPurify.sanitize(req.body.content, { ALLOWED_TAGS: ['b', 'i', 'em'] });
res.json({ content: clean });
```

```python
# BEFORE (vulnerable — Flask/Jinja2 with autoescape disabled)
return render_template_string(f"<p>{user_input}</p>")

# AFTER — Jinja2 autoescape handles it; force it on
from markupsafe import escape
return f"<p>{escape(user_input)}</p>"

# For sanitizing rich HTML
import bleach
clean = bleach.clean(user_input, tags=['b', 'i', 'em'], strip=True)
```

**Libraries:** `escape-html`, `isomorphic-dompurify` (Node); `markupsafe`, `bleach` (Python).

---

### SQL Injection

**Root cause:** User input is concatenated directly into a SQL query string.

**Fix:** Use parameterized queries or ORM methods exclusively. Never build SQL strings from user input.

```javascript
// BEFORE (vulnerable)
const result = await db.query(`SELECT * FROM users WHERE email = '${email}'`);

// AFTER — parameterized (node-postgres / pg)
const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);

// AFTER — ORM (Sequelize / Prisma)
const user = await User.findOne({ where: { email } }); // safe by default
```

```python
# BEFORE (vulnerable)
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# AFTER — parameterized
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

# AFTER — ORM (SQLAlchemy)
user = db.query(User).filter(User.email == email).first()
```

**Libraries:** Use your existing ORM. Never use raw string interpolation for queries.

---

### Command Injection

**Root cause:** User input is passed to `exec`, `spawn`, `subprocess.run(shell=True)`, or similar without validation.

**Fix:** Use argument arrays (never shell strings), allowlists, or eliminate the shell call entirely.

```javascript
// BEFORE (vulnerable)
const { exec } = require('child_process');
exec(`convert ${req.body.filename} output.png`); // shell injection possible

// AFTER — use execFile/spawn with argument array (no shell)
const { execFile } = require('child_process');
const safeName = path.basename(req.body.filename); // strip path traversal too
execFile('convert', [safeName, 'output.png']); // no shell expansion
```

```python
# BEFORE (vulnerable)
subprocess.run(f"ffmpeg -i {filename} output.mp4", shell=True)

# AFTER — argument list, no shell
import subprocess, os
safe_name = os.path.basename(filename)
subprocess.run(["ffmpeg", "-i", safe_name, "output.mp4"])  # shell=False by default
```

---

### Path Traversal

**Root cause:** User-supplied file paths are used to read/write files without normalization or bounds checking.

**Fix:** Normalize the path and assert it stays within the allowed directory.

```javascript
// BEFORE (vulnerable)
const filePath = path.join(__dirname, 'uploads', req.params.filename);
res.sendFile(filePath); // '../../../etc/passwd' bypass possible

// AFTER
const UPLOADS_DIR = path.resolve(__dirname, 'uploads');
const requested = path.resolve(UPLOADS_DIR, req.params.filename);
if (!requested.startsWith(UPLOADS_DIR + path.sep)) {
  return res.status(400).json({ error: 'Invalid path' });
}
res.sendFile(requested);
```

```python
# AFTER (Python)
import os
UPLOADS_DIR = os.path.realpath("uploads")
requested = os.path.realpath(os.path.join(UPLOADS_DIR, filename))
if not requested.startswith(UPLOADS_DIR + os.sep):
    raise HTTPException(status_code=400, detail="Invalid path")
```

---

### Broken Authentication / Missing Authorization Middleware

**Root cause:** Routes lack authentication checks, or JWTs/sessions are not validated on sensitive endpoints.

**Fix:** Apply authentication middleware globally and opt routes out explicitly, rather than opting in per route.

```javascript
// AFTER — Express: apply auth globally, then define public routes above it
app.get('/health', (req, res) => res.send('ok')); // public
app.use(requireAuth); // all routes below are protected

// Middleware
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
```

---

### React: XSS via dangerouslySetInnerHTML

**Root cause:** User-generated content is passed directly to `dangerouslySetInnerHTML` without sanitization.

**Fix:** Sanitize with DOMPurify before rendering. Never pass raw user input to `dangerouslySetInnerHTML`.

```tsx
// BEFORE (vulnerable)
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// AFTER
import DOMPurify from 'dompurify';

const clean = DOMPurify.sanitize(userContent, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
  ALLOWED_ATTR: ['href'],
});
<div dangerouslySetInnerHTML={{ __html: clean }} />
```

**Install:** `npm install dompurify @types/dompurify`
For SSR (Next.js): `npm install isomorphic-dompurify` instead.

---

### Next.js: Missing Auth on API Routes

**Root cause:** API route handlers in `pages/api/` or `app/api/` are publicly accessible with no authentication check.

**Fix — Option A (per-route wrapper):**
```typescript
// lib/withAuth.ts
import jwt from 'jsonwebtoken';
import type { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';

export function withAuth(handler: NextApiHandler): NextApiHandler {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
      (req as any).user = jwt.verify(token, process.env.JWT_SECRET!);
      return handler(req, res);
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// pages/api/user.ts
import { withAuth } from '../../lib/withAuth';
export default withAuth((req, res) => res.json({ user: (req as any).user }));
```

**Fix — Option B (global middleware, preferred for App Router):**
```typescript
// middleware.ts (root of project — protects all /api routes)
import { NextResponse, type NextRequest } from 'next/server';
import { jwtVerify } from 'jose';

export async function middleware(request: NextRequest) {
  const token = request.headers.get('authorization')?.split(' ')[1];
  if (!token) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  try {
    await jwtVerify(token, new TextEncoder().encode(process.env.JWT_SECRET!));
    return NextResponse.next();
  } catch {
    return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
  }
}

export const config = { matcher: '/api/:path*' };
```

---

### React Native / Expo: Sensitive Storage Migration

**Root cause:** Auth tokens stored in `AsyncStorage` are unencrypted and readable on rooted/jailbroken devices.

**Fix:** Replace with `expo-secure-store`, which uses iOS Keychain and Android EncryptedSharedPreferences.

```javascript
// BEFORE (vulnerable)
import AsyncStorage from '@react-native-async-storage/async-storage';
await AsyncStorage.setItem('token', userToken);
const token = await AsyncStorage.getItem('token');

// AFTER
import * as SecureStore from 'expo-secure-store';
await SecureStore.setItemAsync('token', userToken);
const token = await SecureStore.getItemAsync('token');
// On logout:
await SecureStore.deleteItemAsync('token');
```

**Install:** `npx expo install expo-secure-store`
**Note:** `SecureStore` is device-bound and not available in Expo Go web preview — check `SecureStore.isAvailableAsync()` for web fallbacks.

---

### Flutter: Sensitive Storage Migration

**Root cause:** Auth tokens stored in `SharedPreferences` are plain text in app storage — readable on rooted/jailbroken devices.

**Fix:** Replace with `flutter_secure_storage`, which uses iOS Keychain and Android EncryptedSharedPreferences.

```dart
// BEFORE (vulnerable)
final prefs = await SharedPreferences.getInstance();
await prefs.setString('token', userToken);
final token = prefs.getString('token');

// AFTER
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const _storage = FlutterSecureStorage();
await _storage.write(key: 'token', value: userToken);
final token = await _storage.read(key: 'token');
// On logout:
await _storage.delete(key: 'token');
```

**pubspec.yaml:**
```yaml
dependencies:
  flutter_secure_storage: ^9.0.0
```

---

### SSRF (Server-Side Request Forgery)

**Root cause:** The server makes outbound HTTP requests to a URL supplied by the user without validation.

**Fix:** Validate the URL against an explicit allowlist of allowed hostnames. Never make requests to private/internal IP ranges.

```javascript
const { URL } = require('url');

const ALLOWED_ORIGINS = new Set(['api.trusted.com', 'cdn.example.com']);

function validateExternalUrl(rawUrl) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Protocol not allowed');
  if (!ALLOWED_ORIGINS.has(parsed.hostname)) throw new Error('Host not allowed');
  return parsed.toString();
}

// In the route handler:
const safeUrl = validateExternalUrl(req.body.url); // throws on violation
const response = await fetch(safeUrl);
```

**Libraries:** No extra library needed; use the built-in `URL` class.

---

### Open Redirect

**Root cause:** The server redirects the user to a URL supplied in a query parameter without validating the destination.

**Fix:** Only allow relative paths or explicitly allowlisted origins.

```javascript
function safeRedirect(res, destination) {
  // Allow only relative paths (no scheme, no host)
  if (/^https?:\/\//i.test(destination)) {
    return res.status(400).json({ error: 'External redirects not allowed' });
  }
  // Prevent protocol-relative URLs (//evil.com)
  if (destination.startsWith('//')) {
    return res.status(400).json({ error: 'Invalid redirect destination' });
  }
  return res.redirect(destination.startsWith('/') ? destination : `/${destination}`);
}

// Usage:
safeRedirect(res, req.query.redirect || '/dashboard');
```

---

### NoSQL Injection

**Root cause:** A user-supplied value that should be a string is passed directly to MongoDB, allowing operator injection (`{ $gt: '' }`).

**Fix:** Enforce that query values are primitive strings. Reject objects from user input in query fields.

```javascript
// Middleware: sanitize mongo-operator injection
function sanitizeBody(req, res, next) {
  const hasDollar = (obj) =>
    Object.keys(obj || {}).some(k => k.startsWith('$') || (typeof obj[k] === 'object' && hasDollar(obj[k])));
  if (hasDollar(req.body) || hasDollar(req.query)) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  next();
}

app.use(sanitizeBody);
```

**Library alternative:** `express-mongo-sanitize` strips `$` and `.` from user input automatically.
```javascript
const mongoSanitize = require('express-mongo-sanitize');
app.use(mongoSanitize());
```

---

### Mass Assignment

**Root cause:** `req.body` is passed directly to an ORM constructor or update method, allowing users to set any field including privileged ones.

**Fix:** Always destructure and explicitly allowlist the fields you accept from the user.

```javascript
// BEFORE (vulnerable)
const user = await User.create(req.body);

// AFTER — explicit allowlist
const { username, email, password } = req.body;
const user = await User.create({ username, email, password });

// For updates:
const { displayName, bio } = req.body; // only fields users can change
await User.updateOne({ _id: req.user.id }, { displayName, bio });
```

```python
# FastAPI — use a Pydantic schema with only allowed fields
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    # isAdmin NOT here — cannot be set by users

@app.post('/users')
async def create_user(data: UserCreate):
    user = User(**data.dict())  # safe: Pydantic strips unlisted fields
```

---

### Prototype Pollution

**Root cause:** A recursive merge function applied to user-supplied input can overwrite `Object.prototype` properties.

**Fix:** Use a null-prototype target for merges, or sanitize `__proto__` / `constructor` keys before merging.

```javascript
// Option A: sanitize keys before merge (drop __proto__, constructor, prototype)
function safeMerge(target, source) {
  const clean = JSON.parse(
    JSON.stringify(source, (key, val) =>
      ['__proto__', 'constructor', 'prototype'].includes(key) ? undefined : val
    )
  );
  return Object.assign(target, clean);
}

// Option B: use Object.create(null) as the target so there is no prototype to pollute
const settings = safeMerge(Object.create(null), req.body);
```

**Library:** `lodash` ≥ 4.17.21 has this patched. If using `deepmerge`, pass `{ clone: true }` and pre-sanitize keys.

---

### Weak Cryptography (Password Hashing)

**Root cause:** Passwords are hashed with MD5 or SHA1 — fast algorithms that are trivially brute-forced.

**Fix:** Use `bcrypt` or `argon2`. Never use MD5/SHA1/SHA256 directly for passwords.

```javascript
// BEFORE (vulnerable)
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// AFTER — bcrypt
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12; // increase over time as hardware improves

// On registration:
const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
await User.create({ email, passwordHash });

// On login:
const valid = await bcrypt.compare(req.body.password, user.passwordHash);
if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
```

```python
# AFTER — bcrypt (Python)
import bcrypt

# Hash on registration:
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Verify on login:
if not bcrypt.checkpw(password.encode(), stored_hash):
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

**Install:** `npm install bcrypt` / `pip install bcrypt`

---

### Missing Rate Limiting

**Root cause:** Authentication and sensitive mutation endpoints have no throttle, enabling brute-force and credential-stuffing attacks.

**Fix:** Apply `express-rate-limit` (Node.js) to auth routes. Use a stricter window on login than on general API routes.

```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,                    // 10 attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
});

app.use('/api/', apiLimiter);
app.post('/api/auth/login', loginLimiter, loginHandler);
app.post('/api/auth/register', loginLimiter, registerHandler);
```

```python
# FastAPI — slowapi
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post('/auth/login')
@limiter.limit('10/15minutes')
async def login(request: Request, data: LoginRequest):
    ...
```

**Install:** `npm install express-rate-limit` / `pip install slowapi`

---

### Missing Security Headers

**Root cause:** Responses lack HTTP security headers, leaving browsers unprotected against clickjacking, MIME-sniffing, and other attacks.

**Fix:** Install `helmet` as the first middleware. Configure CSP explicitly.

```javascript
const helmet = require('helmet');

// Minimal (all helmet defaults — good for most apps)
app.use(helmet());

// With explicit CSP:
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // tighten further if possible
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);
```

```python
# FastAPI — secure
from secure import Secure
secure_headers = Secure()

@app.middleware('http')
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response
```

**Install:** `npm install helmet` / `pip install secure`

---

### TLS Bypass Fix (Node.js + Flutter/Dart)

**Root cause:** TLS certificate verification is explicitly disabled, allowing man-in-the-middle attacks.

**Fix:** Remove the bypass entirely. For internal CAs, provide the cert — don't disable verification.

```javascript
// BEFORE (vulnerable — Node.js)
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false }); // ❌

// AFTER — remove the override; default is rejectUnauthorized: true ✅
const agent = new https.Agent();

// For internal/self-signed CAs in staging environments:
// NODE_EXTRA_CA_CERTS=/path/to/internal-ca.crt node server.js
```

```dart
// BEFORE (vulnerable — Flutter/Dart)
final client = HttpClient()
  ..badCertificateCallback = (cert, host, port) => true; // ❌

// AFTER — remove the callback (default validates certs) ✅
final client = HttpClient();

// For a private CA in integration tests only:
final context = SecurityContext()
  ..setTrustedCertificates('test/certs/ca.crt');
final client = HttpClient(context: context);
```
