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
