# TDD Remediation: The Exploit (Red Phase)

Before changing a single line of the vulnerable code, you must write a test that successfully executes the exploit. If the test cannot break the app, the vulnerability isn't properly isolated.

## Action
Write an integration or unit test that actively attempts the breach.

## Protocol
The test must fail **your security requirements**, not just produce a 500 Server Error because the app crashed.
In testing frameworks, this usually means writing an assertion that expects a secure block (e.g., `expect(response.status).toBe(403)` or `expect(payload).toBeSanitized()`), but currently receives a `200 OK` or un-sanitized reflection.

## Goal
Establish a measurable baseline. You now have a weaponized test case.

---

## Vulnerability-Specific Strategies

### IDOR (Insecure Direct Object Reference) / Tenant Isolation
Authenticate as User B and request a resource that belongs to User A using its ID directly.
Assert a 403 Forbidden or 404 Not Found — not a 200 returning someone else's data.
```javascript
// Jest/Supertest
const res = await request(app)
  .get(`/api/documents/${userA_doc_id}`)
  .set('Authorization', `Bearer ${userB_token}`);
expect(res.status).toBe(403); // currently returns 200 with userA's data — RED
```
```python
# PyTest
def test_idor_exploit(client, user_b_token, user_a_resource_id):
    res = client.get(f'/api/documents/{user_a_resource_id}',
                     headers={'Authorization': f'Bearer {user_b_token}'})
    assert res.status_code == 403  # currently 200 — RED
```

### XSS (Cross-Site Scripting)
Submit `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>` as user input.
Assert the raw response body either HTML-escapes the payload or rejects the input entirely.
```javascript
const payload = '<script>alert(1)</script>';
const res = await request(app).post('/api/comments').send({ body: payload });
// Should be escaped in the response — currently reflected raw — RED
expect(res.body.comment.body).not.toContain('<script>');
expect(res.body.comment.body).toContain('&lt;script&gt;');
```

### SQL Injection
Submit tautology payloads (`' OR '1'='1`) or union-based extraction attempts.
Assert a 400 Bad Request or that the response does not return all records.
```javascript
const res = await request(app)
  .get('/api/users')
  .query({ email: "' OR '1'='1" });
expect(res.status).toBe(400);         // currently 200 with all user records — RED
expect(res.body.users).toBeUndefined();
```
```python
def test_sql_injection(client):
    res = client.get('/api/users', params={'email': "' OR '1'='1"})
    assert res.status_code == 400  # currently 200 returning all users — RED
```

### Command Injection
Submit shell metacharacters in input that gets passed to a shell command.
Assert the dangerous characters are rejected (400) — not executed.
```javascript
const res = await request(app)
  .post('/api/export')
  .send({ filename: 'report.pdf; rm -rf /tmp/test' });
expect(res.status).toBe(400); // currently executes the command — RED
```

### Path Traversal
Submit a `../` sequence in a file path parameter.
Assert a 400 Bad Request or that the server does not serve files outside the uploads directory.
```javascript
const res = await request(app)
  .get('/api/files/download')
  .query({ name: '../../../etc/passwd' });
expect(res.status).toBe(400); // currently returns file contents — RED
```

### Broken Authentication (Unprotected Route)
Call a protected endpoint with no Authorization header.
Assert a 401 Unauthorized — not a 200 with data.
```javascript
const res = await request(app).get('/api/admin/users'); // no auth header
expect(res.status).toBe(401); // currently returns 200 — RED
```

---

## Framework Templates

### Jest / Supertest (Node.js)
```javascript
const request = require('supertest');
const app = require('../../app');

describe('[VulnType] - Red Phase', () => {
  it('SHOULD block [exploit description]', async () => {
    const res = await request(app)
      .post('/api/vulnerable-endpoint')
      .send({ input: '<exploit payload>' });

    expect(res.status).toBe(403); // currently 200 — this test MUST fail (Red)
    expect(res.body.data).not.toContain('<exploit payload>');
  });
});
```

### PyTest (Python / FastAPI / Flask)
```python
def test_vuln_type_exploit(client, attacker_token):
    response = client.post(
        '/api/vulnerable-endpoint',
        json={'input': '<exploit payload>'},
        headers={'Authorization': f'Bearer {attacker_token}'}
    )
    assert response.status_code == 403  # currently 200 — RED
```
