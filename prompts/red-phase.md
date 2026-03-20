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
Assert that User A receives a 403 Forbidden or 404 Not Found when trying to manipulate User B's resources.
* **Jest/Supertest:** `expect(response.status).toBe(403);`
* **Playwright:** Verify the UI displays an unauthorized banner instead of loading the other user's dashboard.

### XSS (Cross-Site Scripting)
Submit an aggressive payload like `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`.
* **Jest/Supertest:** Assert that the raw response body either HTML-escapes the payload (`&lt;script&gt;`) or rejects the input entirely.
* **Playwright:** Attempt to inject the payload in a form field and verify that the script is not evaluated in the DOM.

### SQL Injection
Submit payloads attempting tautologies (e.g., `' OR 1=1 --`) or union-based extraction.
* **Assertion:** Expect a 400 Bad Request or parameter rejection, and verify that the database did not actually execute the malformed query or return all records.

---

## Framework Templates to Provide

### Jest / Supertest (Node.js)
```javascript
const response = await request(app).post('/api/endpoint').send({ exploit: true });
expect(response.status).toBe(403); // Fails because it currently returns 200
```

### PyTest (Python)
```python
def test_idor_exploit(client, user_b_token):
    response = client.get('/api/user_a_resource/', headers={'Authorization': f'Bearer {user_b_token}'})
    assert response.status_code == 403 # Fails because it currently returns 200
```
