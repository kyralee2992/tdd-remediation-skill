'use strict';

/**
 * SEC-26 — SSRF via unvalidated `webhook` URL in POST /audit (HIGH).
 *
 * Attack vector: POST /audit accepts a `webhook` field in the request body.
 * That URL is passed directly to fetch() as a fire-and-forget POST with the
 * completed job payload — no protocol check, no host allowlist.
 *
 * An attacker with API key access can supply:
 *   webhook: "http://169.254.169.254/latest/meta-data"
 * and receive a POST containing the full job result (which may include
 * project structure, findings, and config details) from the server.
 *
 * Fix: validate `webhook` in the /audit handler before calling fetch().
 * Accept only HTTPS URLs; reject localhost/private-IP targets in production.
 */

const path = require('path');
const { buildApp } = require('../../lib/plugin');
const { loadConfig } = require('../../lib/config');

const cfg = loadConfig(process.cwd());
cfg.serverApiKey = 'test-secret-26';

// Track every URL fetch() is invoked with
const fetchedUrls = [];
beforeEach(() => {
  fetchedUrls.length = 0;
  global.fetch = async (url, opts) => {
    fetchedUrls.push(url);
    return { ok: true, json: async () => ({}) };
  };
});
afterEach(() => {
  delete global.fetch;
});

async function postAudit(payload) {
  const app = buildApp(cfg);
  await app.ready();
  const res = await app.inject({
    method:  'POST',
    url:     '/audit',
    headers: { authorization: 'Bearer test-secret-26', 'content-type': 'application/json' },
    payload,
  });
  await app.close();
  return res;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('SEC-26 — SSRF via webhook URL in POST /audit', () => {
  test('rejects http:// webhook to cloud metadata endpoint with 400', async () => {
    const res = await postAudit({
      path:    '.',
      webhook: 'http://169.254.169.254/latest/meta-data',
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/webhook/i);
  });

  test('rejects http:// webhook to non-localhost host with 400', async () => {
    const res = await postAudit({
      path:    '.',
      webhook: 'http://evil.example.com/collect',
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/webhook/i);
  });

  test('rejects ws:// webhook scheme with 400', async () => {
    const res = await postAudit({
      path:    '.',
      webhook: 'ws://evil.example.com/socket',
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/webhook/i);
  });

  test('rejects file:// webhook scheme with 400', async () => {
    const res = await postAudit({
      path:    '.',
      webhook: 'file:///etc/passwd',
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/webhook/i);
  });

  test('does NOT call fetch() when webhook is rejected', async () => {
    await postAudit({
      path:    '.',
      webhook: 'http://169.254.169.254/latest/meta-data',
    });
    // fetch() must NOT have been called with the malicious URL
    expect(fetchedUrls).not.toContain('http://169.254.169.254/latest/meta-data');
  });

  test('accepts https:// webhook with valid host', async () => {
    const res = await postAudit({
      path:    '.',
      webhook: 'https://hooks.example.com/tdd-audit',
    });
    // 202 Accepted — webhook is queued for fire-and-forget after job completes
    expect(res.statusCode).toBe(202);
  });

  test('omitting webhook is fine — no error', async () => {
    const res = await postAudit({ path: '.' });
    expect(res.statusCode).toBe(202);
  });
});
