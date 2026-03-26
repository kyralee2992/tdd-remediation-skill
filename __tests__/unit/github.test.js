'use strict';

/**
 * Unit tests — lib/github.js
 * Covers: parseRepo, uploadSarif, postReviewComments (fetch mocked)
 */

const { parseRepo, uploadSarif, postReviewComments } = require('../../lib/github');

// ── parseRepo ─────────────────────────────────────────────────────────────────

describe('parseRepo', () => {
  test('splits a valid "owner/repo" string', () => {
    const { owner, repo } = parseRepo('acme/my-app');
    expect(owner).toBe('acme');
    expect(repo).toBe('my-app');
  });

  test('throws when there is no slash', () => {
    expect(() => parseRepo('noslash')).toThrow(/owner\/repo/);
  });

  test('throws on empty string', () => {
    expect(() => parseRepo('')).toThrow();
  });

  test('throws when owner part is missing', () => {
    expect(() => parseRepo('/repo')).toThrow();
  });
});

// ── uploadSarif ───────────────────────────────────────────────────────────────

describe('uploadSarif', () => {
  beforeEach(() => { global.fetch = jest.fn(); });
  afterEach(() => { delete global.fetch; });

  const opts = {
    owner: 'acme', repo: 'app', token: 'ghp_test',
    ref: 'refs/heads/main', commitSha: 'abc123',
    sarif: { version: '2.1.0', runs: [] },
  };

  test('POSTs to /repos/{owner}/{repo}/code-scanning/sarifs', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: 1 }) });
    await uploadSarif(opts);
    const [url, init] = global.fetch.mock.calls[0];
    expect(url).toContain('/acme/app/code-scanning/sarifs');
    expect(init.method).toBe('POST');
  });

  test('SARIF payload is base64-encoded', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await uploadSarif(opts);
    const body = JSON.parse(global.fetch.mock.calls[0][1].body);
    // Verify it's valid base64 that decodes to JSON
    const decoded = JSON.parse(Buffer.from(body.sarif, 'base64').toString('utf8'));
    expect(decoded.version).toBe('2.1.0');
  });

  test('passes Authorization Bearer token', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await uploadSarif(opts);
    const headers = global.fetch.mock.calls[0][1].headers;
    expect(headers.Authorization).toBe('Bearer ghp_test');
  });

  test('throws on non-ok GitHub response', async () => {
    global.fetch.mockResolvedValue({
      ok: false, status: 422,
      text: async () => 'Unprocessable Entity',
    });
    await expect(uploadSarif(opts)).rejects.toThrow(/422/);
  });

  test('returns null for 204 No Content', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 204, json: undefined });
    const result = await uploadSarif(opts);
    expect(result).toBeNull();
  });
});

// ── postReviewComments ────────────────────────────────────────────────────────

describe('postReviewComments', () => {
  beforeEach(() => { global.fetch = jest.fn(); });
  afterEach(() => { delete global.fetch; });

  const base = { owner: 'acme', repo: 'app', pull_number: 42, token: 'ghp_test', commitSha: 'abc' };

  const highFinding = {
    severity: 'HIGH', name: 'XSS', file: 'src/app.js', line: 10,
    snippet: 'res.send(x)', likelyFalsePositive: false,
  };
  const lowFinding = {
    severity: 'LOW', name: 'Verbose Log', file: 'lib/log.js', line: 3,
    snippet: 'console.log(secret)', likelyFalsePositive: false,
  };
  const noisyFinding = {
    severity: 'HIGH', name: 'FP', file: 'test/x.test.js', line: 1,
    snippet: 'x', likelyFalsePositive: true,
  };

  test('returns null when there are no real findings', async () => {
    const result = await postReviewComments({ ...base, findings: [noisyFinding] });
    expect(result).toBeNull();
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('uses REQUEST_CHANGES event for CRITICAL/HIGH findings', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: 1 }) });
    await postReviewComments({ ...base, findings: [highFinding] });
    const body = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(body.event).toBe('REQUEST_CHANGES');
  });

  test('uses COMMENT event for LOW findings only', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await postReviewComments({ ...base, findings: [lowFinding] });
    const body = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(body.event).toBe('COMMENT');
  });

  test('comment body includes severity and name', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await postReviewComments({ ...base, findings: [highFinding] });
    const body = JSON.parse(global.fetch.mock.calls[0][1].body);
    const commentBodies = body.comments.map(c => c.body).join(' ');
    expect(commentBodies).toMatch(/HIGH/);
    expect(commentBodies).toMatch(/XSS/);
  });

  test('POSTs to correct pulls reviews endpoint', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await postReviewComments({ ...base, findings: [highFinding] });
    const url = global.fetch.mock.calls[0][0];
    expect(url).toContain('/acme/app/pulls/42/reviews');
  });

  test('excludes likelyFalsePositive findings from comments', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await postReviewComments({ ...base, findings: [highFinding, noisyFinding] });
    const body = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(body.comments).toHaveLength(1);
  });
});

// ─── ghFetch error — res.text() catch branch ─────────────────────────────────

describe('ghFetch — res.text() failure catch branch', () => {
  beforeEach(() => { global.fetch = jest.fn(); });
  afterEach(() => { delete global.fetch; });

  test('throws with empty message body when res.text() itself rejects', async () => {
    global.fetch.mockResolvedValue({
      ok: false,
      status: 503,
      text: async () => { throw new Error('network'); }, // text() throws
    });
    await expect(uploadSarif({
      owner: 'a', repo: 'b', token: 'tok',
      ref: 'refs/heads/main', commitSha: 'abc',
      sarif: { version: '2.1.0', runs: [] },
    })).rejects.toThrow(/503/);
  });
});

// ─── ghFetch — body=null branch (line 15) ────────────────────────────────────

describe('ghFetch — body=null / GET path (line 15 false branch)', () => {
  const { ghFetch } = require('../../lib/github');
  beforeEach(() => { global.fetch = jest.fn(); });
  afterEach(() => { delete global.fetch; });

  test('does not set opts.body when body argument is null (default GET call)', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: 42 }) });
    await ghFetch('/repos/acme/app', 'ghp_token', 'GET', null);
    const init = global.fetch.mock.calls[0][1];
    expect(init.body).toBeUndefined();
  });

  test('sets opts.body when body argument is provided (POST call)', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await ghFetch('/repos/acme/app/issues', 'ghp_token', 'POST', { title: 'test' });
    const init = global.fetch.mock.calls[0][1];
    expect(init.body).toBeDefined();
    expect(JSON.parse(init.body).title).toBe('test');
  });

  test('uses default method GET when method argument is omitted', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await ghFetch('/repos/acme/app', 'tok');
    const init = global.fetch.mock.calls[0][1];
    expect(init.method).toBe('GET');
  });
});
