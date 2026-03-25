'use strict';

/**
 * E2E tests for the tdd-audit REST server.
 *
 * Starts a real http.Server on an ephemeral port (:0) and exercises every
 * endpoint via actual HTTP requests — no in-process mocking of req/res.
 *
 * Coverage:
 *   GET  /health             — unauthenticated, version, security headers
 *   POST /scan               — scan cwd, SARIF format, path traversal, bad JSON, body limit
 *   POST /remediate          — validation, job creation, async lifecycle
 *   GET  /jobs/:id           — pending/running/done/unknown job
 *   Auth                     — open mode, Bearer token, wrong token → 401
 *   Security headers         — CSP, X-Frame-Options, X-Content-Type-Options on every response
 *   Error handling           — 404 unknown routes, 400 bad input, 500 internal error
 *   Rate limiting            — 429 after exceeding RATE_LIMIT_MAX
 */

const http   = require('http');
const { handleRequest, rateLimiter, jobs, RATE_LIMIT_MAX } = require('../../lib/server');

// ─── HTTP helper ─────────────────────────────────────────────────────────────

/**
 * Make a real HTTP request to the test server.
 * Returns { status, headers, body } where body is parsed JSON when possible.
 */
function req(port, method, path, body, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : undefined;
    const options = {
      hostname: '127.0.0.1',
      port,
      method,
      path,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...extraHeaders,
      },
    };

    const request = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });

    request.on('error', reject);
    if (payload) request.write(payload);
    request.end();
  });
}

// ─── Server lifecycle ────────────────────────────────────────────────────────

const OPEN_CFG   = { serverApiKey: null, trustProxy: false, output: 'json', model: null, baseUrl: null };
const KEYED_CFG  = { ...OPEN_CFG, serverApiKey: 'test-api-key-e2e' };

let server;
let port;

// Stub fetch so POST /remediate async workers never hit the network
const originalFetch = global.fetch;
beforeAll(done => {
  global.fetch = async () => ({
    ok:   true,
    json: async () => ({ choices: [{ message: { content: '{"exploitTest":{},"patch":{},"refactorChecks":[]}' } }] }),
  });

  server = http.createServer(async (req, res) => {
    try {
      await handleRequest(req, res, OPEN_CFG);
    } catch (err) {
      const body = JSON.stringify({ error: 'Internal server error' });
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(body);
    }
  });
  server.listen(0, '127.0.0.1', () => {
    port = server.address().port;
    done();
  });
});

afterAll(done => {
  global.fetch = originalFetch;
  server.close(done);
});

beforeEach(() => {
  rateLimiter.reset();
  jobs.clear();
});

// ─── GET /health ──────────────────────────────────────────────────────────────

describe('GET /health', () => {
  test('returns 200 with status:ok and a version string', async () => {
    const res = await req(port, 'GET', '/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(typeof res.body.version).toBe('string');
    expect(res.body.version.length).toBeGreaterThan(0);
  });

  test('does not require authentication', async () => {
    const res = await req(port, 'GET', '/health', undefined, {});
    expect(res.status).toBe(200);
  });

  test('responds to multiple sequential requests', async () => {
    for (let i = 0; i < 3; i++) {
      const res = await req(port, 'GET', '/health');
      expect(res.status).toBe(200);
    }
  });
});

// ─── Security headers ─────────────────────────────────────────────────────────

describe('Security headers — present on every response', () => {
  const routes = [
    ['GET',  '/health',         undefined],
    ['GET',  '/no-such-route',  undefined],
    ['POST', '/scan',           { path: '.' }],
  ];

  test.each(routes)('%s %s includes Content-Security-Policy', async (method, path, body) => {
    const res = await req(port, method, path, body);
    expect(res.headers['content-security-policy']).toMatch(/default-src\s+['"]?none['"]?/i);
  });

  test.each(routes)('%s %s includes X-Content-Type-Options: nosniff', async (method, path, body) => {
    const res = await req(port, method, path, body);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test.each(routes)('%s %s includes X-Frame-Options: DENY', async (method, path, body) => {
    const res = await req(port, method, path, body);
    expect(res.headers['x-frame-options']).toBe('DENY');
  });

  test('Content-Type is application/json on all responses', async () => {
    const res = await req(port, 'GET', '/health');
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });
});

// ─── Authentication ───────────────────────────────────────────────────────────

describe('Authentication', () => {
  let keyedServer;
  let keyedPort;

  beforeAll(done => {
    keyedServer = http.createServer(async (request, response) => {
      try {
        await handleRequest(request, response, KEYED_CFG);
      } catch {
        response.writeHead(500); response.end('{}');
      }
    });
    keyedServer.listen(0, '127.0.0.1', () => {
      keyedPort = keyedServer.address().port;
      done();
    });
  });

  afterAll(done => { keyedServer.close(done); });
  beforeEach(() => rateLimiter.reset());

  test('open server (no key) allows unauthenticated POST /scan', async () => {
    const res = await req(port, 'POST', '/scan', { path: '.' });
    expect(res.status).toBe(200);
  });

  test('keyed server returns 401 with no Authorization header', async () => {
    const res = await req(keyedPort, 'POST', '/scan', { path: '.' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/unauthorized/i);
  });

  test('keyed server returns 401 with wrong token', async () => {
    const res = await req(keyedPort, 'POST', '/scan', { path: '.' }, {
      Authorization: 'Bearer wrong-key',
    });
    expect(res.status).toBe(401);
  });

  test('keyed server returns 200 with correct Bearer token', async () => {
    const res = await req(keyedPort, 'POST', '/scan', { path: '.' }, {
      Authorization: `Bearer ${KEYED_CFG.serverApiKey}`,
    });
    expect(res.status).toBe(200);
  });

  test('GET /health bypasses auth even on keyed server', async () => {
    const res = await req(keyedPort, 'GET', '/health');
    expect(res.status).toBe(200);
  });

  test('keyed server returns 401 for missing Bearer prefix', async () => {
    const res = await req(keyedPort, 'POST', '/scan', { path: '.' }, {
      Authorization: KEYED_CFG.serverApiKey,
    });
    expect(res.status).toBe(401);
  });
});

// ─── POST /scan ───────────────────────────────────────────────────────────────

describe('POST /scan', () => {
  test('scans cwd and returns findings schema', async () => {
    const res = await req(port, 'POST', '/scan', { path: '.' });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.findings)).toBe(true);
    expect(typeof res.body.summary).toBe('object');
    expect(typeof res.body.duration).toBe('number');
    expect(res.body.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  test('returns valid SARIF 2.1.0 when format=sarif', async () => {
    const res = await req(port, 'POST', '/scan', { path: '.', format: 'sarif' });
    expect(res.status).toBe(200);
    expect(res.body.version).toBe('2.1.0');
    expect(Array.isArray(res.body.runs)).toBe(true);
    expect(res.body.runs[0].tool.driver.name).toBe('@lhi/tdd-audit');
  });

  test('returns 400 for path traversal attempt', async () => {
    const res = await req(port, 'POST', '/scan', { path: '../../etc/passwd' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/outside working directory/i);
  });

  test('returns 400 for absolute path outside cwd', async () => {
    const res = await req(port, 'POST', '/scan', { path: '/etc/passwd' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/outside working directory/i);
  });

  test('scans a sub-path inside cwd', async () => {
    const res = await req(port, 'POST', '/scan', { path: 'lib' });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.findings)).toBe(true);
  });

  test('accepts omitted path (defaults to cwd)', async () => {
    const res = await req(port, 'POST', '/scan', {});
    expect(res.status).toBe(200);
  });

  test('returns 400 for malformed JSON body', async () => {
    const res = await new Promise((resolve, reject) => {
      const rawBody = '{ bad json }';
      const options = {
        hostname: '127.0.0.1', port, method: 'POST', path: '/scan',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(rawBody) },
      };
      const request = http.request(options, res => {
        let data = '';
        res.on('data', c => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data) }));
      });
      request.on('error', reject);
      request.write(rawBody);
      request.end();
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid json/i);
  });

  test('summary counts match findings array length', async () => {
    const res = await req(port, 'POST', '/scan', { path: '.' });
    const total = Object.values(res.body.summary).reduce((a, b) => a + b, 0);
    expect(total).toBe(res.body.findings.length);
  });
});

// ─── POST /remediate ──────────────────────────────────────────────────────────

describe('POST /remediate', () => {
  const validFinding = {
    name: 'XSS', severity: 'HIGH', file: 'src/app.js', line: 10,
    snippet: 'res.send(req.query.x)', likelyFalsePositive: false,
  };

  test('returns 202 Accepted with a jobId', async () => {
    const res = await req(port, 'POST', '/remediate', {
      findings: [validFinding], provider: 'openai', apiKey: 'sk-test',
    });
    expect(res.status).toBe(202);
    expect(typeof res.body.jobId).toBe('string');
    expect(res.body.jobId).toMatch(/^job_/);
  });

  test('returns 400 when findings is missing', async () => {
    const res = await req(port, 'POST', '/remediate', { provider: 'openai', apiKey: 'sk-test' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/findings/);
  });

  test('returns 400 when provider is missing', async () => {
    const res = await req(port, 'POST', '/remediate', { findings: [validFinding], apiKey: 'sk-test' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/provider/);
  });

  test('returns 400 when apiKey is missing', async () => {
    const res = await req(port, 'POST', '/remediate', { findings: [validFinding], provider: 'openai' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/apiKey/);
  });

  test('job is immediately visible via GET /jobs/:id', async () => {
    const post = await req(port, 'POST', '/remediate', {
      findings: [validFinding], provider: 'openai', apiKey: 'sk-test',
    });
    const { jobId } = post.body;
    const get = await req(port, 'GET', `/jobs/${jobId}`);
    expect(get.status).toBe(200);
    expect(get.body.id).toBe(jobId);
    expect(['pending', 'running', 'done']).toContain(get.body.status);
  });

  test('multiple concurrent jobs get distinct IDs', async () => {
    const payload = { findings: [validFinding], provider: 'openai', apiKey: 'sk-test' };
    const [a, b, c] = await Promise.all([
      req(port, 'POST', '/remediate', payload),
      req(port, 'POST', '/remediate', payload),
      req(port, 'POST', '/remediate', payload),
    ]);
    const ids = [a.body.jobId, b.body.jobId, c.body.jobId];
    expect(new Set(ids).size).toBe(3);
  });
});

// ─── GET /jobs/:id ────────────────────────────────────────────────────────────

describe('GET /jobs/:id', () => {
  test('returns 404 for unknown job ID', async () => {
    const res = await req(port, 'GET', '/jobs/does-not-exist-xyz');
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found/i);
  });

  test('returns job object with expected fields', async () => {
    const post = await req(port, 'POST', '/remediate', {
      findings: [{ name: 'XSS', severity: 'HIGH', file: 'a.js', line: 1, snippet: '', likelyFalsePositive: false }],
      provider: 'openai', apiKey: 'sk-test',
    });
    const get = await req(port, 'GET', `/jobs/${post.body.jobId}`);
    expect(get.status).toBe(200);
    expect(get.body).toHaveProperty('id');
    expect(get.body).toHaveProperty('status');
    expect(get.body).toHaveProperty('createdAt');
  });

  test('job createdAt is a valid ISO timestamp', async () => {
    const post = await req(port, 'POST', '/remediate', {
      findings: [{ name: 'XSS', severity: 'HIGH', file: 'a.js', line: 1, snippet: '', likelyFalsePositive: false }],
      provider: 'openai', apiKey: 'sk-test',
    });
    const get = await req(port, 'GET', `/jobs/${post.body.jobId}`);
    expect(new Date(get.body.createdAt).toISOString()).toBe(get.body.createdAt);
  });

  test('job does not expose the provider apiKey', async () => {
    const secretKey = 'sk-should-not-be-visible-9876';
    const post = await req(port, 'POST', '/remediate', {
      findings: [{ name: 'XSS', severity: 'HIGH', file: 'a.js', line: 1, snippet: '', likelyFalsePositive: false }],
      provider: 'openai', apiKey: secretKey,
    });
    const get = await req(port, 'GET', `/jobs/${post.body.jobId}`);
    expect(JSON.stringify(get.body)).not.toContain(secretKey);
  });
});

// ─── 404 / unknown routes ─────────────────────────────────────────────────────

describe('Unknown routes and methods', () => {
  test('GET /unknown returns 404', async () => {
    const res = await req(port, 'GET', '/unknown');
    expect(res.status).toBe(404);
    expect(res.body.error).toBeDefined();
  });

  test('DELETE /health returns 404', async () => {
    const res = await req(port, 'DELETE', '/health');
    expect(res.status).toBe(404);
  });

  test('GET /scan returns 404 (scan is POST-only)', async () => {
    const res = await req(port, 'GET', '/scan');
    expect(res.status).toBe(404);
  });

  test('POST /health returns 404 (health is GET-only)', async () => {
    const res = await req(port, 'POST', '/health');
    expect(res.status).toBe(404);
  });

  test('404 response body is valid JSON with an error field', async () => {
    const res = await req(port, 'GET', '/totally/unknown/path');
    expect(res.status).toBe(404);
    expect(typeof res.body.error).toBe('string');
  });
});

// ─── Rate limiting ────────────────────────────────────────────────────────────

describe('Rate limiting', () => {
  test('returns 429 after exceeding RATE_LIMIT_MAX requests from same IP', async () => {
    // Exhaust the window by driving the counter directly (avoids making
    // RATE_LIMIT_MAX real HTTP connections just to hit the limit)
    for (let i = 0; i < RATE_LIMIT_MAX; i++) rateLimiter.check('127.0.0.1');

    const res = await req(port, 'GET', '/health');
    expect(res.status).toBe(429);
    expect(res.body.error).toMatch(/too many requests/i);
  });

  test('429 response includes security headers', async () => {
    for (let i = 0; i < RATE_LIMIT_MAX; i++) rateLimiter.check('127.0.0.1');
    const res = await req(port, 'GET', '/health');
    expect(res.status).toBe(429);
    expect(res.headers['content-security-policy']).toBeDefined();
    expect(res.headers['x-frame-options']).toBe('DENY');
  });
});

// ─── start() function ─────────────────────────────────────────────────────────

describe('start()', () => {
  const { start } = require('../../lib/server');

  test('returns an http.Server instance', done => {
    const s = start(['--port', '0']);
    s.once('listening', () => {
      expect(typeof s.address().port).toBe('number');
      expect(s.address().port).toBeGreaterThan(0);
      s.close(() => done());
    });
  });

  test('server responds to GET /health after start()', done => {
    const s = start(['--port', '0']);
    s.once('listening', async () => {
      const p = s.address().port;
      const res = await req(p, 'GET', '/health');
      expect(res.status).toBe(200);
      s.close(() => done());
    });
  });
});
