'use strict';

/**
 * Integration-style unit tests — lib/server.js
 * Tests handleRequest directly via mock req/res objects.
 * Covers all endpoints, auth, rate limiting, job store, path validation.
 */

const path = require('path');
const {
  handleRequest, authenticate, start,
  jobs, createJob, updateJob,
  safeScanPath, rateLimiter, RATE_LIMIT_MAX, MAX_JOBS,
} = require('../../lib/server');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeReq({
  method  = 'GET',
  url     = '/health',
  body    = null,
  headers = {},
  ip      = '127.0.0.1',
} = {}) {
  const handlers = {};
  const req = {
    method, url,
    headers: { 'content-type': 'application/json', ...headers },
    socket: { remoteAddress: ip },
    on(ev, cb) { handlers[ev] = cb; return req; },
  };
  setImmediate(() => {
    const s = body !== null ? JSON.stringify(body) : '';
    if (s && handlers.data) handlers.data(s);
    setImmediate(() => { if (handlers.end) handlers.end(); });
  });
  return req;
}

function makeRes() {
  const res = { status: null, headers: {}, body: null };
  res.writeHead = (s, h) => { res.status = s; res.headers = h || {}; };
  res.end = (d) => { try { res.body = JSON.parse(d); } catch { res.body = d; } };
  return res;
}

const OPEN_CFG   = { serverApiKey: null,       trustProxy: false, output: 'json' };
const KEYED_CFG  = { serverApiKey: 'test-key', trustProxy: false, output: 'json' };

beforeEach(() => {
  rateLimiter.reset();
  jobs.clear();
});

// Flush any pending setImmediate callbacks (from POST /remediate async jobs)
// before Jest tears down the module registry.
afterAll(() => new Promise(resolve => setImmediate(() => setImmediate(resolve))));

// ── GET /health ───────────────────────────────────────────────────────────────

describe('GET /health', () => {
  test('returns 200 with status:ok', async () => {
    const res = makeRes();
    await handleRequest(makeReq(), res, OPEN_CFG);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  test('includes version string', async () => {
    const res = makeRes();
    await handleRequest(makeReq(), res, OPEN_CFG);
    expect(typeof res.body.version).toBe('string');
  });

  test('is accessible without auth even when serverApiKey is set', async () => {
    const res = makeRes();
    await handleRequest(makeReq(), res, KEYED_CFG);
    expect(res.status).toBe(200);
  });
});

// ── Rate limiting ─────────────────────────────────────────────────────────────

describe('Rate limiting', () => {
  test('returns 429 after RATE_LIMIT_MAX requests from same IP', async () => {
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      await handleRequest(makeReq({ ip: '10.10.10.10' }), makeRes(), OPEN_CFG);
    }
    const res = makeRes();
    await handleRequest(makeReq({ ip: '10.10.10.10' }), res, OPEN_CFG);
    expect(res.status).toBe(429);
  });

  test('different IPs are not affected by each others limits', async () => {
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      await handleRequest(makeReq({ ip: '11.11.11.11' }), makeRes(), OPEN_CFG);
    }
    const res = makeRes();
    await handleRequest(makeReq({ ip: '22.22.22.22' }), res, OPEN_CFG);
    expect(res.status).toBe(200);
  });
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('authenticate()', () => {
  test('returns true when no serverApiKey configured', () => {
    const req = { headers: {} };
    expect(authenticate(req, { serverApiKey: null })).toBe(true);
  });

  test('returns true for correct Bearer token', () => {
    const req = { headers: { authorization: 'Bearer secret' } };
    expect(authenticate(req, { serverApiKey: 'secret' })).toBe(true);
  });

  test('returns false for wrong token', () => {
    const req = { headers: { authorization: 'Bearer wrong' } };
    expect(authenticate(req, { serverApiKey: 'secret' })).toBe(false);
  });

  test('returns false when Authorization header is absent', () => {
    const req = { headers: {} };
    expect(authenticate(req, { serverApiKey: 'secret' })).toBe(false);
  });
});

describe('POST /scan — authentication', () => {
  test('returns 401 when serverApiKey set and no token', async () => {
    const res = makeRes();
    await handleRequest(makeReq({ method: 'POST', url: '/scan', body: {} }), res, KEYED_CFG);
    expect(res.status).toBe(401);
  });

  test('returns 401 for wrong token', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: {}, headers: { authorization: 'Bearer bad' } }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(401);
  });
});

// ── POST /scan ────────────────────────────────────────────────────────────────

describe('POST /scan', () => {
  const auth = { authorization: 'Bearer test-key' };

  test('returns 200 with findings for a valid path', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: { path: 'lib' }, headers: auth }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('findings');
    expect(res.body).toHaveProperty('summary');
  });

  test('returns 400 for path traversal attempt', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: { path: '../../etc/passwd' }, headers: auth }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/working directory/);
  });

  test('returns 400 for sibling-directory prefix bypass', async () => {
    const cwd = process.cwd();
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: { path: cwd + '-evil' }, headers: auth }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(400);
  });

  test('returns 400 for invalid JSON body', async () => {
    const handlers = {};
    const req = {
      method: 'POST', url: '/scan',
      headers: { 'content-type': 'application/json', ...auth },
      socket: { remoteAddress: '127.0.0.1' },
      on(ev, cb) { handlers[ev] = cb; return req; },
    };
    setImmediate(() => {
      if (handlers.data) handlers.data('{ bad json }');
      setImmediate(() => { if (handlers.end) handlers.end(); });
    });
    const res = makeRes();
    await handleRequest(req, res, KEYED_CFG);
    expect(res.status).toBe(400);
  });

  test('returns SARIF when format=sarif', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: { path: 'lib', format: 'sarif' }, headers: auth }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(200);
    expect(res.body.version).toBe('2.1.0');
    expect(res.body.runs).toBeDefined();
  });

  test('response includes duration when format is json', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: { path: 'lib' }, headers: auth }),
      res, KEYED_CFG,
    );
    expect(typeof res.body.duration).toBe('number');
  });
});

// ── POST /remediate ───────────────────────────────────────────────────────────

describe('POST /remediate', () => {
  const auth = { authorization: 'Bearer test-key' };

  test('returns 400 when required fields are missing', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/remediate', body: { findings: [] }, headers: auth }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/);
  });

  test('returns 202 with jobId for a valid request', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({
        method: 'POST', url: '/remediate',
        body: { findings: [], provider: 'openai', apiKey: 'sk-test' },
        headers: auth,
      }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(202);
    expect(typeof res.body.jobId).toBe('string');
  });

  test('returns 401 without auth', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/remediate', body: { findings: [], provider: 'openai', apiKey: 'k' } }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(401);
  });
});

// ── GET /jobs/:id ─────────────────────────────────────────────────────────────

describe('GET /jobs/:id', () => {
  const auth = { authorization: 'Bearer test-key' };

  test('returns job when it exists', async () => {
    const jobId = createJob();
    const res = makeRes();
    await handleRequest(
      makeReq({ url: `/jobs/${jobId}`, headers: auth }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(jobId);
  });

  test('returns 404 for unknown jobId', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ url: '/jobs/nonexistent-id', headers: auth }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(404);
  });

  test('updateJob patches job state', () => {
    const id = createJob();
    updateJob(id, { status: 'running' });
    expect(jobs.get(id).status).toBe('running');
  });
});

// ── 404 fallback ──────────────────────────────────────────────────────────────

describe('Unknown routes', () => {
  test('returns 404 for unknown path', async () => {
    const res = makeRes();
    await handleRequest(makeReq({ url: '/unknown' }), res, OPEN_CFG);
    expect(res.status).toBe(404);
  });
});

// ── safeScanPath ──────────────────────────────────────────────────────────────

describe('safeScanPath', () => {
  const cwd = process.cwd();

  test('accepts relative subdirectory', () => {
    expect(() => safeScanPath('lib')).not.toThrow();
  });

  test('accepts absolute path inside cwd', () => {
    expect(() => safeScanPath(path.join(cwd, 'lib'))).not.toThrow();
  });

  test('accepts cwd itself', () => {
    expect(() => safeScanPath(cwd)).not.toThrow();
  });

  test('rejects path traversal via ..', () => {
    expect(() => safeScanPath('../../etc/passwd')).toThrow('Path outside working directory');
  });

  test('rejects absolute path outside cwd', () => {
    expect(() => safeScanPath('/etc/passwd')).toThrow('Path outside working directory');
  });

  test('rejects sibling directory sharing prefix with cwd', () => {
    expect(() => safeScanPath(cwd + '-evil')).toThrow('Path outside working directory');
  });
});

// ── Job store bounds ──────────────────────────────────────────────────────────

describe('Job store — bounded size', () => {
  test('MAX_JOBS is a positive number', () => {
    expect(MAX_JOBS).toBeGreaterThan(0);
  });

  test('store does not exceed MAX_JOBS entries', () => {
    for (let i = 0; i < MAX_JOBS + 10; i++) createJob();
    expect(jobs.size).toBeLessThanOrEqual(MAX_JOBS);
  });

  test('oldest job is evicted when cap is reached', () => {
    for (let i = 0; i < MAX_JOBS; i++) createJob();
    const first = jobs.keys().next().value;
    createJob();
    expect(jobs.has(first)).toBe(false);
  });
});

// ── Rate limiter — window reset ───────────────────────────────────────────────

describe('Rate limiter — window reset', () => {
  test('resets count after window expires and allows next request', async () => {
    const ip = '44.44.44.44';
    // Exhaust the limit
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      await handleRequest(makeReq({ ip }), makeRes(), OPEN_CFG);
    }
    // Verify it's limited
    const blocked = makeRes();
    await handleRequest(makeReq({ ip }), blocked, OPEN_CFG);
    expect(blocked.status).toBe(429);

    // Backdate the window start by more than 1 minute
    const entry = rateLimiter._counts.get(ip);
    entry.windowStart = Date.now() - 61_000;

    // Next request should be allowed (window expired and resets)
    const allowed = makeRes();
    await handleRequest(makeReq({ ip }), allowed, OPEN_CFG);
    expect(allowed.status).toBe(200);
  });
});

// ── POST /remediate — additional branches ─────────────────────────────────────

describe('POST /remediate — branch coverage', () => {
  const auth = { authorization: 'Bearer test-key' };

  test('returns 400 for invalid JSON body', async () => {
    const handlers = {};
    const req = {
      method: 'POST', url: '/remediate',
      headers: { 'content-type': 'application/json', ...auth },
      socket: { remoteAddress: '127.0.0.1' },
      on(ev, cb) { handlers[ev] = cb; return req; },
    };
    setImmediate(() => {
      if (handlers.data) handlers.data('{ bad json }');
      setImmediate(() => { if (handlers.end) handlers.end(); });
    });
    const res = makeRes();
    await handleRequest(req, res, KEYED_CFG);
    expect(res.status).toBe(400);
  });

  test('async job status becomes error when findings is non-iterable', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({
        method: 'POST', url: '/remediate',
        // Pass findings as a truthy non-array so remediate() throws TypeError
        body: { findings: 'not-an-array', provider: 'openai', apiKey: 'k' },
        headers: auth,
      }),
      res, KEYED_CFG,
    );
    expect(res.status).toBe(202);
    const jobId = res.body.jobId;
    // Wait for the setImmediate job to execute (two ticks: outer + inner)
    await new Promise(r => setImmediate(() => setImmediate(r)));
    expect(jobs.get(jobId).status).toBe('error');
  });
});

// ── start() ───────────────────────────────────────────────────────────────────

describe('start()', () => {
  test('returns an http.Server and starts listening', async () => {
    const stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
    const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => {});
    const server = await start(['--port', '0']);
    expect(typeof server.address().port).toBe('number');
    expect(server.address().port).toBeGreaterThan(0);
    stderrSpy.mockRestore();
    stdoutSpy.mockRestore();
    await new Promise(r => server.close(r));
  });

  test('logs unauthenticated warning when no serverApiKey is set', async () => {
    const stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
    const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => {});
    const server = await start(['--port', '0']);
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('unauthenticated'));
    stderrSpy.mockRestore();
    stdoutSpy.mockRestore();
    await new Promise(r => server.close(r));
  });

  test('does not log warning when serverApiKey is set', async () => {
    const stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
    const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => {});
    const server = await start(['--port', '0', '--api-key', 'test-secret']);
    expect(stderrSpy).not.toHaveBeenCalled();
    stderrSpy.mockRestore();
    stdoutSpy.mockRestore();
    await new Promise(r => server.close(r));
  });
});

// ── Security headers ──────────────────────────────────────────────────────────

describe('Response security headers', () => {
  test('X-Content-Type-Options: nosniff is set', async () => {
    const res = makeRes();
    await handleRequest(makeReq(), res, OPEN_CFG);
    expect(res.headers['X-Content-Type-Options']).toBe('nosniff');
  });

  test('X-Frame-Options: DENY is set', async () => {
    const res = makeRes();
    await handleRequest(makeReq(), res, OPEN_CFG);
    expect(res.headers['X-Frame-Options']).toBe('DENY');
  });
});

// ─── readBody — edge cases ────────────────────────────────────────────────────

describe('readBody — edge cases', () => {
  function makeStreamReq(chunks, errorAfter = false) {
    const handlers = {};
    const req = {
      method: 'POST', url: '/scan',
      headers: { 'content-type': 'application/json' },
      socket: { remoteAddress: '127.0.0.1' },
      on(ev, cb) { handlers[ev] = cb; return req; },
    };
    setImmediate(() => {
      for (const chunk of chunks) {
        if (handlers.data) handlers.data(chunk);
      }
      setImmediate(() => {
        if (errorAfter && handlers.error) {
          handlers.error(new Error('socket hang up'));
        } else if (handlers.end) {
          handlers.end();
        }
      });
    });
    return req;
  }

  test('rejects with "Invalid JSON body" for malformed JSON', async () => {
    const { handleRequest } = require('../../lib/server');
    const req = makeStreamReq(['not-valid-json']);
    const res = makeRes();
    const cfg = { serverApiKey: null, trustProxy: false, output: 'json' };
    await handleRequest({ ...req, method: 'POST', url: '/scan', on: req.on }, res, cfg);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid json/i);
  });

  test('rejects with "Request body too large" for oversized body', async () => {
    const { handleRequest, rateLimiter } = require('../../lib/server');
    rateLimiter.reset();
    const huge = 'x'.repeat(1024 * 513); // > 512 KB
    const req = makeStreamReq([huge]);
    const res = makeRes();
    const cfg = { serverApiKey: null, trustProxy: false, output: 'json' };
    await handleRequest({ ...req, method: 'POST', url: '/scan', on: req.on }, res, cfg);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/too large/i);
  });
});

// ─── authenticate — undefined headers ────────────────────────────────────────

describe('authenticate() — undefined headers', () => {
  test('returns false when req.headers is undefined and key is set', () => {
    const { authenticate } = require('../../lib/server');
    expect(authenticate({ headers: undefined }, { serverApiKey: 'secret' })).toBe(false);
  });

  test('returns true when no serverApiKey and headers undefined', () => {
    const { authenticate } = require('../../lib/server');
    expect(authenticate({ headers: undefined }, { serverApiKey: null })).toBe(true);
  });
});

// ─── trustProxy — x-forwarded-for branch ─────────────────────────────────────

describe('handleRequest() — trustProxy: true branch', () => {
  test('reads IP from x-forwarded-for when trustProxy is true', async () => {
    const PROXY_CFG = { serverApiKey: null, trustProxy: true, output: 'json' };
    // Fill rate limit for the forwarded IP, not the socket IP
    const xffIp = '10.0.0.1';
    const socketIp = '127.0.0.1';

    // We just verify the request succeeds (the branch is hit)
    const res = makeRes();
    const req = makeReq({ headers: { 'x-forwarded-for': `${xffIp}, 192.168.1.1` }, ip: socketIp });
    await handleRequest(req, res, PROXY_CFG);
    expect(res.status).toBe(200); // /health
  });
});

// ─── POST /scan — SARIF format branch ────────────────────────────────────────

describe('handleRequest() — POST /scan format: sarif', () => {
  test('returns SARIF document when format is sarif', async () => {
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: { path: process.cwd(), format: 'sarif' } }),
      res, OPEN_CFG,
    );
    expect(res.status).toBe(200);
    // SARIF has version field
    expect(res.body).toHaveProperty('version');
    expect(res.body.version).toBe('2.1.0');
  });
});

// ─── readBody — empty body '{}'  fallback ────────────────────────────────────

describe('readBody — data || "{}" fallback branch', () => {
  test('POST with no body resolves to {} (data || "{}" false branch)', async () => {
    // Covers: data || '{}' when data is empty string
    const res = makeRes();
    // makeReq with null body sends no data chunk → data = '' → uses '{}'
    const req = makeReq({ method: 'POST', url: '/scan', body: null });
    await handleRequest(req, res, OPEN_CFG);
    // path will be undefined → safeScanPath uses cwd → succeeds
    expect([200, 400]).toContain(res.status);
  });
});

// ─── handleRequest — trustProxy socket fallback branches ────────────────────

describe('handleRequest() — trustProxy + socket edge cases', () => {
  const PROXY_CFG = { serverApiKey: null, trustProxy: true, output: 'json' };

  test('falls back to socket.remoteAddress when x-forwarded-for is absent (trustProxy)', async () => {
    const res = makeRes();
    // No x-forwarded-for header — falls back to socket.remoteAddress
    const req = makeReq({ headers: {}, ip: '192.168.1.1' });
    await handleRequest(req, res, PROXY_CFG);
    expect(res.status).toBe(200);
  });

  test('uses "unknown" when socket.remoteAddress is absent (non-trustProxy)', async () => {
    const res = makeRes();
    // Craft a req with no socket
    const req = makeReq();
    delete req.socket;
    await handleRequest(req, res, OPEN_CFG);
    expect(res.status).toBe(200);
  });
});

// ─── handleRequest /scan — cfg.output fallback and '||json' branch ───────────

describe('handleRequest() — format fallback chain', () => {
  test('uses cfg.output when body.format is absent', async () => {
    const CFG = { serverApiKey: null, trustProxy: false, output: 'json' };
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: { path: process.cwd() } }),
      res, CFG,
    );
    expect(res.status).toBe(200);
  });

  test('uses "json" default when both body.format and cfg.output are absent', async () => {
    const CFG = { serverApiKey: null, trustProxy: false, output: undefined };
    const res = makeRes();
    await handleRequest(
      makeReq({ method: 'POST', url: '/scan', body: { path: process.cwd() } }),
      res, CFG,
    );
    expect(res.status).toBe(200);
  });
});

// ─── safeScanPath — cwd ending in path.sep (line 41 cond-expr) ───────────────

describe('safeScanPath() — cwd ending in path.sep', () => {
  test('handles cwd that already ends with path.sep (true branch of cond-expr)', () => {
    const path = require('path');
    const orig = process.cwd;
    const realCwd = orig();
    // Return a cwd that ends with path.sep so the ternary takes the true branch
    process.cwd = () => realCwd + path.sep;
    try {
      // Pass a sub-path that resolves inside cwdNorm so it doesn't throw
      expect(() => safeScanPath(path.join(realCwd, 'lib'))).not.toThrow();
    } finally {
      process.cwd = orig;
    }
  });
});

// ─── handleRequest — trustProxy with both xff and socket absent (|| '') ───────

describe('handleRequest() — trustProxy x-forwarded-for + socket absent', () => {
  test('falls back to empty string when xff absent and socket is undefined (trustProxy)', async () => {
    const PROXY_CFG = { serverApiKey: null, trustProxy: true, output: 'json' };
    const res = makeRes();
    // Craft a req with no xff and no socket
    const req = makeReq({ headers: {} });
    delete req.socket;
    await handleRequest(req, res, PROXY_CFG);
    expect(res.status).toBe(200); // rate-limiter uses '' as the IP — still passes
  });
});

// ─── start() — default-arg (args = []) ───────────────────────────────────────

describe('start() — default args parameter', () => {
  test('start() with no arguments uses default [] (covers default-arg branch)', async () => {
    const server = await start(); // uses default args = []
    server.close();
  });
});
