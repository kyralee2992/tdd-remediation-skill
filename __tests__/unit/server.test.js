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
  test('returns an http.Server and starts listening', (done) => {
    const stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
    const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => {});
    const server = start(['--port', '0']);
    expect(typeof server.listen).toBe('function');
    server.on('listening', () => {
      stderrSpy.mockRestore();
      stdoutSpy.mockRestore();
      server.close(done);
    });
  });

  test('logs unauthenticated warning when no serverApiKey is set', (done) => {
    const stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
    const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => {});
    const server = start(['--port', '0']);
    server.on('listening', () => {
      expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('unauthenticated'));
      stderrSpy.mockRestore();
      stdoutSpy.mockRestore();
      server.close(done);
    });
  });

  test('does not log warning when serverApiKey is set', (done) => {
    const stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
    const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => {});
    const server = start(['--port', '0', '--api-key', 'test-secret']);
    server.on('listening', () => {
      expect(stderrSpy).not.toHaveBeenCalled();
      stderrSpy.mockRestore();
      stdoutSpy.mockRestore();
      server.close(done);
    });
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
