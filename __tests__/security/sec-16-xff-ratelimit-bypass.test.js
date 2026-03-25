'use strict';

/**
 * SEC-16 — Rate-limit bypass via forged X-Forwarded-For header.
 *
 * Attack vector: when the rate limiter blindly keys on X-Forwarded-For,
 * an attacker rotates the header on each request, never triggering the
 * per-IP limit, while all requests arrive from one real socket IP.
 *
 * Fix: only trust X-Forwarded-For when cfg.trustProxy is explicitly true.
 * Default is false — rate-limit on socket IP.
 */

const { handleRequest, rateLimiter, RATE_LIMIT_MAX } = require('../../lib/server');

// ── Mock req / res helpers ────────────────────────────────────────────────────

function makeReq({ method = 'GET', url = '/health', body = null, headers = {}, ip = '127.0.0.1' } = {}) {
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
  const res = { status: null, body: null };
  res.writeHead = (s) => { res.status = s; };
  res.end = (d) => { try { res.body = JSON.parse(d); } catch { res.body = d; } };
  return res;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('SEC-16: X-Forwarded-For rate-limit bypass prevention', () => {
  const openCfg = { serverApiKey: null, trustProxy: false };

  beforeEach(() => rateLimiter.reset());

  test('rotating X-Forwarded-For cannot bypass limit (trustProxy: false)', async () => {
    // Exhaust limit with requests from socket IP 1.2.3.4,
    // each carrying a DIFFERENT X-Forwarded-For value
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      const req = makeReq({ headers: { 'x-forwarded-for': `10.0.0.${i}` }, ip: '1.2.3.4' });
      await handleRequest(req, makeRes(), openCfg);
    }
    // A fresh XFF IP but the same real socket — must be throttled
    const req = makeReq({ headers: { 'x-forwarded-for': '9.9.9.9' }, ip: '1.2.3.4' });
    const res = makeRes();
    await handleRequest(req, res, openCfg);
    expect(res.status).toBe(429);
  });

  test('different socket IPs remain independent (trustProxy: false)', async () => {
    // Exhaust limit for socket 2.2.2.2
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      await handleRequest(makeReq({ ip: '2.2.2.2' }), makeRes(), openCfg);
    }
    // A different socket IP is unaffected
    const res = makeRes();
    await handleRequest(makeReq({ ip: '3.3.3.3' }), res, openCfg);
    expect(res.status).toBe(200);
  });

  test('when trustProxy is true, X-Forwarded-For is used for rate limiting', async () => {
    const proxyCfg = { serverApiKey: null, trustProxy: true };
    const FORWARDED = '5.5.5.5';
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      await handleRequest(
        makeReq({ headers: { 'x-forwarded-for': FORWARDED }, ip: 'proxy' }),
        makeRes(), proxyCfg,
      );
    }
    const res = makeRes();
    await handleRequest(
      makeReq({ headers: { 'x-forwarded-for': FORWARDED }, ip: 'proxy' }),
      res, proxyCfg,
    );
    expect(res.status).toBe(429);
  });
});
