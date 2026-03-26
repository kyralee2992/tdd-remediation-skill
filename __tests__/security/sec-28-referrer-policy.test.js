'use strict';

/**
 * SEC-28 — Missing Referrer-Policy header (MEDIUM / OWASP A05).
 *
 * Without Referrer-Policy the browser may leak URL query parameters
 * (including tokens) via the Referer header to third parties.
 *
 * Fix: add `Referrer-Policy: no-referrer` to SECURITY_HEADERS in
 * lib/plugin.js and to the json() helper in lib/server.js.
 *
 * Red phase: both helpers currently omit the header, so these tests FAIL.
 */

const { handleRequest, rateLimiter } = require('../../lib/server');
const { buildApp } = require('../../lib/plugin');
const { loadConfig } = require('../../lib/config');

// ─── Legacy HTTP server (server.js) ──────────────────────────────────────────

function makeReqRes(method, url, headers = {}) {
  const writtenHeaders = {};
  let statusCode;
  const req = {
    method, url,
    headers: { ...headers },
    socket: { remoteAddress: '127.0.0.1' },
    on(event, cb) { if (event === 'end') setImmediate(cb); return this; },
  };
  const res = {
    writeHead(code, hdrs) { statusCode = code; Object.assign(writtenHeaders, hdrs); },
    end() {},
    get status() { return statusCode; },
    get headers() { return writtenHeaders; },
  };
  return { req, res };
}

beforeEach(() => { rateLimiter.reset(); });

const cfg = { serverApiKey: null, trustProxy: false, output: 'json' };

describe('SEC-28: Referrer-Policy header — legacy HTTP server (server.js)', () => {
  test('GET /health includes Referrer-Policy', async () => {
    const { req, res } = makeReqRes('GET', '/health');
    await handleRequest(req, res, cfg);
    expect(res.headers['Referrer-Policy']).toBeDefined();
  });

  test('Referrer-Policy value is no-referrer', async () => {
    const { req, res } = makeReqRes('GET', '/health');
    await handleRequest(req, res, cfg);
    expect(res.headers['Referrer-Policy']).toBe('no-referrer');
  });

  test('404 response includes Referrer-Policy', async () => {
    const { req, res } = makeReqRes('GET', '/no-such-route');
    await handleRequest(req, res, cfg);
    expect(res.headers['Referrer-Policy']).toBeDefined();
  });
});

// ─── Fastify plugin (plugin.js) ───────────────────────────────────────────────

describe('SEC-28: Referrer-Policy header — Fastify plugin (plugin.js)', () => {
  let fastify;

  beforeAll(async () => {
    const config = loadConfig(process.cwd(), {});
    fastify = buildApp({ ...config, serverApiKey: null });
    await fastify.ready();
  });

  afterAll(async () => { await fastify.close(); });

  test('GET /health response includes Referrer-Policy', async () => {
    const res = await fastify.inject({ method: 'GET', url: '/health' });
    expect(res.headers['referrer-policy']).toBeDefined();
  });

  test('Referrer-Policy value is no-referrer', async () => {
    const res = await fastify.inject({ method: 'GET', url: '/health' });
    expect(res.headers['referrer-policy']).toBe('no-referrer');
  });

  test('404 response includes Referrer-Policy', async () => {
    const res = await fastify.inject({ method: 'GET', url: '/no-such-route' });
    expect(res.headers['referrer-policy']).toBeDefined();
  });
});
