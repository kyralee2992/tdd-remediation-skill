'use strict';

/**
 * SEC-20 — Missing Content-Security-Policy header (MEDIUM).
 *
 * The json() response helper in lib/server.js sets X-Content-Type-Options and
 * X-Frame-Options but omits Content-Security-Policy. This is a defence-in-depth
 * gap: CSP is a baseline expectation for any HTTP server.
 *
 * Fix: add `Content-Security-Policy: default-src 'none'` to every response
 * emitted by the json() helper.
 */

const { handleRequest, rateLimiter } = require('../../lib/server');

// Minimal req/res simulator — records written headers and body.
function makeReqRes(method, url, headers = {}) {
  const chunks = [];
  const writtenHeaders = {};
  let statusCode;

  const req = {
    method,
    url,
    headers: { ...headers },
    socket: { remoteAddress: '127.0.0.1' },
    on(event, cb) {
      if (event === 'end') setImmediate(cb);
      return this;
    },
  };

  const res = {
    writeHead(code, hdrs) {
      statusCode = code;
      Object.assign(writtenHeaders, hdrs);
    },
    end(chunk) { if (chunk) chunks.push(chunk); },
    get status() { return statusCode; },
    get headers() { return writtenHeaders; },
  };

  return { req, res };
}

beforeEach(() => {
  rateLimiter.reset();
});

const cfg = { serverApiKey: null, trustProxy: false, output: 'json' };

describe('SEC-20: Missing CSP header on REST API responses', () => {
  test('GET /health response includes Content-Security-Policy header', async () => {
    const { req, res } = makeReqRes('GET', '/health');
    await handleRequest(req, res, cfg);
    expect(res.headers['Content-Security-Policy']).toBeDefined();
  });

  test('GET /health CSP value is restrictive (default-src none)', async () => {
    const { req, res } = makeReqRes('GET', '/health');
    await handleRequest(req, res, cfg);
    expect(res.headers['Content-Security-Policy']).toMatch(/default-src\s+['"]?none['"]?/i);
  });

  test('401 Unauthorized response includes Content-Security-Policy header', async () => {
    const { req, res } = makeReqRes('POST', '/scan', { authorization: 'Bearer wrong' });
    const cfgWithKey = { ...cfg, serverApiKey: 'correct-key' };
    // Attach a minimal body reader so the request doesn't hang
    req.on = (event, cb) => {
      if (event === 'end') setImmediate(cb);
      return req;
    };
    await handleRequest(req, res, cfgWithKey);
    expect(res.headers['Content-Security-Policy']).toBeDefined();
  });

  test('404 Not Found response includes Content-Security-Policy header', async () => {
    const { req, res } = makeReqRes('GET', '/no-such-route');
    await handleRequest(req, res, cfg);
    expect(res.headers['Content-Security-Policy']).toBeDefined();
  });
});
