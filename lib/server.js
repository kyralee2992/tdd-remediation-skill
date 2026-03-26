'use strict';

const crypto = require('crypto');
const path   = require('path');
const { quickScan }                   = require('./scanner');
const { toJson, toSarif }             = require('./reporter');
const { loadConfig, parseCliOverrides } = require('./config');
const { version }                     = require('../package.json');
const { buildApp, RATE_LIMIT_MAX }    = require('./plugin');
const {
  jobs, createJob, updateJob, MAX_JOBS, JOB_TTL_MS,
} = require('./jobs');

// ─── Auth (kept here for backward compat — SEC-17 reads this file) ────────────

// Fixed HMAC key for normalising token lengths before constant-time comparison.
const _authHmacKey = crypto.randomBytes(32);

/**
 * Authenticate incoming requests.
 * Accepts Node.js http.IncomingMessage OR Fastify Request objects.
 * Uses HMAC + timingSafeEqual to prevent timing-oracle attacks.
 */
function authenticate(req, cfg) {
  if (!cfg.serverApiKey) return true;
  const headers = req.headers || {};
  const header  = headers['authorization'] || '';
  const token   = header.startsWith('Bearer ') ? header.slice(7) : '';
  const expected = crypto.createHmac('sha256', _authHmacKey).update(cfg.serverApiKey).digest();
  const actual   = crypto.createHmac('sha256', _authHmacKey).update(token).digest();
  return crypto.timingSafeEqual(expected, actual);
}

/**
 * Validate and sanitise the `path` field from POST /scan.
 * Only allow paths inside cwd to prevent path traversal.
 */
function safeScanPath(rawPath) {
  const cwd      = process.cwd();
  const resolved = path.resolve(cwd, rawPath || cwd);
  const cwdNorm  = cwd.endsWith(path.sep) ? cwd : cwd + path.sep;
  if (resolved !== cwd && !resolved.startsWith(cwdNorm)) {
    throw new Error('Path outside working directory');
  }
  return resolved;
}

// ─── Rate limiter (kept here for backward compat — SEC-14/16/20 read this) ───

const RATE_LIMIT_WINDOW = 60 * 1_000;

const rateLimiter = {
  _counts: new Map(),
  check(ip) {
    const now   = Date.now();
    const entry = this._counts.get(ip) || { count: 0, windowStart: now };
    if (now - entry.windowStart >= RATE_LIMIT_WINDOW) {
      entry.count = 0;
      entry.windowStart = now;
    }
    entry.count += 1;
    this._counts.set(ip, entry);
    return entry.count <= RATE_LIMIT_MAX;
  },
  reset() { this._counts.clear(); },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':            'application/json',
    'Content-Length':           Buffer.byteLength(payload),
    'X-Content-Type-Options':  'nosniff',
    'X-Frame-Options':         'DENY',
    'Content-Security-Policy': "default-src 'none'",
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 1024 * 512) reject(new Error('Request body too large'));
    });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

// ─── Router (kept for backward compat — SEC-16/20 and E2E tests use this) ────

async function handleRequest(req, res, cfg) {
  const { method, url } = req;

  const ip = cfg.trustProxy
    ? (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim()
    : (req.socket?.remoteAddress || 'unknown');
  if (!rateLimiter.check(ip)) {
    return json(res, 429, { error: 'Too Many Requests' });
  }

  if (method === 'GET' && url === '/health') {
    return json(res, 200, { status: 'ok', version });
  }

  if (!authenticate(req, cfg)) {
    return json(res, 401, { error: 'Unauthorized' });
  }

  if (method === 'POST' && url === '/scan') {
    let body;
    try { body = await readBody(req); }
    catch (e) { return json(res, 400, { error: e.message }); }

    let scanPath;
    try { scanPath = safeScanPath(body.path); }
    catch (e) { return json(res, 400, { error: e.message }); }

    const format   = body.format || cfg.output || 'json';
    const t0       = Date.now();
    const findings = quickScan(scanPath);
    const exempted = findings.exempted || [];
    const duration = Date.now() - t0;

    if (format === 'sarif') return json(res, 200, toSarif(findings, scanPath));
    return json(res, 200, { ...toJson(findings, exempted), duration });
  }

  if (method === 'POST' && url === '/remediate') {
    let body;
    try { body = await readBody(req); }
    catch (e) { return json(res, 400, { error: e.message }); }

    const { findings, provider, apiKey, model, baseUrl } = body;
    if (!findings || !provider || !apiKey) {
      return json(res, 400, { error: 'findings, provider, and apiKey are required' });
    }

    const jobId = createJob();

    setImmediate(async () => {
      try {
        updateJob(jobId, { status: 'running', startedAt: new Date().toISOString() });
        const { remediate } = require('./remediator');
        const results = await remediate({
          findings, provider, apiKey,
          model:   model   || cfg.model,
          baseUrl: baseUrl || cfg.baseUrl,
        });
        updateJob(jobId, { status: 'done', completedAt: new Date().toISOString(), results });
      } catch (err) {
        updateJob(jobId, { status: 'error', error: err.message });
      }
    });

    return json(res, 202, { jobId });
  }

  const jobMatch = url.match(/^\/jobs\/([^/?]+)$/);
  if (method === 'GET' && jobMatch) {
    const job = jobs.get(jobMatch[1]);
    if (!job) return json(res, 404, { error: 'Job not found' });
    return json(res, 200, job);
  }

  return json(res, 404, { error: 'Not found' });
}

// ─── Start (uses Fastify) ─────────────────────────────────────────────────────

async function start(args = []) {
  const cfg  = loadConfig(process.cwd(), parseCliOverrides(args));
  const port = cfg.port;

  const fastify = buildApp(cfg);

  await fastify.listen({ port, host: '0.0.0.0' });

  process.stdout.write(`\n🔒 tdd-audit REST API listening on http://localhost:${port}\n`);
  if (!cfg.serverApiKey) {
    process.stderr.write('⚠️  No --api-key set — server is unauthenticated. Set one for production.\n');
  }
  process.stdout.write('   GET  /health\n');
  process.stdout.write('   POST /scan         { path, format? }\n');
  process.stdout.write('   POST /remediate    { findings, provider, apiKey, model? }\n');
  process.stdout.write('   POST /audit        { path, provider?, apiKey?, model? }\n');
  process.stdout.write('   GET  /jobs/:id\n');
  process.stdout.write('   GET  /jobs/:id/stream  (SSE)\n\n');

  return fastify.server; // returned for testing
}

module.exports = {
  start, handleRequest, authenticate,
  jobs, createJob, updateJob,
  safeScanPath, MAX_JOBS, JOB_TTL_MS,
  rateLimiter, RATE_LIMIT_MAX,
};
