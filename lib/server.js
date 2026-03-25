'use strict';

const http  = require('http');
const path  = require('path');
const { quickScan, scanPromptFiles } = require('./scanner');
const { toJson, toSarif, toText }    = require('./reporter');
const { loadConfig, parseCliOverrides } = require('./config');
const { version } = require('../package.json');

// ─── Job store (in-memory) ────────────────────────────────────────────────────

const jobs = new Map();
let jobSeq = 0;

function createJob() {
  const id = `job_${++jobSeq}_${Date.now()}`;
  jobs.set(id, { id, status: 'pending', createdAt: new Date().toISOString() });
  return id;
}

function updateJob(id, patch) {
  const job = jobs.get(id);
  if (job) jobs.set(id, { ...job, ...patch });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':  'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
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

/**
 * Authenticate incoming requests.
 * If serverApiKey is set, require `Authorization: Bearer <key>`.
 */
function authenticate(req, cfg) {
  if (!cfg.serverApiKey) return true; // no key configured — open
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : '';
  return token === cfg.serverApiKey;
}

/**
 * Validate and sanitise the `path` field from POST /scan.
 * Only allow paths inside cwd to prevent path traversal.
 */
function safeScanPath(rawPath) {
  const cwd      = process.cwd();
  const resolved = path.resolve(cwd, rawPath || cwd);
  if (!resolved.startsWith(cwd)) throw new Error('Path outside working directory');
  return resolved;
}

// ─── Router ───────────────────────────────────────────────────────────────────

async function handleRequest(req, res, cfg) {
  const { method, url } = req;

  // ── GET /health ────────────────────────────────────────────────────────────
  if (method === 'GET' && url === '/health') {
    return json(res, 200, { status: 'ok', version });
  }

  // All other routes require authentication
  if (!authenticate(req, cfg)) {
    return json(res, 401, { error: 'Unauthorized' });
  }

  // ── POST /scan ─────────────────────────────────────────────────────────────
  if (method === 'POST' && url === '/scan') {
    let body;
    try { body = await readBody(req); }
    catch (e) { return json(res, 400, { error: e.message }); }

    let scanPath;
    try { scanPath = safeScanPath(body.path); }
    catch (e) { return json(res, 400, { error: e.message }); }

    const format  = body.format || cfg.output || 'json';
    const t0      = Date.now();
    const findings = quickScan(scanPath);
    const exempted = findings.exempted || [];
    const duration = Date.now() - t0;

    if (format === 'sarif') {
      return json(res, 200, toSarif(findings, scanPath));
    }
    return json(res, 200, { ...toJson(findings, exempted), duration });
  }

  // ── POST /remediate ────────────────────────────────────────────────────────
  if (method === 'POST' && url === '/remediate') {
    let body;
    try { body = await readBody(req); }
    catch (e) { return json(res, 400, { error: e.message }); }

    const { findings, provider, apiKey, model } = body;
    if (!findings || !provider || !apiKey) {
      return json(res, 400, { error: 'findings, provider, and apiKey are required' });
    }

    const jobId = createJob();

    // Kick off async remediation (non-blocking)
    setImmediate(async () => {
      try {
        updateJob(jobId, { status: 'running', startedAt: new Date().toISOString() });
        const { remediate } = require('./remediator');
        const results = await remediate({ findings, provider, apiKey, model: model || cfg.model });
        updateJob(jobId, { status: 'done', completedAt: new Date().toISOString(), results });
      } catch (err) {
        updateJob(jobId, { status: 'error', error: err.message });
      }
    });

    return json(res, 202, { jobId });
  }

  // ── GET /jobs/:id ──────────────────────────────────────────────────────────
  const jobMatch = url.match(/^\/jobs\/([^/?]+)$/);
  if (method === 'GET' && jobMatch) {
    const job = jobs.get(jobMatch[1]);
    if (!job) return json(res, 404, { error: 'Job not found' });
    return json(res, 200, job);
  }

  return json(res, 404, { error: 'Not found' });
}

// ─── Start ────────────────────────────────────────────────────────────────────

function start(args = []) {
  const cfg  = loadConfig(process.cwd(), parseCliOverrides(args));
  const port = cfg.port;

  const server = http.createServer(async (req, res) => {
    try {
      await handleRequest(req, res, cfg);
    } catch (err) {
      // Production error handler — no stack traces
      json(res, 500, { error: 'Internal server error' });
    }
  });

  server.listen(port, () => {
    process.stdout.write(`\n🔒 tdd-audit REST API listening on http://localhost:${port}\n`);
    if (!cfg.serverApiKey) {
      process.stderr.write('⚠️  No --api-key set — server is unauthenticated. Set one for production.\n');
    }
    process.stdout.write('   GET  /health\n');
    process.stdout.write('   POST /scan        { path, format? }\n');
    process.stdout.write('   POST /remediate   { findings, provider, apiKey, model? }\n');
    process.stdout.write('   GET  /jobs/:id\n\n');
  });

  return server; // returned for testing
}

module.exports = { start, jobs, createJob, updateJob, safeScanPath };
