'use strict';

const crypto  = require('crypto');
const path    = require('path');
const Fastify = require('fastify');

const { quickScan }   = require('./scanner');
const { remediate }   = require('./remediator');
const { version }          = require('../package.json');
const {
  jobs, createJob, updateJob, subscribe, MAX_JOBS,
} = require('./jobs');

// ─── Auth ─────────────────────────────────────────────────────────────────────

// Fixed HMAC key — normalises token lengths for constant-time comparison.
const _authHmacKey = crypto.randomBytes(32);

/**
 * Authenticate a Fastify request.
 * Accepts either a raw Node req or a Fastify request object.
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

// ─── Rate limiter ─────────────────────────────────────────────────────────────

const RATE_LIMIT_MAX    = 60;
const RATE_LIMIT_WINDOW = 60 * 1_000;

function createRateLimit() {
  const _counts = new Map();
  return {
    _counts,
    check(ip) {
      const now   = Date.now();
      const entry = _counts.get(ip) || { count: 0, windowStart: now };
      if (now - entry.windowStart >= RATE_LIMIT_WINDOW) {
        entry.count = 0;
        entry.windowStart = now;
      }
      entry.count += 1;
      _counts.set(ip, entry);
      return entry.count <= RATE_LIMIT_MAX;
    },
    reset() { _counts.clear(); },
  };
}

// ─── Path validation ──────────────────────────────────────────────────────────

function safeScanPath(rawPath) {
  const cwd      = process.cwd();
  const resolved = path.resolve(cwd, rawPath || cwd);
  const cwdNorm  = cwd.endsWith(path.sep) ? cwd : cwd + path.sep;
  if (resolved !== cwd && !resolved.startsWith(cwdNorm)) {
    throw new Error('Path outside working directory');
  }
  return resolved;
}

// ─── Security headers ────────────────────────────────────────────────────────

const SECURITY_HEADERS = {
  'X-Content-Type-Options':  'nosniff',
  'X-Frame-Options':         'DENY',
  'Content-Security-Policy': "default-src 'none'",
};

// ─── Fastify plugin ───────────────────────────────────────────────────────────

/**
 * Fastify plugin that registers all tdd-audit REST routes.
 *
 * Options:
 *   cfg          - loaded config object
 *   rateLimiter  - rate limiter instance (from createRateLimit())
 */
async function tddAuditPlugin(fastify, opts) {
  const { cfg, rateLimiter } = opts;

  // ── Security headers on every reply ────────────────────────────────────────
  fastify.addHook('onSend', async (request, reply) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
      reply.header(k, v);
    }
  });

  // ── Rate limiting ────────────────────────────────────────────────────────
  fastify.addHook('preHandler', async (request, reply) => {
    const ip = cfg.trustProxy
      ? (request.headers['x-forwarded-for'] || request.ip || '').split(',')[0].trim()
      : (request.ip || 'unknown');
    if (!rateLimiter.check(ip)) {
      reply.code(429).send({ error: 'Too Many Requests' });
    }
  });

  // ── GET /health ──────────────────────────────────────────────────────────
  fastify.get('/health', async () => ({ status: 'ok', version }));

  // ── Authentication for all non-health routes ────────────────────────────
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.routeOptions?.url === '/health') return;
    if (!authenticate(request, cfg)) {
      reply.code(401).send({ error: 'Unauthorized' });
    }
  });

  // ── POST /remediate ──────────────────────────────────────────────────────
  fastify.post('/remediate', async (request, reply) => {
    const body = request.body || {};
    const { findings, provider, apiKey, model, baseUrl } = body;

    if (!findings || !provider || !apiKey) {
      return reply.code(400).send({ error: 'findings, provider, and apiKey are required' });
    }

    const jobId = createJob();

    setImmediate(async () => {
      try {
        updateJob(jobId, { status: 'running', startedAt: new Date().toISOString() });
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

    return reply.code(202).send({ jobId });
  });

  // ── POST /audit — full scan+remediate pipeline ────────────────────────────
  fastify.post('/audit', async (request, reply) => {
    const body = request.body || {};
    const { path: rawPath, provider, apiKey, model, baseUrl, webhook } = body;

    let scanPath;
    try { scanPath = safeScanPath(rawPath); }
    catch (e) { return reply.code(400).send({ error: e.message }); }

    const jobId = createJob();

    setImmediate(async () => {
      try {
        // Phase 1: scan
        updateJob(jobId, { status: 'scanning', startedAt: new Date().toISOString() });
        const findings = quickScan(scanPath);
        updateJob(jobId, { status: 'scanned', findings });

        // Phase 2: remediate (if provider supplied)
        if (provider && apiKey) {
          const total = findings.filter(f => !f.likelyFalsePositive).length;
          updateJob(jobId, { status: 'remediating', total, completed: 0 });

          // remediate is eagerly required at module top
          const results = await remediate({
            findings, provider, apiKey,
            model:   model   || cfg.model,
            baseUrl: baseUrl || cfg.baseUrl,
            onProgress: (completed, current) => {
              updateJob(jobId, { status: 'remediating', total, completed, current });
            },
          });
          updateJob(jobId, {
            status: 'done',
            completedAt: new Date().toISOString(),
            findings,
            results,
          });
        } else {
          updateJob(jobId, { status: 'done', completedAt: new Date().toISOString(), findings });
        }

        // Optional webhook fire-and-forget
        if (webhook) {
          const job = jobs.get(jobId);
          fetch(webhook, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(job),
          }).catch(() => {}); // never throw
        }
      } catch (err) {
        updateJob(jobId, { status: 'error', error: err.message });
      }
    });

    reply.header('Location', `/jobs/${jobId}`);
    reply.header('Retry-After', '2');
    return reply.code(202).send({ jobId });
  });

  // ── POST /audit/ai — LLM-powered agentic audit ────────────────────────────
  // Accepts { path?, provider?, apiKey?, model?, baseUrl?, scanOnly?, allowWrites? }
  // Falls back to cfg values for provider/apiKey/model/baseUrl when not supplied.
  // Returns 202 { jobId }. Poll GET /jobs/:id or stream GET /jobs/:id/stream.
  fastify.post('/audit/ai', async (request, reply) => {
    const body = request.body || {};
    const {
      path:       rawPath,
      provider:   bodyProvider,
      apiKey:     bodyApiKey,
      model:      bodyModel,
      baseUrl:    bodyBaseUrl,
      depth       = 'tier-1',
      // scanOnly / allowWrites may still be overridden explicitly; depth takes precedence otherwise
      scanOnly    = null,
      allowWrites = false,
      // Pre-identified findings from a prior tier-3 report (triggers targeted-apply mode when depth=tier-4)
      findings    = null,
    } = body;

    const provider = bodyProvider || cfg.provider;
    const apiKey   = bodyApiKey   || cfg.apiKey;
    const model    = bodyModel    || cfg.model;
    const baseUrl  = bodyBaseUrl  || cfg.baseUrl;

    if (!provider || !apiKey) {
      return reply.code(400).send({
        error: 'provider and apiKey are required (supply in body or configure in .tdd-audit.json)',
      });
    }

    let scanPath = process.cwd();
    if (rawPath) {
      try { scanPath = safeScanPath(rawPath); }
      catch (e) { return reply.code(400).send({ error: e.message }); }
    }

    const jobId = createJob();
    updateJob(jobId, { depth });  // stamp depth on initial pending state

    setImmediate(async () => {
      try {
        const log = [];

        updateJob(jobId, { status: 'running', depth, startedAt: new Date().toISOString() });

        const { runAudit } = require('./auditor');
        let capturedJson = null;

        await runAudit({
          projectDir:   scanPath,
          packageDir:   path.join(__dirname, '..'),
          provider,
          apiKey,
          model,
          baseUrl,
          outputFormat: 'json',
          depth,
          scanOnly,
          allowWrites,
          findings,
          onText: (text) => {
            log.push(text);
            updateJob(jobId, { status: 'running', log: log.join(''), startedAt: new Date().toISOString() });
          },
          outputWriter: (jsonStr) => { capturedJson = jsonStr; },
        });

        let result;
        try {
          result = capturedJson ? JSON.parse(capturedJson.trim()) : { log: log.join('') };
        } catch {
          result = { raw: capturedJson, log: log.join('') };
        }

        updateJob(jobId, {
          status:      'done',
          completedAt: new Date().toISOString(),
          result,
        });
      } catch (err) {
        updateJob(jobId, { status: 'error', error: err.message });
      }
    });

    reply.header('Location',    `/jobs/${jobId}`);
    reply.header('Retry-After', '5');
    return reply.code(202).send({ jobId });
  });

  // ── GET /jobs/:id ────────────────────────────────────────────────────────
  fastify.get('/jobs/:id', async (request, reply) => {
    const job = jobs.get(request.params.id);
    if (!job) return reply.code(404).send({ error: 'Job not found' });
    return job;
  });

  // ── GET /jobs/:id/stream — SSE real-time job updates ─────────────────────
  fastify.get('/jobs/:id/stream', async (request, reply) => {
    const id  = request.params.id;
    const job = jobs.get(id);
    if (!job) return reply.code(404).send({ error: 'Job not found' });

    reply.hijack();
    const raw = reply.raw;
    raw.writeHead(200, {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      ...SECURITY_HEADERS,
    });

    const send = (data) => {
      raw.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    // Push current state immediately
    send(jobs.get(id));

    if (job.status === 'done' || job.status === 'error') {
      raw.end();
      return;
    }

    const unsubscribe = subscribe(id, (updated) => {
      send(updated);
      if (updated.status === 'done' || updated.status === 'error') {
        unsubscribe();
        raw.end();
      }
    });

    raw.on('close', unsubscribe);
  });
}

// ─── App factory ──────────────────────────────────────────────────────────────

/**
 * Build and return a configured Fastify instance.
 * @param {object} cfg  - loaded config object
 * @param {object} [overrides] - optional overrides (e.g. { logger: true })
 */
function buildApp(cfg, overrides = {}) {
  const fastify = Fastify({
    logger:           false,
    trustProxy:       cfg.trustProxy || false,
    bodyLimit:        512 * 1024, // 512 KB
    ...overrides,
  });

  const rateLimiter = createRateLimit();

  fastify.register(tddAuditPlugin, { cfg, rateLimiter });

  // Expose internals for testing
  fastify.decorate('rateLimiter', rateLimiter);
  fastify.decorate('jobs',        jobs);
  fastify.decorate('cfg',         cfg);

  return fastify;
}

module.exports = {
  tddAuditPlugin,
  buildApp,
  authenticate,
  safeScanPath,
  createRateLimit,
  RATE_LIMIT_MAX,
};
