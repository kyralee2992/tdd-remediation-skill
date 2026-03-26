'use strict';

/**
 * Coverage for plugin.js async error-catch paths:
 *   Line 160 — /remediate setImmediate catch: updateJob({ status: 'error' })
 *   Line 219 — /audit    setImmediate catch: updateJob({ status: 'error' })
 *   Line 293 — /audit/ai JSON parse fallback: { raw: capturedJson, log }
 *
 * Uses jest.mock so that remediate(), quickScan(), and runAudit() can be
 * controlled without real network calls.
 */

jest.mock('../../lib/remediator', () => ({
  remediate: jest.fn(),
}));

jest.mock('../../lib/scanner', () => ({
  quickScan: jest.fn(),
  walkFiles: jest.fn(() => []),
}));

jest.mock('../../lib/auditor', () => ({
  runAudit: jest.fn(),
}));

const { remediate }  = require('../../lib/remediator');
const { quickScan }  = require('../../lib/scanner');
const { runAudit }   = require('../../lib/auditor');
const { buildApp }   = require('../../lib/plugin');

function openApp() {
  return buildApp({ serverApiKey: null, trustProxy: false, output: 'json' });
}

// ─── POST /remediate — line 160 ───────────────────────────────────────────────

describe('POST /remediate — async error catch (line 160)', () => {
  let app;
  beforeAll(async () => { app = openApp(); await app.ready(); });
  afterAll(() => app.close());

  beforeEach(() => {
    remediate.mockRejectedValue(new Error('LLM provider timed out'));
  });

  test('job transitions to error when remediate() throws', async () => {
    const res = await app.inject({
      method:  'POST',
      url:     '/remediate',
      payload: {
        provider: 'openai',
        apiKey:   'sk-test',
        findings: [{ name: 'XSS', severity: 'HIGH', file: 'a.js', line: 1, snippet: 'x' }],
      },
    });

    expect(res.statusCode).toBe(202);
    const { jobId } = JSON.parse(res.body);

    await new Promise(r => setTimeout(r, 200));

    const jobRes = await app.inject({ method: 'GET', url: `/jobs/${jobId}` });
    const job = JSON.parse(jobRes.body);
    expect(job.status).toBe('error');
    expect(job.error).toMatch(/timed out/);
  });
});

// ─── POST /audit — line 219 ───────────────────────────────────────────────────

describe('POST /audit — async error catch (line 219)', () => {
  let app;
  beforeAll(async () => { app = openApp(); await app.ready(); });
  afterAll(() => app.close());

  test('job transitions to error when quickScan() throws', async () => {
    quickScan.mockImplementationOnce(() => { throw new Error('Disk read failed'); });

    const res = await app.inject({
      method:  'POST',
      url:     '/audit',
      payload: { path: '.' },
    });

    expect(res.statusCode).toBe(202);
    const { jobId } = JSON.parse(res.body);

    await new Promise(r => setTimeout(r, 200));

    const jobRes = await app.inject({ method: 'GET', url: `/jobs/${jobId}` });
    const job = JSON.parse(jobRes.body);
    expect(job.status).toBe('error');
    expect(job.error).toMatch(/Disk read failed/);
  });

  test('job transitions to error when remediate() throws after scan', async () => {
    quickScan.mockReturnValueOnce([
      { name: 'XSS', severity: 'HIGH', file: 'a.js', line: 1, likelyFalsePositive: false },
    ]);
    remediate.mockRejectedValueOnce(new Error('Provider quota exceeded'));

    const res = await app.inject({
      method:  'POST',
      url:     '/audit',
      payload: { path: '.', provider: 'openai', apiKey: 'sk-test' },
    });

    expect(res.statusCode).toBe(202);
    const { jobId } = JSON.parse(res.body);

    await new Promise(r => setTimeout(r, 200));

    const jobRes = await app.inject({ method: 'GET', url: `/jobs/${jobId}` });
    const job = JSON.parse(jobRes.body);
    expect(job.status).toBe('error');
    expect(job.error).toMatch(/quota exceeded/);
  });
});

// ─── POST /audit/ai — line 293 (JSON parse fallback) ─────────────────────────

describe('POST /audit/ai — JSON parse fallback (line 293)', () => {
  let app;
  beforeAll(async () => { app = openApp(); await app.ready(); });
  afterAll(() => app.close());

  test('job result falls back to { raw, log } when outputWriter receives non-JSON', async () => {
    // Make runAudit call outputWriter with non-JSON text (simulates LLM returning plain prose)
    runAudit.mockImplementationOnce(async (opts) => {
      if (opts.outputWriter) opts.outputWriter('This is plain text, not JSON at all!');
      if (opts.onText)       opts.onText('chunk');
    });

    const res = await app.inject({
      method:  'POST',
      url:     '/audit/ai',
      payload: { provider: 'anthropic', apiKey: 'sk-test', scanOnly: true },
    });

    expect(res.statusCode).toBe(202);
    const { jobId } = JSON.parse(res.body);

    await new Promise(r => setTimeout(r, 200));

    const jobRes = await app.inject({ method: 'GET', url: `/jobs/${jobId}` });
    const job = JSON.parse(jobRes.body);
    expect(job.status).toBe('done');
    // Line 293: result = { raw: capturedJson, log: log.join('') }
    expect(job.result.raw).toContain('plain text');
    expect(job.result.log).toBeDefined();
  });

  test('job result is log-only when outputWriter is never called (no structured output)', async () => {
    // runAudit writes via onText but never calls outputWriter (text-only mode)
    runAudit.mockImplementationOnce(async (opts) => {
      if (opts.onText) opts.onText('text only output');
    });

    const res = await app.inject({
      method:  'POST',
      url:     '/audit/ai',
      payload: { provider: 'anthropic', apiKey: 'sk-test', scanOnly: true },
    });

    const { jobId } = JSON.parse(res.body);
    await new Promise(r => setTimeout(r, 200));

    const jobRes = await app.inject({ method: 'GET', url: `/jobs/${jobId}` });
    const job = JSON.parse(jobRes.body);
    expect(job.status).toBe('done');
    // capturedJson is null → result = { log: log.join('') }
    expect(job.result.log).toContain('text only output');
  });
});
