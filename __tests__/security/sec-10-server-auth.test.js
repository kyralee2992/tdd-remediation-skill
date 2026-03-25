'use strict';

/**
 * SEC-10 — REST API security: auth, input validation, path traversal guard
 *
 * Tests the server module directly without starting a real HTTP server,
 * using the exported helpers and a lightweight in-process request simulator.
 */

const path = require('path');

// ── safeScanPath ──────────────────────────────────────────────────────────────
const { safeScanPath } = require('../../lib/server');

describe('SEC-10a: safeScanPath — path traversal guard', () => {
  const cwd = process.cwd();

  test('accepts a path inside cwd', () => {
    const result = safeScanPath('lib');
    expect(result.startsWith(cwd)).toBe(true);
  });

  test('rejects a path that escapes cwd via ../', () => {
    expect(() => safeScanPath('../../etc/passwd')).toThrow('Path outside working directory');
  });

  test('rejects an absolute path outside cwd', () => {
    expect(() => safeScanPath('/etc/passwd')).toThrow('Path outside working directory');
  });

  test('accepts an absolute path inside cwd', () => {
    const inside = path.join(cwd, 'lib');
    expect(() => safeScanPath(inside)).not.toThrow();
  });
});

// ── toJson / reporter ─────────────────────────────────────────────────────────
const { toJson, toSarif } = require('../../lib/reporter');

describe('SEC-10b: reporter output schema', () => {
  const mockFindings = [
    { severity: 'HIGH', name: 'XSS', file: 'src/app.js', line: 10,
      snippet: 'res.send(req.query.x)', inTestFile: false, likelyFalsePositive: false },
    { severity: 'LOW', name: 'Sensitive Log', file: '__tests__/foo.test.js', line: 5,
      snippet: 'console.log(token)', inTestFile: true, likelyFalsePositive: true },
  ];

  test('toJson separates real findings from likelyFalsePositives', () => {
    const out = toJson(mockFindings);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0].name).toBe('XSS');
    expect(out.likelyFalsePositives).toHaveLength(1);
    expect(out.summary.HIGH).toBe(1);
  });

  test('toJson includes version and scannedAt', () => {
    const out = toJson(mockFindings);
    expect(out.version).toBeDefined();
    expect(out.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  test('toSarif produces valid SARIF 2.1.0 envelope', () => {
    const sarif = toSarif(mockFindings);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('@lhi/tdd-audit');
    // Only real findings (not likelyFalsePositive) should appear
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].level).toBe('error'); // HIGH → error
  });

  test('toSarif result locations contain file and line', () => {
    const sarif = toSarif(mockFindings);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe('src/app.js');
    expect(loc.region.startLine).toBe(10);
  });
});

// ── config ────────────────────────────────────────────────────────────────────
const { loadConfig } = require('../../lib/config');

describe('SEC-10c: config — CLI flags override file config', () => {
  test('defaults are applied when no config file exists', () => {
    const cfg = loadConfig('/tmp/nonexistent-dir-tdd-audit-test');
    expect(cfg.port).toBe(3000);
    expect(cfg.output).toBe('text');
  });

  test('CLI overrides win over defaults', () => {
    const cfg = loadConfig('/tmp/nonexistent-dir-tdd-audit-test', { port: 4000, output: 'json' });
    expect(cfg.port).toBe(4000);
    expect(cfg.output).toBe('json');
  });

  test('apiKey resolved from env var when apiKeyEnv is set', () => {
    process.env._TDD_AUDIT_TEST_KEY = 'env-secret';
    const cfg = loadConfig('/tmp/nonexistent-dir-tdd-audit-test', { apiKeyEnv: '_TDD_AUDIT_TEST_KEY' });
    expect(cfg.apiKey).toBe('env-secret');
    delete process.env._TDD_AUDIT_TEST_KEY;
  });
});
