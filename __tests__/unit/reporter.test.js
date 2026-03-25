'use strict';

/**
 * Unit tests — lib/reporter.js
 * Covers: toJson, toSarif, toText
 */

const { toJson, toSarif, toText } = require('../../lib/reporter');

const REAL = {
  severity: 'HIGH', name: 'XSS', file: 'src/app.js', line: 10,
  snippet: 'res.send(req.query.x)', inTestFile: false, likelyFalsePositive: false,
};
const CRITICAL = {
  severity: 'CRITICAL', name: 'SQL Injection', file: 'db.js', line: 5,
  snippet: 'query(req.body.id)', inTestFile: false, likelyFalsePositive: false,
};
const NOISY = {
  severity: 'LOW', name: 'Sensitive Log', file: '__tests__/foo.test.js', line: 3,
  snippet: 'console.log(token)', inTestFile: true, likelyFalsePositive: true,
};

// ── toJson ────────────────────────────────────────────────────────────────────

describe('toJson', () => {
  test('separates real findings from likelyFalsePositives', () => {
    const out = toJson([REAL, NOISY]);
    expect(out.findings).toHaveLength(1);
    expect(out.likelyFalsePositives).toHaveLength(1);
  });

  test('summary counts are correct', () => {
    const out = toJson([REAL, CRITICAL]);
    expect(out.summary.CRITICAL).toBe(1);
    expect(out.summary.HIGH).toBe(1);
    expect(out.summary.MEDIUM).toBe(0);
    expect(out.summary.LOW).toBe(0);
  });

  test('includes version string', () => {
    expect(typeof toJson([]).version).toBe('string');
  });

  test('scannedAt is ISO timestamp', () => {
    expect(toJson([]).scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  test('exempted list is included', () => {
    const out = toJson([], ['lib/safe.js']);
    expect(out.exempted).toEqual(['lib/safe.js']);
  });

  test('empty findings returns zero summary', () => {
    const out = toJson([]);
    expect(out.summary).toEqual({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  });

  test('noisy findings excluded from summary counts', () => {
    const out = toJson([NOISY]);
    expect(out.summary).toEqual({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  });
});

// ── toSarif ───────────────────────────────────────────────────────────────────

describe('toSarif', () => {
  test('returns valid SARIF 2.1.0 envelope', () => {
    const sarif = toSarif([REAL]);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toMatch(/sarif/);
    expect(sarif.runs).toHaveLength(1);
  });

  test('driver name is @lhi/tdd-audit', () => {
    expect(toSarif([]).runs[0].tool.driver.name).toBe('@lhi/tdd-audit');
  });

  test('excludes likelyFalsePositive findings', () => {
    const sarif = toSarif([REAL, NOISY]);
    expect(sarif.runs[0].results).toHaveLength(1);
  });

  test('result level maps severity correctly', () => {
    const sarif = toSarif([CRITICAL, REAL]);
    const levels = sarif.runs[0].results.map(r => r.level);
    expect(levels).toEqual(['error', 'error']); // CRITICAL and HIGH both → error
  });

  test('MEDIUM maps to warning', () => {
    const medium = { ...REAL, severity: 'MEDIUM', name: 'CORS Wildcard' };
    const sarif = toSarif([medium]);
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  test('result locations contain file and line', () => {
    const sarif = toSarif([REAL]);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe('src/app.js');
    expect(loc.region.startLine).toBe(10);
  });

  test('duplicate vuln names produce a single rule entry', () => {
    const dup = { ...REAL, line: 20 };
    const sarif = toSarif([REAL, dup]);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  test('CWE relationship is attached for known vuln types', () => {
    const sarif = toSarif([REAL]); // XSS → CWE-79
    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.relationships[0].target.id).toBe('CWE-79');
  });

  test('empty findings returns empty results array', () => {
    expect(toSarif([]).runs[0].results).toHaveLength(0);
  });
});

// ── toText ────────────────────────────────────────────────────────────────────

describe('toText', () => {
  test('no findings returns clean message', () => {
    expect(toText([])).toMatch(/No obvious vulnerability/);
  });

  test('shows count of real findings', () => {
    const text = toText([REAL, NOISY]);
    expect(text).toMatch(/1 potential issue/);
  });

  test('groups findings by severity', () => {
    const text = toText([REAL, CRITICAL]);
    expect(text).toMatch(/CRITICAL/);
    expect(text).toMatch(/HIGH/);
  });

  test('lists likely false positives in separate section', () => {
    const text = toText([REAL, NOISY]);
    expect(text).toMatch(/Likely intentional/);
    expect(text).toMatch(/Sensitive Log/);
  });

  test('lists exempted files', () => {
    const text = toText([], ['lib/safe.js']);
    expect(text).toMatch(/lib\/safe\.js/);
    expect(text).toMatch(/audit_status:safe/);
  });

  test('snippet is included in output', () => {
    expect(toText([REAL])).toMatch(/res\.send/);
  });
});
