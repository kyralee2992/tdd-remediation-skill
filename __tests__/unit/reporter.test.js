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

// ── toJson — security_name / security_email ───────────────────────────────────

describe('toJson — security contact fields', () => {
  test('includes security_name when set in config', () => {
    const out = toJson([REAL], [], { security_name: 'Alice Smith' });
    expect(out.security_name).toBe('Alice Smith');
  });

  test('includes security_email when set in config', () => {
    const out = toJson([REAL], [], { security_email: 'security@example.com' });
    expect(out.security_email).toBe('security@example.com');
  });

  test('includes both when both are set', () => {
    const out = toJson([REAL], [], { security_name: 'Alice', security_email: 'alice@example.com' });
    expect(out.security_name).toBe('Alice');
    expect(out.security_email).toBe('alice@example.com');
  });

  test('omits security_name when not set', () => {
    const out = toJson([REAL], [], {});
    expect(out).not.toHaveProperty('security_name');
  });

  test('omits security_email when not set', () => {
    const out = toJson([REAL], [], {});
    expect(out).not.toHaveProperty('security_email');
  });

  test('backwards-compatible: existing callers without config arg still work', () => {
    const out = toJson([REAL]);
    expect(out.summary).toBeDefined();
    expect(out).not.toHaveProperty('security_name');
    expect(out).not.toHaveProperty('security_email');
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

  test('uses tdd_site as informationUri when config.tdd_site is set', () => {
    const sarif = toSarif([], '', { tdd_site: 'https://security.example.com' });
    expect(sarif.runs[0].tool.driver.informationUri).toBe('https://security.example.com');
  });

  test('falls back to npm URL when config.tdd_site is absent', () => {
    const sarif = toSarif([], '', {});
    expect(sarif.runs[0].tool.driver.informationUri).toContain('npmjs.com');
  });

  test('trims whitespace from tdd_site before use', () => {
    const sarif = toSarif([], '', { tdd_site: '  https://security.example.com  ' });
    expect(sarif.runs[0].tool.driver.informationUri).toBe('https://security.example.com');
  });

  test('uses badge_label as driver name when set', () => {
    const sarif = toSarif([], '', { badge_label: 'dc-audit' });
    expect(sarif.runs[0].tool.driver.name).toBe('dc-audit');
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

  test('real finding with inTestFile:true shows [test file] badge', () => {
    const inTest = { ...REAL, inTestFile: true, likelyFalsePositive: false };
    expect(toText([inTest])).toMatch(/\[test file\]/);
  });

  test('finding with unknown severity falls into LOW bucket without throwing', () => {
    const odd = { ...REAL, severity: 'UNKNOWN' };
    expect(() => toText([odd])).not.toThrow();
    expect(toText([odd])).toMatch(/XSS/);
  });
});

// ── [SEC] tdd_site URL scheme injection — reporter.js (SARIF informationUri) ──

describe('[SEC] tdd_site URL scheme injection — reporter.js SARIF', () => {
  const NPM_URL = 'https://www.npmjs.com/package/@lhi/tdd-audit';

  test('[SEC] javascript: URL in tdd_site is not used as SARIF informationUri', () => {
    const sarif = toSarif([], '', { tdd_site: 'javascript:alert(1)' });
    expect(sarif.runs[0].tool.driver.informationUri).not.toContain('javascript:');
    expect(sarif.runs[0].tool.driver.informationUri).toContain(NPM_URL);
  });

  test('[SEC] data: URL in tdd_site is rejected from SARIF informationUri', () => {
    const sarif = toSarif([], '', { tdd_site: 'data:text/html,<script>xss</script>' });
    expect(sarif.runs[0].tool.driver.informationUri).not.toContain('data:');
    expect(sarif.runs[0].tool.driver.informationUri).toContain(NPM_URL);
  });

  test('[SEC] file: URL in tdd_site is rejected from SARIF informationUri', () => {
    const sarif = toSarif([], '', { tdd_site: 'file:///etc/passwd' });
    expect(sarif.runs[0].tool.driver.informationUri).not.toContain('file:');
    expect(sarif.runs[0].tool.driver.informationUri).toContain(NPM_URL);
  });
});

// ── toSarif — edge branches ───────────────────────────────────────────────────

describe('toSarif — branch coverage', () => {
  test('vuln name not in CWE_MAP omits relationships and uses /0.html helpUri', () => {
    const finding = { ...REAL, name: 'Custom Vuln Not In Map', severity: 'HIGH' };
    const sarif = toSarif([finding]);
    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.relationships).toBeUndefined();
    expect(rule.helpUri).toMatch(/\/0\.html/);
  });

  test('unknown severity falls back to "warning" level in result', () => {
    const finding = { ...REAL, severity: 'UNKNOWN_SEV' };
    const sarif = toSarif([finding]);
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  test('finding with no snippet uses name as message text', () => {
    const finding = { ...REAL, snippet: undefined };
    const sarif = toSarif([finding]);
    expect(sarif.runs[0].results[0].message.text).toBe(REAL.name);
  });

  test('finding with empty snippet uses name as message text', () => {
    const finding = { ...REAL, snippet: '' };
    const sarif = toSarif([finding]);
    expect(sarif.runs[0].results[0].message.text).toBe(REAL.name);
  });
});
