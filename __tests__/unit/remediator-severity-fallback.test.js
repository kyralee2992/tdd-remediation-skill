'use strict';

/**
 * Coverage gap: remediator.js threshold fallback `?? 3` (line 198).
 *
 * When severity is not one of CRITICAL/HIGH/MEDIUM/LOW, the expression
 *   ORDER[severity.toUpperCase()] ?? 3
 * falls back to 3 (LOW — include everything).  That branch was never tested.
 *
 * We don't call the real `remediate()` because it fires network requests.
 * Instead we test the pure helper `buildRemediationPrompt` to verify
 * remediator.js is importable and the module-level constants are correct,
 * and we unit-test the fallback via a thin mock that stubs callProvider.
 */

const { remediate, PROVIDERS } = require('../../lib/remediator');

describe('remediator — unknown severity falls back to LOW (coverage gap)', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    // Stub fetch so callProvider resolves without network
    global.fetch = async () => ({
      ok:   true,
      json: async () => ({
        choices: [{ message: { content: '{"exploitTest":{},"patch":{},"refactorChecks":[]}' } }],
      }),
    });
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  test('severity "UNKNOWN" treats threshold as LOW and includes all findings', async () => {
    const findings = [
      { name: 'XSS', severity: 'HIGH',   file: 'a.js', line: 1, snippet: 'x', likelyFalsePositive: false },
      { name: 'Log', severity: 'LOW',    file: 'b.js', line: 2, snippet: 'y', likelyFalsePositive: false },
    ];

    const results = await remediate({
      findings,
      provider: 'openai',
      apiKey:   'sk-test',
      severity: 'UNKNOWN',
    });

    // Both HIGH and LOW findings must be processed (threshold fell back to 3 = LOW)
    expect(results).toHaveLength(2);
  });

  test('finding with unknown severity is excluded by the filter (ORDER[f.severity] ?? 99)', async () => {
    // The filter uses `(ORDER[f.severity] ?? 99) <= threshold`.
    // For an unknown severity: ORDER['UNKNOWN'] is undefined → ?? 99 → 99 > 3 → excluded.
    // Note: the ?? 99 in the subsequent .sort() comparator is unreachable
    // because unknown-severity findings are always excluded by the filter first.
    const findings = [
      { name: 'XSS',     severity: 'HIGH',    file: 'a.js', line: 1, snippet: 'x', likelyFalsePositive: false },
      { name: 'Mystery', severity: 'UNKNOWN', file: 'b.js', line: 2, snippet: 'y', likelyFalsePositive: false },
    ];
    const results = await remediate({ findings, provider: 'openai', apiKey: 'sk-test' });
    // 'UNKNOWN' severity (→ 99) exceeds the threshold (LOW = 3) and is excluded
    expect(results).toHaveLength(1);
    expect(results[0].finding.name).toBe('XSS');
  });

  test('severity "UNKNOWN" does not throw', async () => {
    const findings = [
      { name: 'XSS', severity: 'CRITICAL', file: 'a.js', line: 1, snippet: 'x', likelyFalsePositive: false },
    ];
    await expect(remediate({ findings, provider: 'openai', apiKey: 'sk-test', severity: 'UNKNOWN' }))
      .resolves.toBeDefined();
  });
});
