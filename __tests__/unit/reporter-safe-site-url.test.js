'use strict';

/**
 * Coverage gap: reporter.js safeSiteUrl catch branch (line 76).
 *
 * safeSiteUrl is called by toSarif() to sanitize config.tdd_site before
 * embedding it in SARIF output.  The catch branch (triggered by an
 * un-parseable URL string) was never exercised — it silently fell back to
 * the npm page URL, but no test verified that behaviour.
 */

const { toSarif } = require('../../lib/reporter');

const NPM_URL = 'https://www.npmjs.com/package/@lhi/tdd-audit';

const finding = {
  severity: 'HIGH', name: 'XSS', file: 'src/app.js', line: 10,
  snippet: 'res.send(x)', inTestFile: false, likelyFalsePositive: false,
};

describe('reporter safeSiteUrl — invalid URL fallback (coverage gap)', () => {
  test('un-parseable tdd_site falls back to npm URL in SARIF informationUri', () => {
    const sarif = toSarif([finding], '', { tdd_site: 'not a url %%' });
    expect(sarif.runs[0].tool.driver.informationUri).toBe(NPM_URL);
  });

  test('javascript: scheme falls back to npm URL', () => {
    const sarif = toSarif([finding], '', { tdd_site: 'javascript:alert(1)' });
    expect(sarif.runs[0].tool.driver.informationUri).toBe(NPM_URL);
  });

  test('empty tdd_site falls back to npm URL', () => {
    const sarif = toSarif([finding], '', { tdd_site: '' });
    expect(sarif.runs[0].tool.driver.informationUri).toBe(NPM_URL);
  });

  test('valid https URL is preserved', () => {
    const sarif = toSarif([finding], '', { tdd_site: 'https://example.com/audit' });
    expect(sarif.runs[0].tool.driver.informationUri).toBe('https://example.com/audit');
  });
});
