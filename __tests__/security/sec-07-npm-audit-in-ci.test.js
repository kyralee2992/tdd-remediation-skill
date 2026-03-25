'use strict';

/**
 * SEC-07 — npm audit step must be present in CI workflows
 *
 * Red phase: asserts that the live security-tests.yml and ci.yml both
 * contain an `npm audit` step so dependency vulnerabilities are caught
 * automatically on every push and PR.
 *
 * This test MUST fail before the fix is applied.
 */

const fs   = require('fs');
const path = require('path');

const WORKFLOWS_DIR = path.join(__dirname, '../../.github/workflows');

const REQUIRED_AUDIT_WORKFLOWS = [
  'security-tests.yml',
  'ci.yml',
];

describe('SEC-07: npm audit present in CI workflows', () => {
  test.each(REQUIRED_AUDIT_WORKFLOWS)(
    '%s contains an npm audit --audit-level=high step',
    (name) => {
      const content = fs.readFileSync(path.join(WORKFLOWS_DIR, name), 'utf8');
      expect(content).toMatch(/npm audit.*--audit-level/);
    }
  );
});
