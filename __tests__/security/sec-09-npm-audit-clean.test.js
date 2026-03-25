'use strict';

/**
 * SEC-09 — npm audit must report 0 high/critical vulnerabilities
 *
 * Red phase: this test MUST fail before the picomatch fix is applied.
 * Green phase: passes once package-lock.json is updated via npm audit fix.
 */

const { execSync } = require('child_process');
const path = require('path');

describe('SEC-09: no high/critical npm vulnerabilities', () => {
  test('npm audit --audit-level=high exits 0', () => {
    let output = '';
    let exitCode = 0;
    try {
      output = execSync('npm audit --audit-level=high --json', {
        cwd: path.join(__dirname, '../..'),
        encoding: 'utf8',
      });
    } catch (err) {
      output   = err.stdout || '';
      exitCode = err.status || 1;
    }

    let highCount = 0;
    try {
      const report = JSON.parse(output);
      highCount = (report.metadata?.vulnerabilities?.high   || 0)
                + (report.metadata?.vulnerabilities?.critical || 0);
    } catch {
      // non-JSON output means audit failed for another reason — still a failure
      exitCode = exitCode || 1;
    }

    expect(exitCode).toBe(0);
    expect(highCount).toBe(0);
  });
});
