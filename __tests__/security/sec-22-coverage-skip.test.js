'use strict';

/**
 * SEC-22 — Scanner descends into coverage/ artifacts.
 *
 * Attack vector: Istanbul / nyc writes third-party JS (prettify.js, sorter.js)
 * into coverage/lcov-report/. Those files contain XSS patterns that are not
 * vulnerabilities in the project's own code. When the scanner lacks 'coverage'
 * in SKIP_DIRS it reports spurious HIGH findings, causing CI pipelines to
 * fail on false positives and undermining trust in scan output.
 *
 * Fix: add 'coverage' to SKIP_DIRS so walkFiles() never descends into
 * generated Istanbul/nyc report directories.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { quickScan, walkFiles } = require('../../lib/scanner');

describe('SEC-22: Scanner skips coverage/ directory', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec22-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('walkFiles does not yield files inside coverage/', () => {
    // Create coverage/lcov-report/prettify.js with XSS content (mimics Istanbul output)
    const covDir = path.join(tmpDir, 'coverage', 'lcov-report');
    fs.mkdirSync(covDir, { recursive: true });
    fs.writeFileSync(
      path.join(covDir, 'prettify.js'),
      'window.PR_SHOULD_USE_CONTINUATION=true; element.innerHTML = userInput;\n',
    );
    // Also plant a real source file at the root to confirm scanning works
    fs.writeFileSync(path.join(tmpDir, 'app.js'), 'console.log("hello");\n');

    const walked = [];
    for (const f of walkFiles(tmpDir)) walked.push(f);

    const coveragePaths = walked.filter(f => f.includes(`${path.sep}coverage${path.sep}`));
    expect(coveragePaths).toHaveLength(0);
  });

  test('quickScan does not report XSS findings from coverage/ files', () => {
    const covDir = path.join(tmpDir, 'coverage', 'lcov-report');
    fs.mkdirSync(covDir, { recursive: true });
    // The line below would normally trigger the XSS VULN_PATTERN
    fs.writeFileSync(
      path.join(covDir, 'sorter.js'),
      'colNode.innerHTML = sortDir;\n',
    );

    const findings = quickScan(tmpDir);
    const coverageFindings = findings.filter(f =>
      f.file.includes('coverage') || f.file.includes('lcov-report'),
    );
    expect(coverageFindings).toHaveLength(0);
  });

  test('quickScan still detects XSS in non-coverage source files', () => {
    // Confirm the scanner did not become blind — only coverage is skipped
    const srcDir = path.join(tmpDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });
    fs.writeFileSync(path.join(srcDir, 'render.js'), 'element.innerHTML = userInput;\n');

    const findings = quickScan(tmpDir);
    const xss = findings.filter(f => f.name === 'XSS');
    expect(xss.length).toBeGreaterThan(0);
  });
});
