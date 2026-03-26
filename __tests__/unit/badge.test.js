'use strict';

/**
 * Unit tests for the badge injection helpers in index.js.
 *
 * These are tested via the exported helpers — the badge logic is pure and
 * deterministic, so we test it in isolation before wiring it to the installer.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { badgeLine, injectBadge, BADGE_MARKER } = require('../../lib/badge');

// ─── badgeLine() ──────────────────────────────────────────────────────────────

describe('badgeLine()', () => {
  test('returns a markdown badge string', () => {
    const line = badgeLine([]);
    expect(line).toMatch(/!\[tdd-audit\]/);
    expect(line).toMatch(/shields\.io/);
    expect(line).toMatch(/npmjs\.com.*tdd-audit/);
  });

  test('shows "passing" in green when no critical or high findings', () => {
    const findings = [
      { severity: 'MEDIUM', likelyFalsePositive: false },
      { severity: 'LOW',    likelyFalsePositive: false },
    ];
    const line = badgeLine(findings);
    expect(line).toMatch(/passing/i);
    expect(line).toMatch(/brightgreen/);
  });

  test('shows critical count and red when critical findings exist', () => {
    const findings = [
      { severity: 'CRITICAL', likelyFalsePositive: false },
      { severity: 'CRITICAL', likelyFalsePositive: false },
      { severity: 'HIGH',     likelyFalsePositive: false },
    ];
    const line = badgeLine(findings);
    expect(line).toMatch(/2%20critical/i);
    expect(line).toMatch(/red/);
  });

  test('shows high count and orange when only high findings exist', () => {
    const findings = [
      { severity: 'HIGH', likelyFalsePositive: false },
      { severity: 'HIGH', likelyFalsePositive: false },
    ];
    const line = badgeLine(findings);
    expect(line).toMatch(/2%20high/i);
    expect(line).toMatch(/orange/);
  });

  test('excludes likelyFalsePositive findings from the badge count', () => {
    const findings = [
      { severity: 'CRITICAL', likelyFalsePositive: true,  inTestFile: false },
      { severity: 'HIGH',     likelyFalsePositive: true,  inTestFile: false },
    ];
    const line = badgeLine(findings);
    expect(line).toMatch(/passing/i);
    expect(line).toMatch(/brightgreen/);
  });

  test('excludes inTestFile findings — exploit fixtures are not production bugs', () => {
    const findings = [
      { severity: 'CRITICAL', likelyFalsePositive: false, inTestFile: true },
      { severity: 'HIGH',     likelyFalsePositive: false, inTestFile: true },
    ];
    const line = badgeLine(findings);
    expect(line).toMatch(/passing/i);
    expect(line).toMatch(/brightgreen/);
  });

  test('badge line ends with a newline', () => {
    expect(badgeLine([])).toMatch(/\n$/);
  });
});

// ─── injectBadge() ────────────────────────────────────────────────────────────

describe('injectBadge()', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'badge-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('injects badge after the first h1 heading', () => {
    fs.writeFileSync(path.join(tmpDir, 'README.md'), [
      '# My Project',
      '',
      'Description here.',
    ].join('\n'));

    injectBadge(tmpDir, badgeLine([]));

    const content = fs.readFileSync(path.join(tmpDir, 'README.md'), 'utf8');
    const lines = content.split('\n');
    expect(lines[0]).toBe('# My Project');
    expect(lines[1]).toMatch(/!\[tdd-audit\]/);
  });

  test('injects badge at the top when no h1 heading exists', () => {
    fs.writeFileSync(path.join(tmpDir, 'README.md'), 'Just some text.\n');

    injectBadge(tmpDir, badgeLine([]));

    const content = fs.readFileSync(path.join(tmpDir, 'README.md'), 'utf8');
    expect(content.split('\n')[0]).toMatch(/!\[tdd-audit\]/);
  });

  test('is idempotent — does not inject the badge twice', () => {
    fs.writeFileSync(path.join(tmpDir, 'README.md'), '# App\n');

    injectBadge(tmpDir, badgeLine([]));
    injectBadge(tmpDir, badgeLine([]));

    const content = fs.readFileSync(path.join(tmpDir, 'README.md'), 'utf8');
    const count = (content.match(/!\[tdd-audit\]/g) || []).length;
    expect(count).toBe(1);
  });

  test('updates an existing badge (re-scan with different result)', () => {
    fs.writeFileSync(path.join(tmpDir, 'README.md'), '# App\n');

    injectBadge(tmpDir, badgeLine([]));  // passing
    injectBadge(tmpDir, badgeLine([
      { severity: 'CRITICAL', likelyFalsePositive: false },
    ]));  // now critical

    const content = fs.readFileSync(path.join(tmpDir, 'README.md'), 'utf8');
    expect(content).toMatch(/critical/i);
    expect(content).not.toMatch(/passing/i);
    const count = (content.match(/!\[tdd-audit\]/g) || []).length;
    expect(count).toBe(1);
  });

  test('does nothing when no README exists', () => {
    expect(() => injectBadge(tmpDir, badgeLine([]))).not.toThrow();
  });

  test('finds README.md case-insensitively (readme.md)', () => {
    fs.writeFileSync(path.join(tmpDir, 'readme.md'), '# App\n');
    injectBadge(tmpDir, badgeLine([]));
    const content = fs.readFileSync(path.join(tmpDir, 'readme.md'), 'utf8');
    expect(content).toMatch(/!\[tdd-audit\]/);
  });
});

// ─── badgeLine — null/undefined findings ─────────────────────────────────────

describe('badgeLine() — null / undefined findings', () => {
  test('badgeLine(null) returns passing badge without throwing', () => {
    const line = badgeLine(null);
    expect(line).toMatch(/passing/i);
    expect(line).toMatch(/brightgreen/);
  });

  test('badgeLine(undefined) returns passing badge without throwing', () => {
    const line = badgeLine(undefined);
    expect(line).toMatch(/passing/i);
  });
});
