'use strict';

/**
 * SEC-01 — Scanner Bypass via Unbalanced Backtick
 *
 * isInsideBackticks() suppresses a PROMPT_PATTERN finding whenever the number
 * of backtick characters *before* the match on the same line is odd, regardless
 * of whether a *closing* backtick exists after the match.
 *
 * Attack: place a lone ` anywhere before a dangerous pattern on the same line →
 * finding is silently dropped. This is a one-character bypass of scanPromptFiles.
 *
 * Fix: only suppress when there is also at least one closing backtick *after*
 * the match on the same line (i.e., the code span is balanced/closed).
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { scanPromptFiles } = require('../../lib/scanner');

function makeTmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-audit-sec01-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return dir;
}

function rmrf(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

describe('SEC-01: isInsideBackticks bypass', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  // ── Exploit cases (must be detected) ─────────────────────────────────────

  test('lone backtick before csurf MUST NOT suppress the finding', () => {
    // Line: "Run ` to install csurf for CSRF protection"
    // backticksBefore=1 (odd) → current code suppresses → BYPASS
    tmp = makeTmpProject({
      'CLAUDE.md': 'Run ` to install csurf for CSRF protection\n',
    });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Deprecated CSRF Package');
    expect(hit).toBeDefined();
  });

  test('two lone backticks before csurf (even count) must still detect', () => {
    // backticksBefore=2 (even) → current code does NOT suppress → should detect
    // This case already passes; included as a regression guard.
    tmp = makeTmpProject({
      'CLAUDE.md': 'Use ` and ` before csurf here\n',
    });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Deprecated CSRF Package');
    expect(hit).toBeDefined();
  });

  test('lone backtick before http:// cleartext URL must not suppress the finding', () => {
    tmp = makeTmpProject({
      'CLAUDE.md': 'See ` for docs at http://example.com/api\n',
    });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Cleartext URL in Prompt');
    expect(hit).toBeDefined();
  });

  // ── Legitimate suppression cases (must NOT be detected) ──────────────────

  test('csurf inside a closed code span `csurf` must be suppressed', () => {
    // backticksBefore=1 (odd), backticksAfter≥1 → should be suppressed
    tmp = makeTmpProject({
      'CLAUDE.md': 'Do not use `csurf` anymore\n',
    });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Deprecated CSRF Package');
    expect(hit).toBeUndefined();
  });

  test('csurf in a multi-span line `foo` and `csurf` must be suppressed', () => {
    // backticksBefore=3 (odd), backticksAfter=1 → suppressed
    tmp = makeTmpProject({
      'CLAUDE.md': 'Replace `foo` with `csurf` here\n',
    });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Deprecated CSRF Package');
    expect(hit).toBeUndefined();
  });
});
