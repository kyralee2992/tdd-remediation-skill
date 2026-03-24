'use strict';

/**
 * SEC-02 — Binary .md Files Processed Without Null-Byte Guard
 *
 * quickScan() guards against binary files by checking content.includes('\0')
 * immediately after readFileSync.  scanPromptFiles() has no such guard: a binary
 * file with a .md extension placed in a prompt directory (e.g. CLAUDE.md) is
 * read and every line is tested against PROMPT_PATTERNS.  This can produce
 * garbled false-positive findings with null-byte characters embedded in the
 * reported snippet.
 *
 * Fix: add the same null-byte guard to scanPromptFiles() after readFileSync.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { scanPromptFiles } = require('../../lib/scanner');

function makeTmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-audit-sec02-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return dir;
}

function rmrf(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

describe('SEC-02: binary .md files must not be scanned', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('CLAUDE.md with null bytes + matching pattern must produce no findings', () => {
    // Null byte before the pattern makes this a binary file.
    // quickScan skips it; scanPromptFiles currently does NOT → false positive.
    tmp = makeTmpProject({
      'CLAUDE.md': 'binary\x00data\ncsurf package install\n',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.length).toBe(0);
  });

  test('skills/ .md with null bytes + cleartext URL must produce no findings', () => {
    tmp = makeTmpProject({
      'skills/api.md': '\x00binary header\nFetch from http://internal.example.com/api\n',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.length).toBe(0);
  });

  test('clean .md file with a matching pattern still produces findings (regression guard)', () => {
    // Ensure the guard does not swallow legitimate text-only files.
    tmp = makeTmpProject({
      'CLAUDE.md': 'Install csurf for CSRF protection\n',
    });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Deprecated CSRF Package');
    expect(hit).toBeDefined();
  });

  test('snippet field must not contain null bytes for any finding', () => {
    // Even if we somehow produced a finding, the snippet must be safe to print.
    tmp = makeTmpProject({
      'CLAUDE.md': 'clean line\ncsurf here\n',
    });
    const findings = scanPromptFiles(tmp);
    for (const f of findings) {
      expect(f.snippet).not.toMatch('\x00');
    }
  });
});
