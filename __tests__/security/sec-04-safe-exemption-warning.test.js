'use strict';

/**
 * SEC-04 — audit_status:safe Exemption Must Be Visible in Output
 *
 * Any file with `audit_status: safe` in its YAML frontmatter is silently
 * exempt from scanPromptFiles.  There is no record in the printed output,
 * so an attacker or careless contributor can permanently silence findings
 * with no CI-visible trace.
 *
 * Hardening:
 *  1. scanPromptFiles() attaches a non-enumerable `.exempted` array on the
 *     returned findings array.  This preserves backward-compat (spread and
 *     toEqual still work) while exposing which files were skipped.
 *  2. printFindings() accepts an optional second argument `exempted` and
 *     prints a warning line for each exempted path.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { scanPromptFiles, printFindings } = require('../../lib/scanner');

function makeTmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-audit-sec04-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return dir;
}

function rmrf(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

const SAFE_FRONTMATTER = `---\naudit_status: safe\n---\n`;

describe('SEC-04: audit_status:safe exemption warning', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  // ── scanPromptFiles: .exempted property ──────────────────────────────────

  test('scanPromptFiles result has a non-enumerable .exempted array', () => {
    tmp = makeTmpProject({ 'CLAUDE.md': 'normal content\n' });
    const findings = scanPromptFiles(tmp);
    expect(Array.isArray(findings.exempted)).toBe(true);
  });

  test('exempted array contains files skipped via audit_status:safe', () => {
    tmp = makeTmpProject({
      'CLAUDE.md': SAFE_FRONTMATTER + 'install csurf for CSRF\n',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.length).toBe(0);           // no findings — file was suppressed
    expect(findings.exempted).toContain('CLAUDE.md');
  });

  test('clean files (no frontmatter) are NOT in the exempted array', () => {
    tmp = makeTmpProject({ 'CLAUDE.md': 'normal content\n' });
    const findings = scanPromptFiles(tmp);
    expect(findings.exempted).not.toContain('CLAUDE.md');
  });

  test('.exempted is non-enumerable: spread and toEqual remain unaffected', () => {
    // Existing code that spreads `...scanPromptFiles(...)` or asserts
    // toEqual([]) must not be broken by the new .exempted property.
    tmp = makeTmpProject({ 'CLAUDE.md': 'normal content\n' });
    const findings = scanPromptFiles(tmp);
    const spread = [...findings];
    expect(spread.length).toBe(findings.length);
    expect(findings).toEqual([]);              // no enumerable difference
  });

  // ── printFindings: exemption warning ─────────────────────────────────────

  test('printFindings emits a warning for each exempted file', () => {
    const output = [];
    const origLog = console.log;
    console.log = (...args) => output.push(args.join(' '));
    try {
      printFindings([], ['CLAUDE.md', 'skills/api.md']);
    } finally {
      console.log = origLog;
    }
    const joined = output.join('\n');
    expect(joined).toMatch(/audit_status.*safe/i);
    expect(joined).toMatch('CLAUDE.md');
    expect(joined).toMatch('skills/api.md');
  });

  test('printFindings with empty exempted array emits no exemption warning', () => {
    const output = [];
    const origLog = console.log;
    console.log = (...args) => output.push(args.join(' '));
    try {
      printFindings([], []);
    } finally {
      console.log = origLog;
    }
    expect(output.join('\n')).not.toMatch(/audit_status.*safe/i);
  });

  test('printFindings with no second arg (legacy call) emits no exemption warning', () => {
    const output = [];
    const origLog = console.log;
    console.log = (...args) => output.push(args.join(' '));
    try {
      printFindings([]);
    } finally {
      console.log = origLog;
    }
    expect(output.join('\n')).not.toMatch(/audit_status.*safe/i);
  });
});
