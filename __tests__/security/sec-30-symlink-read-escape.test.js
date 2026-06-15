'use strict';

/**
 * SEC-30 — Symlink escape in LLM read_file tool (HIGH).
 *
 * Attack surface: safePath() uses path.resolve() which is lexical and does NOT
 * follow symlinks. If a symlink inside the project points to a file outside
 * (e.g. project/evil -> /etc/passwd), path.resolve("evil") stays inside the
 * project boundary and passes the guard — but fs.readFileSync follows the
 * symlink and reads the target outside the project.
 *
 * Fix: after the lexical guard, call fs.realpathSync() on the resolved path
 * and re-check the canonical path is still inside projectDir.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { toolReadFile, safePath } = require('../../lib/auditor');

let tmpDir;
let secretFile;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-sec30-'));

  // Create a "secret" file outside the project directory
  secretFile = path.join(os.tmpdir(), `sec30-secret-${Date.now()}.txt`);
  fs.writeFileSync(secretFile, 'TOP SECRET OUTSIDE PROJECT', 'utf8');

  // Plant a symlink inside the project pointing to the external file
  fs.symlinkSync(secretFile, path.join(tmpDir, 'evil-link'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  try { fs.unlinkSync(secretFile); } catch { /* already gone */ }
});

describe('SEC-30: symlink escape — read_file must not follow symlinks outside project', () => {
  test('safePath() rejects a path that resolves to a symlink pointing outside the project', () => {
    // The lexical path "evil-link" looks fine, but resolving via realpath escapes
    expect(() => safePath('evil-link', tmpDir)).toThrow(/Access denied/);
  });

  test('toolReadFile() returns error when path is a symlink to an external file', () => {
    const result = toolReadFile({ path: 'evil-link' }, tmpDir);
    expect(result.error).toBeDefined();
    expect(result.content).toBeUndefined();
  });

  test('toolReadFile() does NOT return the content of the external file', () => {
    const result = toolReadFile({ path: 'evil-link' }, tmpDir);
    expect(result.content).not.toBe('TOP SECRET OUTSIDE PROJECT');
  });

  test('toolReadFile() still reads a real (non-symlink) file inside the project', () => {
    fs.writeFileSync(path.join(tmpDir, 'real.txt'), 'safe content', 'utf8');
    const result = toolReadFile({ path: 'real.txt' }, tmpDir);
    expect(result.error).toBeUndefined();
    expect(result.content).toBe('safe content');
  });
});
