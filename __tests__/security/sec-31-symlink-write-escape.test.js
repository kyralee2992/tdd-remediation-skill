'use strict';

/**
 * SEC-31 — Symlink escape in LLM write_file tool (HIGH).
 *
 * Same root cause as SEC-30: safePath() is lexical-only, and fs.writeFileSync
 * follows symlinks. An attacker who has planted a symlink inside the project
 * (e.g. via a prompt-injected earlier write, or a malicious fixture) can
 * redirect a write_file call to any writable path on the filesystem.
 *
 * This compounds SEC-30: read leaks data; write can overwrite arbitrary files
 * (cron jobs, authorized_keys, etc.) when allowWrites=true (tier-4 mode).
 *
 * Fix: same realpathSync guard in safePath(); O_NOFOLLOW flag in toolWriteFile().
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { toolWriteFile, safePath } = require('../../lib/auditor');

let tmpDir;
let externalTarget;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-sec31-'));

  // Target outside the project that the attacker wants to overwrite
  externalTarget = path.join(os.tmpdir(), `sec31-target-${Date.now()}.txt`);
  fs.writeFileSync(externalTarget, 'ORIGINAL CONTENT', 'utf8');

  // Symlink inside the project pointing to the external target
  fs.symlinkSync(externalTarget, path.join(tmpDir, 'evil-write-link'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  try { fs.unlinkSync(externalTarget); } catch { /* already gone */ }
});

describe('SEC-31: symlink escape — write_file must not follow symlinks outside project', () => {
  test('safePath() rejects a path that is a symlink pointing outside the project', () => {
    expect(() => safePath('evil-write-link', tmpDir)).toThrow(/Access denied/);
  });

  test('toolWriteFile() returns error when path is a symlink to an external file', () => {
    const result = toolWriteFile({ path: 'evil-write-link', content: 'INJECTED' }, tmpDir);
    expect(result.error).toBeDefined();
    expect(result.ok).toBeUndefined();
  });

  test('external target file is NOT modified after blocked symlink write', () => {
    toolWriteFile({ path: 'evil-write-link', content: 'INJECTED' }, tmpDir);
    const contents = fs.readFileSync(externalTarget, 'utf8');
    expect(contents).toBe('ORIGINAL CONTENT');
  });

  test('toolWriteFile() still writes a real (non-symlink) path inside the project', () => {
    const result = toolWriteFile({ path: 'legit.txt', content: 'ok' }, tmpDir);
    expect(result.ok).toBe(true);
    expect(fs.readFileSync(path.join(tmpDir, 'legit.txt'), 'utf8')).toBe('ok');
  });
});
