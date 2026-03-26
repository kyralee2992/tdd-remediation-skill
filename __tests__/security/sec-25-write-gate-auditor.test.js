'use strict';

/**
 * SEC-25 — write_file tool requires allowWrites=true (MEDIUM).
 *
 * The LLM can call write_file to create or overwrite files in the project.
 * This is intentional for the remediation phase, but must be gated behind
 * an explicit user opt-in (--allow-writes) so that a plain `tdd-audit --ai`
 * (scan-only analysis) cannot silently modify the codebase.
 *
 * executeToolCall() must refuse write_file when opts.allowWrites is falsy
 * and return a clear error rather than writing.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { executeToolCall } = require('../../lib/auditor');

let tmpDir;
beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-sec25-'));
});
afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('SEC-25: write_file gate — allowWrites must be true', () => {
  const writeInput = { path: 'new-file.txt', content: 'injected content' };

  test('blocks write_file when allowWrites is false', () => {
    const result = executeToolCall('write_file', writeInput, tmpDir, { allowWrites: false });
    expect(result.error).toMatch(/allow-writes/i);
    expect(fs.existsSync(path.join(tmpDir, 'new-file.txt'))).toBe(false);
  });

  test('blocks write_file when allowWrites is omitted (default)', () => {
    const result = executeToolCall('write_file', writeInput, tmpDir);
    expect(result.error).toMatch(/allow-writes/i);
    expect(fs.existsSync(path.join(tmpDir, 'new-file.txt'))).toBe(false);
  });

  test('allows write_file when allowWrites is true', () => {
    const result = executeToolCall('write_file', writeInput, tmpDir, { allowWrites: true });
    expect(result.ok).toBe(true);
    expect(fs.readFileSync(path.join(tmpDir, 'new-file.txt'), 'utf8')).toBe('injected content');
  });

  test('read_file is never blocked by allowWrites flag', () => {
    fs.writeFileSync(path.join(tmpDir, 'readable.txt'), 'data');
    const result = executeToolCall('read_file', { path: 'readable.txt' }, tmpDir, { allowWrites: false });
    expect(result.error).toBeUndefined();
    expect(result.content).toBe('data');
  });

  test('list_files is never blocked by allowWrites flag', () => {
    const result = executeToolCall('list_files', { pattern: '**/*' }, tmpDir, { allowWrites: false });
    expect(result.error).toBeUndefined();
  });

  test('search_in_files is never blocked by allowWrites flag', () => {
    fs.writeFileSync(path.join(tmpDir, 'code.js'), 'const x = 1;');
    const result = executeToolCall('search_in_files', { pattern: 'const' }, tmpDir, { allowWrites: false });
    expect(result.error).toBeUndefined();
    expect(result.matches.length).toBeGreaterThan(0);
  });

  test('unknown tool returns error regardless of allowWrites', () => {
    const result = executeToolCall('delete_file', {}, tmpDir, { allowWrites: true });
    expect(result.error).toMatch(/Unknown tool/);
  });
});
