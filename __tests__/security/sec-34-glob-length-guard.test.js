'use strict';

/**
 * SEC-34 — Missing length guard on glob field in toolSearchInFiles (MEDIUM/ReDoS).
 *
 * toolSearchInFiles() validates the `pattern` (regex) field with a length cap
 * and a ReDoS heuristic, but the `glob` field (also LLM-supplied) is passed
 * directly to globToRegex() without any length check.
 *
 * A prompt-injected LLM response could supply a glob of tens of thousands of
 * characters, causing slow regex compilation and stalling the Node.js event loop.
 *
 * Fix: before calling globToRegex(globPattern), reject globs longer than
 * MAX_PATTERN_LEN (500 chars) with the same pattern used for the regex field.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { toolSearchInFiles } = require('../../lib/auditor');

let tmpDir;
beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-sec34-'));
  fs.writeFileSync(path.join(tmpDir, 'test.js'), 'const x = 1;', 'utf8');
});
afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('SEC-34: toolSearchInFiles — glob field must have a length guard', () => {
  test('rejects a glob longer than 500 characters', () => {
    const longGlob = '*'.repeat(501);
    const result = toolSearchInFiles({ pattern: 'x', glob: longGlob }, tmpDir);
    expect(result.error).toBeDefined();
    expect(result.error).toMatch(/too long|rejected/i);
  });

  test('rejects a glob of exactly 501 characters', () => {
    const longGlob = 'a'.repeat(501);
    const result = toolSearchInFiles({ pattern: 'x', glob: longGlob }, tmpDir);
    expect(result.error).toBeDefined();
  });

  test('accepts a glob of exactly 500 characters', () => {
    // 500 chars of 'a' — valid but matches nothing; should not error on length
    const okGlob = 'a'.repeat(500);
    const result = toolSearchInFiles({ pattern: 'x', glob: okGlob }, tmpDir);
    if (result.error) {
      expect(result.error).not.toMatch(/too long|rejected/i);
    }
  });

  test('accepts a normal short glob and still returns matches', () => {
    const result = toolSearchInFiles({ pattern: 'const', glob: '*.js' }, tmpDir);
    expect(result.error).toBeUndefined();
    expect(result.matches.length).toBeGreaterThan(0);
  });

  test('still rejects an oversized pattern (existing guard unchanged)', () => {
    const longPattern = 'a'.repeat(501);
    const result = toolSearchInFiles({ pattern: longPattern }, tmpDir);
    expect(result.error).toMatch(/too long/i);
  });
});
