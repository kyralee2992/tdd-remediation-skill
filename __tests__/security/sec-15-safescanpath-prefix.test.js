'use strict';

/**
 * SEC-15 — safeScanPath sibling-directory prefix bypass.
 *
 * Attack vector: if cwd is "/app", the current check
 *   resolved.startsWith(cwd)  →  "/app-secret".startsWith("/app") === true
 * allows POST /scan to scan a sibling directory that merely shares the
 * cwd string as a prefix.
 *
 * Fix: normalise cwd with a trailing path separator before comparing.
 */

const path = require('path');
const { safeScanPath } = require('../../lib/server');

describe('SEC-15: safeScanPath — sibling-directory prefix bypass', () => {
  const cwd = process.cwd();

  test('rejects a sibling directory whose name is a prefix of cwd', () => {
    // e.g. cwd = /Users/x/tdd-audit  →  sibling = /Users/x/tdd-audit-evil
    const sibling = cwd + '-evil';
    expect(() => safeScanPath(sibling)).toThrow('Path outside working directory');
  });

  test('still accepts a legitimate subdirectory', () => {
    expect(() => safeScanPath('lib')).not.toThrow();
  });

  test('accepts cwd itself', () => {
    expect(() => safeScanPath(cwd)).not.toThrow();
  });

  test('accepts an absolute path inside cwd', () => {
    expect(() => safeScanPath(path.join(cwd, 'lib'))).not.toThrow();
  });
});
