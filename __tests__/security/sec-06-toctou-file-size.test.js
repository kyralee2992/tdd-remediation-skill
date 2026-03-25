'use strict';

/**
 * SEC-06 — TOCTOU race in file-size guard (lib/scanner.js)
 *
 * Red phase: asserts that quickScan and scanPromptFiles do NOT call
 * fs.statSync before fs.readFileSync on the same path within the same
 * loop body. The safe pattern is to read first, then check length.
 *
 * This test MUST fail before the fix is applied.
 */

const fs   = require('fs');
const path = require('path');

const SCANNER_SRC = path.join(__dirname, '../../lib/scanner.js');

describe('SEC-06: no statSync-before-readFileSync TOCTOU pattern', () => {
  let src;

  beforeAll(() => {
    src = fs.readFileSync(SCANNER_SRC, 'utf8');
  });

  test('scanner source does not contain statSync().size guard before readFileSync', () => {
    // The unsafe pattern is: statSync(filePath).size on one line, followed
    // by readFileSync on a subsequent line inside the same conditional block.
    // We detect it by checking that the two-call sequence no longer appears.
    //
    // Safe alternative: read the file first, then check content.length.
    const hasUnsafePattern = /fs\.statSync\([^)]+\)\.size[^}]+fs\.readFileSync/s.test(src);
    expect(hasUnsafePattern).toBe(false);
  });
});
