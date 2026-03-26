'use strict';

/**
 * SEC-27 — ReDoS via LLM-supplied regex in toolSearchInFiles (ASI07).
 *
 * Attack vector: a prompt-injection payload inside a scanned file instructs
 * the LLM to call search_in_files with a catastrophic regex such as
 * `(a+)+$`.  Without a complexity guard the Node.js event loop blocks.
 *
 * Red phase: toolSearchInFiles must REJECT known-catastrophic patterns
 * with an error before the RegExp is constructed.  Before the guard is
 * added the function returns { matches:[], count:0 } — NOT an error —
 * so these tests FAIL.
 */

const { toolSearchInFiles } = require('../../lib/auditor');

describe('SEC-27: ReDoS guard — toolSearchInFiles rejects catastrophic patterns', () => {
  const dir = process.cwd();

  test('rejects (a+)+$ — nested quantifier', () => {
    const result = toolSearchInFiles({ pattern: '(a+)+$' }, dir);
    expect(result.error).toMatch(/catastrophic|backtrack|redos/i);
  });

  test('rejects (a*)* — star-of-star', () => {
    const result = toolSearchInFiles({ pattern: '(a*)*' }, dir);
    expect(result.error).toMatch(/catastrophic|backtrack|redos/i);
  });

  test('rejects (a|aa)+ — alternation amplification', () => {
    const result = toolSearchInFiles({ pattern: '(a|aa)+' }, dir);
    expect(result.error).toMatch(/catastrophic|backtrack|redos/i);
  });

  test('rejects excessively long patterns (>500 chars)', () => {
    const result = toolSearchInFiles({ pattern: 'a'.repeat(501) }, dir);
    expect(result.error).toMatch(/too long|length|redos/i);
  });

  test('still allows a safe, simple pattern', () => {
    const result = toolSearchInFiles({ pattern: 'function\\s+\\w+', glob: '*.js' }, dir);
    // safe pattern must NOT produce an error (may return empty results in cwd)
    expect(result.error).toBeUndefined();
    expect(result).toHaveProperty('matches');
  });
});
