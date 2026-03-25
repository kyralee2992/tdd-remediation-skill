'use strict';

/**
 * SEC-05 — Unpinned GitHub Action in SKILL.md documentation example (ASI09)
 *
 * Red phase: asserts that every `uses:` line in SKILL.md references a full
 * commit SHA (40 hex chars), not a mutable version tag like @v3 or @main.
 * This test MUST fail before the fix is applied.
 */

const fs = require('fs');
const path = require('path');

const SKILL_MD = path.join(__dirname, '../../SKILL.md');
// Matches `uses: owner/repo@<ref>` — captures the ref portion
const USES_RE = /^\s*-\s+uses:\s+\S+@(\S+)/;
const SHA_RE  = /^[0-9a-f]{40}$/i;

describe('SEC-05: SKILL.md — no unpinned GitHub Actions', () => {
  let lines;

  beforeAll(() => {
    const content = fs.readFileSync(SKILL_MD, 'utf8');
    lines = content.split('\n');
  });

  test('every uses: line references a full 40-char commit SHA', () => {
    const violations = [];
    for (let i = 0; i < lines.length; i++) {
      const m = USES_RE.exec(lines[i]);
      if (!m) continue;
      const ref = m[1];
      if (!SHA_RE.test(ref)) {
        violations.push(`Line ${i + 1}: ${lines[i].trim()} — ref "${ref}" is not a SHA`);
      }
    }
    expect(violations).toEqual([]);
  });
});
