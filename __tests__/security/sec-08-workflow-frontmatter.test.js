'use strict';

/**
 * SEC-08 — All files in workflows/ must declare audit_status in frontmatter
 *
 * Workflow shortcode files live in the PROMPT_DIRS set and are scanned by
 * scanPromptFiles(). Without an explicit audit_status declaration, the
 * scanner's exemption decision is unrecorded — future pattern additions
 * could produce un-reviewed findings or silently miss real issues.
 *
 * This test MUST fail before the fix is applied.
 */

const fs   = require('fs');
const path = require('path');

const WORKFLOWS_DIR = path.join(__dirname, '../../workflows');

describe('SEC-08: workflows/ files have audit_status frontmatter', () => {
  let mdFiles;

  beforeAll(() => {
    mdFiles = fs.readdirSync(WORKFLOWS_DIR).filter(f => f.endsWith('.md'));
  });

  test('at least one .md file exists in workflows/', () => {
    expect(mdFiles.length).toBeGreaterThan(0);
  });

  test.each(
    // populated at runtime from beforeAll — use a lazy accessor
    // Jest evaluates test.each descriptors before beforeAll runs,
    // so we drive from a glob instead.
    fs.existsSync(WORKFLOWS_DIR)
      ? fs.readdirSync(WORKFLOWS_DIR).filter(f => f.endsWith('.md'))
      : []
  )('%s declares audit_status in YAML frontmatter', (name) => {
    const content = fs.readFileSync(path.join(WORKFLOWS_DIR, name), 'utf8');
    const lines   = content.split('\n');

    // Must open with --- and contain audit_status: <value>
    expect(lines[0].trim()).toBe('---');
    const closingIdx = lines.indexOf('---', 1);
    expect(closingIdx).toBeGreaterThan(0);

    const frontmatter = lines.slice(1, closingIdx).join('\n');
    expect(frontmatter).toMatch(/^audit_status\s*:/m);
  });
});
