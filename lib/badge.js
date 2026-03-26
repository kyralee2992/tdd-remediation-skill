'use strict';

const fs   = require('fs');
const path = require('path');

// Marker embedded in the badge line — used to find and replace it on re-scan.
const BADGE_MARKER = 'tdd-audit-badge';

const NPM_URL = 'https://www.npmjs.com/package/@lhi/tdd-audit';

/**
 * Build a shields.io badge markdown line reflecting actual scan results.
 *
 * - 0 critical/high (real) findings → "passing" · brightgreen
 * - ≥1 high (no critical)           → "{n} high"  · orange
 * - ≥1 critical                     → "{n} critical" · red
 *
 * likelyFalsePositive findings (test fixtures) are excluded from the count.
 *
 * The badge links to `siteUrl` when provided (set via `tdd_site` in
 * .tdd-audit.json). When absent — including all skill-mode invocations where
 * no config file exists — the link falls back to the @lhi/tdd-audit npm page
 * so readers always know where the security tooling came from.
 *
 * @param {Array}  findings  - findings array returned by quickScan()
 * @param {string} [siteUrl] - optional override link (from config.tdd_site)
 * @returns {string}         - single-line markdown badge ending with \n
 */
function badgeLine(findings, siteUrl) {
  // Exclude test-file findings and likely false positives — badge reflects production code only
  const real     = (findings || []).filter(f => !f.likelyFalsePositive && !f.inTestFile);
  const criticals = real.filter(f => f.severity === 'CRITICAL').length;
  const highs     = real.filter(f => f.severity === 'HIGH').length;

  let message, color;
  if (criticals > 0) {
    message = `${criticals}%20critical`;
    color   = 'red';
  } else if (highs > 0) {
    message = `${highs}%20high`;
    color   = 'orange';
  } else {
    message = 'passing';
    color   = 'brightgreen';
  }

  const badgeUrl  = `https://img.shields.io/badge/tdd--audit-${message}-${color}`;
  const targetUrl = (siteUrl && siteUrl.trim()) ? siteUrl.trim() : NPM_URL;
  // Embed the marker as a hidden HTML comment after the badge so injectBadge()
  // can locate and replace the line on subsequent runs.
  return `[![tdd-audit](${badgeUrl})](${targetUrl}) <!-- ${BADGE_MARKER} -->\n`;
}

/**
 * Inject or update the tdd-audit badge in the project's README.md.
 *
 * Behaviour:
 *  - Searches for README.md / readme.md / README in the project root.
 *  - If a badge line (identified by BADGE_MARKER) already exists, replaces it.
 *  - Otherwise inserts the badge immediately after the first `# Heading` line.
 *    If no heading exists, prepends to the file.
 *  - No-ops silently when no README is found.
 *  - Idempotent: running twice with the same inputs produces the same output.
 *
 * @param {string} projectDir  - absolute path to the project root
 * @param {string} badge       - badge markdown line from badgeLine()
 */
function injectBadge(projectDir, badge) {
  const candidates = ['README.md', 'readme.md', 'Readme.md', 'README'];
  let readmePath = null;
  for (const name of candidates) {
    const p = path.join(projectDir, name);
    if (fs.existsSync(p)) { readmePath = p; break; }
  }
  if (!readmePath) return;

  const original = fs.readFileSync(readmePath, 'utf8');

  // Replace existing badge (idempotent + allows re-scan update)
  if (original.includes(BADGE_MARKER)) {
    const updated = original.replace(/^.*tdd-audit-badge.*$/m, badge.trimEnd());
    fs.writeFileSync(readmePath, updated);
    return;
  }

  // Insert after the first h1 line, or prepend if no h1 exists
  const lines = original.split('\n');
  const h1Idx = lines.findIndex(l => /^#\s/.test(l));

  let updated;
  if (h1Idx !== -1) {
    lines.splice(h1Idx + 1, 0, badge.trimEnd());
    updated = lines.join('\n');
  } else {
    updated = badge.trimEnd() + '\n' + original;
  }

  fs.writeFileSync(readmePath, updated);
}

module.exports = { badgeLine, injectBadge, BADGE_MARKER };
