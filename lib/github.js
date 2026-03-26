'use strict';

// ─── GitHub REST helpers ──────────────────────────────────────────────────────

async function ghFetch(path, token, method = 'GET', body = null) {
  const opts = {
    method,
    headers: {
      'Accept':        'application/vnd.github+json',
      'Authorization': `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type':  'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`https://api.github.com${path}`, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`GitHub API ${method} ${path} → ${res.status}: ${text.slice(0, 200)}`);
  }
  return res.status === 204 ? null : res.json();
}

// ─── SARIF upload ─────────────────────────────────────────────────────────────

/**
 * Upload a SARIF report to GitHub code scanning.
 * Findings will appear inline in PRs and the Security tab.
 *
 * @param {object} opts
 * @param {string} opts.owner
 * @param {string} opts.repo
 * @param {string} opts.token   - GitHub token with `security_events` write scope
 * @param {string} opts.ref     - full git ref, e.g. "refs/heads/main"
 * @param {string} opts.commitSha
 * @param {object} opts.sarif   - SARIF 2.1.0 object from toSarif()
 * @returns {Promise<object>}
 */
async function uploadSarif({ owner, repo, token, ref, commitSha, sarif }) {
  const encoded = Buffer.from(JSON.stringify(sarif)).toString('base64');
  return ghFetch(`/repos/${owner}/${repo}/code-scanning/sarifs`, token, 'POST', {
    ref,
    commit_sha: commitSha,
    sarif:      encoded,
    tool_name:  '@lhi/tdd-audit',
  });
}

// ─── PR review comments ───────────────────────────────────────────────────────

/**
 * Post inline review comments on a pull request for each finding.
 * CRITICAL and HIGH findings request changes; others leave comments only.
 *
 * @param {object} opts
 * @param {string} opts.owner
 * @param {string} opts.repo
 * @param {number} opts.pull_number
 * @param {string} opts.token
 * @param {string} opts.commitSha  - head SHA of the PR
 * @param {Array}  opts.findings
 * @returns {Promise<object>} - GitHub review object
 */
async function postReviewComments({ owner, repo, pull_number, token, commitSha, findings }) {
  const real = findings.filter(f => !f.likelyFalsePositive);
  if (!real.length) return null;

  const hasCritical = real.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');

  const comments = real.map(f => ({
    path:     f.file,
    line:     f.line,
    side:     'RIGHT',
    body:     `**[${f.severity}] ${f.name}**\n\`\`\`\n${f.snippet}\n\`\`\`\nRun \`/tdd-audit\` to remediate.`,
  }));

  return ghFetch(`/repos/${owner}/${repo}/pulls/${pull_number}/reviews`, token, 'POST', {
    commit_id: commitSha,
    body:      `**@lhi/tdd-audit** found ${real.length} issue(s). ${hasCritical ? 'CRITICAL/HIGH findings require changes.' : 'See inline comments.'}`,
    event:     hasCritical ? 'REQUEST_CHANGES' : 'COMMENT',
    comments,
  });
}

// ─── Parse "owner/repo" helper ────────────────────────────────────────────────

function parseRepo(repoStr) {
  const [owner, repo] = (repoStr || '').split('/');
  if (!owner || !repo) throw new Error('--repo must be in "owner/repo" format');
  return { owner, repo };
}

module.exports = { uploadSarif, postReviewComments, parseRepo, ghFetch };
