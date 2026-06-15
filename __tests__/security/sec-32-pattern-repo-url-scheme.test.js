'use strict';

/**
 * SEC-32 — Unvalidated URL scheme in pattern_repos git clone (MEDIUM).
 *
 * syncPatternRepos() passes repo.url directly to `git clone <url>` without
 * validating the URL scheme. An attacker who can write .tdd-audit.json can
 * set a repo.url to:
 *   - git://internal-host:9418/  → SSRF probe of internal git daemons
 *   - file:///home/runner/...    → exfiltrate local git repos (old git versions)
 *   - ext::some-binary           → RCE via git's ext:: protocol
 *
 * Fix: before calling git clone, validate that url.startsWith('https://')
 * or url.startsWith('ssh://'); reject everything else with an error entry
 * (do not call spawnSync at all for disallowed schemes).
 */

const { syncPatternRepos } = require('../../lib/auditor');

// syncPatternRepos returns an array of result objects.
// The built-in tdd-patterns repo may also appear in results if present locally.
// We find our test repo by name rather than by index.

function findResult(results, name) {
  return results.find(r => r.name === name);
}

describe('SEC-32: pattern_repos git clone — URL scheme must be validated', () => {
  test('rejects git:// scheme without cloning', () => {
    const results = syncPatternRepos([{
      name: 'sec32-evil-git',
      url: 'git://internal-host:9418/repo.git',
      local_path: `/tmp/sec32-git-${Date.now()}`,
    }]);
    const r = findResult(results, 'sec32-evil-git');
    expect(r).toBeDefined();
    expect(r.status).toBe('error');
    expect(r.error).toMatch(/scheme/i);
  });

  test('rejects file:// scheme without cloning', () => {
    const results = syncPatternRepos([{
      name: 'sec32-evil-file',
      url: 'file:///etc/passwd',
      local_path: `/tmp/sec32-file-${Date.now()}`,
    }]);
    const r = findResult(results, 'sec32-evil-file');
    expect(r).toBeDefined();
    expect(r.status).toBe('error');
    expect(r.error).toMatch(/scheme/i);
  });

  test('rejects ext:: protocol without cloning', () => {
    const results = syncPatternRepos([{
      name: 'sec32-evil-ext',
      url: 'ext::malicious-binary arg',
      local_path: `/tmp/sec32-ext-${Date.now()}`,
    }]);
    const r = findResult(results, 'sec32-evil-ext');
    expect(r).toBeDefined();
    expect(r.status).toBe('error');
    expect(r.error).toMatch(/scheme/i);
  });

  test('rejects http:// scheme (requires https)', () => {
    const results = syncPatternRepos([{
      name: 'sec32-plain-http',
      url: 'http://example.com/repo.git',
      local_path: `/tmp/sec32-http-${Date.now()}`,
    }]);
    const r = findResult(results, 'sec32-plain-http');
    expect(r).toBeDefined();
    expect(r.status).toBe('error');
    expect(r.error).toMatch(/scheme/i);
  });

  test('accepts https:// scheme (error must not be about scheme)', () => {
    const results = syncPatternRepos([{
      name: 'sec32-legit-https',
      url: 'https://example.com/nonexistent.git',
      local_path: `/tmp/sec32-https-${Date.now()}`,
    }]);
    const r = findResult(results, 'sec32-legit-https');
    expect(r).toBeDefined();
    if (r.error) expect(r.error).not.toMatch(/scheme/i);
  });

  test('accepts ssh:// scheme (error must not be about scheme)', () => {
    const results = syncPatternRepos([{
      name: 'sec32-legit-ssh',
      url: 'ssh://git@github.com/org/repo.git',
      local_path: `/tmp/sec32-ssh-${Date.now()}`,
    }]);
    const r = findResult(results, 'sec32-legit-ssh');
    expect(r).toBeDefined();
    if (r.error) expect(r.error).not.toMatch(/scheme/i);
  });

  test('repos with no url bypass scheme validation entirely (unchanged behaviour)', () => {
    const results = syncPatternRepos([{
      name: 'sec32-no-url',
      url: null,
      local_path: `/tmp/sec32-nourl-${Date.now()}`,
    }]);
    const r = findResult(results, 'sec32-no-url');
    expect(r).toBeDefined();
    if (r.error) expect(r.error).not.toMatch(/scheme/i);
  });
});
