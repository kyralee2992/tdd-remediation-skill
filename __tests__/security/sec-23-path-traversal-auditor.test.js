'use strict';

/**
 * SEC-23 — Path Traversal protection in lib/auditor.js tool functions (HIGH).
 *
 * Attack surface: the LLM (or a prompt-injected payload) can call
 * read_file / write_file / list_files / search_in_files with paths like
 * "../../etc/passwd" or "/etc/shadow" and escape the project root.
 *
 * safePath() guards against this: it resolves the path, then verifies it
 * stays inside projectDir using the `+ path.sep` sibling-prefix fix
 * (matching the pattern from SEC-15 in lib/server.js).
 *
 * These tests confirm the guards work correctly and cannot be bypassed.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const {
  safePath,
  toolReadFile,
  toolWriteFile,
  toolListFiles,
  toolSearchInFiles,
} = require('../../lib/auditor');

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeTmpDir(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-sec23-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return dir;
}

let tmpDir;
beforeEach(() => {
  tmpDir = makeTmpDir({ 'safe.txt': 'hello', 'sub/file.js': 'const x = 1;' });
});
afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ─── safePath ─────────────────────────────────────────────────────────────────

describe('safePath() — path traversal guard', () => {
  test('allows a normal relative path inside the project', () => {
    const resolved = safePath('sub/file.js', tmpDir);
    expect(resolved).toBe(path.join(tmpDir, 'sub/file.js'));
  });

  test('allows the project root itself', () => {
    const resolved = safePath('.', tmpDir);
    expect(resolved).toBe(path.resolve(tmpDir));
  });

  test('allows an absolute path inside the project', () => {
    const abs = path.join(tmpDir, 'safe.txt');
    expect(() => safePath(abs, tmpDir)).not.toThrow();
  });

  test('rejects "../" traversal one level up', () => {
    expect(() => safePath('../evil.txt', tmpDir)).toThrow(/Access denied/);
  });

  test('rejects deep traversal "../../etc/passwd"', () => {
    expect(() => safePath('../../etc/passwd', tmpDir)).toThrow(/Access denied/);
  });

  test('rejects absolute path outside the project', () => {
    expect(() => safePath('/etc/passwd', tmpDir)).toThrow(/Access denied/);
  });

  test('rejects sibling-directory prefix bypass (SEC-15 pattern)', () => {
    // e.g. project=/tmp/foo, attacker supplies /tmp/foo-evil
    const sibling = tmpDir + '-evil';
    expect(() => safePath(sibling, tmpDir)).toThrow(/Access denied/);
  });

  test('throws on empty string', () => {
    expect(() => safePath('', tmpDir)).toThrow();
  });

  test('throws on whitespace-only string', () => {
    expect(() => safePath('   ', tmpDir)).toThrow();
  });

  test('throws on non-string input', () => {
    expect(() => safePath(null, tmpDir)).toThrow();
    expect(() => safePath(undefined, tmpDir)).toThrow();
  });
});

// ─── toolReadFile ─────────────────────────────────────────────────────────────

describe('toolReadFile() — path traversal via LLM tool call', () => {
  test('returns { error } for "../" traversal', () => {
    const result = toolReadFile({ path: '../secret.txt' }, tmpDir);
    expect(result.error).toMatch(/Access denied/);
    expect(result.content).toBeUndefined();
  });

  test('returns { error } for absolute path outside project', () => {
    const result = toolReadFile({ path: '/etc/passwd' }, tmpDir);
    expect(result.error).toMatch(/Access denied/);
  });

  test('returns { error } for sibling-prefix bypass', () => {
    const result = toolReadFile({ path: tmpDir + '-evil/secret' }, tmpDir);
    expect(result.error).toMatch(/Access denied/);
  });

  test('returns { content } for a legitimate relative path', () => {
    const result = toolReadFile({ path: 'safe.txt' }, tmpDir);
    expect(result.error).toBeUndefined();
    expect(result.content).toBe('hello');
  });
});

// ─── toolWriteFile ────────────────────────────────────────────────────────────

describe('toolWriteFile() — path traversal via LLM tool call', () => {
  test('returns { error } for "../" traversal', () => {
    const result = toolWriteFile({ path: '../evil.txt', content: 'bad' }, tmpDir);
    expect(result.error).toMatch(/Access denied/);
    // Verify the file was NOT written
    expect(fs.existsSync(path.join(path.dirname(tmpDir), 'evil.txt'))).toBe(false);
  });

  test('returns { error } for absolute path outside project', () => {
    const result = toolWriteFile({ path: '/tmp/evil.txt', content: 'bad' }, tmpDir);
    expect(result.error).toMatch(/Access denied/);
  });

  test('returns { ok: true } for a legitimate relative path', () => {
    const result = toolWriteFile({ path: 'new-file.txt', content: 'safe' }, tmpDir);
    expect(result.ok).toBe(true);
    expect(fs.readFileSync(path.join(tmpDir, 'new-file.txt'), 'utf8')).toBe('safe');
  });
});

// ─── toolListFiles ────────────────────────────────────────────────────────────

describe('toolListFiles() — cannot traverse outside project', () => {
  test('glob pattern cannot list files outside the project', () => {
    // The walker is rooted at tmpDir, so ../../etc/** returns empty
    const result = toolListFiles({ pattern: '../../etc/**' }, tmpDir);
    expect(result.files).toHaveLength(0);
  });
});

// ─── toolSearchInFiles ────────────────────────────────────────────────────────

describe('toolSearchInFiles() — regex injection guard', () => {
  test('returns { error } for an invalid regex', () => {
    const result = toolSearchInFiles({ pattern: '[unclosed' }, tmpDir);
    expect(result.error).toMatch(/Invalid regex/);
  });
});
