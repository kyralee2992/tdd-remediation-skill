'use strict';

/**
 * SEC-03 — No File-Size Limit Before Reading
 *
 * quickScan() and scanPromptFiles() call fs.readFileSync() with no prior size
 * check.  A large file (generated bundle, crafted file) in the scan path is
 * read fully into memory before any line processing begins.  On a constrained
 * CI runner this can cause OOM / process kill, silently skipping the security
 * scan with no error or exit code.
 *
 * Fix: check fs.statSync(filePath).size before reading; skip files that exceed
 * MAX_SCAN_FILE_BYTES (exported from scanner.js so tests can reference it).
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const scanner = require('../../lib/scanner');
const { quickScan, scanPromptFiles } = scanner;

// MAX_SCAN_FILE_BYTES must be exported so tests can size files precisely.
const MAX_BYTES = scanner.MAX_SCAN_FILE_BYTES;

function makeTmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-audit-sec03-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    if (Buffer.isBuffer(content)) {
      fs.writeFileSync(full, content);
    } else {
      fs.writeFileSync(full, content, 'utf8');
    }
  }
  return dir;
}

function rmrf(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

// Build a buffer of `size` bytes that ends with a vulnerable snippet.
function largeFileWith(size, snippet) {
  const padding = Buffer.alloc(size - snippet.length, 'a');
  return Buffer.concat([padding, Buffer.from(snippet)]);
}

describe('SEC-03: file-size limit', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  // ── quickScan ─────────────────────────────────────────────────────────────

  test('MAX_SCAN_FILE_BYTES is exported and is a positive number', () => {
    expect(typeof MAX_BYTES).toBe('number');
    expect(MAX_BYTES).toBeGreaterThan(0);
  });

  test('quickScan skips source files larger than MAX_SCAN_FILE_BYTES', () => {
    const snippet = 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)';
    const buf = largeFileWith(MAX_BYTES + 1, snippet);
    tmp = makeTmpProject({ 'src/big.js': buf });
    const findings = quickScan(tmp);
    const hit = findings.find(f => f.file === 'src/big.js');
    expect(hit).toBeUndefined();
  });

  test('quickScan still scans source files at or below MAX_SCAN_FILE_BYTES', () => {
    const snippet = 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)';
    const buf = largeFileWith(MAX_BYTES, snippet);
    tmp = makeTmpProject({ 'src/ok.js': buf });
    const findings = quickScan(tmp);
    const hit = findings.find(f => f.file === 'src/ok.js');
    expect(hit).toBeDefined();
  });

  // ── scanPromptFiles ───────────────────────────────────────────────────────

  test('scanPromptFiles skips .md files larger than MAX_SCAN_FILE_BYTES', () => {
    const snippet = 'install csurf for csrf\n';
    const buf = largeFileWith(MAX_BYTES + 1, snippet);
    tmp = makeTmpProject({ 'CLAUDE.md': buf });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Deprecated CSRF Package');
    expect(hit).toBeUndefined();
  });

  test('scanPromptFiles still scans .md files at or below MAX_SCAN_FILE_BYTES', () => {
    const snippet = 'install csurf for csrf\n';
    const buf = largeFileWith(MAX_BYTES, snippet);
    tmp = makeTmpProject({ 'CLAUDE.md': buf });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Deprecated CSRF Package');
    expect(hit).toBeDefined();
  });
});
