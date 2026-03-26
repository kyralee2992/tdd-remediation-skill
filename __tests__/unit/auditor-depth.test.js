'use strict';

/**
 * Depth-tier architecture tests for lib/auditor.js
 *
 * Verifies that each depth tier (tier-1 / tier-2 / tier-3 / tier-4):
 *   1. Emits the correct JSON schema instruction to the LLM
 *   2. Enables/disables allowWrites correctly
 *   3. Sets scanOnly correctly
 *   4. Includes `depth` in the output envelope
 *   5. `aiToJson` includes depth in the envelope
 *   6. `buildJsonOutputInstruction` returns distinct schemas per tier
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const {
  runAudit,
  aiToJson,
  buildJsonOutputInstruction,
  DEPTH_JSON_INSTRUCTIONS,
} = require('../../lib/auditor');

const PACKAGE_DIR = path.join(__dirname, '../..');

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeTmpDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-depth-'));
  fs.writeFileSync(path.join(dir, 'README.md'), '# Project');
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', 'index.js'), 'const x = 1;');
  return dir;
}

let tmpDir;
beforeEach(() => {
  tmpDir = makeTmpDir();
  jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
});
afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  jest.restoreAllMocks();
  delete global.fetch;
});

// LLM response helpers
const AI_JSON_TIER2 = JSON.stringify({
  stack: 'Node.js',
  findings: [{
    name: 'SQL Injection',
    severity: 'CRITICAL',
    file: 'src/db.js',
    line: 10,
    snippet: 'db.query(input)',
    risk: 'Full database exfiltration',
    effort: 'low',
    cwe: 'CWE-89',
    owasp: 'A03:2021 — Injection',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  }],
  likelyFalsePositives: [],
  remediation: [],
});

const AI_JSON_TIER3 = JSON.stringify({
  stack: 'Node.js',
  findings: [{
    name: 'SQL Injection',
    severity: 'CRITICAL',
    file: 'src/db.js',
    line: 10,
    snippet: 'db.query(input)',
    risk: 'Full database exfiltration',
    effort: 'low',
    cwe: 'CWE-89',
    patch: "const stmt = db.prepare('SELECT * FROM users WHERE id = ?');\nstmt.run(input);",
    testSnippet: "test('prevents SQL injection', () => { expect(() => query(\"'; DROP TABLE users--\")).not.toThrow(); });",
  }],
  likelyFalsePositives: [],
  remediation: [],
});

function anthropicResp(jsonStr) {
  return {
    ok:   true,
    json: async () => ({
      content:     [{ type: 'text', text: '```json\n' + jsonStr + '\n```' }],
      stop_reason: 'end_turn',
    }),
  };
}

// ─── buildJsonOutputInstruction ───────────────────────────────────────────────

describe('buildJsonOutputInstruction()', () => {
  test('tier-1 schema has no risk/effort/cwe/patch fields', () => {
    const inst = buildJsonOutputInstruction('tier-1');
    expect(inst).not.toContain('"risk"');
    expect(inst).not.toContain('"effort"');
    expect(inst).not.toContain('"patch"');
  });

  test('tier-2 schema includes risk, effort, cwe, owasp, references', () => {
    const inst = buildJsonOutputInstruction('tier-2');
    expect(inst).toContain('"risk"');
    expect(inst).toContain('"effort"');
    expect(inst).toContain('"cwe"');
    expect(inst).toContain('"owasp"');
    expect(inst).toContain('"references"');
  });

  test('tier-3 schema includes patch and testSnippet fields', () => {
    const inst = buildJsonOutputInstruction('tier-3');
    expect(inst).toContain('"patch"');
    expect(inst).toContain('"testSnippet"');
  });

  test('tier-4 schema includes write_file instruction and patch field', () => {
    const inst = buildJsonOutputInstruction('tier-4');
    expect(inst).toContain('write_file');
    expect(inst).toContain('"patch"');
    expect(inst).toContain('"remediation"');
  });

  test('unknown depth falls back to tier-1 schema', () => {
    const inst = buildJsonOutputInstruction('unknown-tier');
    expect(inst).toBeDefined();
    expect(typeof inst).toBe('string');
    expect(inst).not.toContain('"patch"');
  });

  test('all four tier keys exist in DEPTH_JSON_INSTRUCTIONS', () => {
    expect(DEPTH_JSON_INSTRUCTIONS).toHaveProperty('tier-1');
    expect(DEPTH_JSON_INSTRUCTIONS).toHaveProperty('tier-2');
    expect(DEPTH_JSON_INSTRUCTIONS).toHaveProperty('tier-3');
    expect(DEPTH_JSON_INSTRUCTIONS).toHaveProperty('tier-4');
  });

  test('each tier produces a distinct instruction string', () => {
    const instructions = ['tier-1', 'tier-2', 'tier-3', 'tier-4'].map(buildJsonOutputInstruction);
    const unique = new Set(instructions);
    expect(unique.size).toBe(4);
  });
});

// ─── aiToJson — patchesApplied billing unit ───────────────────────────────────

describe('aiToJson() — patchesApplied billing unit', () => {
  test('patchesApplied is 0 when remediation is empty (tier-1/tier-2/tier-3)', () => {
    const r = aiToJson(
      { stack: 'Node.js', findings: [], likelyFalsePositives: [], remediation: [] },
      { provider: 'anthropic', model: null, scanOnly: true, depth: 'tier-1' },
    );
    expect(r.patchesApplied).toBe(0);
  });

  test('patchesApplied counts only status=fixed remediation entries', () => {
    const r = aiToJson(
      {
        stack: 'Node.js',
        findings: [],
        likelyFalsePositives: [],
        remediation: [
          { name: 'SQL Injection', status: 'fixed',   testFile: 'test/sql.test.js', fixApplied: 'parameterized query' },
          { name: 'XSS',          status: 'skipped',  testFile: null,               fixApplied: 'manual review required' },
          { name: 'SSRF',         status: 'fixed',    testFile: 'test/ssrf.test.js', fixApplied: 'url allowlist added' },
        ],
      },
      { provider: 'anthropic', model: null, scanOnly: false, depth: 'tier-4' },
    );
    expect(r.patchesApplied).toBe(2);  // 2 fixed, 1 skipped
  });

  test('patchesApplied is 0 when all remediation entries are skipped', () => {
    const r = aiToJson(
      {
        stack: 'Node.js', findings: [], likelyFalsePositives: [],
        remediation: [
          { name: 'A', status: 'skipped' },
          { name: 'B', status: 'skipped' },
        ],
      },
      { provider: 'anthropic', model: null, scanOnly: false, depth: 'tier-4' },
    );
    expect(r.patchesApplied).toBe(0);
  });

  test('patchesApplied field appears in envelope before findings', () => {
    const r = aiToJson(
      { stack: 'Node.js', findings: [], likelyFalsePositives: [], remediation: [] },
      { provider: 'anthropic', model: null, scanOnly: false, depth: 'tier-4' },
    );
    const keys = Object.keys(r);
    expect(keys).toContain('patchesApplied');
    expect(keys.indexOf('patchesApplied')).toBeLessThan(keys.indexOf('findings'));
  });

  test('tier-3 reports have patchesApplied=0 (patches are copy-only, not applied)', () => {
    const r = aiToJson(
      {
        stack: 'Node.js',
        findings: [{ name: 'XSS', severity: 'HIGH', file: 'a.js', line: 1, snippet: 'x', patch: 'sanitize(x)' }],
        likelyFalsePositives: [],
        remediation: [],  // tier-3 LLM never writes files → remediation stays empty
      },
      { provider: 'anthropic', model: null, scanOnly: false, depth: 'tier-3' },
    );
    expect(r.patchesApplied).toBe(0);
    // The patch is still in the findings for the user to copy
    expect(r.findings[0].patch).toBe('sanitize(x)');
  });
});

// ─── aiToJson — depth field in envelope ───────────────────────────────────────

describe('aiToJson() — depth field in envelope', () => {
  const sample = { stack: 'Node.js', findings: [], likelyFalsePositives: [], remediation: [] };

  test('includes depth="tier-1" in envelope when not specified', () => {
    const r = aiToJson(sample, { provider: 'anthropic', model: null, scanOnly: true });
    expect(r.depth).toBe('tier-1');
  });

  test('includes depth="tier-2" when specified', () => {
    const r = aiToJson(sample, { provider: 'anthropic', model: null, scanOnly: true, depth: 'tier-2' });
    expect(r.depth).toBe('tier-2');
  });

  test('includes depth="tier-3" when specified', () => {
    const r = aiToJson(sample, { provider: 'openai', model: 'gpt-4o', scanOnly: false, depth: 'tier-3' });
    expect(r.depth).toBe('tier-3');
  });

  test('includes depth="tier-4" when specified', () => {
    const r = aiToJson(sample, { provider: 'gemini', model: null, scanOnly: false, depth: 'tier-4' });
    expect(r.depth).toBe('tier-4');
  });

  test('depth field appears before findings in envelope', () => {
    const r = aiToJson(sample, { provider: 'anthropic', model: null, scanOnly: false, depth: 'tier-3' });
    const keys = Object.keys(r);
    expect(keys.indexOf('depth')).toBeLessThan(keys.indexOf('findings'));
  });
});

// ─── runAudit() — capability resolution per depth ─────────────────────────────

describe('runAudit() — depth auto-resolves scanOnly and allowWrites', () => {
  function makeAnthropicMock(jsonStr) {
    global.fetch = jest.fn(async () => anthropicResp(jsonStr));
  }

  test('depth=tier-1 → scan-only mode, no writes', async () => {
    makeAnthropicMock(AI_JSON_TIER2);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-1',
      onText: () => {}, outputWriter: () => {},
    });

    expect(stderrLines.join('')).toMatch(/scan-only\/tier-1/);
  });

  test('depth=tier-2 → scan-only mode, no writes', async () => {
    makeAnthropicMock(AI_JSON_TIER2);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-2',
      onText: () => {}, outputWriter: () => {},
    });

    expect(stderrLines.join('')).toMatch(/scan-only\/tier-2/);
  });

  test('depth=tier-3 → full audit, writes disabled', async () => {
    makeAnthropicMock(AI_JSON_TIER3);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-3',
      onText: () => {}, outputWriter: () => {},
    });

    const stderr = stderrLines.join('');
    expect(stderr).toMatch(/full\/tier-3/);
    // tier-3 does NOT write files
    const capturedBody = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(capturedBody.messages[0].content).toMatch(/File writes are disabled/);
  });

  test('depth=tier-4 → full audit, writes enabled', async () => {
    makeAnthropicMock(AI_JSON_TIER3);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-4',
      onText: () => {}, outputWriter: () => {},
    });

    const stderr = stderrLines.join('');
    expect(stderr).toMatch(/full\/tier-4\+writes/);
    const capturedBody = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(capturedBody.messages[0].content).toMatch(/permission to write files/);
  });

  test('tier-2 instruction is included in user message for json outputFormat', async () => {
    makeAnthropicMock(AI_JSON_TIER2);
    let capturedBody;
    global.fetch = jest.fn(async (_, init) => {
      capturedBody = JSON.parse(init.body);
      return anthropicResp(AI_JSON_TIER2);
    });

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-2',
      onText: () => {}, outputWriter: () => {},
    });

    const userMsg = capturedBody.messages[0].content;
    expect(userMsg).toContain('"owasp"');
    expect(userMsg).toContain('"references"');
  });

  test('output envelope contains depth="tier-2" and tier-2 fields', async () => {
    makeAnthropicMock(AI_JSON_TIER2);
    let captured = null;

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-2',
      onText: () => {}, outputWriter: (s) => { captured = s; },
    });

    const parsed = JSON.parse(captured.trim());
    expect(parsed.depth).toBe('tier-2');
    expect(parsed.findings[0].cwe).toBe('CWE-89');
    expect(parsed.findings[0].owasp).toContain('Injection');
  });

  test('output envelope contains depth="tier-3" and patch/testSnippet fields', async () => {
    makeAnthropicMock(AI_JSON_TIER3);
    let captured = null;

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-3',
      onText: () => {}, outputWriter: (s) => { captured = s; },
    });

    const parsed = JSON.parse(captured.trim());
    expect(parsed.depth).toBe('tier-3');
    expect(parsed.findings[0].patch).toContain('db.prepare');
    expect(parsed.findings[0].testSnippet).toContain('SQL injection');
  });

  test('targeted-apply mode: depth=tier-4 + findings array → mode string contains targeted-apply', async () => {
    makeAnthropicMock(AI_JSON_TIER3);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    const preIdentified = [{ name: 'SQL Injection', file: 'src/db.js', line: 10, patch: 'db.prepare(...)' }];

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-4',
      findings: preIdentified,
      onText: () => {}, outputWriter: () => {},
    });

    expect(stderrLines.join('')).toMatch(/targeted-apply\/tier-4\(1\)/);
  });

  test('targeted-apply mode: user message instructs LLM to skip re-scan', async () => {
    let capturedBody;
    global.fetch = jest.fn(async (_, init) => {
      capturedBody = JSON.parse(init.body);
      return anthropicResp(AI_JSON_TIER3);
    });

    const preIdentified = [{ name: 'XSS', file: 'src/view.js', line: 5, patch: 'textContent = x' }];

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-4',
      findings: preIdentified,
      onText: () => {}, outputWriter: () => {},
    });

    const userMsg = capturedBody.messages[0].content;
    expect(userMsg).toContain('Do NOT re-scan the codebase');
    expect(userMsg).toContain('XSS');
  });

  test('targeted-apply mode: multiple findings → count reflected in mode string', async () => {
    makeAnthropicMock(AI_JSON_TIER3);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    const preIdentified = [
      { name: 'SQL Injection', file: 'src/db.js', line: 10, patch: 'db.prepare(...)' },
      { name: 'XSS',          file: 'src/view.js', line: 5, patch: 'textContent = x' },
      { name: 'SSRF',         file: 'src/http.js', line: 20, patch: 'allowlist check' },
    ];

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-4',
      findings: preIdentified,
      onText: () => {}, outputWriter: () => {},
    });

    expect(stderrLines.join('')).toMatch(/targeted-apply\/tier-4\(3\)/);
  });

  test('empty findings array does NOT trigger targeted-apply (falls back to full audit)', async () => {
    makeAnthropicMock(AI_JSON_TIER3);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-4',
      findings: [],   // empty — should NOT trigger targeted apply
      onText: () => {}, outputWriter: () => {},
    });

    const stderr = stderrLines.join('');
    expect(stderr).toMatch(/full\/tier-4\+writes/);
    expect(stderr).not.toContain('targeted-apply');
  });

  test('null findings does NOT trigger targeted-apply', async () => {
    makeAnthropicMock(AI_JSON_TIER3);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-4',
      findings: null,
      onText: () => {}, outputWriter: () => {},
    });

    expect(stderrLines.join('')).toMatch(/full\/tier-4\+writes/);
  });

  test('tier-3 with findings does NOT trigger targeted-apply (only tier-4)', async () => {
    makeAnthropicMock(AI_JSON_TIER3);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    const preIdentified = [{ name: 'XSS', file: 'src/view.js', line: 5, patch: 'textContent = x' }];

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'json', depth: 'tier-3',
      findings: preIdentified,
      onText: () => {}, outputWriter: () => {},
    });

    const stderr = stderrLines.join('');
    expect(stderr).toMatch(/full\/tier-3/);
    expect(stderr).not.toContain('targeted-apply');
  });

  test('explicit scanOnly=false overrides tier-1 default', async () => {
    makeAnthropicMock(AI_JSON_TIER2);
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    await runAudit({
      projectDir: tmpDir, packageDir: PACKAGE_DIR,
      provider: 'anthropic', apiKey: 'sk-test',
      outputFormat: 'text', depth: 'tier-1',
      scanOnly: false,
      onText: () => {},
    });

    expect(stderrLines.join('')).toMatch(/full\/tier-1/);
  });
});
