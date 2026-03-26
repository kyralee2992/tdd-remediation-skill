'use strict';

/**
 * Unit tests — lib/auditor.js
 *
 * Covers every exported pure function:
 *   safePath, toolReadFile, toolListFiles, toolSearchInFiles, toolWriteFile,
 *   executeToolCall, extractJsonBlock, aiToJson, aiToSarif,
 *   buildSystemPrompt, loadSkillSuite, TOOLS_ANTHROPIC/OPENAI/GEMINI
 *
 * Network-dependent functions (runAudit, runAnthropicAudit, etc.) are
 * covered by the security tests (sec-24) with global.fetch mocked.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const {
  safePath,
  toolReadFile,
  toolListFiles,
  toolSearchInFiles,
  toolWriteFile,
  executeToolCall,
  extractJsonBlock,
  aiToJson,
  aiToSarif,
  buildSystemPrompt,
  loadSkillSuite,
  TOOLS_ANTHROPIC,
  TOOLS_OPENAI,
  TOOLS_GEMINI,
} = require('../../lib/auditor');

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeTmpDir(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-auditor-unit-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    if (content === null) fs.mkdirSync(full, { recursive: true });
    else fs.writeFileSync(full, content, 'utf8');
  }
  return dir;
}

let tmpDir;
beforeEach(() => {
  tmpDir = makeTmpDir({
    'README.md':          '# Project',
    'src/index.js':       'const x = 1;',
    'src/utils.js':       'function helper() {}',
    'test/sample.test.js': 'test("ok", () => {})',
  });
});
afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ─── safePath ─────────────────────────────────────────────────────────────────

describe('safePath()', () => {
  test('resolves a normal relative path', () => {
    const r = safePath('src/index.js', tmpDir);
    expect(r).toBe(path.join(tmpDir, 'src/index.js'));
  });

  test('allows the project root itself', () => {
    expect(safePath('.', tmpDir)).toBe(path.resolve(tmpDir));
  });

  test('throws on path traversal "../"', () => {
    expect(() => safePath('../outside.txt', tmpDir)).toThrow(/Access denied/);
  });

  test('throws on absolute path outside project', () => {
    expect(() => safePath('/etc/passwd', tmpDir)).toThrow(/Access denied/);
  });

  test('throws on empty string', () => {
    expect(() => safePath('', tmpDir)).toThrow();
  });

  test('throws on non-string', () => {
    expect(() => safePath(42, tmpDir)).toThrow();
  });

  test('sibling-prefix bypass is rejected (project + "-evil")', () => {
    expect(() => safePath(tmpDir + '-evil', tmpDir)).toThrow(/Access denied/);
  });
});

// ─── toolReadFile ─────────────────────────────────────────────────────────────

describe('toolReadFile()', () => {
  test('reads an existing file and returns content + bytes', () => {
    const r = toolReadFile({ path: 'README.md' }, tmpDir);
    expect(r.content).toBe('# Project');
    expect(r.bytes).toBeGreaterThan(0);
    expect(r.error).toBeUndefined();
  });

  test('returns { error } for a missing file', () => {
    const r = toolReadFile({ path: 'missing.txt' }, tmpDir);
    expect(r.error).toMatch(/Not found/);
  });

  test('returns { error } for a directory path', () => {
    const r = toolReadFile({ path: 'src' }, tmpDir);
    expect(r.error).toMatch(/Not a file/);
  });

  test('returns { error } for path traversal', () => {
    const r = toolReadFile({ path: '../../etc/passwd' }, tmpDir);
    expect(r.error).toMatch(/Access denied/);
  });

  test('returns { error } for a binary file (null bytes)', () => {
    const binPath = path.join(tmpDir, 'binary.bin');
    fs.writeFileSync(binPath, Buffer.from([0x00, 0x01, 0x02]));
    const r = toolReadFile({ path: 'binary.bin' }, tmpDir);
    expect(r.error).toMatch(/Binary/);
  });

  test('returns { error } for a file exceeding 512 KB', () => {
    const bigPath = path.join(tmpDir, 'big.txt');
    fs.writeFileSync(bigPath, 'x'.repeat(513 * 1024));
    const r = toolReadFile({ path: 'big.txt' }, tmpDir);
    expect(r.error).toMatch(/too large/);
  });

  test('returns { error } when path is missing from input', () => {
    const r = toolReadFile({}, tmpDir);
    expect(r.error).toBeDefined();
  });
});

// ─── toolListFiles ────────────────────────────────────────────────────────────

describe('toolListFiles()', () => {
  test('lists files matching a simple *.md glob', () => {
    const r = toolListFiles({ pattern: '*.md' }, tmpDir);
    expect(r.files).toContain('README.md');
    expect(r.count).toBeGreaterThan(0);
  });

  test('lists files matching **/*.js', () => {
    const r = toolListFiles({ pattern: '**/*.js' }, tmpDir);
    expect(r.files).toContain('src/index.js');
    expect(r.files).toContain('src/utils.js');
  });

  test('returns empty array for a pattern with no matches', () => {
    const r = toolListFiles({ pattern: '**/*.py' }, tmpDir);
    expect(r.files).toHaveLength(0);
    expect(r.count).toBe(0);
  });

  test('returns { error } when pattern is missing', () => {
    const r = toolListFiles({}, tmpDir);
    expect(r.error).toBeDefined();
  });

  test('skips node_modules directory', () => {
    fs.mkdirSync(path.join(tmpDir, 'node_modules', 'pkg'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'node_modules', 'pkg', 'index.js'), 'x');
    const r = toolListFiles({ pattern: '**/*.js' }, tmpDir);
    const hasNodeModules = r.files.some(f => f.includes('node_modules'));
    expect(hasNodeModules).toBe(false);
  });
});

// ─── toolSearchInFiles ────────────────────────────────────────────────────────

describe('toolSearchInFiles()', () => {
  test('finds matches and returns file, line, content', () => {
    const r = toolSearchInFiles({ pattern: 'const x' }, tmpDir);
    expect(r.count).toBeGreaterThan(0);
    expect(r.matches[0]).toMatchObject({
      file:    expect.stringContaining('.js'),
      line:    expect.any(Number),
      content: expect.stringContaining('const x'),
    });
  });

  test('returns empty matches for a pattern with no hits', () => {
    const r = toolSearchInFiles({ pattern: 'ZZZNOMATCH_XYZ' }, tmpDir);
    expect(r.count).toBe(0);
    expect(r.matches).toHaveLength(0);
  });

  test('respects optional glob filter', () => {
    const r = toolSearchInFiles({ pattern: 'function', glob: '**/*.js' }, tmpDir);
    // All matches must come from .js files
    for (const m of r.matches) expect(m.file).toMatch(/\.js$/);
  });

  test('returns { error } for an invalid regex', () => {
    const r = toolSearchInFiles({ pattern: '[unclosed' }, tmpDir);
    expect(r.error).toMatch(/Invalid regex/);
  });

  test('returns { error } when pattern is missing', () => {
    const r = toolSearchInFiles({}, tmpDir);
    expect(r.error).toBeDefined();
  });

  test('skips binary files', () => {
    fs.writeFileSync(path.join(tmpDir, 'blob.bin'), Buffer.from([0x00, 0x68, 0x65, 0x6c, 0x6c]));
    // Should not crash or include the binary file
    const r = toolSearchInFiles({ pattern: 'hel' }, tmpDir);
    const hasBin = r.matches.some(m => m.file === 'blob.bin');
    expect(hasBin).toBe(false);
  });

  test('content in results is capped at 200 chars', () => {
    const longLine = 'const ' + 'x'.repeat(300);
    fs.writeFileSync(path.join(tmpDir, 'long.js'), longLine);
    const r = toolSearchInFiles({ pattern: 'const' }, tmpDir);
    for (const m of r.matches) expect(m.content.length).toBeLessThanOrEqual(200);
  });

  test('skips files larger than 512 KB (line 275 continue branch)', () => {
    fs.writeFileSync(path.join(tmpDir, 'huge.js'), 'const x = 1;\n'.repeat(1000) + 'x'.repeat(512 * 1024));
    const r = toolSearchInFiles({ pattern: 'const' }, tmpDir);
    const hasHuge = r.matches.some(m => m.file === 'huge.js');
    expect(hasHuge).toBe(false);
  });
});

// ─── toolWriteFile ────────────────────────────────────────────────────────────

describe('toolWriteFile()', () => {
  test('writes a new file and returns { ok, path, bytes }', () => {
    const r = toolWriteFile({ path: 'output.txt', content: 'written!' }, tmpDir);
    expect(r.ok).toBe(true);
    expect(r.path).toBe('output.txt');
    expect(r.bytes).toBe(Buffer.byteLength('written!'));
    expect(fs.readFileSync(path.join(tmpDir, 'output.txt'), 'utf8')).toBe('written!');
  });

  test('creates parent directories automatically', () => {
    const r = toolWriteFile({ path: 'deep/nested/file.js', content: 'x' }, tmpDir);
    expect(r.ok).toBe(true);
    expect(fs.existsSync(path.join(tmpDir, 'deep', 'nested', 'file.js'))).toBe(true);
  });

  test('overwrites an existing file', () => {
    const p = path.join(tmpDir, 'existing.txt');
    fs.writeFileSync(p, 'old');
    toolWriteFile({ path: 'existing.txt', content: 'new' }, tmpDir);
    expect(fs.readFileSync(p, 'utf8')).toBe('new');
  });

  test('returns { error } for path traversal', () => {
    const r = toolWriteFile({ path: '../escape.txt', content: 'x' }, tmpDir);
    expect(r.error).toMatch(/Access denied/);
    expect(fs.existsSync(path.join(path.dirname(tmpDir), 'escape.txt'))).toBe(false);
  });

  test('returns { error } when content is not a string', () => {
    const r = toolWriteFile({ path: 'out.txt', content: 42 }, tmpDir);
    expect(r.error).toBeDefined();
  });

  test('returns { error: "Write failed: ..." } when fs.writeFileSync throws', () => {
    jest.spyOn(fs, 'writeFileSync').mockImplementationOnce(() => {
      throw new Error('EACCES: permission denied');
    });
    const r = toolWriteFile({ path: 'no-write.txt', content: 'data' }, tmpDir);
    expect(r.error).toMatch(/Write failed/);
    expect(r.error).toMatch(/EACCES/);
  });
});

// ─── executeToolCall ─────────────────────────────────────────────────────────

describe('executeToolCall()', () => {
  test('dispatches read_file correctly', () => {
    const r = executeToolCall('read_file', { path: 'README.md' }, tmpDir);
    expect(r.content).toBe('# Project');
  });

  test('dispatches list_files correctly', () => {
    const r = executeToolCall('list_files', { pattern: '*.md' }, tmpDir);
    expect(r.files).toContain('README.md');
  });

  test('dispatches search_in_files correctly', () => {
    const r = executeToolCall('search_in_files', { pattern: 'Project' }, tmpDir);
    expect(r.count).toBeGreaterThan(0);
  });

  test('dispatches write_file when allowWrites=true', () => {
    const r = executeToolCall('write_file', { path: 'x.txt', content: '1' }, tmpDir, { allowWrites: true });
    expect(r.ok).toBe(true);
  });

  test('blocks write_file when allowWrites=false (default)', () => {
    const r = executeToolCall('write_file', { path: 'x.txt', content: '1' }, tmpDir);
    expect(r.error).toMatch(/allow-writes/i);
  });

  test('returns { error } for an unknown tool', () => {
    const r = executeToolCall('delete_file', {}, tmpDir, { allowWrites: true });
    expect(r.error).toMatch(/Unknown tool/);
  });
});

// ─── extractJsonBlock ─────────────────────────────────────────────────────────

describe('extractJsonBlock()', () => {
  test('extracts a fenced ```json block', () => {
    const text = 'Here is the report:\n```json\n{"findings":[]}\n```\n';
    expect(extractJsonBlock(text)).toEqual({ findings: [] });
  });

  test('returns the LAST ```json block when multiple are present', () => {
    const text = '```json\n{"v":1}\n```\nsome text\n```json\n{"v":2}\n```';
    expect(extractJsonBlock(text)).toEqual({ v: 2 });
  });

  test('falls back to bare JSON object when no fenced block is present', () => {
    const text = 'Analysis complete.\n{"findings":[{"name":"XSS"}]}';
    expect(extractJsonBlock(text)).toEqual({ findings: [{ name: 'XSS' }] });
  });

  test('returns null when no JSON at all', () => {
    expect(extractJsonBlock('No JSON here at all.')).toBeNull();
  });

  test('falls back to bare JSON when fenced block is absent and bare JSON is valid', () => {
    // No fenced block — bare JSON only
    const text = 'Analysis done.\n{"findings":[{"name":"XSS"}]}';
    expect(extractJsonBlock(text)).toEqual({ findings: [{ name: 'XSS' }] });
  });

  test('returns null when fenced block is invalid and remaining text has no valid JSON', () => {
    // The greedy bare-JSON regex captures across the whole string; if the
    // fenced block contains invalid JSON it poisons the capture → returns null.
    const text = '```json\n{broken json\n```\nno json after';
    expect(extractJsonBlock(text)).toBeNull();
  });

  test('returns null when both fenced block and bare JSON are invalid', () => {
    const text = '```json\n{broken}\n```\nno json here';
    expect(extractJsonBlock(text)).toBeNull();
  });

  test('returns null for empty string', () => {
    expect(extractJsonBlock('')).toBeNull();
  });
});

// ─── aiToJson ─────────────────────────────────────────────────────────────────

describe('aiToJson()', () => {
  const sample = {
    stack: 'Node.js',
    findings: [
      { name: 'SQL Injection', severity: 'CRITICAL', file: 'a.js', line: 1, snippet: 'x', risk: 'bad' },
      { name: 'XSS',           severity: 'HIGH',     file: 'b.js', line: 2, snippet: 'y', risk: 'bad' },
      { name: 'IDOR',          severity: 'MEDIUM',   file: 'c.js', line: 3, snippet: 'z', risk: 'bad' },
    ],
    likelyFalsePositives: [{ name: 'FP', severity: 'LOW' }],
    remediation: [{ name: 'SQL Injection', status: 'fixed' }],
  };

  test('produces the standard envelope shape', () => {
    const r = aiToJson(sample, { provider: 'anthropic', model: 'claude-opus-4-6', scanOnly: false });
    expect(r.version).toBeDefined();
    expect(r.provider).toBe('anthropic');
    expect(r.model).toBe('claude-opus-4-6');
    expect(r.mode).toBe('full');
    expect(r.stack).toBe('Node.js');
    expect(r.findings).toHaveLength(3);
    expect(r.likelyFalsePositives).toHaveLength(1);
    expect(r.remediation).toHaveLength(1);
    expect(r.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}/);
  });

  test('computes summary counts correctly', () => {
    const r = aiToJson(sample, { provider: 'anthropic', model: null, scanOnly: true });
    expect(r.summary).toMatchObject({ CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0 });
  });

  test('sets mode to "scan-only" when scanOnly=true', () => {
    const r = aiToJson(sample, { provider: 'gemini', model: null, scanOnly: true });
    expect(r.mode).toBe('scan-only');
  });

  test('handles empty/missing findings gracefully', () => {
    const r = aiToJson({}, { provider: 'openai', model: null, scanOnly: false });
    expect(r.findings).toEqual([]);
    expect(r.summary).toMatchObject({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  });

  test('handles null extracted gracefully', () => {
    const r = aiToJson(null, { provider: 'openai', model: null, scanOnly: false });
    expect(r.findings).toEqual([]);
  });
});

// ─── aiToSarif ────────────────────────────────────────────────────────────────

describe('aiToSarif()', () => {
  const envelope = {
    findings: [
      { name: 'SQL Injection', severity: 'CRITICAL', file: 'src/db.js', line: 10, snippet: 'SELECT * FROM...' },
      { name: 'XSS',           severity: 'HIGH',     file: 'src/view.js', line: 5,  snippet: 'innerHTML =' },
      { name: 'IDOR',          severity: 'MEDIUM',   file: 'api/get.js', line: 20,  snippet: 'findById' },
      { name: 'Rate Limit',    severity: 'LOW',       file: 'server.js',  line: 1,   snippet: 'app.post' },
    ],
  };

  let sarif;
  beforeEach(() => { sarif = aiToSarif(envelope); });

  test('produces SARIF 2.1.0 schema', () => {
    expect(sarif.$schema).toMatch(/sarif-2\.1\.0/);
    expect(sarif.version).toBe('2.1.0');
  });

  test('has a runs array with exactly one run', () => {
    expect(sarif.runs).toHaveLength(1);
  });

  test('tool driver is @lhi/tdd-audit', () => {
    expect(sarif.runs[0].tool.driver.name).toBe('@lhi/tdd-audit');
  });

  test('CRITICAL/HIGH findings map to level "error"', () => {
    const levels = sarif.runs[0].results.slice(0, 2).map(r => r.level);
    expect(levels).toEqual(['error', 'error']);
  });

  test('MEDIUM findings map to level "warning"', () => {
    const mediumResult = sarif.runs[0].results[2];
    expect(mediumResult.level).toBe('warning');
  });

  test('LOW findings map to level "note"', () => {
    const lowResult = sarif.runs[0].results[3];
    expect(lowResult.level).toBe('note');
  });

  test('each result has a physicalLocation with correct file and line', () => {
    const first = sarif.runs[0].results[0];
    expect(first.locations[0].physicalLocation.artifactLocation.uri).toBe('src/db.js');
    expect(first.locations[0].physicalLocation.region.startLine).toBe(10);
  });

  test('SQL Injection maps to CWE-89 rule relationship', () => {
    const sqlRule = sarif.runs[0].tool.driver.rules.find(r => r.name === 'SQL Injection');
    expect(sqlRule.relationships[0].target.id).toBe('CWE-89');
  });

  test('unknown vuln name still produces a valid result (no CWE)', () => {
    const s = aiToSarif({ findings: [{ name: 'Novel Attack', severity: 'HIGH', file: 'x.js', line: 1 }] });
    expect(s.runs[0].results).toHaveLength(1);
    // No relationships property on the rule (no CWE known)
    expect(s.runs[0].tool.driver.rules[0].relationships).toBeUndefined();
  });

  test('handles empty findings gracefully', () => {
    const s = aiToSarif({ findings: [] });
    expect(s.runs[0].results).toHaveLength(0);
    expect(s.runs[0].tool.driver.rules).toHaveLength(0);
  });

  test('de-duplicates rules for repeated vuln types', () => {
    const s = aiToSarif({
      findings: [
        { name: 'XSS', severity: 'HIGH', file: 'a.js', line: 1 },
        { name: 'XSS', severity: 'HIGH', file: 'b.js', line: 2 },
      ],
    });
    expect(s.runs[0].tool.driver.rules).toHaveLength(1);
    expect(s.runs[0].results).toHaveLength(2);
  });

  test('backslashes in file paths are normalised to forward slashes', () => {
    const s = aiToSarif({ findings: [{ name: 'XSS', severity: 'HIGH', file: 'src\\view.js', line: 1 }] });
    expect(s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/view.js');
  });

  test('line defaults to 1 when not a number', () => {
    const s = aiToSarif({ findings: [{ name: 'XSS', severity: 'HIGH', file: 'x.js', line: null }] });
    expect(s.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(1);
  });

  test('unknown severity defaults to level "warning" (line 160 || branch)', () => {
    const s = aiToSarif({ findings: [{ name: 'Custom', severity: 'INFO', file: 'x.js', line: 1 }] });
    expect(s.runs[0].results[0].level).toBe('warning');
  });

  test('finding with no name produces a valid result', () => {
    const s = aiToSarif({ findings: [{ severity: 'HIGH', file: 'x.js', line: 1, snippet: 'x' }] });
    expect(s.runs[0].results).toHaveLength(1);
  });
});

// ─── buildSystemPrompt ────────────────────────────────────────────────────────

describe('buildSystemPrompt()', () => {
  test('includes skill content in the prompt', () => {
    const suite = { 'SKILL.md': '# TDD Remediation Protocol', 'auto-audit.md': '## Phase 0' };
    const prompt = buildSystemPrompt(suite);
    expect(prompt).toContain('TDD Remediation Protocol');
    expect(prompt).toContain('Phase 0');
  });

  test('includes the security engineer persona', () => {
    const prompt = buildSystemPrompt({});
    expect(prompt).toMatch(/security engineer/i);
  });

  test('includes the "paths are relative" instruction', () => {
    const prompt = buildSystemPrompt({});
    expect(prompt).toMatch(/relative to the project root/i);
  });

  test('handles empty suite without throwing', () => {
    expect(() => buildSystemPrompt({})).not.toThrow();
  });
});

// ─── loadSkillSuite ───────────────────────────────────────────────────────────

describe('loadSkillSuite()', () => {
  const PACKAGE_DIR = path.join(__dirname, '../..');

  test('loads SKILL.md from the real package directory', () => {
    const suite = loadSkillSuite(PACKAGE_DIR);
    expect(suite['SKILL.md']).toBeDefined();
    expect(suite['SKILL.md'].length).toBeGreaterThan(0);
  });

  test('loads auto-audit.md from prompts/', () => {
    const suite = loadSkillSuite(PACKAGE_DIR);
    expect(suite['auto-audit.md']).toBeDefined();
  });

  test('loads all skill files including AI, Node, and test-patterns companions', () => {
    const suite = loadSkillSuite(PACKAGE_DIR);
    const keys = Object.keys(suite);
    expect(keys).toContain('SKILL.md');
    expect(keys).toContain('auto-audit.md');
    expect(keys).toContain('red-phase.md');
    expect(keys).toContain('green-phase.md');
    expect(keys).toContain('refactor-phase.md');
    expect(keys).toContain('hardening-phase.md');
    expect(keys).toContain('ai-security.md');
    expect(keys).toContain('node-advanced-security.md');
    expect(keys).toContain('security-test-patterns.md');
  });

  test('silently skips missing files when packageDir has no prompts', () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-empty-'));
    try {
      const suite = loadSkillSuite(empty);
      expect(Object.keys(suite)).toHaveLength(0);
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });
});

// ─── Tool schema shapes ───────────────────────────────────────────────────────

describe('TOOLS_ANTHROPIC / TOOLS_OPENAI / TOOLS_GEMINI', () => {
  const toolNames = ['read_file', 'list_files', 'search_in_files', 'write_file'];

  test('TOOLS_ANTHROPIC has all 4 tools with input_schema', () => {
    expect(TOOLS_ANTHROPIC).toHaveLength(4);
    for (const t of TOOLS_ANTHROPIC) {
      expect(toolNames).toContain(t.name);
      expect(t.input_schema).toBeDefined();
      expect(t.input_schema.type).toBe('object');
    }
  });

  test('TOOLS_OPENAI wraps each tool as a function call', () => {
    expect(TOOLS_OPENAI).toHaveLength(4);
    for (const t of TOOLS_OPENAI) {
      expect(t.type).toBe('function');
      expect(toolNames).toContain(t.function.name);
      expect(t.function.parameters).toBeDefined();
    }
  });

  test('TOOLS_GEMINI has all 4 tools with parameters', () => {
    expect(TOOLS_GEMINI).toHaveLength(4);
    for (const t of TOOLS_GEMINI) {
      expect(toolNames).toContain(t.name);
      expect(t.parameters).toBeDefined();
    }
  });

  test('write_file tool requires path and content', () => {
    const writeTool = TOOLS_ANTHROPIC.find(t => t.name === 'write_file');
    expect(writeTool.input_schema.required).toContain('path');
    expect(writeTool.input_schema.required).toContain('content');
  });

  test('read_file tool requires path', () => {
    const readTool = TOOLS_ANTHROPIC.find(t => t.name === 'read_file');
    expect(readTool.input_schema.required).toContain('path');
  });

  test('search_in_files glob is optional (not in required)', () => {
    const searchTool = TOOLS_ANTHROPIC.find(t => t.name === 'search_in_files');
    expect(searchTool.input_schema.required).not.toContain('glob');
  });
});

// ─── runAudit — onText / outputWriter callbacks ───────────────────────────────

describe('runAudit() — onText and outputWriter callbacks', () => {
  const { runAudit }  = require('../../lib/auditor');
  const PACKAGE_DIR   = path.join(__dirname, '../..');
  const AI_JSON       = JSON.stringify({ findings: [], likelyFalsePositives: [], remediation: [], stack: 'Node.js' });
  const anthropicResp = {
    ok:   true,
    json: async () => ({
      content:     [{ type: 'text', text: 'Here is the report:\n```json\n' + AI_JSON + '\n```' }],
      stop_reason: 'end_turn',
    }),
  };

  beforeEach(() => {
    global.fetch = async () => anthropicResp;
    jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
  });
  afterEach(() => {
    delete global.fetch;
    jest.restoreAllMocks();
  });

  test('onText is called with LLM text chunks during text-mode audit', async () => {
    const chunks = [];
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       (t) => chunks.push(t),
    });
    expect(chunks.length).toBeGreaterThan(0);
    expect(chunks.join('')).toContain('json');
  });

  test('onText is NOT called when it is not provided (text mode writes to stdout)', async () => {
    const written = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((t) => { written.push(t); });
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
    });
    expect(written.length).toBeGreaterThan(0);
  });

  test('outputWriter receives the final JSON string instead of stdout in json mode', async () => {
    let captured = null;
    const stdoutWrites = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((s) => stdoutWrites.push(s));

    await runAudit({
      projectDir:    tmpDir,
      packageDir:    PACKAGE_DIR,
      provider:      'anthropic',
      apiKey:        'sk-test',
      outputFormat:  'json',
      scanOnly:      true,
      outputWriter:  (s) => { captured = s; },
    });

    expect(captured).not.toBeNull();
    const parsed = JSON.parse(captured.trim());
    expect(Array.isArray(parsed.findings)).toBe(true);
    // stdout should NOT have received the JSON payload (outputWriter intercepted it)
    expect(stdoutWrites.join('')).not.toContain('"findings"');
  });

  test('onText + outputWriter together: chunks stream in, final JSON captured', async () => {
    const chunks = [];
    let captured = null;

    await runAudit({
      projectDir:    tmpDir,
      packageDir:    PACKAGE_DIR,
      provider:      'anthropic',
      apiKey:        'sk-test',
      outputFormat:  'json',
      scanOnly:      true,
      onText:        (t) => chunks.push(t),
      outputWriter:  (s) => { captured = s; },
    });

    expect(chunks.length).toBeGreaterThan(0);
    expect(captured).not.toBeNull();
    const parsed = JSON.parse(captured.trim());
    expect(parsed.findings).toBeDefined();
  });

  test('outputWriter receives sarif when outputFormat is sarif', async () => {
    let captured = null;
    await runAudit({
      projectDir:    tmpDir,
      packageDir:    PACKAGE_DIR,
      provider:      'anthropic',
      apiKey:        'sk-test',
      outputFormat:  'sarif',
      scanOnly:      true,
      outputWriter:  (s) => { captured = s; },
    });
    const parsed = JSON.parse(captured.trim());
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toMatch(/sarif/);
  });
});

// ─── runAudit — input validation ──────────────────────────────────────────────

describe('runAudit() — input validation', () => {
  const { runAudit } = require('../../lib/auditor');
  const PACKAGE_DIR  = path.join(__dirname, '../..');

  beforeEach(() => {
    jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
  });
  afterEach(() => { jest.restoreAllMocks(); });

  test('throws when provider is missing', async () => {
    await expect(runAudit({ projectDir: tmpDir, packageDir: PACKAGE_DIR, apiKey: 'k' }))
      .rejects.toThrow(/provider/i);
  });

  test('throws when apiKey is missing', async () => {
    await expect(runAudit({ projectDir: tmpDir, packageDir: PACKAGE_DIR, provider: 'anthropic' }))
      .rejects.toThrow(/api key/i);
  });
});
