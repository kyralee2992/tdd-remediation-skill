'use strict';

/**
 * TDD Remediation — Unit Tests for lib/scanner.js
 *
 * These tests cover every exported function. They were written RED-first:
 * the test suite was run against the original index.js (which had no exports)
 * and failed before lib/scanner.js existed.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  detectFramework,
  detectAppFramework,
  detectTestBaseDir,
  walkFiles,
  walkMdFiles,
  isTestFile,
  isPromptFile,
  scanAppConfig,
  scanAndroidManifest,
  scanPromptFiles,
  quickScan,
  printFindings,
  VULN_PATTERNS,
  PROMPT_PATTERNS,
} = require('../../lib/scanner');

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Create a temporary directory with the given file map.
 * Returns the tmp dir path. Caller is responsible for cleanup via afterEach.
 */
function makeTmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-audit-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    if (content === null) {
      // directory marker
      fs.mkdirSync(full, { recursive: true });
    } else {
      fs.writeFileSync(full, content, 'utf8');
    }
  }
  return dir;
}

function rmrf(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ─── detectFramework ──────────────────────────────────────────────────────────

describe('detectFramework', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('returns "flutter" when pubspec.yaml exists', () => {
    tmp = makeTmpProject({ 'pubspec.yaml': 'name: my_app\n' });
    expect(detectFramework(tmp)).toBe('flutter');
  });

  test('returns "flutter" for Flutter even when package.json also present', () => {
    tmp = makeTmpProject({
      'pubspec.yaml': 'name: my_app\n',
      'package.json': JSON.stringify({ devDependencies: { jest: '^29.0.0' } }),
    });
    expect(detectFramework(tmp)).toBe('flutter');
  });

  test('returns "vitest" when package.json has vitest dep', () => {
    tmp = makeTmpProject({
      'package.json': JSON.stringify({ devDependencies: { vitest: '^1.0.0' } }),
    });
    expect(detectFramework(tmp)).toBe('vitest');
  });

  test('returns "jest" when package.json has jest dep', () => {
    tmp = makeTmpProject({
      'package.json': JSON.stringify({ devDependencies: { jest: '^29.0.0' } }),
    });
    expect(detectFramework(tmp)).toBe('jest');
  });

  test('returns "jest" when package.json has supertest dep (no explicit jest)', () => {
    tmp = makeTmpProject({
      'package.json': JSON.stringify({ devDependencies: { supertest: '^6.0.0' } }),
    });
    expect(detectFramework(tmp)).toBe('jest');
  });

  test('returns "mocha" when package.json has mocha dep', () => {
    tmp = makeTmpProject({
      'package.json': JSON.stringify({ devDependencies: { mocha: '^10.0.0' } }),
    });
    expect(detectFramework(tmp)).toBe('mocha');
  });

  test('returns "pytest" when pytest.ini exists', () => {
    tmp = makeTmpProject({ 'pytest.ini': '[pytest]\n' });
    expect(detectFramework(tmp)).toBe('pytest');
  });

  test('returns "pytest" when pyproject.toml exists', () => {
    tmp = makeTmpProject({ 'pyproject.toml': '[tool.pytest]\n' });
    expect(detectFramework(tmp)).toBe('pytest');
  });

  test('returns "pytest" when requirements.txt exists', () => {
    tmp = makeTmpProject({ 'requirements.txt': 'flask\n' });
    expect(detectFramework(tmp)).toBe('pytest');
  });

  test('returns "go" when go.mod exists', () => {
    tmp = makeTmpProject({ 'go.mod': 'module example.com/app\n' });
    expect(detectFramework(tmp)).toBe('go');
  });

  test('returns "jest" as default when no indicators exist', () => {
    tmp = makeTmpProject({});
    expect(detectFramework(tmp)).toBe('jest');
  });

  test('handles malformed package.json gracefully and falls through to default', () => {
    tmp = makeTmpProject({ 'package.json': '{ invalid json' });
    expect(detectFramework(tmp)).toBe('jest');
  });
});

// ─── detectAppFramework ───────────────────────────────────────────────────────

describe('detectAppFramework', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('returns "flutter" when pubspec.yaml exists', () => {
    tmp = makeTmpProject({ 'pubspec.yaml': '' });
    expect(detectAppFramework(tmp)).toBe('flutter');
  });

  test('returns "expo" when expo is in dependencies', () => {
    tmp = makeTmpProject({
      'package.json': JSON.stringify({ dependencies: { expo: '~50.0.0' } }),
    });
    expect(detectAppFramework(tmp)).toBe('expo');
  });

  test('returns "react-native" when react-native is in dependencies', () => {
    tmp = makeTmpProject({
      'package.json': JSON.stringify({ dependencies: { 'react-native': '0.73.0' } }),
    });
    expect(detectAppFramework(tmp)).toBe('react-native');
  });

  test('returns "nextjs" when next is in dependencies', () => {
    tmp = makeTmpProject({
      'package.json': JSON.stringify({ dependencies: { next: '14.0.0' } }),
    });
    expect(detectAppFramework(tmp)).toBe('nextjs');
  });

  test('returns "react" when react is in dependencies', () => {
    tmp = makeTmpProject({
      'package.json': JSON.stringify({ dependencies: { react: '18.0.0' } }),
    });
    expect(detectAppFramework(tmp)).toBe('react');
  });

  test('returns null when no UI framework is detected', () => {
    tmp = makeTmpProject({});
    expect(detectAppFramework(tmp)).toBeNull();
  });

  test('handles malformed package.json and returns null', () => {
    tmp = makeTmpProject({ 'package.json': 'bad json' });
    expect(detectAppFramework(tmp)).toBeNull();
  });
});

// ─── detectTestBaseDir ────────────────────────────────────────────────────────

describe('detectTestBaseDir', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('returns "__tests__" when __tests__ dir exists', () => {
    tmp = makeTmpProject({ '__tests__': null });
    expect(detectTestBaseDir(tmp, 'jest')).toBe('__tests__');
  });

  test('returns "tests" when tests dir exists', () => {
    tmp = makeTmpProject({ 'tests': null });
    expect(detectTestBaseDir(tmp, 'jest')).toBe('tests');
  });

  test('returns "test" when test dir exists', () => {
    tmp = makeTmpProject({ 'test': null });
    expect(detectTestBaseDir(tmp, 'jest')).toBe('test');
  });

  test('returns "spec" when spec dir exists', () => {
    tmp = makeTmpProject({ 'spec': null });
    expect(detectTestBaseDir(tmp, 'jest')).toBe('spec');
  });

  test('prefers __tests__ over tests when both exist', () => {
    tmp = makeTmpProject({ '__tests__': null, 'tests': null });
    expect(detectTestBaseDir(tmp, 'jest')).toBe('__tests__');
  });

  test('falls back to "tests" for pytest when no dir exists', () => {
    tmp = makeTmpProject({});
    expect(detectTestBaseDir(tmp, 'pytest')).toBe('tests');
  });

  test('falls back to "test" for go when no dir exists', () => {
    tmp = makeTmpProject({});
    expect(detectTestBaseDir(tmp, 'go')).toBe('test');
  });

  test('falls back to "__tests__" for jest when no dir exists', () => {
    tmp = makeTmpProject({});
    expect(detectTestBaseDir(tmp, 'jest')).toBe('__tests__');
  });
});

// ─── isTestFile ───────────────────────────────────────────────────────────────

describe('isTestFile', () => {
  const base = '/project';

  test('returns true for .test.js files', () => {
    expect(isTestFile('/project/src/auth.test.js', base)).toBe(true);
  });

  test('returns true for .spec.ts files', () => {
    expect(isTestFile('/project/src/auth.spec.ts', base)).toBe(true);
  });

  test('returns true for _test.dart files', () => {
    expect(isTestFile('/project/test/auth_test.dart', base)).toBe(true);
  });

  test('returns true for files inside __tests__ dir', () => {
    expect(isTestFile('/project/__tests__/security/exploit.js', base)).toBe(true);
  });

  test('returns true for files inside tests/ dir', () => {
    expect(isTestFile('/project/tests/auth.js', base)).toBe(true);
  });

  test('returns true for files inside spec/ dir', () => {
    expect(isTestFile('/project/spec/auth.js', base)).toBe(true);
  });

  test('returns false for regular source files', () => {
    expect(isTestFile('/project/src/auth.js', base)).toBe(false);
  });

  test('returns false for files with "test" in directory name that is not tests/ or test/', () => {
    // e.g. /project/contest/helper.js — should not be flagged
    expect(isTestFile('/project/src/contest/helper.js', base)).toBe(false);
  });
});

// ─── walkFiles ────────────────────────────────────────────────────────────────

describe('walkFiles', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('yields .js and .ts files', () => {
    tmp = makeTmpProject({
      'src/app.js': 'console.log("hi")',
      'src/types.ts': 'type Foo = string',
    });
    const files = [...walkFiles(tmp)].map(f => path.relative(tmp, f));
    expect(files).toContain('src/app.js');
    expect(files).toContain('src/types.ts');
  });

  test('skips node_modules', () => {
    tmp = makeTmpProject({
      'src/app.js': '',
      'node_modules/lodash/index.js': '',
    });
    const files = [...walkFiles(tmp)].map(f => path.relative(tmp, f));
    expect(files.some(f => f.includes('node_modules'))).toBe(false);
  });

  test('skips .git directory', () => {
    tmp = makeTmpProject({
      'src/app.js': '',
      '.git/hooks/pre-commit': '',
    });
    const files = [...walkFiles(tmp)].map(f => path.relative(tmp, f));
    expect(files.some(f => f.startsWith('.git'))).toBe(false);
  });

  test('does not yield non-scannable extensions like .md or .json', () => {
    tmp = makeTmpProject({
      'README.md': '# Readme',
      'package.json': '{}',
      'src/app.js': '',
    });
    const files = [...walkFiles(tmp)].map(f => path.relative(tmp, f));
    expect(files).not.toContain('README.md');
    expect(files).not.toContain('package.json');
    expect(files).toContain('src/app.js');
  });

  test('skips symlinks (M2: symlink escape guard)', () => {
    tmp = makeTmpProject({ 'src/app.js': '' });
    const linkPath = path.join(tmp, 'outside-link');
    try {
      fs.symlinkSync(os.tmpdir(), linkPath);
    } catch {
      return; // symlink creation may fail in some CI environments — skip
    }
    const files = [...walkFiles(tmp)].map(f => path.relative(tmp, f));
    expect(files.some(f => f.startsWith('outside-link'))).toBe(false);
  });
});

// ─── scanAppConfig ────────────────────────────────────────────────────────────

describe('scanAppConfig', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('returns empty array when no config files exist', () => {
    tmp = makeTmpProject({});
    expect(scanAppConfig(tmp)).toEqual([]);
  });

  test('detects hardcoded secret in app.json', () => {
    tmp = makeTmpProject({
      'app.json': JSON.stringify({
        expo: { extra: { apiKey: 'AAABBBCCC111222333444555666777888999000aaa' } },
      }),
    });
    const findings = scanAppConfig(tmp);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].name).toBe('Config Secret');
    expect(findings[0].severity).toBe('CRITICAL');
    expect(findings[0].file).toBe('app.json');
  });

  test('detects hardcoded secret in app.config.js', () => {
    tmp = makeTmpProject({
      'app.config.js': `module.exports = { secret: 'AAABBBCCC111222333444555XXXX' }`,
    });
    const findings = scanAppConfig(tmp);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].file).toBe('app.config.js');
  });

  test('detects template-literal secret fallback (L2 fix)', () => {
    tmp = makeTmpProject({
      'app.config.js': "const apiKey = `${process.env.KEY || 'hardcoded_secret_value_1234'}`;",
    });
    const findings = scanAppConfig(tmp);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].name).toBe('Config Secret');
  });

  test('does not flag short values that are not secrets', () => {
    tmp = makeTmpProject({
      'app.json': JSON.stringify({ name: 'myapp', version: '1.0.0' }),
    });
    const findings = scanAppConfig(tmp);
    expect(findings).toEqual([]);
  });
});

// ─── scanAndroidManifest ──────────────────────────────────────────────────────

describe('scanAndroidManifest', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('returns empty array when no manifest exists', () => {
    tmp = makeTmpProject({});
    expect(scanAndroidManifest(tmp)).toEqual([]);
  });

  test('detects android:debuggable="true"', () => {
    const manifestContent = `<manifest>
  <application android:debuggable="true">
  </application>
</manifest>`;
    tmp = makeTmpProject({
      'android/app/src/main/AndroidManifest.xml': manifestContent,
    });
    const findings = scanAndroidManifest(tmp);
    expect(findings.length).toBe(1);
    expect(findings[0].name).toBe('Android Debuggable');
    expect(findings[0].severity).toBe('HIGH');
  });

  test('does not flag android:debuggable="false"', () => {
    const manifestContent = `<application android:debuggable="false"></application>`;
    tmp = makeTmpProject({
      'android/app/src/main/AndroidManifest.xml': manifestContent,
    });
    expect(scanAndroidManifest(tmp)).toEqual([]);
  });
});

// ─── quickScan — vulnerability pattern coverage ───────────────────────────────

describe('quickScan — vulnerability detection', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  function scanFile(filename, content) {
    tmp = makeTmpProject({ [filename]: content });
    return quickScan(tmp);
  }

  test('detects SQL Injection — template literal query', () => {
    const findings = scanFile('src/db.js', 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)');
    expect(findings.some(f => f.name === 'SQL Injection')).toBe(true);
  });

  test('detects Command Injection — exec with req.body', () => {
    const findings = scanFile('src/util.js', 'exec(`ls ${req.body.dir}`)');
    expect(findings.some(f => f.name === 'Command Injection')).toBe(true);
  });

  test('detects IDOR — findById with req.params', () => {
    const findings = scanFile('src/user.js', 'User.findById(req.params.id)');
    expect(findings.some(f => f.name === 'IDOR')).toBe(true);
  });

  test('detects XSS — innerHTML assignment', () => {
    const findings = scanFile('src/render.js', 'element.innerHTML = userInput');
    expect(findings.some(f => f.name === 'XSS')).toBe(true);
  });

  test('detects TLS Bypass — rejectUnauthorized: false', () => {
    const findings = scanFile('src/http.js', 'https.request({ rejectUnauthorized: false })');
    expect(findings.some(f => f.name === 'TLS Bypass')).toBe(true);
  });

  test('detects CORS Wildcard — single-quote header name (existing)', () => {
    const findings = scanFile('src/server.js', "res.setHeader('Access-Control-Allow-Origin', '*')");
    expect(findings.some(f => f.name === 'CORS Wildcard')).toBe(true);
  });

  test('detects CORS Wildcard — double-quote header name (H3 fix)', () => {
    const findings = scanFile('src/server.js', 'res.setHeader("Access-Control-Allow-Origin", "*")');
    expect(findings.some(f => f.name === 'CORS Wildcard')).toBe(true);
  });

  test('detects multiple vulnerabilities on different lines in same file', () => {
    const content = [
      'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)',
      'exec(`ls ${req.body.dir}`)',
    ].join('\n');
    const findings = scanFile('src/bad.js', content);
    const names = findings.map(f => f.name);
    expect(names).toContain('SQL Injection');
    expect(names).toContain('Command Injection');
  });

  test('reports multiple vulnerabilities on the same line (M3 fix)', () => {
    // Craft a line that matches both IDOR and NoSQL Injection patterns
    const line = 'User.findById(req.params.id); User.find(req.body)';
    const findings = scanFile('src/bad.js', line);
    const names = findings.map(f => f.name);
    expect(names).toContain('IDOR');
    expect(names).toContain('NoSQL Injection');
  });

  test('marks findings in test files as inTestFile=true', () => {
    const content = 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)';
    tmp = makeTmpProject({ '__tests__/auth.test.js': content });
    const findings = quickScan(tmp);
    expect(findings.some(f => f.inTestFile === true)).toBe(true);
  });

  test('skips binary files (L1 fix — null byte guard)', () => {
    tmp = makeTmpProject({});
    // Write a file with a null byte to simulate binary content
    const binPath = path.join(tmp, 'src', 'binary.js');
    fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
    fs.writeFileSync(binPath, Buffer.from([0x00, 0x01, 0x02, 0x03]));
    expect(() => quickScan(tmp)).not.toThrow();
    const findings = quickScan(tmp);
    // Should produce 0 findings from the binary file
    expect(findings.filter(f => f.file.includes('binary.js'))).toHaveLength(0);
  });

  test('returns empty array for a clean project', () => {
    tmp = makeTmpProject({
      'src/index.js': 'console.log("hello world")',
      'src/utils.js': 'module.exports = { add: (a, b) => a + b }',
    });
    const findings = quickScan(tmp);
    expect(findings).toHaveLength(0);
  });
});

// ─── printFindings ────────────────────────────────────────────────────────────

describe('printFindings', () => {
  let consoleSpy;
  beforeEach(() => { consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {}); });
  afterEach(() => consoleSpy.mockRestore());

  test('prints clean message when findings is empty', () => {
    printFindings([]);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('No obvious vulnerability'));
  });

  test('prints finding count for non-empty findings', () => {
    const findings = [{
      severity: 'HIGH', name: 'XSS', file: 'src/app.js', line: 10,
      snippet: 'element.innerHTML = x', inTestFile: false, likelyFalsePositive: false,
    }];
    printFindings(findings);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('1 potential issue'));
  });

  test('separates real findings from likely-false-positive test-file findings', () => {
    const findings = [
      { severity: 'MEDIUM', name: 'Sensitive Log', file: 'src/app.js', line: 5,
        snippet: 'console.log(password)', inTestFile: false, likelyFalsePositive: false },
      { severity: 'MEDIUM', name: 'Sensitive Log', file: '__tests__/auth.test.js', line: 3,
        snippet: 'console.log(password)', inTestFile: true, likelyFalsePositive: true },
    ];
    printFindings(findings);
    const allArgs = consoleSpy.mock.calls.map(c => c[0]).join('\n');
    expect(allArgs).toContain('Likely intentional');
  });

  test('includes severity icons in output', () => {
    const findings = [
      { severity: 'CRITICAL', name: 'SQL Injection', file: 'db.js', line: 1,
        snippet: 'SELECT * FROM ...', inTestFile: false, likelyFalsePositive: false },
    ];
    printFindings(findings);
    const allArgs = consoleSpy.mock.calls.map(c => c[0]).join('\n');
    expect(allArgs).toContain('🔴');
  });
});

// ─── quickScan — new scanner patterns (Red-Green-Refactor) ───────────────────

describe('quickScan — JWT alg:none, timing-unsafe comparison, ReDoS', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  function scanFile(filename, content) {
    tmp = makeTmpProject({ [filename]: content });
    return quickScan(tmp);
  }

  // RED: these tests fail until the 3 new patterns are added to VULN_PATTERNS

  test('detects JWT alg:none — algorithm set to none (broken auth)', () => {
    const findings = scanFile('src/auth.js', "jwt.sign(payload, secret, { algorithm: 'none' })");
    expect(findings.some(f => f.name === 'JWT Alg None')).toBe(true);
  });

  test('detects JWT alg:none — algorithm: "none" double-quote variant', () => {
    const findings = scanFile('src/auth.js', 'jwt.sign(payload, secret, { algorithm: "none" })');
    expect(findings.some(f => f.name === 'JWT Alg None')).toBe(true);
  });

  test('detects timing-unsafe comparison — == on token/password/secret', () => {
    const findings = scanFile('src/auth.js', 'if (req.headers.authorization == storedToken)');
    expect(findings.some(f => f.name === 'Timing-Unsafe Comparison')).toBe(true);
  });

  test('detects timing-unsafe comparison — === comparing req.body value to hash', () => {
    const findings = scanFile('src/login.js', 'if (req.body.password === storedHash) return true;');
    expect(findings.some(f => f.name === 'Timing-Unsafe Comparison')).toBe(true);
  });

  test('detects user-controlled RegExp (ReDoS)', () => {
    const findings = scanFile('src/search.js', 'new RegExp(req.query.pattern).test(input)');
    expect(findings.some(f => f.name === 'ReDoS')).toBe(true);
  });

  test('detects user-controlled RegExp — RegExp from req.body', () => {
    const findings = scanFile('src/filter.js', 'const re = new RegExp(req.body.filter); re.test(data)');
    expect(findings.some(f => f.name === 'ReDoS')).toBe(true);
  });
});

// ─── VULN_PATTERNS — catalogue integrity ─────────────────────────────────────

describe('VULN_PATTERNS', () => {
  test('every pattern has a name, severity, and valid RegExp', () => {
    for (const p of VULN_PATTERNS) {
      expect(typeof p.name).toBe('string');
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).toContain(p.severity);
      expect(p.pattern).toBeInstanceOf(RegExp);
    }
  });

  test('no pattern uses the global flag (which causes stateful .test() bugs)', () => {
    for (const p of VULN_PATTERNS) {
      expect(p.pattern.global).toBe(false);
    }
  });

  test('has at least one CRITICAL, HIGH, and MEDIUM pattern', () => {
    const severities = new Set(VULN_PATTERNS.map(p => p.severity));
    expect(severities.has('CRITICAL')).toBe(true);
    expect(severities.has('HIGH')).toBe(true);
    expect(severities.has('MEDIUM')).toBe(true);
  });
});

// ─── PROMPT_PATTERNS — catalogue integrity ────────────────────────────────────

describe('PROMPT_PATTERNS', () => {
  test('every pattern has a name, severity, and valid RegExp', () => {
    for (const p of PROMPT_PATTERNS) {
      expect(typeof p.name).toBe('string');
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).toContain(p.severity);
      expect(p.pattern).toBeInstanceOf(RegExp);
    }
  });

  test('no pattern uses the global flag', () => {
    for (const p of PROMPT_PATTERNS) {
      expect(p.pattern.global).toBe(false);
    }
  });
});

// ─── isPromptFile ─────────────────────────────────────────────────────────────

describe('isPromptFile', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('returns true for CLAUDE.md at project root', () => {
    tmp = makeTmpProject({ 'CLAUDE.md': '' });
    expect(isPromptFile(path.join(tmp, 'CLAUDE.md'), tmp)).toBe(true);
  });

  test('returns true for SKILL.md at project root', () => {
    tmp = makeTmpProject({ 'SKILL.md': '' });
    expect(isPromptFile(path.join(tmp, 'SKILL.md'), tmp)).toBe(true);
  });

  test('returns true for a file inside prompts/', () => {
    tmp = makeTmpProject({ 'prompts/auto-audit.md': '' });
    expect(isPromptFile(path.join(tmp, 'prompts/auto-audit.md'), tmp)).toBe(true);
  });

  test('returns true for a file inside skills/', () => {
    tmp = makeTmpProject({ 'skills/tdd-remediation/SKILL.md': '' });
    expect(isPromptFile(path.join(tmp, 'skills/tdd-remediation/SKILL.md'), tmp)).toBe(true);
  });

  test('returns true for a file inside .claude/', () => {
    tmp = makeTmpProject({ '.claude/commands/tdd-audit.md': '' });
    expect(isPromptFile(path.join(tmp, '.claude/commands/tdd-audit.md'), tmp)).toBe(true);
  });

  test('returns true for a file inside workflows/', () => {
    tmp = makeTmpProject({ 'workflows/tdd-audit.md': '' });
    expect(isPromptFile(path.join(tmp, 'workflows/tdd-audit.md'), tmp)).toBe(true);
  });

  test('returns false for README.md at project root', () => {
    tmp = makeTmpProject({ 'README.md': '' });
    expect(isPromptFile(path.join(tmp, 'README.md'), tmp)).toBe(false);
  });

  test('returns false for a random .md file in src/', () => {
    tmp = makeTmpProject({ 'src/notes.md': '' });
    expect(isPromptFile(path.join(tmp, 'src/notes.md'), tmp)).toBe(false);
  });
});

// ─── walkMdFiles ──────────────────────────────────────────────────────────────

describe('walkMdFiles', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('yields .md files and skips node_modules', () => {
    tmp = makeTmpProject({
      'CLAUDE.md': '',
      'README.md': '',
      'node_modules/some-pkg/README.md': '',
    });
    const found = [...walkMdFiles(tmp)].map(f => path.relative(tmp, f).replace(/\\/g, '/'));
    expect(found).toContain('CLAUDE.md');
    expect(found).toContain('README.md');
    expect(found.every(f => !f.includes('node_modules'))).toBe(true);
  });

  test('does not yield non-.md files', () => {
    tmp = makeTmpProject({ 'src/app.js': 'console.log(1)', 'CLAUDE.md': '' });
    const found = [...walkMdFiles(tmp)].map(f => path.relative(tmp, f));
    expect(found.every(f => f.endsWith('.md'))).toBe(true);
  });
});

// ─── scanPromptFiles ──────────────────────────────────────────────────────────

describe('scanPromptFiles', () => {
  let tmp;
  afterEach(() => tmp && rmrf(tmp));

  test('returns empty array when no prompt files exist', () => {
    tmp = makeTmpProject({ 'src/app.js': 'console.log(1)' });
    expect(scanPromptFiles(tmp)).toEqual([]);
  });

  test('flags deprecated csurf in a prompt file as CRITICAL', () => {
    tmp = makeTmpProject({
      'prompts/hardening.md': 'npm install csurf\nconst csrf = require("csurf");',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.some(f => f.name === 'Deprecated CSRF Package' && f.severity === 'CRITICAL')).toBe(true);
  });

  test('does NOT flag csurf in a regular source file', () => {
    tmp = makeTmpProject({ 'src/app.js': 'const csurf = require("csurf")' });
    expect(scanPromptFiles(tmp)).toEqual([]);
  });

  test('flags unpinned npx MCP server in CLAUDE.md', () => {
    tmp = makeTmpProject({
      'CLAUDE.md': '{"command": "npx", "args": ["@mcp/server"]}',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.some(f => f.name === 'Unpinned npx MCP Server' && f.severity === 'HIGH')).toBe(true);
  });

  test('flags cleartext URL in a skills/ prompt file', () => {
    tmp = makeTmpProject({
      'skills/my-skill/SKILL.md': 'See http://api.example.com/docs for details',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.some(f => f.name === 'Cleartext URL in Prompt')).toBe(true);
  });

  test('does NOT flag localhost http URLs', () => {
    tmp = makeTmpProject({
      'SKILL.md': 'curl http://localhost:3000/health',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.every(f => f.name !== 'Cleartext URL in Prompt')).toBe(true);
  });

  test('quickScan includes prompt findings', () => {
    tmp = makeTmpProject({
      'prompts/bad.md': 'const csrf = require("csurf")',
    });
    const findings = quickScan(tmp);
    expect(findings.some(f => f.name === 'Deprecated CSRF Package')).toBe(true);
  });

  test('includes file and line number in findings', () => {
    tmp = makeTmpProject({
      'CLAUDE.md': 'line one\nnpm install csurf\nline three',
    });
    const findings = scanPromptFiles(tmp);
    const hit = findings.find(f => f.name === 'Deprecated CSRF Package');
    expect(hit.line).toBe(2);
    expect(hit.file).toMatch(/CLAUDE\.md/);
  });

  // ── False-positive suppression ──────────────────────────────────────────────

  test('does NOT flag csurf when it appears inside backtick code span in a Markdown table row', () => {
    tmp = makeTmpProject({
      'prompts/audit.md': '| `csurf` package reference | CRITICAL | use csrf-csrf instead |',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.every(f => f.name !== 'Deprecated CSRF Package')).toBe(true);
  });

  test('does NOT flag npx when "command": "npx" appears inside backtick code span', () => {
    tmp = makeTmpProject({
      'prompts/audit.md': '| `"command": "npx"` in MCP config | HIGH | unpinned |',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.every(f => f.name !== 'Unpinned npx MCP Server')).toBe(true);
  });

  test('does NOT flag csurf on a // comment line (deprecation warning)', () => {
    tmp = makeTmpProject({
      'prompts/hardening.md': '// Express — csrf-csrf (csurf is deprecated since March 2023)',
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.every(f => f.name !== 'Deprecated CSRF Package')).toBe(true);
  });

  test('does NOT flag cleartext URL for link-local 169.254.x.x addresses (SSRF test payloads)', () => {
    tmp = makeTmpProject({
      'prompts/red-phase.md': ".send({ url: 'http://169.254.169.254/latest/meta-data/' });",
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.every(f => f.name !== 'Cleartext URL in Prompt')).toBe(true);
  });

  test('still flags csurf in actual require() on a non-comment line', () => {
    tmp = makeTmpProject({
      'prompts/hardening.md': "const csrf = require('csurf');",
    });
    const findings = scanPromptFiles(tmp);
    expect(findings.some(f => f.name === 'Deprecated CSRF Package')).toBe(true);
  });

  // ── audit_status: safe frontmatter suppression ───────────────────────────────

  test('skips a prompt file with audit_status: safe in frontmatter', () => {
    tmp = makeTmpProject({
      'prompts/hardening.md': [
        '---',
        'audit_status: safe',
        'audited_by: test',
        '---',
        "const csrf = require('csurf');",
      ].join('\n'),
    });
    expect(scanPromptFiles(tmp)).toEqual([]);
  });

  test('still scans a prompt file with no frontmatter', () => {
    tmp = makeTmpProject({
      'prompts/hardening.md': "const csrf = require('csurf');",
    });
    expect(scanPromptFiles(tmp).some(f => f.name === 'Deprecated CSRF Package')).toBe(true);
  });

  test('still scans a prompt file with audit_status: reviewed (not safe)', () => {
    tmp = makeTmpProject({
      'prompts/hardening.md': [
        '---',
        'audit_status: reviewed',
        '---',
        "const csrf = require('csurf');",
      ].join('\n'),
    });
    expect(scanPromptFiles(tmp).some(f => f.name === 'Deprecated CSRF Package')).toBe(true);
  });

  test('skips CLAUDE.md with audit_status: safe', () => {
    tmp = makeTmpProject({
      'CLAUDE.md': '---\naudit_status: safe\n---\n{"command": "npx", "args": []}',
    });
    expect(scanPromptFiles(tmp)).toEqual([]);
  });
});
