'use strict';

const fs = require('fs');
const path = require('path');

// ─── Vulnerability Patterns ───────────────────────────────────────────────────

const VULN_PATTERNS = [
  { name: 'SQL Injection',     severity: 'CRITICAL', pattern: /(`SELECT[^`]*\$\{|"SELECT[^"]*"\s*\+|execute\(f"|cursor\.execute\(.*%s|\.query\(`[^`]*\$\{)/i },
  { name: 'Command Injection', severity: 'CRITICAL', pattern: /\bexec(Sync)?\s*\(.*req\.(params|body|query)|subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True/i },
  { name: 'IDOR',              severity: 'HIGH',     pattern: /findById\s*\(\s*req\.(params|body|query)\.|findOne\s*\(\s*\{[^}]*id\s*:\s*req\.(params|body|query)/i },
  { name: 'XSS',               severity: 'HIGH',     pattern: /[^/]innerHTML\s*=(?!=)|dangerouslySetInnerHTML\s*=\s*\{\{|document\.write\s*\(|res\.send\s*\(`[^`]*\$\{req\./i },
  { name: 'Path Traversal',    severity: 'HIGH',     pattern: /(readFile|sendFile|createReadStream|open)\s*\(.*req\.(params|body|query)|path\.join\s*\([^)]*req\.(params|body|query)/i },
  { name: 'Broken Auth',       severity: 'HIGH',     pattern: /jwt\.decode\s*\((?![^;]*\.verify)|verify\s*:\s*false|secret\s*=\s*['"][a-z0-9]{1,20}['"]/i },
  // Vibecoding / mobile stacks
  { name: 'Sensitive Storage', severity: 'HIGH',     pattern: /(localStorage|AsyncStorage)\.setItem\s*\(\s*['"](token|password|secret|auth|jwt|api.?key)['"]/i },
  { name: 'TLS Bypass',        severity: 'CRITICAL', pattern: /badCertificateCallback[^;]*=\s*true|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i },
  { name: 'Hardcoded Secret',  severity: 'CRITICAL', skipInTests: true,  pattern: /(?:const|final|var|let|static)\s+(?:API_KEY|PRIVATE_KEY|SECRET_KEY|ACCESS_TOKEN|CLIENT_SECRET)\s*=\s*['"][A-Za-z0-9+/=_\-]{20,}['"]/i },
  { name: 'eval() Injection',  severity: 'HIGH',     pattern: /\beval\s*\([^)]*(?:route\.params|searchParams\.get|req\.(query|body)|params\[)/i },
  // Common vibecoding anti-patterns
  { name: 'Insecure Random',   severity: 'HIGH',     pattern: /(?:token|sessionId|nonce|secret|csrf)\w*\s*=.*Math\.random\(\)|Math\.random\(\).*(?:token|session|nonce|secret)/i },
  { name: 'Sensitive Log',     severity: 'MEDIUM',   skipInTests: true,  pattern: /console\.(log|info|debug)\([^)]*(?:token|password|secret|jwt|authorization|apiKey|api_key)/i },
  { name: 'Secret Fallback',   severity: 'HIGH',     pattern: /process\.env\.\w+\s*\|\|\s*['"][A-Za-z0-9+/=_\-]{10,}['"]/i },
  // SSRF, redirects, injection
  { name: 'SSRF',                    severity: 'CRITICAL', pattern: /\b(?:fetch|axios\.(?:get|post|put|patch|delete|request)|got|https?\.get)\s*\(\s*req\.(?:query|body|params)\./i },
  { name: 'Open Redirect',           severity: 'HIGH',     pattern: /res\.redirect\s*\(\s*req\.(?:query|body|params)\.|window\.location(?:\.href)?\s*=\s*(?:params\.|route\.params\.|searchParams\.get)/i },
  { name: 'NoSQL Injection',         severity: 'HIGH',     pattern: /\.(?:find|findOne|findById|updateOne|deleteOne)\s*\(\s*req\.(?:body|query|params)\b|\$where\s*:\s*['"`]/i },
  { name: 'Template Injection',      severity: 'HIGH',     pattern: /res\.render\s*\(\s*req\.(?:params|body|query)\.|(?:ejs|pug|nunjucks|handlebars)\.render(?:File)?\s*\([^)]*req\.(?:body|params|query)/i },
  { name: 'Insecure Deserialization',severity: 'CRITICAL', pattern: /\.unserialize\s*\(.*req\.|__proto__\s*[=:][^=]|Object\.setPrototypeOf\s*\([^,]+,\s*req\./i },
  // Assignment / pollution
  { name: 'Mass Assignment',         severity: 'HIGH',     pattern: /new\s+\w+\s*\(\s*req\.body\b|\.create\s*\(\s*req\.body\b|\.update(?:One)?\s*\(\s*\{[^}]*\},\s*req\.body\b/i },
  { name: 'Prototype Pollution',     severity: 'HIGH',     pattern: /(?:_\.merge|lodash\.merge|deepmerge|hoek\.merge)\s*\([^)]*req\.(?:body|query|params)/i },
  // Crypto / config
  { name: 'Weak Crypto',             severity: 'HIGH',     pattern: /createHash\s*\(\s*['"](?:md5|sha1)['"]\)|(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd|secret)/i },
  { name: 'CORS Wildcard',           severity: 'MEDIUM',   pattern: /cors\s*\(\s*\{\s*origin\s*:\s*['"]?\*['"]?|['"]Access-Control-Allow-Origin['"]\s*,\s*['"]?\*/i },
  { name: 'Cleartext Traffic',       severity: 'MEDIUM',   skipInTests: true, pattern: /(?:baseURL|apiUrl|API_URL|endpoint|baseUrl)\s*[:=]\s*['"]http:\/\/(?!localhost|127\.0\.0\.1)/i },
  { name: 'XXE',                     severity: 'HIGH',     pattern: /noent\s*:\s*true|expand_entities\s*=\s*True|resolve_entities\s*=\s*True/i },
  // Mobile / WebView
  { name: 'WebView JS Bridge',       severity: 'HIGH',     pattern: /addJavascriptInterface\s*\(|javaScriptEnabled\s*:\s*true|allowFileAccess\s*:\s*true|allowUniversalAccessFromFileURLs\s*:\s*true/i },
  { name: 'Deep Link Injection',     severity: 'MEDIUM',   pattern: /Linking\.getInitialURL\s*\(\)|Linking\.addEventListener\s*\(\s*['"]url['"]/i },
  // JWT / crypto / ReDoS
  { name: 'JWT Alg None',            severity: 'CRITICAL', pattern: /algorithm\s*:\s*['"]none['"]/i },
  { name: 'Timing-Unsafe Comparison',severity: 'HIGH',     pattern: /\b(?:token|password|secret|hash|digest|hmac|signature|api.?key)\w*\s*={2,3}\s*\w|(?:req\.(?:headers?|body|query|params)\.\w+)\s*={2,3}/i },
  { name: 'ReDoS',                   severity: 'HIGH',     pattern: /new\s+RegExp\s*\(\s*req\.(?:query|body|params)\./i },
];

const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.go', '.dart']);

/** Maximum file size to read before skipping (512 KB). Prevents OOM on large generated files. */
const MAX_SCAN_FILE_BYTES = 512 * 1024;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', '__pycache__', 'venv', '.venv', 'vendor', '.expo', '.dart_tool', '.pub-cache']);

// ─── Prompt / Skill Patterns ──────────────────────────────────────────────────

const PROMPT_PATTERNS = [
  { name: 'Deprecated CSRF Package',  severity: 'CRITICAL', pattern: /\bcsurf\b/,               skipCommentLine: true },
  { name: 'Unpinned npx MCP Server',  severity: 'HIGH',     pattern: /"command"\s*:\s*"npx"/ },
  { name: 'Cleartext URL in Prompt',  severity: 'MEDIUM',   pattern: /\bhttp:\/\/(?!localhost|127\.0\.0\.1|169\.254\.)[a-zA-Z0-9]/ },
];

const PROMPT_FILE_NAMES = new Set(['CLAUDE.md', 'SKILL.md', '.cursorrules', '.clinerules']);
const PROMPT_DIRS = new Set(['prompts', 'skills', '.claude', 'workflows']);

// ─── Framework Detection ──────────────────────────────────────────────────────

/**
 * Detect the test framework used in the given project directory.
 * @param {string} dir - absolute path to the project root
 * @returns {'flutter'|'vitest'|'jest'|'mocha'|'pytest'|'go'}
 */
function detectFramework(dir) {
  // Flutter / Dart — check before package.json since a Flutter project may have both
  if (fs.existsSync(path.join(dir, 'pubspec.yaml'))) return 'flutter';

  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      if (deps.vitest) return 'vitest';
      if (deps.jest || deps.supertest) return 'jest';
      if (deps.mocha) return 'mocha';
    } catch {}
  }
  if (
    fs.existsSync(path.join(dir, 'pytest.ini')) ||
    fs.existsSync(path.join(dir, 'pyproject.toml')) ||
    fs.existsSync(path.join(dir, 'setup.py')) ||
    fs.existsSync(path.join(dir, 'requirements.txt'))
  ) return 'pytest';
  if (fs.existsSync(path.join(dir, 'go.mod'))) return 'go';
  return 'jest';
}

/**
 * Detect the UI/app framework used in the given project directory.
 * @param {string} dir - absolute path to the project root
 * @returns {'flutter'|'expo'|'react-native'|'nextjs'|'react'|null}
 */
function detectAppFramework(dir) {
  if (fs.existsSync(path.join(dir, 'pubspec.yaml'))) return 'flutter';
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      if (deps.expo) return 'expo';
      if (deps['react-native']) return 'react-native';
      if (deps.next) return 'nextjs';
      if (deps.react) return 'react';
    } catch {}
  }
  return null;
}

// ─── Test Directory Detection ─────────────────────────────────────────────────

/**
 * Detect the test base directory convention used in the given project.
 * @param {string} dir - absolute path to the project root
 * @param {string} framework - test framework (from detectFramework)
 * @returns {string} - relative directory name, e.g. '__tests__'
 */
function detectTestBaseDir(dir, framework) {
  const candidates = ['__tests__', 'tests', 'test', 'spec'];
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(dir, candidate))) return candidate;
  }
  if (framework === 'pytest') return 'tests';
  if (framework === 'go') return 'test';
  return '__tests__';
}

// ─── File Walking ─────────────────────────────────────────────────────────────

/**
 * Generator that yields all scannable file paths under dir, skipping
 * known noise dirs and symlinks (to avoid escaping the project root).
 * @param {string} dir - directory to walk
 */
function* walkFiles(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    // Skip symlinks — they can escape the project root (M2 fix)
    if (entry.isSymbolicLink()) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walkFiles(fullPath);
    else if (SCAN_EXTENSIONS.has(path.extname(entry.name))) yield fullPath;
  }
}

// ─── Test-file detection ──────────────────────────────────────────────────────

/**
 * Returns true if the file is a test/spec file.
 * @param {string} filePath - absolute path
 * @param {string} projectDir - absolute project root (used for relative path calc)
 */
function isTestFile(filePath, projectDir) {
  const rel = path.relative(projectDir, filePath).replace(/\\/g, '/');
  return (
    /[._-]test\.[a-z]+$/.test(rel) ||      // *.test.js / *.test.ts
    /[._-]spec\.[a-z]+$/.test(rel) ||      // *.spec.js / *.spec.ts
    /_test\.dart$/.test(rel) ||            // *_test.dart (Flutter)
    /(^|\/)(__tests__|tests?)\//.test(rel) || // __tests__/ or tests/ at any depth
    /(^|\/)spec\//.test(rel) ||            // spec/ at any depth
    /(^|\/)test_/.test(rel)               // test_helpers.js style
  );
}

// ─── Prompt File Detection ────────────────────────────────────────────────────

/**
 * Returns true if the file is a prompt/skill file that should be scanned for
 * prompt-specific vulnerabilities (e.g. deprecated packages, injection risks).
 * @param {string} filePath - absolute path
 * @param {string} projectDir - absolute project root
 */
function isPromptFile(filePath, projectDir) {
  const basename = path.basename(filePath);
  if (PROMPT_FILE_NAMES.has(basename)) return true;
  const rel = path.relative(projectDir, filePath).replace(/\\/g, '/');
  const firstSegment = rel.split('/')[0];
  return PROMPT_DIRS.has(firstSegment);
}

/**
 * Generator that yields all .md file paths under dir, skipping SKIP_DIRS.
 * @param {string} dir - directory to walk
 */
function* walkMdFiles(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.isSymbolicLink()) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walkMdFiles(fullPath);
    else if (path.extname(entry.name) === '.md') yield fullPath;
  }
}

/**
 * Returns true if the file's YAML frontmatter contains audit_status: safe.
 * Allows prompt owners to mark a reviewed file as exempt from scanner noise.
 * @param {string[]} lines - file content split by newline
 */
function hasSafeAuditStatus(lines) {
  if (!lines.length || lines[0].trim() !== '---') return false;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === '---') break;
    if (/^audit_status\s*:\s*['"]?safe['"]?/.test(lines[i].trim())) return true;
  }
  return false;
}

/**
 * Returns true if the match at matchIndex falls inside a *closed* backtick
 * code span on the same line.  A code span is closed only when there is an
 * odd number of backticks before the match AND at least one closing backtick
 * after it on the same line.  A lone, unmatched backtick before the pattern
 * does NOT constitute a code span and must NOT suppress the finding.
 * @param {string} line
 * @param {number} matchIndex - character index of the match start
 */
function isInsideBackticks(line, matchIndex) {
  const before = line.slice(0, matchIndex);
  const after  = line.slice(matchIndex);
  const backticksBefore = (before.match(/`/g) || []).length;
  const backticksAfter  = (after.match(/`/g)  || []).length;
  // Suppress only when the span is properly closed: odd opening count + at
  // least one closing backtick exists after the match position.
  return backticksBefore % 2 === 1 && backticksAfter >= 1;
}

/**
 * Returns true if the line is a code comment (starts with // or #).
 * @param {string} line
 */
function isCommentLine(line) {
  return /^\s*(\/\/|#)/.test(line);
}

/**
 * Scan all prompt/skill .md files in projectDir for prompt-specific patterns.
 *
 * Returns a findings array with a non-enumerable `.exempted` property — an
 * array of relative paths for files skipped via `audit_status: safe`.  Using
 * a non-enumerable property preserves full backward compatibility: spread,
 * toEqual([]), and quickScan's `...scanPromptFiles()` all continue to work.
 *
 * @param {string} projectDir - project root
 * @returns {Array} findings  (with non-enumerable .exempted: string[])
 */
function scanPromptFiles(projectDir) {
  const findings = [];
  const exempted = [];
  for (const filePath of walkMdFiles(projectDir)) {
    if (!isPromptFile(filePath, projectDir)) continue;
    let lines;
    try {
      // Skip files larger than MAX_SCAN_FILE_BYTES to prevent OOM on large files.
      if (fs.statSync(filePath).size > MAX_SCAN_FILE_BYTES) continue;
      const content = fs.readFileSync(filePath, 'utf8');
      if (content.includes('\0')) continue; // skip binary files (mirrors quickScan guard)
      lines = content.split('\n');
    } catch { continue; }
    if (hasSafeAuditStatus(lines)) {
      exempted.push(path.relative(projectDir, filePath));
      continue;
    }
    for (let i = 0; i < lines.length; i++) {
      for (const p of PROMPT_PATTERNS) {
        const match = p.pattern.exec(lines[i]);
        if (!match) continue;
        if (isInsideBackticks(lines[i], match.index)) continue;
        if (p.skipCommentLine && isCommentLine(lines[i])) continue;
        findings.push({
          severity: p.severity,
          name: p.name,
          file: path.relative(projectDir, filePath),
          line: i + 1,
          snippet: lines[i].trim().slice(0, 80),
          inTestFile: false,
          likelyFalsePositive: false,
        });
      }
    }
  }
  // Attach exempted as non-enumerable so spread / toEqual([]) are unaffected.
  Object.defineProperty(findings, 'exempted', { value: exempted, enumerable: false, configurable: true });
  return findings;
}

// ─── Config / Manifest Scanners ───────────────────────────────────────────────

/**
 * Scan app.json / app.config.* for embedded secrets.
 * @param {string} projectDir - project root
 * @returns {Array}
 */
function scanAppConfig(projectDir) {
  const findings = [];
  const configCandidates = ['app.json', 'app.config.js', 'app.config.ts'];
  // Match quoted string values AND template-literal fallback secrets (L2 fix)
  const secretPattern = /['"]?(?:apiKey|api_key|secret|privateKey|accessToken|clientSecret)['"]?\s*[:=]\s*(?:['"][A-Za-z0-9+/=_\-]{20,}['"]|`[^`]*['"][A-Za-z0-9+/=_\-]{10,}['"][^`]*`)/i;

  for (const name of configCandidates) {
    const filePath = path.join(projectDir, name);
    if (!fs.existsSync(filePath)) continue;
    let lines;
    try { lines = fs.readFileSync(filePath, 'utf8').split('\n'); } catch { continue; }
    for (let i = 0; i < lines.length; i++) {
      if (secretPattern.test(lines[i])) {
        findings.push({
          severity: 'CRITICAL',
          name: 'Config Secret',
          file: name,
          line: i + 1,
          snippet: lines[i].trim().slice(0, 80),
          inTestFile: false,
        });
      }
    }
  }
  return findings;
}

/**
 * Scan AndroidManifest.xml for android:debuggable="true".
 * @param {string} projectDir - project root
 * @returns {Array}
 */
function scanAndroidManifest(projectDir) {
  const findings = [];
  const manifestPath = path.join(projectDir, 'android', 'app', 'src', 'main', 'AndroidManifest.xml');
  if (!fs.existsSync(manifestPath)) return findings;
  let lines;
  try { lines = fs.readFileSync(manifestPath, 'utf8').split('\n'); } catch { return findings; }
  for (let i = 0; i < lines.length; i++) {
    if (/android:debuggable\s*=\s*["']true["']/i.test(lines[i])) {
      findings.push({
        severity: 'HIGH',
        name: 'Android Debuggable',
        file: 'android/app/src/main/AndroidManifest.xml',
        line: i + 1,
        snippet: lines[i].trim().slice(0, 80),
        inTestFile: false,
        likelyFalsePositive: false,
      });
    }
  }
  return findings;
}

// ─── Quick Scan ───────────────────────────────────────────────────────────────

/**
 * Scan all source files in projectDir for known vulnerability patterns.
 * @param {string} projectDir - project root to scan
 * @returns {Array} findings
 */
function quickScan(projectDir) {
  const findings = [];
  for (const filePath of walkFiles(projectDir)) {
    const inTest = isTestFile(filePath, projectDir);
    let content;
    // L1 fix: guard against binary / non-UTF-8 files
    try {
      // Skip files larger than MAX_SCAN_FILE_BYTES to prevent OOM on large bundles.
      if (fs.statSync(filePath).size > MAX_SCAN_FILE_BYTES) continue;
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    // Skip files that contain null bytes — likely binary
    if (content.includes('\0')) continue;

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      // M3 fix: collect ALL matching patterns per line (no break)
      for (const vuln of VULN_PATTERNS) {
        if (vuln.pattern.test(lines[i])) {
          findings.push({
            severity: vuln.severity,
            name: vuln.name,
            file: path.relative(projectDir, filePath),
            line: i + 1,
            snippet: lines[i].trim().slice(0, 80),
            inTestFile: inTest,
            likelyFalsePositive: inTest && !!vuln.skipInTests,
          });
        }
      }
    }
  }
  return [...findings, ...scanAppConfig(projectDir), ...scanAndroidManifest(projectDir), ...scanPromptFiles(projectDir)];
}

// ─── Print Findings ───────────────────────────────────────────────────────────

/**
 * Print a human-readable findings report to stdout.
 * @param {Array}    findings - array of finding objects
 * @param {string[]} [exempted=[]] - relative paths of files skipped via audit_status:safe
 */
function printFindings(findings, exempted = []) {
  if (findings.length === 0) {
    console.log('   ✅ No obvious vulnerability patterns detected.\n');
  } else {
    const real = findings.filter(f => !f.likelyFalsePositive);
    const noisy = findings.filter(f => f.likelyFalsePositive);

    const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    for (const f of real) (bySeverity[f.severity] || bySeverity.LOW).push(f);
    const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };

    console.log(`\n   Found ${real.length} potential issue(s)${noisy.length ? ` (+${noisy.length} in test files — see below)` : ''}:\n`);
    for (const [sev, list] of Object.entries(bySeverity)) {
      if (!list.length) continue;
      for (const f of list) {
        const testBadge = f.inTestFile ? ' [test file]' : '';
        console.log(`   ${icons[sev]} [${sev}] ${f.name} — ${f.file}:${f.line}${testBadge}`);
        console.log(`         ${f.snippet}`);
      }
    }

    if (noisy.length) {
      console.log('\n   ⚪ Likely intentional (in test files — verify manually):');
      for (const f of noisy) {
        console.log(`      ${f.name} — ${f.file}:${f.line}`);
      }
    }

    console.log('\n   Run /tdd-audit in your agent to remediate.\n');
  }

  if (exempted.length) {
    console.log('   ⚠️  Files skipped via audit_status:safe (verify these exemptions are intentional):');
    for (const p of exempted) {
      console.log(`      ${p}`);
    }
    console.log('');
  }
}

module.exports = {
  VULN_PATTERNS,
  PROMPT_PATTERNS,
  SCAN_EXTENSIONS,
  SKIP_DIRS,
  MAX_SCAN_FILE_BYTES,
  detectFramework,
  detectAppFramework,
  detectTestBaseDir,
  walkFiles,
  walkMdFiles,
  isTestFile,
  isPromptFile,
  hasSafeAuditStatus,
  scanAppConfig,
  scanAndroidManifest,
  scanPromptFiles,
  quickScan,
  printFindings,
};
