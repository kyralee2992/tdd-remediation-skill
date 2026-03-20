#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

const args = process.argv.slice(2);
const isLocal = args.includes('--local');
const isClaude = args.includes('--claude');
const withHooks = args.includes('--with-hooks');
const skipScan = args.includes('--skip-scan');

const agentBaseDir = isLocal ? process.cwd() : os.homedir();
const agentDirName = isClaude ? '.claude' : '.agents';
const projectDir = process.cwd();

const targetSkillDir = path.join(agentBaseDir, agentDirName, 'skills', 'tdd-remediation');
const targetWorkflowDir = path.join(agentBaseDir, agentDirName, 'workflows');

// ─── 1. Framework Detection ──────────────────────────────────────────────────

function detectFramework() {
  const pkgPath = path.join(projectDir, 'package.json');
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
    fs.existsSync(path.join(projectDir, 'pytest.ini')) ||
    fs.existsSync(path.join(projectDir, 'pyproject.toml')) ||
    fs.existsSync(path.join(projectDir, 'setup.py')) ||
    fs.existsSync(path.join(projectDir, 'requirements.txt'))
  ) return 'pytest';
  if (fs.existsSync(path.join(projectDir, 'go.mod'))) return 'go';
  return 'jest';
}

const framework = detectFramework();

// ─── 2. Test Directory Detection ─────────────────────────────────────────────

function detectTestBaseDir() {
  // Respect an existing convention before inventing one
  const candidates = ['__tests__', 'tests', 'test', 'spec'];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(projectDir, dir))) return dir;
  }
  // Framework-informed defaults when no directory exists yet
  if (framework === 'pytest') return 'tests';
  if (framework === 'go') return 'test';
  return '__tests__';
}

const testBaseDir = detectTestBaseDir();
const targetTestDir = path.join(projectDir, testBaseDir, 'security');

// ─── 3. Quick Scan ───────────────────────────────────────────────────────────

const VULN_PATTERNS = [
  { name: 'SQL Injection',     severity: 'CRITICAL', pattern: /(`SELECT[^`]*\$\{|"SELECT[^"]*"\s*\+|execute\(f"|cursor\.execute\(.*%s|\.query\(`[^`]*\$\{)/i },
  { name: 'Command Injection', severity: 'CRITICAL', pattern: /\bexec(Sync)?\s*\(.*req\.(params|body|query)|subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True/i },
  { name: 'IDOR',              severity: 'HIGH',     pattern: /findById\s*\(\s*req\.(params|body|query)\.|findOne\s*\(\s*\{[^}]*id\s*:\s*req\.(params|body|query)/i },
  { name: 'XSS',               severity: 'HIGH',     pattern: /[^/]innerHTML\s*=(?!=)|dangerouslySetInnerHTML\s*=\s*\{\{|document\.write\s*\(|res\.send\s*\(`[^`]*\$\{req\./i },
  { name: 'Path Traversal',    severity: 'HIGH',     pattern: /(readFile|sendFile|createReadStream|open)\s*\(.*req\.(params|body|query)|path\.join\s*\([^)]*req\.(params|body|query)/i },
  { name: 'Broken Auth',       severity: 'HIGH',     pattern: /jwt\.decode\s*\((?![^;]*\.verify)|verify\s*:\s*false|secret\s*=\s*['"][a-z0-9]{1,20}['"]/i },
];

const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.go']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', '__pycache__', 'venv', '.venv', 'vendor']);

function* walkFiles(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walkFiles(fullPath);
    else if (SCAN_EXTENSIONS.has(path.extname(entry.name))) yield fullPath;
  }
}

function quickScan() {
  const findings = [];
  for (const filePath of walkFiles(projectDir)) {
    let lines;
    try { lines = fs.readFileSync(filePath, 'utf8').split('\n'); } catch { continue; }
    for (let i = 0; i < lines.length; i++) {
      for (const vuln of VULN_PATTERNS) {
        if (vuln.pattern.test(lines[i])) {
          findings.push({
            severity: vuln.severity,
            name: vuln.name,
            file: path.relative(projectDir, filePath),
            line: i + 1,
            snippet: lines[i].trim().slice(0, 80),
          });
          break; // one finding per line
        }
      }
    }
  }
  return findings;
}

function printFindings(findings) {
  if (findings.length === 0) {
    console.log('   ✅ No obvious vulnerability patterns detected.\n');
    return;
  }
  const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  for (const f of findings) (bySeverity[f.severity] || bySeverity.LOW).push(f);
  const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };

  console.log(`\n   Found ${findings.length} potential issue(s):\n`);
  for (const [sev, list] of Object.entries(bySeverity)) {
    if (!list.length) continue;
    for (const f of list) {
      console.log(`   ${icons[sev]} [${sev}] ${f.name} — ${f.file}:${f.line}`);
      console.log(`         ${f.snippet}`);
    }
  }
  console.log('\n   Run /tdd-audit in your agent to remediate.\n');
}

// ─── 4. Install Skill Files ───────────────────────────────────────────────────

console.log(`\nInstalling TDD Remediation Skill (${isLocal ? 'local' : 'global'}, framework: ${framework}, test dir: ${testBaseDir}/)...\n`);

if (!fs.existsSync(targetSkillDir)) fs.mkdirSync(targetSkillDir, { recursive: true });

for (const item of ['SKILL.md', 'prompts', 'templates']) {
  const src = path.join(__dirname, item);
  const dest = path.join(targetSkillDir, item);
  if (fs.existsSync(src)) fs.cpSync(src, dest, { recursive: true });
}

// ─── 5. Scaffold Security Test Boilerplate ────────────────────────────────────

if (!fs.existsSync(targetTestDir)) {
  fs.mkdirSync(targetTestDir, { recursive: true });
  console.log(`✅ Created ${path.relative(projectDir, targetTestDir)}/`);
}

const testTemplateMap = {
  jest:   'sample.exploit.test.js',
  vitest: 'sample.exploit.test.vitest.js',
  mocha:  'sample.exploit.test.js',
  pytest: 'sample.exploit.test.pytest.py',
  go:     'sample.exploit.test.go',
};

const testTemplateName = testTemplateMap[framework];
const srcTest = path.join(__dirname, 'templates', testTemplateName);
const destTest = path.join(targetTestDir, testTemplateName);

if (!fs.existsSync(destTest) && fs.existsSync(srcTest)) {
  fs.copyFileSync(srcTest, destTest);
  console.log(`✅ Scaffolded ${path.relative(projectDir, destTest)}`);
}

// ─── 6. Install Workflow Shortcode ────────────────────────────────────────────

if (!fs.existsSync(targetWorkflowDir)) fs.mkdirSync(targetWorkflowDir, { recursive: true });
const srcWorkflow = path.join(__dirname, 'workflows', 'tdd-audit.md');
const destWorkflow = path.join(targetWorkflowDir, 'tdd-audit.md');
if (fs.existsSync(srcWorkflow)) {
  fs.copyFileSync(srcWorkflow, destWorkflow);
  console.log(`✅ Installed /tdd-audit workflow shortcode`);
}

// ─── 7. Inject test:security into package.json ────────────────────────────────

const pkgPath = path.join(projectDir, 'package.json');
if (framework !== 'pytest' && framework !== 'go' && fs.existsSync(pkgPath)) {
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    if (!pkg.scripts?.['test:security']) {
      pkg.scripts = pkg.scripts || {};
      const secDir = `${testBaseDir}/security`;
      pkg.scripts['test:security'] = {
        jest:   `jest --testPathPattern=${secDir} --forceExit`,
        vitest: `vitest run ${secDir}`,
        mocha:  `mocha '${secDir}/**/*.spec.js'`,
      }[framework] || `jest --testPathPattern=${secDir} --forceExit`;
      fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
      console.log(`✅ Added "test:security" script to package.json`);
    } else {
      console.log(`   "test:security" already in package.json — skipped`);
    }
  } catch (e) {
    console.warn(`   ⚠️  Could not update package.json: ${e.message}`);
  }
}

// ─── 8. Scaffold CI Workflow ─────────────────────────────────────────────────

const ciWorkflowDir = path.join(projectDir, '.github', 'workflows');
const ciWorkflowPath = path.join(ciWorkflowDir, 'security-tests.yml');

if (!fs.existsSync(ciWorkflowPath)) {
  const ciTemplateMap = {
    jest:   'security-tests.node.yml',
    vitest: 'security-tests.node.yml',
    mocha:  'security-tests.node.yml',
    pytest: 'security-tests.python.yml',
    go:     'security-tests.go.yml',
  };
  const ciTemplatePath = path.join(__dirname, 'templates', 'workflows', ciTemplateMap[framework]);
  if (fs.existsSync(ciTemplatePath)) {
    fs.mkdirSync(ciWorkflowDir, { recursive: true });
    fs.copyFileSync(ciTemplatePath, ciWorkflowPath);
    console.log(`✅ Scaffolded .github/workflows/security-tests.yml`);
  }
} else {
  console.log(`   .github/workflows/security-tests.yml already exists — skipped`);
}

// ─── 9. Pre-commit Hook (opt-in) ─────────────────────────────────────────────

if (withHooks) {
  const gitDir = path.join(projectDir, '.git');
  if (fs.existsSync(gitDir)) {
    const hooksDir = path.join(gitDir, 'hooks');
    if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir);
    const hookPath = path.join(hooksDir, 'pre-commit');

    const testCmd = {
      pytest: 'pytest tests/security/ -q',
      go:     'go test ./security/... -v',
    }[framework] || 'npm run test:security --silent';

    const injection = [
      '# tdd-remediation: security gate',
      testCmd,
      'if [ $? -ne 0 ]; then',
      '  printf "\\n\\033[0;31m❌ Security tests failed. Commit blocked.\\033[0m\\n"',
      '  exit 1',
      'fi',
      '',
    ].join('\n');

    const existing = fs.existsSync(hookPath) ? fs.readFileSync(hookPath, 'utf8') : '#!/bin/sh\n';
    if (existing.includes('tdd-remediation')) {
      console.log(`   Pre-commit hook already has security gate — skipped`);
    } else {
      const newContent = existing.trimEnd() + '\n\n' + injection;
      fs.writeFileSync(hookPath, newContent);
      fs.chmodSync(hookPath, '755');
      console.log(`✅ Installed pre-commit hook (.git/hooks/pre-commit)`);
    }
  } else {
    console.warn(`   ⚠️  No .git directory found — skipping pre-commit hook`);
  }
}

// ─── 10. Quick Scan ──────────────────────────────────────────────────────────

if (!skipScan) {
  process.stdout.write('\n🔍 Scanning for vulnerability patterns...');
  const findings = quickScan();
  process.stdout.write('\n');
  printFindings(findings);
}

console.log(`\nSkill installed to ${path.relative(os.homedir(), targetSkillDir)}`);
console.log('Run /tdd-audit in your agent to begin remediation.\n');
