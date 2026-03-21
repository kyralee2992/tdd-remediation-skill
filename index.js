#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

const {
  detectFramework,
  detectAppFramework,
  detectTestBaseDir,
  quickScan,
  printFindings,
} = require('./lib/scanner');

const args = process.argv.slice(2);
const isLocal = args.includes('--local');
const isClaude = args.includes('--claude');
const withHooks = args.includes('--with-hooks');
const skipScan = args.includes('--skip-scan');
const scanOnly = args.includes('--scan-only');

const agentBaseDir = isLocal ? process.cwd() : os.homedir();
const agentDirName = isClaude ? '.claude' : '.agents';
const projectDir = process.cwd();

const targetSkillDir = path.join(agentBaseDir, agentDirName, 'skills', 'tdd-remediation');
const targetWorkflowDir = isClaude
  ? path.join(agentBaseDir, agentDirName, 'commands')
  : path.join(agentBaseDir, agentDirName, 'workflows');

const appFramework = detectAppFramework(projectDir);
const framework = detectFramework(projectDir);
const testBaseDir = detectTestBaseDir(projectDir, framework);
const targetTestDir = path.join(projectDir, testBaseDir, 'security');

// ─── Scan-only early exit ─────────────────────────────────────────────────────

if (scanOnly) {
  process.stdout.write('\n🔍 Scanning for vulnerability patterns...');
  const findings = quickScan(projectDir);
  process.stdout.write('\n');
  printFindings(findings);
  process.exit(0);
}

// ─── Install Skill Files ──────────────────────────────────────────────────────

const appLabel = appFramework ? `, app: ${appFramework}` : '';
console.log(`\nInstalling TDD Remediation Skill (${isLocal ? 'local' : 'global'}, framework: ${framework}${appLabel}, test dir: ${testBaseDir}/)...\n`);

if (!fs.existsSync(targetSkillDir)) fs.mkdirSync(targetSkillDir, { recursive: true });

for (const item of ['SKILL.md', 'prompts', 'templates']) {
  const src = path.join(__dirname, item);
  const dest = path.join(targetSkillDir, item);
  if (fs.existsSync(src)) fs.cpSync(src, dest, { recursive: true });
}

// ─── Scaffold Security Test Boilerplate ───────────────────────────────────────

if (!fs.existsSync(targetTestDir)) {
  fs.mkdirSync(targetTestDir, { recursive: true });
  console.log(`✅ Created ${path.relative(projectDir, targetTestDir)}/`);
}

const testTemplateMap = {
  jest:    'sample.exploit.test.js',
  vitest:  'sample.exploit.test.vitest.js',
  mocha:   'sample.exploit.test.js',
  pytest:  'sample.exploit.test.pytest.py',
  go:      'sample.exploit.test.go',
  flutter: 'sample.exploit.test.dart',
};

const testTemplateName = testTemplateMap[framework];
const srcTest = path.join(__dirname, 'templates', testTemplateName);
const destTest = path.join(targetTestDir, testTemplateName);

if (!fs.existsSync(destTest) && fs.existsSync(srcTest)) {
  fs.copyFileSync(srcTest, destTest);
  console.log(`✅ Scaffolded ${path.relative(projectDir, destTest)}`);
}

// ─── Install Workflow Shortcode ───────────────────────────────────────────────

if (!fs.existsSync(targetWorkflowDir)) fs.mkdirSync(targetWorkflowDir, { recursive: true });
const srcWorkflow = path.join(__dirname, 'workflows', 'tdd-audit.md');
const destWorkflow = path.join(targetWorkflowDir, 'tdd-audit.md');
if (fs.existsSync(srcWorkflow)) {
  fs.copyFileSync(srcWorkflow, destWorkflow);
  console.log(`✅ Installed /tdd-audit workflow shortcode`);
}

// ─── Inject test:security into package.json ───────────────────────────────────

const pkgPath = path.join(projectDir, 'package.json');
if (framework !== 'pytest' && framework !== 'go' && fs.existsSync(pkgPath)) {
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    if (!pkg.scripts?.['test:security']) {
      pkg.scripts = pkg.scripts || {};
      const secDir = `${testBaseDir}/security`;
      pkg.scripts['test:security'] = {
        jest:   `jest --testPathPatterns=${secDir} --forceExit`,
        vitest: `vitest run ${secDir}`,
        mocha:  `mocha '${secDir}/**/*.spec.js'`,
      }[framework] || `jest --testPathPatterns=${secDir} --forceExit`;
      fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
      console.log(`✅ Added "test:security" script to package.json`);
    } else {
      console.log(`   "test:security" already in package.json — skipped`);
    }
  } catch (e) {
    console.warn(`   ⚠️  Could not update package.json: ${e.message}`);
  }
}

// ─── Scaffold CI Workflows ────────────────────────────────────────────────────

const ciWorkflowDir = path.join(projectDir, '.github', 'workflows');
fs.mkdirSync(ciWorkflowDir, { recursive: true });

const ciWorkflows = [
  {
    destName: 'security-tests.yml',
    templateMap: {
      jest: 'security-tests.node.yml', vitest: 'security-tests.node.yml',
      mocha: 'security-tests.node.yml', pytest: 'security-tests.python.yml',
      go: 'security-tests.go.yml', flutter: 'security-tests.flutter.yml',
    },
  },
  {
    destName: 'ci.yml',
    templateMap: {
      jest: 'ci.node.yml', vitest: 'ci.node.yml', mocha: 'ci.node.yml',
      pytest: 'ci.python.yml', go: 'ci.go.yml', flutter: 'ci.flutter.yml',
    },
  },
];

for (const { destName, templateMap } of ciWorkflows) {
  const destPath = path.join(ciWorkflowDir, destName);
  if (!fs.existsSync(destPath)) {
    const srcPath = path.join(__dirname, 'templates', 'workflows', templateMap[framework]);
    if (fs.existsSync(srcPath)) {
      fs.copyFileSync(srcPath, destPath);
      console.log(`✅ Scaffolded .github/workflows/${destName}`);
    }
  } else {
    console.log(`   .github/workflows/${destName} already exists — skipped`);
  }
}

// ─── Pre-commit Hook (opt-in) ─────────────────────────────────────────────────

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

// ─── Quick Scan ───────────────────────────────────────────────────────────────

if (!skipScan) {
  process.stdout.write('\n🔍 Scanning for vulnerability patterns...');
  const findings = quickScan(projectDir);
  process.stdout.write('\n');
  printFindings(findings);
}

console.log(`\nSkill installed to ${path.relative(os.homedir(), targetSkillDir)}`);
console.log('Run /tdd-audit in your agent to begin remediation.\n');
