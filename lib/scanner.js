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
  { name: 'Broken Auth',       severity: 'HIGH',     confidence: 0.75, pattern: /jwt\.decode\s*\((?![^;]*\.verify)|verify\s*:\s*false|secret\s*=\s*['"][a-z0-9]{1,20}['"]/i },
  // Vibecoding / mobile stacks
  { name: 'Sensitive Storage', severity: 'HIGH',     pattern: /(localStorage|AsyncStorage)\.setItem\s*\(\s*['"](token|password|secret|auth|jwt|api.?key)['"]/i },
  { name: 'TLS Bypass',        severity: 'CRITICAL', pattern: /badCertificateCallback[^;]*=\s*true|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i },
  { name: 'Hardcoded Secret',  severity: 'CRITICAL', skipInTests: true,  pattern: /(?:const|final|var|let|static)\s+(?:API_KEY|PRIVATE_KEY|SECRET_KEY|ACCESS_TOKEN|CLIENT_SECRET)\s*=\s*['"][A-Za-z0-9+/=_\-]{20,}['"]/i },
  { name: 'eval() Injection',  severity: 'HIGH',     pattern: /\beval\s*\([^)]*(?:route\.params|searchParams\.get|req\.(query|body)|params\[)/i },
  // Common vibecoding anti-patterns
  { name: 'Insecure Random',   severity: 'HIGH',     pattern: /(?:token|sessionId|nonce|secret|csrf)\w*\s*=.*Math\.random\(\)|Math\.random\(\).*(?:token|session|nonce|secret)/i },
  { name: 'Sensitive Log',     severity: 'MEDIUM',   confidence: 0.7, skipInTests: true,  pattern: /console\.(log|info|debug)\([^)]*(?:token|password|secret|jwt|authorization|apiKey|api_key)/i },
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
  { name: 'CORS Wildcard',           severity: 'MEDIUM',   confidence: 0.7, pattern: /cors\s*\(\s*\{\s*origin\s*:\s*['"]?\*['"]?|['"]Access-Control-Allow-Origin['"]\s*,\s*['"]?\*/i },
  { name: 'Cleartext Traffic',       severity: 'MEDIUM',   skipInTests: true, pattern: /(?:baseURL|apiUrl|API_URL|endpoint|baseUrl)\s*[:=]\s*['"]http:\/\/(?!localhost|127\.0\.0\.1)/i },
  { name: 'XXE',                     severity: 'HIGH',     pattern: /noent\s*:\s*true|expand_entities\s*=\s*True|resolve_entities\s*=\s*True/i },
  // Mobile / WebView
  { name: 'WebView JS Bridge',       severity: 'HIGH',     pattern: /addJavascriptInterface\s*\(|javaScriptEnabled\s*:\s*true|allowFileAccess\s*:\s*true|allowUniversalAccessFromFileURLs\s*:\s*true/i },
  { name: 'Deep Link Injection',     severity: 'MEDIUM',   confidence: 0.7, pattern: /Linking\.getInitialURL\s*\(\)|Linking\.addEventListener\s*\(\s*['"]url['"]/i },
  // JWT / crypto / ReDoS
  { name: 'JWT Alg None',            severity: 'CRITICAL', pattern: /algorithm\s*:\s*['"]none['"]/i },
  { name: 'Timing-Unsafe Comparison',severity: 'HIGH',     confidence: 0.75, pattern: /\b(?:token|password|secret|hash|digest|hmac|signature|api.?key)\w*\s*={2,3}\s*\w|(?:req\.(?:headers?|body|query|params)\.\w+)\s*={2,3}/i },
  { name: 'ReDoS',                   severity: 'HIGH',     pattern: /new\s+RegExp\s*\(\s*req\.(?:query|body|params)\./i },
  // ── AI / LLM Security ───────────────────────────────────────────────────────
  { name: 'LLM Prompt Injection',       severity: 'CRITICAL', pattern: /\{\s*role\s*:\s*['"](?:user|system)['"]\s*,\s*content\s*:\s*req\.(body|query|params)|messages\b[^;\n]{0,100}push\s*\([^)]*req\.(body|query|params)/i },
  { name: 'LLM Output Execution',       severity: 'CRITICAL', pattern: /\beval\s*\(\s*(?:await\s+)?(?:response|result|output|completion|generated|llmResult|aiResult)\b/i },
  { name: 'LangChain ShellTool',        severity: 'CRITICAL', pattern: /\bShellTool\s*\(\)|LLMMathChain\.from_llm\s*\(|PALChain\.from_llm\s*\(/i },
  { name: 'Dynamic Require',            severity: 'CRITICAL', pattern: /\brequire\s*\(\s*req\.(query|body|params)\./i },
  { name: 'VM Code Injection',          severity: 'CRITICAL', pattern: /\bvm\.(runInNewContext|runInContext|runInThisContext)\s*\(\s*req\.(body|query|params)/i },
  { name: 'node-serialize RCE',         severity: 'CRITICAL', pattern: /require\s*\(\s*['"]node-serialize['"]\s*\)/ },
  { name: 'Electron nodeIntegration',   severity: 'CRITICAL', pattern: /\bnodeIntegration\s*:\s*true\b/ },
  { name: 'Electron webSecurity Off',   severity: 'CRITICAL', pattern: /\bwebSecurity\s*:\s*false\b/ },
  { name: 'GitHub Actions Injection',   severity: 'CRITICAL', pattern: /\$\{\{\s*github\.(event\.(pull_request\.(title|body)|issue\.(title|body)|comment\.body|review\.body)|head_ref)\s*\}\}/ },
  { name: 'Hardcoded OpenAI Key',       severity: 'CRITICAL', skipInTests: true, pattern: /['"]sk-(?:proj-[A-Za-z0-9_\-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9_\-]{20,})['"]/ },
  { name: 'Hardcoded Anthropic Key',    severity: 'CRITICAL', skipInTests: true, pattern: /['"]sk-ant-api03-[A-Za-z0-9_\-]{10,}['"]/ },
  // ── HIGH — web / protocol / AI ──────────────────────────────────────────────
  { name: 'Header Injection',           severity: 'HIGH',     pattern: /res\.(?:setHeader|set)\s*\([^,]+,\s*req\.(body|query|params)\b/i },
  { name: 'XPath Injection',            severity: 'HIGH',     pattern: /xpath\.(?:select|evaluate|selectNodes?)\s*\([^)]*req\.(query|body|params)/i },
  { name: 'Insecure Cookie',            severity: 'HIGH',     pattern: /\bhttpOnly\s*:\s*false\b/ },
  { name: 'Credentials in AI Prompt',   severity: 'HIGH',     pattern: /(?:system_prompt|systemPrompt|system|prompt|instruction)\s*[=:+][^;\n]{0,120}(?:mongodb(?:\+srv)?|postgresql?|mysql|redis):\/\/[a-zA-Z0-9_\-]+:[^@\s]{3,}@/ },
  { name: 'LangChain Experimental',     severity: 'HIGH',     confidence: 0.7, pattern: /from\s+langchain_experimental\b|from\s+['"]langchain\/experimental['"]/i },
  { name: 'Hardcoded HuggingFace Token',severity: 'HIGH',     skipInTests: true, pattern: /['"]hf_[A-Za-z0-9]{30,}['"]/ },
  { name: 'NEXT_PUBLIC Secret',         severity: 'HIGH',     skipInTests: true, pattern: /\bNEXT_PUBLIC_\w*(?:SECRET|PRIVATE|API_KEY|TOKEN|PASSWORD|CREDENTIAL)\w*/i },
  { name: 'Electron contextIsolation Off', severity: 'HIGH',  pattern: /\bcontextIsolation\s*:\s*false\b/ },
  { name: 'Trojan Source',              severity: 'HIGH',     pattern: /[\u202A-\u202E\u2066-\u2069]/ },

  // ── AI/LLM — deeper coverage (Semgrep ai-best-practices + OWASP LLM Top 10) ─
  { name: 'Hardcoded Gemini Key',       severity: 'CRITICAL', skipInTests: true, pattern: /['"]AIza[A-Za-z0-9_\-]{35}['"]/ },
  { name: 'Hardcoded Cohere Key',       severity: 'CRITICAL', skipInTests: true, pattern: /['"][A-Za-z0-9]{40}['"]\s*[,\n].*cohere|cohere.*['"][A-Za-z0-9]{40}['"]/i },
  { name: 'Hardcoded Mistral Key',      severity: 'CRITICAL', skipInTests: true, pattern: /['"][A-Za-z0-9]{32}['"]\s*[,\n].*mistral|mistral.*['"][A-Za-z0-9]{32}['"]/i },
  { name: 'LLM Output to exec',         severity: 'CRITICAL', pattern: /(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:response|result|output|completion|generated|llmResult|aiResult)\b/i },
  { name: 'Missing max_tokens',         severity: 'HIGH',     pattern: /(?:messages\.create|chat\.completions\.create|generateContent)\s*\(\s*\{(?![^}]*max_tokens)(?![^}]*maxTokens)/i },
  { name: 'Missing system message',     severity: 'MEDIUM',   confidence: 0.65, pattern: /(?:messages\.create|chat\.completions\.create)\s*\(\s*\{[^}]*messages\s*:\s*\[[^\]]*\{[^\]]*role\s*:\s*['"]user['"]/i },
  { name: 'MCP Credential in Response', severity: 'HIGH',     confidence: 0.7, pattern: /(?:tool_result|toolResult|function_result)\s*[=:][^;\n]{0,200}(?:password|secret|token|api.?key|credential)/i },
  { name: 'Agent Unbounded Loop',       severity: 'HIGH',     pattern: /while\s*\(\s*true\s*\)[^}]*(?:tool_use|function_call|tool_calls|runAgent|agent\.run)/i },
  { name: 'Unsafe Model Load',          severity: 'HIGH',     pattern: /torch\.load\s*\([^)]*(?<!weights_only\s*=\s*True)|pickle\.load\s*\([^)]*(?:req\.|url\.|download)/i },

  // ── Node.js advanced (njsscan + Bearer + ESLint security) ────────────────────
  { name: 'Host Header Injection',      severity: 'HIGH',     pattern: /req\.(?:headers\[['"]host['"]\]|hostname|get\s*\(\s*['"]host['"]\))[^;\n]{0,120}(?:redirect|resetLink|confirmUrl|href|url)/i },
  { name: 'Headless Browser SSRF',      severity: 'CRITICAL', pattern: /(?:page\.goto|page\.navigate|browser\.goto|wkhtmltopdf|wkhtmltoimage|phantom\.create)\s*\([^)]*req\.(?:query|body|params)/i },
  { name: 'Body Parser DoS',            severity: 'HIGH',     confidence: 0.7, pattern: /express\.(?:json|urlencoded|text|raw)\s*\(\s*\)(?!\s*\/\/)|bodyParser\.(?:json|urlencoded)\s*\(\s*\)(?!\s*\/\/)/ },
  { name: 'vm2 Deprecated',             severity: 'CRITICAL', pattern: /require\s*\(\s*['"]vm2['"]\)|from\s*['"]vm2['"]/i },
  { name: 'Pug Raw Output',             severity: 'HIGH',     pattern: /!\{(?!\s*#\{)[^}]+\}/  },
  { name: 'EJS Unescaped Output',       severity: 'HIGH',     pattern: /<%[-=](?!=)/            },
  { name: 'Handlebars Triple-Stache',   severity: 'HIGH',     pattern: /\{\{\{(?!\s*>)[^}]+\}\}\}/ },
  { name: 'postMessage No Origin',      severity: 'HIGH',     pattern: /addEventListener\s*\(\s*['"]message['"]\s*,[^)]+\)(?![^{]*event\.origin|[^{]*e\.origin)/i },
  { name: 'Dynamic Import User Input',  severity: 'HIGH',     pattern: /import\s*\(\s*req\.|import\s*\(\s*[a-z_]*[Pp]ath\s*\+|import\s*\(\s*`[^`]*\$\{req\./i },
  { name: 'JWT No Revocation',          severity: 'HIGH',     confidence: 0.7, pattern: /jwt\.sign\s*\([^)]*expiresIn\s*:\s*['"][0-9]+[dDhH](?:[0-9]+)?['"]/i },
  { name: 'X-Powered-By Exposed',       severity: 'MEDIUM',   confidence: 0.7, pattern: /app\s*=\s*express\s*\(\s*\)(?![^;]{0,500}disable\s*\(\s*['"]x-powered-by['"])/i },
  { name: 'GraphQL Introspection On',   severity: 'HIGH',     pattern: /introspection\s*:\s*true\b/i },
  { name: 'GraphQL No Depth Limit',     severity: 'MEDIUM',   pattern: /new ApolloServer\s*\(\s*\{(?![^}]*depthLimit|[^}]*createDepthLimitPlugin)/i },
  { name: 'Sequelize TLS Disabled',     severity: 'HIGH',     pattern: /dialectOptions[^}]*ssl\s*:\s*(?:false|require\s*:\s*false)/i },
  { name: 'Silent Exception Swallow',   severity: 'MEDIUM',   confidence: 0.65, skipInTests: true, pattern: /catch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*)?\s*\}/i },
  { name: 'Insecure WebSocket URL',     severity: 'MEDIUM',   skipInTests: true, pattern: /new WebSocket\s*\(\s*['"]ws:\/\/(?!localhost|127\.0\.0\.1)/i },

  // ── Catalog gaps from tdd-patterns (v1.22.0) ────────────────────────────────
  { name: 'Prototype Pollution Bracket', severity: 'HIGH', pattern: /(?:target|obj|dest|result|acc|output)\s*\[\s*(?:key|k|prop|field|param|input)\s*\]\s*=|(?:target|obj|dest)\s*\[\s*(?:key|k)\s*\]\s*=\s*(?:source|src|input|data)\s*\[\s*(?:key|k)\s*\]/i },
  { name: 'Excessive Agency Write Tool', severity: 'HIGH', confidence: 0.75, pattern: /(?:server|mcp|agent)\.tool\s*\(\s*['"`](?:delete|remove|drop|write|send|post|patch|update|create)[^'"`]*['"`]\s*,\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z_$][\w$]*)\s*=>/i },
  { name: 'Hardcoded Transactional URL', severity: 'HIGH', confidence: 0.75, skipInTests: true, pattern: /[`'"]https:\/\/(?!localhost|127\.0\.0\.1)[^`'"]*(?:\/(?:auth\/)?(?:confirm|reset|unsubscribe|verify|callback|invite|rsvp)|password-reset|email-confirm)[^`'"]*[`'"]/i },
  { name: 'Transactional Bulk Email Header', severity: 'MEDIUM', pattern: /['"]Precedence['"]\s*:\s*['"]bulk['"]|Precedence\s*[:=]\s*['"]?bulk['"]?/i },
  { name: 'DB Admin Auth Check',         severity: 'HIGH', confidence: 0.75, pattern: /\.select\s*\(\s*['"`][^'"`]*\bis_admin\b[^'"`]*['"`]\s*\)|\.from\s*\(\s*['"`]profiles['"`]\s*\)[^;\n]{0,100}\bis_admin\b/i },
];
const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.py', '.go', '.dart', '.yml', '.yaml']);

/** Maximum file size to read before skipping (512 KB). Prevents OOM on large generated files. */
const MAX_SCAN_FILE_BYTES = 512 * 1024;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'out', '__pycache__', 'venv', '.venv', 'vendor', '.expo', '.dart_tool', '.pub-cache']);

// ─── Prompt / Skill Patterns ──────────────────────────────────────────────────

const PROMPT_PATTERNS = [
  { name: 'Deprecated CSRF Package',  severity: 'CRITICAL', pattern: /\bcsurf\b/,               skipCommentLine: true },
  { name: 'Unpinned npx MCP Server',  severity: 'HIGH',     pattern: /"command"\s*:\s*"npx"/ },
  { name: 'MCP Tool Poisoning',       severity: 'HIGH',     pattern: /"description"\s*:\s*"[^"]*(?:ignore (?:previous|all)|override (?:previous )?instructions?|disregard|forget (?:all )?(?:previous )?instructions?|you are now|new instructions?)/i },
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
      // SEC-06: read first, then check length — eliminates statSync/readFileSync TOCTOU race.
      const content = fs.readFileSync(filePath, 'utf8');
      if (content.length > MAX_SCAN_FILE_BYTES) continue;
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

/**
 * Scan package.json for supply-chain exfiltration: postinstall/preinstall scripts
 * that shell out to curl/wget, which can silently steal data at install time.
 * @param {string} projectDir - project root
 * @returns {Array}
 */
function scanPackageJson(projectDir) {
  const findings = [];
  const filePath = path.join(projectDir, 'package.json');
  if (!fs.existsSync(filePath)) return findings;
  let lines;
  try { lines = fs.readFileSync(filePath, 'utf8').split('\n'); } catch { return findings; }
  const supplyChainRe = /["'](?:postinstall|preinstall)["']\s*:\s*["'][^"']*(?:curl|wget)\s+https?:\/\//i;
  for (let i = 0; i < lines.length; i++) {
    if (supplyChainRe.test(lines[i])) {
      findings.push({
        severity: 'CRITICAL',
        name: 'Supply Chain Exfiltration',
        file: 'package.json',
        line: i + 1,
        snippet: lines[i].trim().slice(0, 80),
        inTestFile: false,
        likelyFalsePositive: false,
      });
    }
  }
  return findings;
}

/**
 * Scan .env files for NEXT_PUBLIC_ variables containing secrets.
 * NEXT_PUBLIC_ variables are inlined into the client-side JS bundle at build
 * time, so any secret stored with this prefix is exposed to all browsers.
 * @param {string} projectDir - project root
 * @returns {Array}
 */
function scanEnvFiles(projectDir) {
  const findings = [];
  const candidates = ['.env', '.env.local', '.env.development', '.env.production', '.env.test', '.env.staging'];
  const nextPublicSecretRe = /^NEXT_PUBLIC_\w*(?:SECRET|PRIVATE|API_KEY|TOKEN|PASSWORD|CREDENTIAL)\w*\s*=/i;
  for (const name of candidates) {
    const filePath = path.join(projectDir, name);
    if (!fs.existsSync(filePath)) continue;
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
      if (content.length > MAX_SCAN_FILE_BYTES) continue;
    } catch { continue; }
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim() || line.trim().startsWith('#')) continue;
      if (nextPublicSecretRe.test(line)) {
        findings.push({
          severity: 'HIGH',
          name: 'NEXT_PUBLIC Secret',
          file: name,
          line: i + 1,
          snippet: line.trim().slice(0, 80),
          inTestFile: false,
          likelyFalsePositive: false,
        });
      }
    }
  }
  return findings;
}

// ─── Structural / Config Scanners (tdd-patterns catalog gaps) ─────────────────

/**
 * Broken API Route Auth Chain — Next.js/Express mutating handlers with no auth.
 * Flags route files that export POST/PUT/PATCH/DELETE without any auth signal.
 * @param {string} projectDir
 * @returns {Array}
 */
function scanAuthChain(projectDir) {
  const findings = [];
  const authSignal = /\b(?:getUser|getSession|authenticate|requireAuth|requireUser|verifyToken|auth\.uid|getServerSession|currentUser|req\.user|authorize)\b/;
  const mutatingExport = /export\s+async\s+function\s+(POST|PUT|PATCH|DELETE)\b|router\.(post|put|patch|delete)\s*\(|app\.(post|put|patch|delete)\s*\(/i;

  for (const filePath of walkFiles(projectDir)) {
    if (isTestFile(filePath, projectDir)) continue;
    const rel = path.relative(projectDir, filePath).replace(/\\/g, '/');
    // Focus on API route conventions
    if (!/(^|\/)(api|routes|controllers)\//.test(rel) && !/route\.(js|ts|mjs)$/.test(rel)) continue;
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
      if (content.length > MAX_SCAN_FILE_BYTES || content.includes('\0')) continue;
    } catch { continue; }

    if (!mutatingExport.test(content)) continue;
    if (authSignal.test(content)) continue;

    // Find first mutating handler line for the report
    const lines = content.split('\n');
    let lineNo = 1;
    for (let i = 0; i < lines.length; i++) {
      if (mutatingExport.test(lines[i])) { lineNo = i + 1; break; }
    }
    findings.push({
      severity: 'CRITICAL',
      confidence: 0.7,
      name: 'Broken Auth Chain',
      file: rel,
      line: lineNo,
      snippet: lines[lineNo - 1].trim().slice(0, 80),
      inTestFile: false,
      likelyFalsePositive: false,
    });
  }
  return findings;
}

/**
 * Missing Rate Limiting — auth/mutation route files with no rate-limit signal.
 * @param {string} projectDir
 * @returns {Array}
 */
function scanMissingRateLimit(projectDir) {
  const findings = [];
  const authPathHint = /(?:login|register|signup|sign-up|sign_in|signin|forgot|password|reset|verify|auth)/i;
  const rateLimitSignal = /\b(?:rateLimit|rateLimiter|rate-limit|rate_limit|isIpRateLimited|express-rate-limit|@upstash\/ratelimit|slowDown|throttle)\b/i;
  const mutatingHandler = /export\s+async\s+function\s+POST\b|\.(?:post|put|patch|delete)\s*\(\s*['"`][^'"`]*(?:login|register|signup|password|forgot|reset|verify|auth)/i;

  for (const filePath of walkFiles(projectDir)) {
    if (isTestFile(filePath, projectDir)) continue;
    const rel = path.relative(projectDir, filePath).replace(/\\/g, '/');
    if (!authPathHint.test(rel) && !/(^|\/)(api|routes)\//.test(rel)) continue;

    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
      if (content.length > MAX_SCAN_FILE_BYTES || content.includes('\0')) continue;
    } catch { continue; }

    // Only flag files that look like auth endpoints
    const looksLikeAuth = authPathHint.test(rel) || authPathHint.test(content.slice(0, 2000));
    if (!looksLikeAuth) continue;
    if (!mutatingHandler.test(content) && !/export\s+async\s+function\s+POST\b/.test(content)) continue;
    if (rateLimitSignal.test(content)) continue;

    // Require an auth-ish path segment or explicit login route string to cut noise
    if (!authPathHint.test(rel) && !/(?:login|register|signup|password|forgot|reset)/i.test(content)) continue;

    const lines = content.split('\n');
    let lineNo = 1;
    for (let i = 0; i < lines.length; i++) {
      if (/export\s+async\s+function\s+POST\b|\.post\s*\(/.test(lines[i])) { lineNo = i + 1; break; }
    }
    findings.push({
      severity: 'HIGH',
      confidence: 0.7,
      name: 'Missing Rate Limiting',
      file: rel,
      line: lineNo,
      snippet: lines[lineNo - 1].trim().slice(0, 80),
      inTestFile: false,
      likelyFalsePositive: false,
    });
  }
  return findings;
}

/**
 * Missing HTTP Security Headers — Express/Next apps with no helmet/CSP/headers config.
 * Emits at most one finding per project.
 * @param {string} projectDir
 * @returns {Array}
 */
function scanMissingSecurityHeaders(projectDir) {
  const pkgPath = path.join(projectDir, 'package.json');
  if (!fs.existsSync(pkgPath)) return [];

  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch { return []; }
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const isExpress = !!deps.express;
  const isNext = !!deps.next;
  if (!isExpress && !isNext) return [];

  // Positive signals that headers are configured
  if (deps.helmet) return [];
  const headerSignal = /\bhelmet\b|contentSecurityPolicy|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|async\s+headers\s*\(/i;

  // Check next.config.* and common app entry points quickly
  const configCandidates = [
    'next.config.js', 'next.config.mjs', 'next.config.ts', 'next.config.cjs',
    'src/middleware.js', 'src/middleware.ts', 'middleware.js', 'middleware.ts',
    'src/app.js', 'src/server.js', 'src/index.js', 'app.js', 'server.js', 'index.js',
  ];
  for (const name of configCandidates) {
    const fp = path.join(projectDir, name);
    if (!fs.existsSync(fp)) continue;
    try {
      const content = fs.readFileSync(fp, 'utf8');
      if (headerSignal.test(content)) return [];
    } catch { /* continue */ }
  }

  // Light walk of source for helmet()/headers() — stop early if found
  let sawApp = isNext; // Next apps always "have an app"
  for (const filePath of walkFiles(projectDir)) {
    if (isTestFile(filePath, projectDir)) continue;
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
      if (content.length > MAX_SCAN_FILE_BYTES || content.includes('\0')) continue;
    } catch { continue; }
    if (headerSignal.test(content)) return [];
    if (!sawApp && /\bexpress\s*\(\s*\)/.test(content)) sawApp = true;
  }
  if (!sawApp) return [];

  return [{
    severity: 'HIGH',
    confidence: 0.7,
    name: 'Missing Security Headers',
    file: isNext ? (fs.existsSync(path.join(projectDir, 'next.config.js')) ? 'next.config.js'
      : fs.existsSync(path.join(projectDir, 'next.config.mjs')) ? 'next.config.mjs'
      : fs.existsSync(path.join(projectDir, 'next.config.ts')) ? 'next.config.ts'
      : 'package.json') : 'package.json',
    line: 1,
    snippet: isNext
      ? 'Next.js app with no security headers() / helmet configuration detected'
      : 'Express app with no helmet dependency or security header middleware detected',
    inTestFile: false,
    likelyFalsePositive: false,
  }];
}

/**
 * Package Lockfile Out of Sync — deps in package.json missing from lockfile.
 * @param {string} projectDir
 * @returns {Array}
 */
function scanLockfileSync(projectDir) {
  const findings = [];
  const pkgPath = path.join(projectDir, 'package.json');
  if (!fs.existsSync(pkgPath)) return findings;

  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch { return findings; }
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const depNames = Object.keys(deps);
  if (!depNames.length) return findings;

  const npmLock = path.join(projectDir, 'package-lock.json');
  const pnpmLock = path.join(projectDir, 'pnpm-lock.yaml');
  const yarnLock = path.join(projectDir, 'yarn.lock');

  let missing = [];
  let lockFile = null;

  if (fs.existsSync(npmLock)) {
    lockFile = 'package-lock.json';
    let lock;
    try { lock = JSON.parse(fs.readFileSync(npmLock, 'utf8')); } catch { return findings; }
    // npm v7+ uses packages["node_modules/foo"]; v6 uses dependencies
    const locked = new Set();
    if (lock.packages) {
      for (const key of Object.keys(lock.packages)) {
        const m = key.match(/^node_modules\/(@[^/]+\/[^/]+|[^/]+)$/);
        if (m) locked.add(m[1]);
      }
    }
    if (lock.dependencies) {
      for (const name of Object.keys(lock.dependencies)) locked.add(name);
    }
    missing = depNames.filter(d => !locked.has(d));
  } else if (fs.existsSync(pnpmLock)) {
    lockFile = 'pnpm-lock.yaml';
    let content;
    try { content = fs.readFileSync(pnpmLock, 'utf8'); } catch { return findings; }
    // pnpm lock lists packages as  /name@version: or 'name@version':
    missing = depNames.filter(d => {
      const esc = d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`[/']${esc}@`);
      return !re.test(content);
    });
  } else if (fs.existsSync(yarnLock)) {
    lockFile = 'yarn.lock';
    let content;
    try { content = fs.readFileSync(yarnLock, 'utf8'); } catch { return findings; }
    missing = depNames.filter(d => {
      // yarn classic: "name@version:" or name@version:
      const esc = d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`(^|\\n)"?${esc}@`, 'm');
      return !re.test(content);
    });
  } else {
    return findings; // no lockfile present — different problem
  }

  if (!missing.length) return findings;

  // Report against package.json — list up to 5 missing deps in snippet
  const sample = missing.slice(0, 5).join(', ') + (missing.length > 5 ? ` (+${missing.length - 5} more)` : '');
  findings.push({
    severity: 'HIGH',
    confidence: 0.85,
    name: 'Lockfile Out of Sync',
    file: 'package.json',
    line: 1,
    snippet: `${missing.length} package.json dep(s) missing from ${lockFile}: ${sample}`,
    inTestFile: false,
    likelyFalsePositive: false,
  });
  return findings;
}

/**
 * tsconfig.json does not exclude test files while a test runner is present.
 * @param {string} projectDir
 * @returns {Array}
 */
function scanTsconfigTestExclusion(projectDir) {
  const tsconfigPath = path.join(projectDir, 'tsconfig.json');
  if (!fs.existsSync(tsconfigPath)) return [];

  // Only relevant when a JS/TS test runner is configured
  const pkgPath = path.join(projectDir, 'package.json');
  let hasTestRunner = fs.existsSync(path.join(projectDir, 'vitest.config.ts'))
    || fs.existsSync(path.join(projectDir, 'vitest.config.js'))
    || fs.existsSync(path.join(projectDir, 'vitest.config.mts'))
    || fs.existsSync(path.join(projectDir, 'jest.config.ts'))
    || fs.existsSync(path.join(projectDir, 'jest.config.js'))
    || fs.existsSync(path.join(projectDir, 'jest.config.mjs'));
  if (!hasTestRunner && fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      hasTestRunner = !!(deps.vitest || deps.jest || deps['@jest/globals']);
    } catch { /* ignore */ }
  }
  if (!hasTestRunner) return [];

  let raw;
  try { raw = fs.readFileSync(tsconfigPath, 'utf8'); } catch { return []; }

  // Strip // and /* */ comments for JSONC parse
  const stripped = raw
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
  let tsconfig;
  try { tsconfig = JSON.parse(stripped); } catch { return []; }

  const exclude = Array.isArray(tsconfig.exclude) ? tsconfig.exclude.map(String) : [];
  const excludeBlob = exclude.join('\n');
  const hasTestExclude = /(?:\*\*\/)?__tests__|(?:\*\*\/)?\*\.test\.|(?:\*\*\/)?\*\.spec\.|vitest\.|jest\.config|jest\.setup|vitest\.setup|\/tests?\/|\\tests?\\/.test(excludeBlob);

  if (hasTestExclude) return [];

  // Find the exclude line or top of file
  const lines = raw.split('\n');
  let lineNo = 1;
  for (let i = 0; i < lines.length; i++) {
    if (/"exclude"\s*:/.test(lines[i])) { lineNo = i + 1; break; }
  }

  return [{
    severity: 'MEDIUM',
    confidence: 0.8,
    name: 'Tsconfig Test Exclusion',
    file: 'tsconfig.json',
    line: lineNo,
    snippet: (lines[lineNo - 1] || '"exclude" missing').trim().slice(0, 80),
    inTestFile: false,
    likelyFalsePositive: false,
  }];
}

/**
 * Vercel Deployment Protection — preview E2E/fetch without bypass token.
 * @param {string} projectDir
 * @returns {Array}
 */
function scanVercelProtectionBypass(projectDir) {
  const findings = [];
  const previewUrl = /(?:VERCEL_URL|VERCEL_BRANCH_URL|PREVIEW_URL|\.vercel\.app)/i;
  const bypass = /x-vercel-protection-bypass|VERCEL_AUTOMATION_BYPASS_SECRET|protection-bypass/i;

  for (const filePath of walkFiles(projectDir)) {
    const rel = path.relative(projectDir, filePath).replace(/\\/g, '/');
    // Focus on e2e / CI / test helpers that hit preview URLs
    const inScope = isTestFile(filePath, projectDir)
      || /\.github\/workflows\//.test(rel)
      || /e2e|playwright|cypress/i.test(rel);
    if (!inScope) continue;

    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
      if (content.length > MAX_SCAN_FILE_BYTES || content.includes('\0')) continue;
    } catch { continue; }

    if (!previewUrl.test(content)) continue;
    if (bypass.test(content)) continue;

    const lines = content.split('\n');
    let lineNo = 1;
    for (let i = 0; i < lines.length; i++) {
      if (previewUrl.test(lines[i])) { lineNo = i + 1; break; }
    }
    findings.push({
      severity: 'MEDIUM',
      confidence: 0.7,
      name: 'Vercel Protection Bypass Missing',
      file: rel,
      line: lineNo,
      snippet: lines[lineNo - 1].trim().slice(0, 80),
      inTestFile: isTestFile(filePath, projectDir),
      likelyFalsePositive: false,
    });
  }
  return findings;
}

// ─── Quick Scan ───────────────────────────────────────────────────────────────

/**
 * Scan all source files in projectDir for known vulnerability patterns.
 * @param {string} projectDir - project root to scan
 * @returns {Array} findings
 */
function quickScan(projectDir, ignoreList = []) {
  const findings = [];
  for (const filePath of walkFiles(projectDir)) {
    const relPath = path.relative(projectDir, filePath).replace(/\\/g, '/');
    if (ignoreList.some(p => relPath === p || relPath.startsWith(p + '/'))) {
      continue;
    }
    const inTest = isTestFile(filePath, projectDir);
    let content;
    // L1 fix: guard against binary / non-UTF-8 files
    // SEC-06: read first, then check length — eliminates statSync/readFileSync TOCTOU race.
    try {
      content = fs.readFileSync(filePath, 'utf8');
      if (content.length > MAX_SCAN_FILE_BYTES) continue;
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
            confidence: vuln.confidence ?? 0.85,
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
  const allFindings = [
    ...findings,
    ...scanAppConfig(projectDir),
    ...scanAndroidManifest(projectDir),
    ...scanPromptFiles(projectDir),
    ...scanPackageJson(projectDir),
    ...scanEnvFiles(projectDir),
    ...scanAuthChain(projectDir),
    ...scanMissingRateLimit(projectDir),
    ...scanMissingSecurityHeaders(projectDir),
    ...scanLockfileSync(projectDir),
    ...scanTsconfigTestExclusion(projectDir),
    ...scanVercelProtectionBypass(projectDir),
  ];
  return allFindings.filter(f => {
    const rel = f.file.replace(/\\/g, '/');
    return !ignoreList.some(p => rel === p || rel.startsWith(p + '/'));
  });
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
  scanPackageJson,
  scanEnvFiles,
  scanPromptFiles,
  scanAuthChain,
  scanMissingRateLimit,
  scanMissingSecurityHeaders,
  scanLockfileSync,
  scanTsconfigTestExclusion,
  scanVercelProtectionBypass,
  quickScan,
  printFindings,
};
