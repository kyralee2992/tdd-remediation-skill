'use strict';

const fs      = require('fs');
const path    = require('path');
const { version } = require('../package.json');

// ─── Skill Suite Loader ───────────────────────────────────────────────────────

function loadSkillSuite(packageDir) {
  const entries = [
    ['SKILL.md',           path.join(packageDir, 'SKILL.md')],
    ['auto-audit.md',      path.join(packageDir, 'prompts', 'auto-audit.md')],
    ['red-phase.md',       path.join(packageDir, 'prompts', 'red-phase.md')],
    ['green-phase.md',     path.join(packageDir, 'prompts', 'green-phase.md')],
    ['refactor-phase.md',  path.join(packageDir, 'prompts', 'refactor-phase.md')],
    ['hardening-phase.md', path.join(packageDir, 'prompts', 'hardening-phase.md')],
  ];
  const suite = {};
  for (const [name, filePath] of entries) {
    try { suite[name] = fs.readFileSync(filePath, 'utf8'); } catch { /* not present */ }
  }
  return suite;
}

function buildSystemPrompt(suite) {
  const parts = [
    'You are a security engineer running the TDD Remediation Protocol audit.',
    'Use the tools provided to explore the repository, identify vulnerabilities, and (when permitted) apply fixes.',
    'File paths passed to tools are always relative to the project root.',
  ];
  for (const [name, content] of Object.entries(suite)) {
    parts.push(`\n---\n## ${name}\n\n${content}`);
  }
  return parts.join('\n');
}

// ─── Structured Output Helpers ────────────────────────────────────────────────

// ─── Depth-tier output schemas ────────────────────────────────────────────────

/**
 * Depth controls what the LLM produces and what capabilities are enabled.
 *
 *   tier-1 — scan-only, minimal fields (name, severity, file, line, snippet)
 *   tier-2 — scan-only, adds risk, effort, cwe, owasp, references[]
 *   tier-3 — full audit, read-only; each finding includes a copy-ready `patch`
 *             and `testSnippet`. The user applies the patches manually.
 *             Billing unit: per report.
 *   tier-4 — full audit, writes enabled; LLM applies each patch via write_file.
 *             The `remediation` array tracks every applied patch (status=fixed).
 *             Billing unit: patchesApplied (remediation entries with status=fixed).
 *             `patchesApplied` is computed and added to the output envelope.
 *
 * The depth value is included in the output envelope so downstream consumers
 * (UI, CI parsers, billing systems) can branch on it without parsing content.
 */
const DEPTH_JSON_INSTRUCTIONS = {

  'tier-1': `
IMPORTANT — OUTPUT FORMAT:
Output a single fenced JSON block as your final message (nothing after it):

\`\`\`json
{
  "stack": "<detected stack>",
  "findings": [
    {
      "name": "<vulnerability type>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "<relative path>",
      "line": <integer>,
      "snippet": "<code snippet up to 200 chars>"
    }
  ],
  "likelyFalsePositives": [],
  "remediation": []
}
\`\`\`
`,

  'tier-2': `
IMPORTANT — OUTPUT FORMAT:
Output a single fenced JSON block as your final message (nothing after it):

\`\`\`json
{
  "stack": "<detected stack>",
  "findings": [
    {
      "name": "<vulnerability type>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "<relative path>",
      "line": <integer>,
      "snippet": "<code snippet up to 200 chars>",
      "risk": "<plain-language explanation of what an attacker can do>",
      "effort": "low|medium|high",
      "cwe": "CWE-NNN",
      "owasp": "A01:2021 — <category name>",
      "references": ["<URL or standard citation>"]
    }
  ],
  "likelyFalsePositives": [],
  "remediation": []
}
\`\`\`
`,

  'tier-3': `
IMPORTANT — OUTPUT FORMAT:
For each finding, generate a complete, copy-paste-ready patch.
Do NOT call write_file — the user will apply the patches manually.

Output a single fenced JSON block as your final message (nothing after it):

\`\`\`json
{
  "stack": "<detected stack>",
  "findings": [
    {
      "name": "<vulnerability type>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "<relative path>",
      "line": <integer>,
      "snippet": "<vulnerable code up to 200 chars>",
      "risk": "<plain-language risk>",
      "effort": "low|medium|high",
      "cwe": "CWE-NNN",
      "patch": "<complete replacement code block — ready to copy-paste>",
      "testSnippet": "<Jest/Mocha/etc test that proves the fix works>"
    }
  ],
  "likelyFalsePositives": [],
  "remediation": []
}
\`\`\`
`,

  'tier-4': `
IMPORTANT — OUTPUT FORMAT:
For each finding, apply the patch by calling write_file before writing the report.
Call write_file once per vulnerability — one patch, one file write.
Track every patch attempt in the remediation array (status=fixed if written, skipped otherwise).

Output a single fenced JSON block as your final message (nothing after it):

\`\`\`json
{
  "stack": "<detected stack>",
  "findings": [
    {
      "name": "<vulnerability type>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "<relative path>",
      "line": <integer>,
      "snippet": "<vulnerable code up to 200 chars>",
      "risk": "<plain-language risk>",
      "effort": "low|medium|high",
      "cwe": "CWE-NNN",
      "patch": "<the code block that was written via write_file>"
    }
  ],
  "likelyFalsePositives": [],
  "remediation": [
    {
      "name": "<vulnerability type>",
      "status": "fixed|skipped",
      "testFile": "<relative path or null>",
      "fixApplied": "<one-line description of the change written>"
    }
  ]
}
\`\`\`
`,
};

/** Return the JSON output instruction for the given depth tier. */
function buildJsonOutputInstruction(depth) {
  return DEPTH_JSON_INSTRUCTIONS[depth] || DEPTH_JSON_INSTRUCTIONS['tier-1'];
}

// Keep legacy constant for any external callers (backwards compat)
const JSON_OUTPUT_INSTRUCTION = DEPTH_JSON_INSTRUCTIONS['tier-1'];

/**
 * Extract the last \`\`\`json ... \`\`\` block from buffered LLM output.
 * Falls back to the last bare top-level JSON object if no fenced block is found.
 */
function extractJsonBlock(text) {
  // Walk backwards through all ```json blocks to find the last one
  const fenceRe = /```json\s*([\s\S]*?)```/g;
  let last = null;
  let m;
  while ((m = fenceRe.exec(text)) !== null) last = m[1].trim();
  if (last) {
    try { return JSON.parse(last); } catch { /* fall through */ }
  }
  // Bare JSON fallback: match the last {...} in the output
  const bareRe = /\{[\s\S]*\}/g;
  let bare = null;
  while ((m = bareRe.exec(text)) !== null) bare = m[0];
  if (bare) {
    try { return JSON.parse(bare); } catch { /* fall through */ }
  }
  return null;
}

/**
 * Wrap AI-extracted findings in the same envelope shape as toJson() so
 * downstream consumers (CI parsers, badge logic) can treat both identically.
 */
function aiToJson(extracted, { provider, model, scanOnly, depth = 'tier-1' }) {
  const findings             = Array.isArray(extracted?.findings)             ? extracted.findings             : [];
  const likelyFalsePositives = Array.isArray(extracted?.likelyFalsePositives) ? extracted.likelyFalsePositives : [];
  const remediation          = Array.isArray(extracted?.remediation)          ? extracted.remediation          : [];

  const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) summary[f.severity] = (summary[f.severity] || 0) + 1;

  // patchesApplied is the billable unit for tier-4:
  // count of remediation entries where status === 'fixed' (i.e. write_file was called).
  const patchesApplied = remediation.filter(r => r.status === 'fixed').length;

  return {
    version,
    provider,
    model:          model || null,
    depth,
    mode:           scanOnly ? 'scan-only' : 'full',
    stack:          extracted?.stack || null,
    summary,
    patchesApplied,
    findings,
    likelyFalsePositives,
    remediation,
    scannedAt:      new Date().toISOString(),
  };
}

// CWE map mirrored from reporter.js so SARIF output stays consistent
const CWE_MAP = {
  'SQL Injection': 'CWE-89', 'Command Injection': 'CWE-78', 'Path Traversal': 'CWE-22',
  'XSS': 'CWE-79', 'IDOR': 'CWE-639', 'Broken Auth': 'CWE-287',
  'Hardcoded Secret': 'CWE-798', 'SSRF': 'CWE-918', 'Open Redirect': 'CWE-601',
  'NoSQL Injection': 'CWE-943', 'Mass Assignment': 'CWE-915', 'Prototype Pollution': 'CWE-1321',
  'Weak Crypto': 'CWE-327', 'Insecure Deserialization': 'CWE-502', 'TLS Bypass': 'CWE-295',
  'Sensitive Storage': 'CWE-312', 'JWT Alg None': 'CWE-347', 'Secret Fallback': 'CWE-798',
  'eval() Injection': 'CWE-95', 'Template Injection': 'CWE-94', 'CORS Wildcard': 'CWE-942',
};
const SARIF_LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };

/** Convert AI JSON findings envelope to SARIF 2.1.0. */
function aiToSarif(envelope) {
  const findings = envelope.findings || [];
  const rules = [];
  const ruleIndex = {};

  const results = findings.map(f => {
    if (ruleIndex[f.name] === undefined) {
      ruleIndex[f.name] = rules.length;
      const cwe = CWE_MAP[f.name];
      rules.push({
        id: (f.name || 'unknown').replace(/\s+/g, '-').replace(/[()]/g, '').toLowerCase(),
        name: f.name,
        shortDescription: { text: f.name },
        fullDescription:  { text: `${f.name} — severity: ${f.severity}` },
        defaultConfiguration: { level: SARIF_LEVEL[f.severity] || 'warning' },
        ...(cwe && { relationships: [{ target: { id: cwe, toolComponent: { name: 'CWE' } } }] }),
        helpUri: `https://cwe.mitre.org/data/definitions/${cwe ? cwe.replace('CWE-', '') : '0'}.html`,
      });
    }
    return {
      ruleId:    rules[ruleIndex[f.name]].id,
      ruleIndex: ruleIndex[f.name],
      level:     SARIF_LEVEL[f.severity] || 'warning',
      message:   { text: f.snippet || f.name },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: (f.file || '').replace(/\\/g, '/'), uriBaseId: '%SRCROOT%' },
          region: { startLine: typeof f.line === 'number' ? f.line : 1 },
        },
      }],
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name:           '@lhi/tdd-audit',
          version,
          informationUri: 'https://www.npmjs.com/package/@lhi/tdd-audit',
          rules,
        },
      },
      results,
    }],
  };
}

// ─── Safe File-System Tools ───────────────────────────────────────────────────

const MAX_FILE_BYTES     = 512 * 1024;
const MAX_LIST_RESULTS   = 500;
const MAX_SEARCH_RESULTS = 100;

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'out',
  '__pycache__', 'venv', '.venv', 'vendor', '.expo', '.dart_tool', '.pub-cache',
]);

/**
 * Resolve a user-supplied relative path and verify it stays inside projectDir.
 * Throws if the resolved path escapes the project root (path traversal guard).
 */
function safePath(inputPath, projectDir) {
  if (typeof inputPath !== 'string' || !inputPath.trim()) {
    throw new Error('path must be a non-empty string');
  }
  const resolved   = path.resolve(projectDir, inputPath);
  const projectAbs = path.resolve(projectDir);
  if (resolved !== projectAbs && !resolved.startsWith(projectAbs + path.sep)) {
    throw new Error(`Access denied: "${inputPath}" is outside the project directory`);
  }
  return resolved;
}

function* walkDir(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walkDir(full);
    else if (entry.isFile()) yield full;
  }
}

/** Convert a simple glob pattern (**\/*.js, src/**\/*.ts, *.md) to a RegExp. */
function globToRegex(pattern) {
  const re = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\x00')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/\x00/g, '.*');
  return new RegExp(`^${re}$`);
}

function toolReadFile(input, projectDir) {
  const { path: inputPath } = input;
  let resolved;
  try { resolved = safePath(inputPath, projectDir); } catch (e) { return { error: e.message }; }
  if (!fs.existsSync(resolved))    return { error: `Not found: ${inputPath}` };
  const stat = fs.statSync(resolved);
  if (!stat.isFile())              return { error: `Not a file: ${inputPath}` };
  if (stat.size > MAX_FILE_BYTES)  return { error: `File too large (${stat.size} bytes, max 512 KB)` };
  const buf = fs.readFileSync(resolved);
  if (buf.indexOf(0) !== -1)       return { error: 'Binary file — skipping' };
  return { content: buf.toString('utf8'), bytes: stat.size };
}

function toolListFiles(input, projectDir) {
  const { pattern } = input;
  if (!pattern || typeof pattern !== 'string') return { error: 'pattern is required' };
  const re = globToRegex(pattern);
  const results = [];
  for (const filePath of walkDir(projectDir)) {
    if (results.length >= MAX_LIST_RESULTS) break;
    const rel = path.relative(projectDir, filePath);
    if (re.test(rel)) results.push(rel);
  }
  return { files: results, count: results.length };
}

function toolSearchInFiles(input, projectDir) {
  const { pattern, glob: globPattern } = input;
  if (!pattern || typeof pattern !== 'string') return { error: 'pattern is required' };
  let re;
  try { re = new RegExp(pattern, 'g'); } catch (e) { return { error: `Invalid regex: ${e.message}` }; }
  const fileFilter = globPattern ? globToRegex(globPattern) : null;
  const results = [];
  for (const filePath of walkDir(projectDir)) {
    if (results.length >= MAX_SEARCH_RESULTS) break;
    const rel = path.relative(projectDir, filePath);
    if (fileFilter && !fileFilter.test(rel)) continue;
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_BYTES) continue;
    const buf = fs.readFileSync(filePath);
    if (buf.indexOf(0) !== -1) continue;
    const lines = buf.toString('utf8').split('\n');
    for (let i = 0; i < lines.length && results.length < MAX_SEARCH_RESULTS; i++) {
      re.lastIndex = 0;
      if (re.test(lines[i])) results.push({ file: rel, line: i + 1, content: lines[i].trim().slice(0, 200) });
    }
  }
  return { matches: results, count: results.length };
}

function toolWriteFile(input, projectDir) {
  const { path: inputPath, content } = input;
  if (typeof content !== 'string') return { error: 'content must be a string' };
  let resolved;
  try { resolved = safePath(inputPath, projectDir); } catch (e) { return { error: e.message }; }
  try {
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, content, 'utf8');
    return { ok: true, path: inputPath, bytes: Buffer.byteLength(content) };
  } catch (e) {
    return { error: `Write failed: ${e.message}` };
  }
}

function executeToolCall(name, input, projectDir, { allowWrites = false } = {}) {
  switch (name) {
    case 'read_file':       return toolReadFile(input, projectDir);
    case 'list_files':      return toolListFiles(input, projectDir);
    case 'search_in_files': return toolSearchInFiles(input, projectDir);
    case 'write_file':
      if (!allowWrites) return { error: 'Write access is disabled. Re-run with --allow-writes to enable file modifications.' };
      return toolWriteFile(input, projectDir);
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// ─── Tool Schemas ─────────────────────────────────────────────────────────────

const TOOL_DEFS = [
  {
    name: 'read_file',
    description: 'Read the contents of a file in the project.',
    params: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Relative path from the project root.' },
      },
      required: ['path'],
    },
  },
  {
    name: 'list_files',
    description: 'List files matching a glob pattern (e.g. "src/**/*.js", "**/*.test.ts").',
    params: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Glob pattern relative to the project root.' },
      },
      required: ['pattern'],
    },
  },
  {
    name: 'search_in_files',
    description: 'Search for a regex pattern across source files. Returns matching lines with file and line number.',
    params: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Regex pattern to search for.' },
        glob:    { type: 'string', description: 'Optional glob to restrict which files are searched.' },
      },
      required: ['pattern'],
    },
  },
  {
    name: 'write_file',
    description: 'Write content to a file (creates parent directories as needed). Requires --allow-writes.',
    params: {
      type: 'object',
      properties: {
        path:    { type: 'string', description: 'Relative path from the project root.' },
        content: { type: 'string', description: 'Full file content to write.' },
      },
      required: ['path', 'content'],
    },
  },
];

const TOOLS_ANTHROPIC = TOOL_DEFS.map(t => ({ name: t.name, description: t.description, input_schema: t.params }));
const TOOLS_OPENAI    = TOOL_DEFS.map(t => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.params } }));
const TOOLS_GEMINI    = TOOL_DEFS.map(t => ({ name: t.name, description: t.description, parameters: t.params }));

// ─── Shared Helpers ───────────────────────────────────────────────────────────

const MAX_TURNS        = 60;
const MAX_OUTPUT_TOKENS = 8192;

function redact(text, apiKey) {
  if (!apiKey || !text) return text || '';
  return text.split(apiKey).join('[REDACTED]');
}

function logTool(name, input, verbose) {
  if (!verbose) return;
  const preview = JSON.stringify(input || {}).slice(0, 100);
  process.stderr.write(`  [tool: ${name}] ${preview}\n`);
}

// ─── Anthropic Agentic Loop ───────────────────────────────────────────────────

async function runAnthropicAudit({ systemPrompt, userMessage, apiKey, model, projectDir, allowWrites, verbose, writer }) {
  const MODEL   = model || 'claude-opus-4-6';
  const URL     = 'https://api.anthropic.com/v1/messages';
  const headers = {
    'Content-Type':      'application/json',
    'x-api-key':         apiKey,
    'anthropic-version': '2023-06-01',
  };

  const messages = [{ role: 'user', content: userMessage }];

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const res = await fetch(URL, {
      method:  'POST',
      headers,
      body: JSON.stringify({
        model:      MODEL,
        max_tokens: MAX_OUTPUT_TOKENS,
        system:     systemPrompt,
        tools:      TOOLS_ANTHROPIC,
        messages,
      }),
    });

    if (!res.ok) {
      const raw = await res.text().catch(() => '');
      throw new Error(`Anthropic returned ${res.status}: ${redact(raw, apiKey).slice(0, 300)}`);
    }

    const data = await res.json();
    const { content, stop_reason } = data;

    messages.push({ role: 'assistant', content });

    for (const block of content) {
      if (block.type === 'text' && block.text) writer(block.text);
    }

    if (stop_reason !== 'tool_use') break;

    const toolResults = [];
    for (const block of content) {
      if (block.type !== 'tool_use') continue;
      logTool(block.name, block.input, verbose);
      const result = executeToolCall(block.name, block.input || {}, projectDir, { allowWrites });
      toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: JSON.stringify(result) });
    }
    messages.push({ role: 'user', content: toolResults });
  }
}

// ─── OpenAI / OpenAI-Compatible Agentic Loop ──────────────────────────────────

async function runOpenAIAudit({ systemPrompt, userMessage, apiKey, model, baseUrl, projectDir, allowWrites, verbose, writer }) {
  // Validate baseUrl to prevent SSRF — same guard as callProvider() in remediator.js (SEC-19/SEC-24).
  // Only HTTPS is allowed for non-localhost hosts.
  if (baseUrl) {
    let parsed;
    try { parsed = new URL(baseUrl); } catch {
      throw new Error(`Invalid baseUrl "${baseUrl}" — must be a valid URL`);
    }
    const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
    if (parsed.protocol !== 'https:' && !isLocalhost) {
      throw new Error(
        `baseUrl must use HTTPS for non-localhost hosts (got "${parsed.protocol}//${parsed.hostname}"). ` +
        'Plain HTTP is only allowed for localhost.',
      );
    }
  }

  const MODEL    = model || 'gpt-4o';
  const base     = (baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
  const endpoint = `${base}/chat/completions`;
  const headers  = {
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${apiKey}`,
  };

  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user',   content: userMessage },
  ];

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const res = await fetch(endpoint, {
      method:  'POST',
      headers,
      body: JSON.stringify({ model: MODEL, tools: TOOLS_OPENAI, messages, max_tokens: MAX_OUTPUT_TOKENS }),
    });

    if (!res.ok) {
      const raw = await res.text().catch(() => '');
      throw new Error(`OpenAI returned ${res.status}: ${redact(raw, apiKey).slice(0, 300)}`);
    }

    const data   = await res.json();
    const choice = data.choices?.[0];
    if (!choice) throw new Error('Empty response from OpenAI');

    const { message, finish_reason } = choice;
    messages.push(message);

    if (message.content) writer(message.content);
    if (finish_reason === 'stop') break;

    if (finish_reason === 'tool_calls' && message.tool_calls?.length) {
      for (const tc of message.tool_calls) {
        let input = {};
        try { input = JSON.parse(tc.function.arguments || '{}'); } catch { /* malformed */ }
        logTool(tc.function.name, input, verbose);
        const result = executeToolCall(tc.function.name, input, projectDir, { allowWrites });
        messages.push({ role: 'tool', tool_call_id: tc.id, content: JSON.stringify(result) });
      }
    }
  }
}

// ─── Gemini Agentic Loop ──────────────────────────────────────────────────────

async function runGeminiAudit({ systemPrompt, userMessage, apiKey, model, projectDir, allowWrites, verbose, writer }) {
  const MODEL   = model || 'gemini-2.0-flash';
  const URL     = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(MODEL)}:generateContent`;
  const headers = { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey };

  const contents = [{ role: 'user', parts: [{ text: userMessage }] }];

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const res = await fetch(URL, {
      method:  'POST',
      headers,
      body: JSON.stringify({
        contents,
        systemInstruction: { parts: [{ text: systemPrompt }] },
        tools: [{ functionDeclarations: TOOLS_GEMINI }],
      }),
    });

    if (!res.ok) {
      const raw = await res.text().catch(() => '');
      throw new Error(`Gemini returned ${res.status}: ${redact(raw, apiKey).slice(0, 300)}`);
    }

    const data      = await res.json();
    const candidate = data.candidates?.[0];
    if (!candidate) throw new Error('Empty response from Gemini');

    const parts        = candidate.content?.parts || [];
    const finishReason = candidate.finishReason;

    contents.push({ role: 'model', parts });

    const functionCalls = parts.filter(p => p.functionCall);
    for (const p of parts.filter(pp => pp.text)) writer(p.text);

    if (finishReason === 'STOP' || functionCalls.length === 0) break;

    const functionResponses = [];
    for (const p of functionCalls) {
      const { name, args } = p.functionCall;
      logTool(name, args, verbose);
      const result = executeToolCall(name, args || {}, projectDir, { allowWrites });
      functionResponses.push({ functionResponse: { name, response: result } });
    }
    contents.push({ role: 'user', parts: functionResponses });
  }
}

// ─── Fallback: single-shot for providers without tool use (e.g. ollama) ───────

async function runFallbackAudit({ systemPrompt, userMessage, provider, apiKey, model, baseUrl, projectDir, writer }) {
  const { callProvider } = require('./remediator');
  const { walkFiles }    = require('./scanner');

  process.stderr.write('  (provider does not support tool use — bundling project context for single-shot audit)\n\n');

  const fileSamples = [];
  for (const filePath of walkFiles(projectDir)) {
    if (fileSamples.length >= 15) break;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 8000) continue;
      const buf = fs.readFileSync(filePath);
      if (buf.indexOf(0) !== -1) continue;
      const rel = path.relative(projectDir, filePath);
      fileSamples.push(`### ${rel}\n\`\`\`\n${buf.toString('utf8').slice(0, 3000)}\n\`\`\``);
    } catch { /* skip */ }
  }

  const bundled = [systemPrompt, '\n\n## Project Files (sample)\n\n', fileSamples.join('\n\n'), '\n\n## Task\n\n', userMessage].join('');
  const result  = await callProvider(provider, apiKey, model, bundled, baseUrl);
  writer(result);
}

// ─── Output Post-Processing ───────────────────────────────────────────────────

/**
 * Given the buffered LLM text, extract the structured JSON report,
 * wrap it in the standard envelope, and emit it via outputWriter.
 *
 * @param {string}   buffered      - raw LLM text accumulated by the writer
 * @param {string}   outputFormat  - 'json' | 'sarif'
 * @param {object}   meta          - { provider, model, scanOnly }
 * @param {Function} [outputWriter] - where to send the final output
 *                                    (defaults to process.stdout.write)
 */
function emitStructuredOutput(buffered, outputFormat, meta, outputWriter) {
  const write = outputWriter || ((s) => process.stdout.write(s));
  const { provider, model, scanOnly, depth } = meta;

  const extracted = extractJsonBlock(buffered);
  if (!extracted) {
    process.stderr.write('\n⚠️  Could not extract a JSON report from the LLM response. Raw output:\n\n');
    write(buffered + '\n');
    return;
  }
  const envelope = aiToJson(extracted, { provider, model, scanOnly, depth });
  write(JSON.stringify(outputFormat === 'sarif' ? aiToSarif(envelope) : envelope, null, 2) + '\n');
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

/**
 * Run the TDD Audit against a project using an LLM with tool use.
 *
 * @param {object}  opts
 * @param {string}   opts.projectDir    - absolute path to the project being audited
 * @param {string}   opts.packageDir    - absolute path to the tdd-audit package (where SKILL.md lives)
 * @param {string}   opts.provider      - 'anthropic' | 'openai' | 'gemini' | 'ollama' | openai-compat
 * @param {string}   opts.apiKey        - API key for the provider
 * @param {string}   [opts.model]       - model override
 * @param {string}   [opts.baseUrl]     - base URL override (OpenAI-compatible providers)
 * @param {string}   [opts.outputFormat]- 'text' (default) | 'json' | 'sarif'
 * @param {boolean}  [opts.scanOnly]    - generate audit report only, no code changes
 * @param {boolean}  [opts.allowWrites] - allow the LLM to write files (default false)
 * @param {boolean}  [opts.verbose]     - print tool call details to stderr
 * @param {Function} [opts.onText]      - called with each text chunk as the LLM streams output.
 *                                        When provided AND outputFormat is 'text', stdout is NOT
 *                                        written — the caller is responsible for all output.
 * @param {Function} [opts.outputWriter]- replaces process.stdout.write for the final structured
 *                                        output when outputFormat is 'json' or 'sarif'.
 *                                        Useful for capturing output in plugin/server mode.
 */
async function runAudit(opts) {
  const {
    projectDir,
    packageDir,
    provider,
    apiKey,
    model,
    baseUrl,
    outputFormat = 'text',
    depth        = 'tier-1',
    findings     = null,   // pre-identified findings from a prior tier-3 report
    verbose      = false,
    onText,
    outputWriter,
  } = opts;

  if (!provider) throw new Error('No provider specified. Use --provider or set it in .tdd-audit.json');
  if (!apiKey)   throw new Error('No API key found. Use --api-key, set apiKey in .tdd-audit.json, or use apiKeyEnv');

  // Depth-tier capability resolution:
  //   tier-4 → allowWrites=true, full audit (or targeted patch apply when findings supplied)
  //   tier-3 → read-only, full audit with copy-ready patch fields
  //   tier-2 → read-only, scan-only audit with rich fields
  //   tier-1 → read-only, scan-only audit, minimal fields
  const allowWrites = opts.allowWrites || depth === 'tier-4';
  const scanOnly    = opts.scanOnly    != null ? opts.scanOnly : (depth === 'tier-1' || depth === 'tier-2');

  // Targeted apply: when findings are pre-supplied with depth=tier-4, skip scanning
  // entirely and instruct the LLM to apply only those specific patches.
  const isTargetedApply = depth === 'tier-4' && Array.isArray(findings) && findings.length > 0;

  const suite        = loadSkillSuite(packageDir);
  const systemPrompt = buildSystemPrompt(suite);

  // Compose user message
  const structured = outputFormat !== 'text';
  let lines;

  if (isTargetedApply) {
    // Targeted mode: no scan, apply only the supplied patches
    lines = [
      'Apply the following pre-identified patch(es) to the project using write_file.',
      'Do NOT re-scan the codebase. Only work on the findings listed below.',
      'For each finding: read the current file, apply the patch, write the result back.',
      '',
      '## Findings to apply',
      '',
      JSON.stringify(findings, null, 2),
      '',
      'Track every patch attempt in the remediation array (status=fixed if written, skipped if not).',
    ];
  } else if (scanOnly) {
    lines = [
      'Run the TDD Remediation Protocol Auto-Audit on this project in scan-only mode.',
      'Use the available tools to explore the codebase. Follow Phase 0 of the auto-audit protocol:',
      '  1. Detect the tech stack',
      '  2. Explore the architecture',
      '  3. Search for vulnerability patterns',
      '  4. Present the Audit Report (grouped by severity: CRITICAL / HIGH / MEDIUM / LOW)',
      'Stop after presenting the Audit Report. Do not write any files.',
    ];
  } else {
    lines = [
      'Run the TDD Remediation Protocol Auto-Audit on this project.',
      'Use the available tools to explore the codebase, identify vulnerabilities, and follow the full protocol:',
      '  Phase 0   — Detect stack, explore architecture, present Audit Report',
      '  Phase 1–3 — Remediate each vulnerability using Red-Green-Refactor (one at a time, CRITICAL first)',
      '  Phase 4   — Coverage gate (≥ 95%)',
      '  Phase 5   — README badge',
      '  Phase 6   — SECURITY.md',
      allowWrites
        ? 'You have permission to write files using the write_file tool.'
        : 'File writes are disabled. Describe the changes you would make but do not call write_file.',
    ];
  }

  if (structured) lines.push(buildJsonOutputInstruction(depth));

  const userMessage = lines.join('\n');

  const mode = isTargetedApply
    ? `targeted-apply/${depth}(${findings.length})`
    : scanOnly ? `scan-only/${depth}` : allowWrites ? `full/${depth}+writes` : `full/${depth}`;
  process.stderr.write(`\n🤖 TDD Audit — provider: ${provider}, model: ${model || '(default)'}, mode: ${mode}, format: ${outputFormat}\n\n`);

  // Build the text writer.
  // - When structured output is requested, always buffer for JSON extraction.
  // - When onText is provided, forward each chunk to the caller (for SSE streaming etc.).
  // - When neither structured nor onText, write directly to stdout (CLI text mode).
  const buffer = [];
  const writer = (text) => {
    if (structured) buffer.push(text);
    if (onText) onText(text);
    else if (!structured) process.stdout.write(text);
  };

  const ctx = { systemPrompt, userMessage, apiKey, model, baseUrl, projectDir, allowWrites, verbose, writer };

  switch (provider) {
    case 'anthropic': await runAnthropicAudit(ctx); break;
    case 'openai':    await runOpenAIAudit(ctx);    break;
    case 'gemini':    await runGeminiAudit(ctx);    break;
    default:
      // OpenAI-compatible providers (groq, together, openrouter, etc.) go through the OpenAI loop
      if (baseUrl) await runOpenAIAudit(ctx);
      else         await runFallbackAudit({ ...ctx, provider });
  }

  if (structured) {
    emitStructuredOutput(buffer.join(''), outputFormat, { provider, model, scanOnly, depth }, outputWriter);
  }

  process.stderr.write('\n✅ Audit complete.\n');
}

module.exports = {
  runAudit,
  loadSkillSuite,
  buildSystemPrompt,
  buildJsonOutputInstruction,
  DEPTH_JSON_INSTRUCTIONS,
  executeToolCall,
  extractJsonBlock,
  aiToJson,
  aiToSarif,
  TOOLS_ANTHROPIC,
  TOOLS_OPENAI,
  TOOLS_GEMINI,
  // exported for tests
  safePath,
  toolReadFile,
  toolListFiles,
  toolSearchInFiles,
  toolWriteFile,
};
