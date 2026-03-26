'use strict';

// ─── Provider endpoints ───────────────────────────────────────────────────────

const PROVIDERS = {
  anthropic: {
    url:     'https://api.anthropic.com/v1/messages',
    headers: (apiKey) => ({
      'Content-Type':      'application/json',
      'x-api-key':         apiKey,
      'anthropic-version': '2023-06-01',
    }),
    body: (model, prompt) => ({
      model:      model || 'claude-opus-4-6',
      max_tokens: 8192,
      messages:   [{ role: 'user', content: prompt }],
    }),
    extract: (data) => data?.content?.[0]?.text || '',
  },
  openai: {
    url:          'https://api.openai.com/v1/chat/completions',
    openaiCompat: true,  // supports --base-url override for compatible APIs
    headers: (apiKey) => ({
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${apiKey}`,
    }),
    body: (model, prompt) => ({
      model:    model || 'gpt-4o',
      messages: [{ role: 'user', content: prompt }],
    }),
    extract: (data) => data?.choices?.[0]?.message?.content || '',
  },
  gemini: {
    url:     'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent',
    headers: (apiKey) => ({ 'Content-Type': 'application/json', 'x-goog-api-key': apiKey }),
    body: (model, prompt) => ({
      contents: [{ parts: [{ text: prompt }] }],
    }),
    extract: (data) => data?.candidates?.[0]?.content?.parts?.[0]?.text || '',
  },
  ollama: {
    url:     'http://localhost:11434/api/generate',
    headers: () => ({ 'Content-Type': 'application/json' }),
    body: (model, prompt) => ({
      model:  model || 'llama3',
      prompt,
      stream: false,
    }),
    extract: (data) => data?.response || '',
  },
};

// ─── Prompt builder ───────────────────────────────────────────────────────────

const MAX_SNIPPET_CHARS = 500;

/**
 * Sanitize a raw code snippet before embedding it in an AI prompt.
 * Strips null bytes, limits length, and trims whitespace so that
 * injected newlines cannot introduce new top-level instruction lines.
 */
function sanitizeSnippet(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .replace(/\x00/g, '')          // strip null bytes
    .replace(/[\r\n]+/g, ' ')      // collapse newlines → prevent line injection
    .slice(0, MAX_SNIPPET_CHARS)
    .trim();
}

/**
 * Sanitize a scalar finding field (name, file, line, severity) before
 * embedding it in an AI prompt. Strips null bytes and collapses newlines
 * so that attacker-controlled metadata cannot inject top-level instructions.
 */
function sanitizeField(raw) {
  const s = typeof raw === 'string' ? raw : String(raw ?? '');
  return s
    .replace(/\x00/g, '')
    .replace(/[\r\n]+/g, ' ')
    .trim();
}

function buildRemediationPrompt(finding) {
  const snippet  = sanitizeSnippet(finding.snippet);
  const name     = sanitizeField(finding.name);
  const severity = sanitizeField(finding.severity);
  const file     = sanitizeField(finding.file);
  const line     = sanitizeField(finding.line);
  return `You are a security engineer applying the Red-Green-Refactor TDD remediation protocol.

VULNERABILITY FINDING:
- Type: ${name}
- Severity: ${severity}
- File: ${file}
- Line: ${line}
- Code snippet: <snippet>${snippet}</snippet>

TASK:
1. Write a Jest/supertest exploit test (Red phase) that proves this vulnerability exists.
   The test must be placed in __tests__/security/ and must FAIL before the fix.
2. Write the minimum code patch (Green phase) that closes the vulnerability.
   Show it as a unified diff against the original file.
3. Confirm what regression checks to run (Refactor phase).

Respond with valid JSON in exactly this shape:
{
  "exploitTest": {
    "filename": "__tests__/security/<slug>.test.js",
    "content": "<full test file content>"
  },
  "patch": {
    "filename": "<path to file being patched>",
    "diff": "<unified diff>"
  },
  "refactorChecks": ["<check 1>", "<check 2>"]
}`;
}

// ─── HTTP call ────────────────────────────────────────────────────────────────

/**
 * @param {string}  provider  - 'anthropic' | 'openai' | 'gemini' | 'ollama'
 * @param {string}  apiKey
 * @param {string}  model
 * @param {string}  prompt
 * @param {string}  [baseUrl] - override base URL for OpenAI-compatible providers
 *                              e.g. 'https://api.groq.com/openai/v1'
 *                                   'https://openrouter.ai/api/v1'
 *                                   'https://api.together.xyz/v1'
 */
async function callProvider(provider, apiKey, model, prompt, baseUrl) {
  const p = PROVIDERS[provider];
  if (!p) throw new Error(`Unknown provider "${provider}". Supported: ${Object.keys(PROVIDERS).join(', ')}`);

  let url = typeof p.url === 'function' ? p.url(apiKey) : p.url;
  if (baseUrl && p.openaiCompat) {
    // Validate baseUrl to prevent SSRF: must be HTTPS or a localhost origin.
    let parsed;
    try { parsed = new URL(baseUrl); } catch {
      throw new Error(`Invalid baseUrl "${baseUrl}" — must be a valid URL`);
    }
    const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
    if (parsed.protocol !== 'https:' && !isLocalhost) {
      throw new Error(
        `baseUrl must use HTTPS for non-localhost hosts (got "${parsed.protocol}//${parsed.hostname}"). ` +
        'Plain HTTP is only allowed for localhost.'
      );
    }
    // Any OpenAI-compatible service: strip trailing slash and append path
    url = baseUrl.replace(/\/+$/, '') + '/chat/completions';
  }
  const headers = p.headers(apiKey);
  const body    = JSON.stringify(p.body(model, prompt));

  const res = await fetch(url, { method: 'POST', headers, body });
  if (!res.ok) {
    const raw  = await res.text().catch(() => '');
    // Redact the apiKey from provider error bodies before surfacing the message —
    // some providers echo the submitted key in 401/403 responses.
    const safe = apiKey ? raw.split(apiKey).join('[REDACTED]') : raw;
    throw new Error(`Provider ${provider} returned ${res.status}: ${safe.slice(0, 200)}`);
  }
  const data = await res.json();
  return p.extract(data);
}

// ─── Parse model response ─────────────────────────────────────────────────────

function parseResponse(text) {
  // Extract JSON from response (model may wrap it in markdown)
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) throw new Error('Model response did not contain a JSON object');
  return JSON.parse(match[0]);
}

// ─── Main remediate function ──────────────────────────────────────────────────

/**
 * Run AI-powered remediation for a list of findings.
 *
 * @param {object} opts
 * @param {Array}  opts.findings  - finding objects from quickScan
 * @param {string} opts.provider  - 'anthropic' | 'openai' | 'gemini' | 'ollama'
 * @param {string} opts.apiKey
 * @param {string} [opts.model]
 * @param {string} [opts.baseUrl]  - override base URL for OpenAI-compatible providers
 * @param {string}   [opts.severity]    - minimum severity to fix ('CRITICAL','HIGH','MEDIUM','LOW')
 * @param {Function} [opts.onProgress]  - called with (completedCount, currentFindingName) after each finding
 * @returns {Promise<Array>} - results per finding
 */
async function remediate({ findings, provider, apiKey, model, baseUrl, severity = 'LOW', onProgress }) {
  const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const threshold = ORDER[severity.toUpperCase()] ?? 3;

  const targets = findings
    .filter(f => !f.likelyFalsePositive && (ORDER[f.severity] ?? 99) <= threshold)
    .sort((a, b) => (ORDER[a.severity] ?? 99) - (ORDER[b.severity] ?? 99));

  const results = [];
  for (let i = 0; i < targets.length; i++) {
    const finding = targets[i];
    try {
      const prompt   = buildRemediationPrompt(finding);
      const raw      = await callProvider(provider, apiKey, model, prompt, baseUrl);
      const parsed   = parseResponse(raw);
      results.push({ finding, status: 'remediated', ...parsed });
    } catch (err) {
      results.push({ finding, status: 'error', error: err.message });
    }
    if (typeof onProgress === 'function') {
      onProgress(i + 1, finding.name);
    }
  }
  return results;
}

module.exports = { remediate, callProvider, buildRemediationPrompt, PROVIDERS };
