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
    url:     'https://api.openai.com/v1/chat/completions',
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
    url:     (apiKey) => `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
    headers: () => ({ 'Content-Type': 'application/json' }),
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

function buildRemediationPrompt(finding) {
  return `You are a security engineer applying the Red-Green-Refactor TDD remediation protocol.

VULNERABILITY FINDING:
- Type: ${finding.name}
- Severity: ${finding.severity}
- File: ${finding.file}
- Line: ${finding.line}
- Code snippet: ${finding.snippet}

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

async function callProvider(provider, apiKey, model, prompt) {
  const p = PROVIDERS[provider];
  if (!p) throw new Error(`Unknown provider "${provider}". Supported: ${Object.keys(PROVIDERS).join(', ')}`);

  const url     = typeof p.url === 'function' ? p.url(apiKey) : p.url;
  const headers = p.headers(apiKey);
  const body    = JSON.stringify(p.body(model, prompt));

  const res = await fetch(url, { method: 'POST', headers, body });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Provider ${provider} returned ${res.status}: ${text.slice(0, 200)}`);
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
 * @param {string} [opts.severity] - minimum severity to fix ('CRITICAL','HIGH','MEDIUM','LOW')
 * @returns {Promise<Array>} - results per finding
 */
async function remediate({ findings, provider, apiKey, model, severity = 'LOW' }) {
  const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const threshold = ORDER[severity.toUpperCase()] ?? 3;

  const targets = findings
    .filter(f => !f.likelyFalsePositive && (ORDER[f.severity] ?? 99) <= threshold)
    .sort((a, b) => (ORDER[a.severity] ?? 99) - (ORDER[b.severity] ?? 99));

  const results = [];
  for (const finding of targets) {
    try {
      const prompt   = buildRemediationPrompt(finding);
      const raw      = await callProvider(provider, apiKey, model, prompt);
      const parsed   = parseResponse(raw);
      results.push({ finding, status: 'remediated', ...parsed });
    } catch (err) {
      results.push({ finding, status: 'error', error: err.message });
    }
  }
  return results;
}

module.exports = { remediate, callProvider, buildRemediationPrompt, PROVIDERS };
