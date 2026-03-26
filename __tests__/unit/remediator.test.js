'use strict';

/**
 * Unit tests — lib/remediator.js
 * Covers: PROVIDERS, buildRemediationPrompt, callProvider (mocked), remediate (mocked)
 */

const { PROVIDERS, buildRemediationPrompt, callProvider, remediate } = require('../../lib/remediator');

// ── PROVIDERS ─────────────────────────────────────────────────────────────────

describe('PROVIDERS registry', () => {
  test('contains anthropic, openai, gemini, ollama', () => {
    expect(Object.keys(PROVIDERS)).toEqual(
      expect.arrayContaining(['anthropic', 'openai', 'gemini', 'ollama']),
    );
  });

  test('openai has openaiCompat: true', () => {
    expect(PROVIDERS.openai.openaiCompat).toBe(true);
  });

  test('openai default URL points to api.openai.com', () => {
    const url = typeof PROVIDERS.openai.url === 'function'
      ? PROVIDERS.openai.url('key')
      : PROVIDERS.openai.url;
    expect(url).toContain('api.openai.com');
  });

  test('gemini URL is a static string (no key in URL)', () => {
    expect(typeof PROVIDERS.gemini.url).toBe('string');
    expect(PROVIDERS.gemini.url).not.toMatch(/[?&]key=/);
  });

  test('gemini passes key via x-goog-api-key header', () => {
    expect(PROVIDERS.gemini.headers('my-key')['x-goog-api-key']).toBe('my-key');
  });

  test('anthropic passes key via x-api-key header', () => {
    expect(PROVIDERS.anthropic.headers('ak')['x-api-key']).toBe('ak');
  });

  test('openai uses Bearer auth', () => {
    expect(PROVIDERS.openai.headers('ok').Authorization).toContain('ok');
  });

  test('ollama body includes prompt field', () => {
    const body = PROVIDERS.ollama.body('llama3', 'Hello');
    expect(body.prompt).toBe('Hello');
    expect(body.stream).toBe(false);
  });

  test('anthropic extract pulls content[0].text', () => {
    const data = { content: [{ text: 'result' }] };
    expect(PROVIDERS.anthropic.extract(data)).toBe('result');
  });

  test('openai extract pulls choices[0].message.content', () => {
    const data = { choices: [{ message: { content: 'result' } }] };
    expect(PROVIDERS.openai.extract(data)).toBe('result');
  });

  test('gemini extract pulls candidates[0].content.parts[0].text', () => {
    const data = { candidates: [{ content: { parts: [{ text: 'result' }] } }] };
    expect(PROVIDERS.gemini.extract(data)).toBe('result');
  });

  test('ollama extract pulls response', () => {
    expect(PROVIDERS.ollama.extract({ response: 'text' })).toBe('text');
  });

  test('extractors return empty string on missing data', () => {
    expect(PROVIDERS.anthropic.extract({})).toBe('');
    expect(PROVIDERS.openai.extract({})).toBe('');
    expect(PROVIDERS.gemini.extract({})).toBe('');
    expect(PROVIDERS.ollama.extract({})).toBe('');
  });
});

// ── buildRemediationPrompt ────────────────────────────────────────────────────

describe('buildRemediationPrompt', () => {
  const base = { name: 'XSS', severity: 'HIGH', file: 'src/app.js', line: 10, snippet: 'res.send(x)' };

  test('prompt contains finding fields', () => {
    const p = buildRemediationPrompt(base);
    expect(p).toMatch(/XSS/);
    expect(p).toMatch(/HIGH/);
    expect(p).toMatch(/src\/app\.js/);
    expect(p).toMatch(/10/);
  });

  test('snippet is wrapped in <snippet> delimiters', () => {
    const p = buildRemediationPrompt(base);
    expect(p).toMatch(/<snippet>res\.send\(x\)<\/snippet>/);
  });

  test('newlines in snippet are collapsed', () => {
    const p = buildRemediationPrompt({ ...base, snippet: 'line1\nline2' });
    expect(p).not.toMatch(/^line2/m);
  });

  test('null bytes in snippet are stripped', () => {
    const p = buildRemediationPrompt({ ...base, snippet: 'ok\x00bad' });
    expect(p).not.toContain('\x00');
  });

  test('long snippet is truncated to ≤500 chars within delimiters', () => {
    const p = buildRemediationPrompt({ ...base, snippet: 'x'.repeat(2000) });
    // Extract what's between <snippet> tags
    const inner = p.match(/<snippet>(.*?)<\/snippet>/s)?.[1] || '';
    expect(inner.length).toBeLessThanOrEqual(500);
  });

  test('prompt requests JSON response with exploitTest + patch + refactorChecks', () => {
    const p = buildRemediationPrompt(base);
    expect(p).toMatch(/exploitTest/);
    expect(p).toMatch(/patch/);
    expect(p).toMatch(/refactorChecks/);
  });

  test('undefined snippet produces empty content between snippet delimiters', () => {
    const p = buildRemediationPrompt({ ...base, snippet: undefined });
    expect(p).toContain('<snippet></snippet>');
  });
});

// ── callProvider ──────────────────────────────────────────────────────────────

describe('callProvider', () => {
  beforeEach(() => { global.fetch = jest.fn(); });
  afterEach(() => { delete global.fetch; });

  test('throws for unknown provider', async () => {
    await expect(callProvider('unknown', 'key', 'model', 'prompt'))
      .rejects.toThrow(/Unknown provider/);
  });

  test('calls the correct URL for anthropic', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ content: [{ text: 'ok' }] }),
    });
    await callProvider('anthropic', 'ak', 'claude-opus-4-6', 'hello');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('anthropic.com'),
      expect.any(Object),
    );
  });

  test('overrides openai URL when baseUrl is provided', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ choices: [{ message: { content: 'ok' } }] }),
    });
    await callProvider('openai', 'ok', 'llama3', 'hello', 'https://api.groq.com/openai/v1');
    const calledUrl = global.fetch.mock.calls[0][0];
    expect(calledUrl).toContain('groq.com');
    expect(calledUrl).toContain('chat/completions');
  });

  test('baseUrl trailing slash is stripped before appending path', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ choices: [{ message: { content: 'ok' } }] }),
    });
    await callProvider('openai', 'ok', null, 'hello', 'https://api.example.com/v1/');
    const calledUrl = global.fetch.mock.calls[0][0];
    expect(calledUrl).not.toMatch(/\/\/chat/);
    expect(calledUrl).toBe('https://api.example.com/v1/chat/completions');
  });

  test('throws on non-ok provider response', async () => {
    global.fetch.mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => 'Unauthorized',
    });
    await expect(callProvider('anthropic', 'bad', null, 'hi'))
      .rejects.toThrow(/401/);
  });

  test('baseUrl does not affect non-openaiCompat providers', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ candidates: [{ content: { parts: [{ text: 'ok' }] } }] }),
    });
    await callProvider('gemini', 'gk', null, 'hello', 'https://custom.example.com');
    const calledUrl = global.fetch.mock.calls[0][0];
    expect(calledUrl).toContain('generativelanguage.googleapis.com');
  });

  test('calls ollama with correct localhost URL and uses default model when null', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ response: 'fixed code' }),
    });
    // null model → triggers `model || 'llama3'` default branch in ollama body builder
    await callProvider('ollama', '', null, 'hello');
    const calledUrl = global.fetch.mock.calls[0][0];
    expect(calledUrl).toContain('localhost:11434');
    const sentBody = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(sentBody.model).toBe('llama3');
  });

  test('error message is not redacted when apiKey is empty string', async () => {
    global.fetch.mockResolvedValue({
      ok: false, status: 403,
      text: async () => 'Forbidden body without key',
    });
    // Empty string apiKey is falsy → `apiKey ? ... : raw` false branch
    await expect(callProvider('ollama', '', null, 'hi')).rejects.toThrow(/403/);
  });

  test('res.text() failure is swallowed and returns empty string in error message', async () => {
    global.fetch.mockResolvedValue({
      ok: false, status: 500,
      text: () => Promise.reject(new Error('stream error')),
    });
    await expect(callProvider('anthropic', 'key', null, 'hi')).rejects.toThrow(/500/);
  });

  test('throws for invalid baseUrl format', async () => {
    await expect(callProvider('openai', 'key', null, 'hi', 'not-a-valid-url'))
      .rejects.toThrow(/valid URL/);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('throws for HTTP non-localhost baseUrl (SSRF protection)', async () => {
    await expect(callProvider('openai', 'key', null, 'hi', 'http://evil.example.com/v1'))
      .rejects.toThrow(/HTTPS/);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

// ── remediate ─────────────────────────────────────────────────────────────────

describe('remediate', () => {
  beforeEach(() => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        choices: [{
          message: {
            content: JSON.stringify({
              exploitTest:    { filename: 'test.js', content: '// test' },
              patch:          { filename: 'src.js', diff: '--- a' },
              refactorChecks: ['run tests'],
            }),
          },
        }],
      }),
    });
  });

  afterEach(() => { delete global.fetch; });

  const findings = [
    { severity: 'HIGH',   name: 'XSS',           file: 'a.js', line: 1, snippet: 'x', likelyFalsePositive: false },
    { severity: 'MEDIUM', name: 'Open Redirect',  file: 'b.js', line: 2, snippet: 'y', likelyFalsePositive: false },
    { severity: 'LOW',    name: 'Sensitive Storage', file: 'c.js', line: 3, snippet: 'z', likelyFalsePositive: false },
    { severity: 'HIGH',   name: 'FP finding',     file: 'd.js', line: 4, snippet: 'w', likelyFalsePositive: true  },
  ];

  test('excludes likelyFalsePositive findings', async () => {
    const results = await remediate({ findings, provider: 'openai', apiKey: 'k' });
    const names = results.map(r => r.finding.name);
    expect(names).not.toContain('FP finding');
  });

  test('filters by severity threshold', async () => {
    const results = await remediate({ findings, provider: 'openai', apiKey: 'k', severity: 'HIGH' });
    // Only HIGH (and above) should be included; MEDIUM and LOW excluded
    expect(results.every(r => r.finding.severity === 'HIGH')).toBe(true);
  });

  test('results include remediated status and parsed fields', async () => {
    const results = await remediate({
      findings: [findings[0]],
      provider: 'openai', apiKey: 'k',
    });
    expect(results[0].status).toBe('remediated');
    expect(results[0].exploitTest).toBeDefined();
    expect(results[0].patch).toBeDefined();
  });

  test('errors per finding are captured without throwing', async () => {
    global.fetch.mockRejectedValueOnce(new Error('Network failure'));
    const results = await remediate({
      findings: [findings[0]],
      provider: 'openai', apiKey: 'k',
    });
    expect(results[0].status).toBe('error');
    expect(results[0].error).toMatch(/Network failure/);
  });

  test('unknown severity threshold falls back to LOW (?? 3 branch)', async () => {
    const results = await remediate({
      findings: [findings[0]], // HIGH finding
      provider: 'openai', apiKey: 'k',
      severity: 'UNKNOWN_LEVEL', // not in ORDER → threshold = undefined ?? 3 = 3 (LOW)
    });
    // HIGH (ORDER=1) <= threshold 3, so finding is included
    expect(results.length).toBeGreaterThan(0);
  });

  test('finding with unknown severity maps to 99 and is filtered by HIGH threshold', async () => {
    const unknownSevFinding = {
      severity: 'CUSTOM', name: 'Custom', file: 'a.js', line: 1,
      snippet: 'x', likelyFalsePositive: false,
    };
    // severity threshold HIGH (ORDER=1); CUSTOM maps to 99 > 1, so filtered out
    const results = await remediate({
      findings: [unknownSevFinding],
      provider: 'openai', apiKey: 'k',
      severity: 'HIGH',
    });
    expect(results).toHaveLength(0);
  });

  test('model response with no JSON object results in error status', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ choices: [{ message: { content: 'sorry, no json here at all' } }] }),
    });
    const results = await remediate({
      findings: [findings[0]],
      provider: 'openai', apiKey: 'k',
    });
    expect(results[0].status).toBe('error');
    expect(results[0].error).toMatch(/JSON/);
  });
});

// ─── remediate — onProgress callback ─────────────────────────────────────────

describe('remediate — onProgress callback', () => {
  const mockFindings = [
    { severity: 'HIGH', name: 'XSS', file: 'a.js', line: 1, snippet: 'x', likelyFalsePositive: false },
    { severity: 'HIGH', name: 'SQLi', file: 'b.js', line: 2, snippet: 'y', likelyFalsePositive: false },
  ];

  beforeEach(() => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"exploitTest":{},"patch":{},"refactorChecks":[]}' } }] }),
    });
  });

  test('onProgress is called once per finding with (completed, name)', async () => {
    const calls = [];
    await remediate({
      findings: mockFindings,
      provider: 'openai', apiKey: 'k',
      onProgress: (completed, name) => calls.push({ completed, name }),
    });
    expect(calls).toHaveLength(2);
    expect(calls[0]).toEqual({ completed: 1, name: 'XSS' });
    expect(calls[1]).toEqual({ completed: 2, name: 'SQLi' });
  });

  test('remediate works normally when onProgress is not supplied', async () => {
    const results = await remediate({
      findings: mockFindings,
      provider: 'openai', apiKey: 'k',
      // no onProgress
    });
    expect(results).toHaveLength(2);
  });
});

// ─── buildRemediationPrompt — null / undefined fields ────────────────────────

describe('buildRemediationPrompt() — null/undefined field sanitization', () => {
  test('handles null fields without throwing (covers raw ?? "" branch)', () => {
    const prompt = buildRemediationPrompt({
      name: null, severity: null, file: null, line: null, snippet: null,
    });
    expect(typeof prompt).toBe('string');
    expect(prompt).toContain('VULNERABILITY FINDING');
  });

  test('handles undefined fields without throwing', () => {
    const prompt = buildRemediationPrompt({
      name: undefined, severity: undefined, file: undefined, line: undefined, snippet: undefined,
    });
    expect(typeof prompt).toBe('string');
  });
});

// ─── remediate() — unknown severity ?? 99 branch ─────────────────────────────

describe('remediate() — unknown severity ?? 99 in filter', () => {
  beforeEach(() => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"exploitTest":{},"patch":{},"refactorChecks":[]}' } }] }),
    });
  });
  afterEach(() => { delete global.fetch; });

  test('finding with unknown severity is filtered out via ?? 99 branch', async () => {
    // ORDER['UNKNOWN'] is undefined — ?? 99 evaluates to 99, which exceeds LOW threshold (3)
    const findings = [
      { severity: 'UNKNOWN', name: 'Mystery', file: 'a.js', line: 1, snippet: 'x', likelyFalsePositive: false },
      { severity: 'HIGH',    name: 'XSS',     file: 'b.js', line: 2, snippet: 'y', likelyFalsePositive: false },
    ];
    const results = await remediate({ findings, provider: 'openai', apiKey: 'k' });
    // Only HIGH passes the filter; UNKNOWN is excluded (99 > threshold=3)
    expect(results).toHaveLength(1);
    expect(results[0].finding.name).toBe('XSS');
  });
});
