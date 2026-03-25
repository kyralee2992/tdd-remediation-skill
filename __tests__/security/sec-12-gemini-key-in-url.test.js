'use strict';

/**
 * SEC-12 — Gemini API key must not be passed as a URL query parameter.
 *
 * Attack vector: the API key appears in server access logs, proxy logs,
 * HTTP Referer headers, and any HTTP debugging toolkit trace whenever
 * it is embedded in the URL as `?key=<apiKey>`.
 *
 * Fix: pass the key via the `x-goog-api-key` request header instead.
 */

const { PROVIDERS } = require('../../lib/remediator');

describe('SEC-12: Gemini API key must not appear in the request URL', () => {
  const TEST_KEY = 'test-gemini-key-abc123';

  test('Gemini URL is a static string (not a function receiving the key)', () => {
    const gemini = PROVIDERS.gemini;
    const url = typeof gemini.url === 'function' ? gemini.url(TEST_KEY) : gemini.url;
    expect(typeof url).toBe('string');
    expect(url).not.toContain(TEST_KEY);
  });

  test('Gemini URL does not include ?key= query parameter', () => {
    const gemini = PROVIDERS.gemini;
    const url = typeof gemini.url === 'function' ? gemini.url(TEST_KEY) : gemini.url;
    expect(url).not.toMatch(/[?&]key=/);
  });

  test('Gemini passes API key via x-goog-api-key header', () => {
    const headers = PROVIDERS.gemini.headers(TEST_KEY);
    expect(headers['x-goog-api-key']).toBe(TEST_KEY);
  });

  test('other providers are unaffected', () => {
    // Anthropic should still use x-api-key header
    expect(PROVIDERS.anthropic.headers(TEST_KEY)['x-api-key']).toBe(TEST_KEY);
    // OpenAI should still use Authorization: Bearer
    expect(PROVIDERS.openai.headers(TEST_KEY)['Authorization']).toContain(TEST_KEY);
  });
});
