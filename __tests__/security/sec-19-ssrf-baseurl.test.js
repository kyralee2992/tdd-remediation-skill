'use strict';

/**
 * SEC-19 — SSRF via user-controlled baseUrl in callProvider() (MEDIUM).
 *
 * Attack vector: POST /remediate accepts a `baseUrl` field in the request body.
 * That value is passed directly to callProvider() and used in fetch() with only
 * a trailing-slash trim — no protocol check, no host allowlist.
 * An attacker can supply `http://169.254.169.254` (cloud metadata) or any
 * internal service URL and make the server issue a request on their behalf.
 *
 * Fix: validate `baseUrl` in callProvider() before constructing the fetch URL.
 * Reject any non-localhost URL that does not use HTTPS.
 */

const { callProvider } = require('../../lib/remediator');

// Track whether fetch was called — we want to verify the guard fires BEFORE any
// network attempt, not just that the call eventually fails.
let fetchCalled = false;
const originalFetch = global.fetch;

beforeEach(() => {
  fetchCalled = false;
  global.fetch = async (url) => {
    fetchCalled = true;
    // Simulate a reachable response so no network error masks a missing guard
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"exploitTest":{},"patch":{},"refactorChecks":[]}' } }] }),
    };
  };
});

afterEach(() => {
  global.fetch = originalFetch;
});

describe('SEC-19: SSRF — baseUrl validation in callProvider()', () => {
  test('rejects http:// baseUrl targeting cloud metadata endpoint', async () => {
    await expect(
      callProvider('openai', 'sk-test', 'gpt-4o', 'prompt', 'http://169.254.169.254')
    ).rejects.toThrow(/https|non-localhost|SSRF/i);
    expect(fetchCalled).toBe(false);
  });

  test('rejects http:// baseUrl targeting arbitrary internal host', async () => {
    await expect(
      callProvider('openai', 'sk-test', 'gpt-4o', 'prompt', 'http://internal.corp')
    ).rejects.toThrow(/https|non-localhost|SSRF/i);
    expect(fetchCalled).toBe(false);
  });

  test('rejects http:// baseUrl targeting private IP', async () => {
    await expect(
      callProvider('openai', 'sk-test', 'gpt-4o', 'prompt', 'http://10.0.0.1')
    ).rejects.toThrow(/https|non-localhost|SSRF/i);
    expect(fetchCalled).toBe(false);
  });

  test('allows https:// baseUrl for OpenAI-compatible providers', async () => {
    await expect(
      callProvider('openai', 'sk-test', 'gpt-4o', 'prompt', 'https://api.groq.com/openai/v1')
    ).resolves.toBeDefined();
    expect(fetchCalled).toBe(true);
  });

  test('allows http://localhost baseUrl for local providers', async () => {
    await expect(
      callProvider('openai', 'sk-test', 'gpt-4o', 'prompt', 'http://localhost:11434')
    ).resolves.toBeDefined();
    expect(fetchCalled).toBe(true);
  });

  test('allows http://127.0.0.1 baseUrl for local providers', async () => {
    await expect(
      callProvider('openai', 'sk-test', 'gpt-4o', 'prompt', 'http://127.0.0.1:11434')
    ).resolves.toBeDefined();
    expect(fetchCalled).toBe(true);
  });

  test('rejects malformed baseUrl', async () => {
    await expect(
      callProvider('openai', 'sk-test', 'gpt-4o', 'prompt', 'not-a-url')
    ).rejects.toThrow();
    expect(fetchCalled).toBe(false);
  });
});
