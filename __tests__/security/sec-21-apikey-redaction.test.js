'use strict';

/**
 * SEC-21 — Provider API key leakage in error messages (LOW).
 *
 * Attack vector: callProvider() includes up to 200 chars of the provider's
 * HTTP response body in the thrown error message. Some providers echo the
 * submitted API key in their error responses (e.g. "Invalid key: sk-abc...").
 * That error propagates to updateJob() and becomes visible via GET /jobs/:id —
 * leaking a credential to anyone with read access to the job store.
 *
 * Fix: redact the apiKey from callProvider() error messages before throwing.
 */

const { callProvider } = require('../../lib/remediator');

const FAKE_KEY = 'sk-test-super-secret-1234567890';

describe('SEC-21: API key redaction in provider error messages', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  test('apiKey is not present in the thrown error when provider echoes it back', async () => {
    // Simulate a provider that echoes the API key in its error body
    global.fetch = async () => ({
      ok:   false,
      status: 401,
      text: async () => `Unauthorized: invalid key ${FAKE_KEY} — please check your credentials`,
    });

    let caughtError;
    try {
      await callProvider('openai', FAKE_KEY, 'gpt-4o', 'prompt');
    } catch (e) {
      caughtError = e;
    }

    expect(caughtError).toBeDefined();
    expect(caughtError.message).not.toContain(FAKE_KEY);
  });

  test('error message still contains useful context (status code and provider)', async () => {
    global.fetch = async () => ({
      ok:   false,
      status: 429,
      text: async () => `Rate limited. Key=${FAKE_KEY}`,
    });

    let caughtError;
    try {
      await callProvider('openai', FAKE_KEY, 'gpt-4o', 'prompt');
    } catch (e) {
      caughtError = e;
    }

    expect(caughtError.message).toContain('429');
    expect(caughtError.message).toContain('openai');
  });

  test('redaction works even when apiKey appears multiple times in response', async () => {
    global.fetch = async () => ({
      ok:   false,
      status: 403,
      text: async () => `Key ${FAKE_KEY} rejected. Hint: key is ${FAKE_KEY}`,
    });

    let caughtError;
    try {
      await callProvider('openai', FAKE_KEY, 'gpt-4o', 'prompt');
    } catch (e) {
      caughtError = e;
    }

    expect(caughtError.message).not.toContain(FAKE_KEY);
  });
});
