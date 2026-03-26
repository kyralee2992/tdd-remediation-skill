'use strict';

/**
 * SEC-24 — SSRF via unvalidated `baseUrl` in runOpenAIAudit() (HIGH).
 *
 * Attack vector: `tdd-audit --ai --base-url http://169.254.169.254` (or a
 * malicious .tdd-audit.json) passes an HTTP URL for a non-localhost host into
 * runOpenAIAudit(), which constructs the fetch URL as:
 *
 *   const base = (baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
 *   const URL  = `${base}/chat/completions`;
 *
 * No protocol or hostname validation — fetch() fires against the attacker-
 * controlled target before any auth checks.  callProvider() in remediator.js
 * already guards against this (SEC-19), but runOpenAIAudit bypasses it.
 *
 * Fix: add the same HTTPS/localhost guard before constructing the URL in
 * runOpenAIAudit().
 */

const path = require('path');
const os   = require('os');
const { runAudit } = require('../../lib/auditor');

const PACKAGE_DIR = path.join(__dirname, '../..');
const PROJECT_DIR = os.tmpdir();

let fetchCalled = false;
let fetchUrl    = null;

beforeEach(() => {
  fetchCalled = false;
  fetchUrl    = null;
  global.fetch = async (url) => {
    fetchCalled = true;
    fetchUrl    = url;
    // Return a valid-looking OpenAI response so the loop doesn't crash on body parsing
    return {
      ok:   true,
      json: async () => ({
        choices: [{ message: { content: 'audit done' }, finish_reason: 'stop' }],
      }),
    };
  };
  // Suppress stderr noise from runAudit
  jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
});

afterEach(() => {
  delete global.fetch;
  jest.restoreAllMocks();
});

describe('SEC-24: SSRF — baseUrl validation in runOpenAIAudit()', () => {
  test('rejects http:// baseUrl targeting cloud metadata endpoint', async () => {
    await expect(
      runAudit({
        projectDir: PROJECT_DIR,
        packageDir: PACKAGE_DIR,
        provider:   'openai',
        apiKey:     'sk-test',
        baseUrl:    'http://169.254.169.254',
        scanOnly:   true,
      }),
    ).rejects.toThrow(/https|HTTPS|non-localhost/i);

    // Guard must fire BEFORE any network attempt
    expect(fetchCalled).toBe(false);
  });

  test('rejects http:// baseUrl targeting private IP range', async () => {
    await expect(
      runAudit({
        projectDir: PROJECT_DIR,
        packageDir: PACKAGE_DIR,
        provider:   'openai',
        apiKey:     'sk-test',
        baseUrl:    'http://10.0.0.1',
        scanOnly:   true,
      }),
    ).rejects.toThrow(/https|HTTPS|non-localhost/i);
    expect(fetchCalled).toBe(false);
  });

  test('rejects http:// baseUrl targeting arbitrary internal host', async () => {
    await expect(
      runAudit({
        projectDir: PROJECT_DIR,
        packageDir: PACKAGE_DIR,
        provider:   'openai',
        apiKey:     'sk-test',
        baseUrl:    'http://internal.corp',
        scanOnly:   true,
      }),
    ).rejects.toThrow(/https|HTTPS|non-localhost/i);
    expect(fetchCalled).toBe(false);
  });

  test('rejects malformed baseUrl', async () => {
    await expect(
      runAudit({
        projectDir: PROJECT_DIR,
        packageDir: PACKAGE_DIR,
        provider:   'openai',
        apiKey:     'sk-test',
        baseUrl:    'not-a-url',
        scanOnly:   true,
      }),
    ).rejects.toThrow(/valid URL|invalid/i);
    expect(fetchCalled).toBe(false);
  });

  test('allows https:// baseUrl for OpenAI-compatible providers', async () => {
    // Should NOT throw — should proceed to fetch
    await runAudit({
      projectDir: PROJECT_DIR,
      packageDir: PACKAGE_DIR,
      provider:   'openai',
      apiKey:     'sk-test',
      baseUrl:    'https://api.groq.com/openai/v1',
      scanOnly:   true,
    });
    expect(fetchCalled).toBe(true);
    expect(fetchUrl).toContain('groq.com');
  });

  test('allows http://localhost for local providers', async () => {
    await runAudit({
      projectDir: PROJECT_DIR,
      packageDir: PACKAGE_DIR,
      provider:   'openai',
      apiKey:     'sk-test',
      baseUrl:    'http://localhost:11434',
      scanOnly:   true,
    });
    expect(fetchCalled).toBe(true);
    expect(fetchUrl).toContain('localhost');
  });

  test('allows http://127.0.0.1 for local providers', async () => {
    await runAudit({
      projectDir: PROJECT_DIR,
      packageDir: PACKAGE_DIR,
      provider:   'openai',
      apiKey:     'sk-test',
      baseUrl:    'http://127.0.0.1:11434',
      scanOnly:   true,
    });
    expect(fetchCalled).toBe(true);
    expect(fetchUrl).toContain('127.0.0.1');
  });

  test('default openai URL (no baseUrl) reaches api.openai.com', async () => {
    await runAudit({
      projectDir: PROJECT_DIR,
      packageDir: PACKAGE_DIR,
      provider:   'openai',
      apiKey:     'sk-test',
      scanOnly:   true,
    });
    expect(fetchCalled).toBe(true);
    expect(fetchUrl).toContain('api.openai.com');
  });
});
