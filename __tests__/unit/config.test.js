'use strict';

/**
 * Unit tests — lib/config.js
 * Covers: DEFAULTS, loadConfig (file/CLI/env merging), parseCliOverrides, writeInitConfig
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { loadConfig, parseCliOverrides, writeInitConfig, DEFAULTS, INIT_TEMPLATE, PROVIDER_TEMPLATES, CONFIG_FILE } = require('../../lib/config');

// ── DEFAULTS ──────────────────────────────────────────────────────────────────

describe('DEFAULTS', () => {
  test('contains expected keys', () => {
    expect(DEFAULTS).toMatchObject({
      port:              expect.any(Number),
      output:            'text',
      severityThreshold: 'LOW',
      ignore:            expect.any(Array),
      provider:          null,
      model:             null,
      apiKey:            null,
      baseUrl:           null,
      apiKeyEnv:         null,
      serverApiKey:      null,
      trustProxy:        false,
    });
  });

  test('default port is 3000', () => expect(DEFAULTS.port).toBe(3000));
  test('trustProxy is false by default', () => expect(DEFAULTS.trustProxy).toBe(false));

  test('security_name defaults to null', () => {
    expect(DEFAULTS.security_name).toBeNull();
  });

  test('security_email defaults to null', () => {
    expect(DEFAULTS.security_email).toBeNull();
  });

  test('platform expansion fields have correct defaults', () => {
    expect(DEFAULTS.severity_overrides).toEqual({});
    expect(DEFAULTS.webhook_url).toBeNull();
    expect(DEFAULTS.slack_webhook).toBeNull();
    expect(DEFAULTS.slack_channel).toBeNull();
    expect(DEFAULTS.open_pr).toBe(false);
    expect(DEFAULTS.github_token).toBeNull();
    expect(DEFAULTS.github_repo).toBeNull();
    expect(DEFAULTS.schedule).toBeNull();
    expect(DEFAULTS.pr_mode).toBe(false);
    expect(DEFAULTS.org_scan).toBeNull();
    expect(DEFAULTS.sbom).toBe(false);
    expect(DEFAULTS.report).toBe(false);
    expect(DEFAULTS.watch).toBe(false);
    expect(DEFAULTS.rotate_secrets).toBe(false);
  });
});

// ── loadConfig ────────────────────────────────────────────────────────────────

describe('loadConfig — no config file', () => {
  const EMPTY = '/tmp/nonexistent-tdd-audit-dir-9999';

  test('returns DEFAULTS when no file present', () => {
    const cfg = loadConfig(EMPTY);
    expect(cfg.port).toBe(3000);
    expect(cfg.output).toBe('text');
    expect(cfg.trustProxy).toBe(false);
  });

  test('uses process.cwd() when called without arguments', () => {
    // Covers the `cwd = process.cwd()` default parameter branch
    const cfg = loadConfig();
    expect(typeof cfg.port).toBe('number');
  });

  test('CLI overrides win over defaults', () => {
    const cfg = loadConfig(EMPTY, { port: 4000, output: 'json' });
    expect(cfg.port).toBe(4000);
    expect(cfg.output).toBe('json');
  });
});

describe('loadConfig — with config file', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-audit-cfg-'));
  });

  afterEach(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  test('file values override DEFAULTS', () => {
    fs.writeFileSync(
      path.join(tmpDir, CONFIG_FILE),
      JSON.stringify({ port: 5000, output: 'sarif' }),
    );
    const cfg = loadConfig(tmpDir);
    expect(cfg.port).toBe(5000);
    expect(cfg.output).toBe('sarif');
  });

  test('CLI overrides win over file config', () => {
    fs.writeFileSync(path.join(tmpDir, CONFIG_FILE), JSON.stringify({ port: 5000 }));
    const cfg = loadConfig(tmpDir, { port: 9000 });
    expect(cfg.port).toBe(9000);
  });

  test('invalid JSON in config file writes warning but returns DEFAULTS', () => {
    fs.writeFileSync(path.join(tmpDir, CONFIG_FILE), '{ bad json }');
    const cfg = loadConfig(tmpDir);
    expect(cfg.port).toBe(3000); // falls back to DEFAULTS
  });

  test('loads severity_overrides from file', () => {
    fs.writeFileSync(
      path.join(tmpDir, CONFIG_FILE),
      JSON.stringify({ severity_overrides: { 'CORS Wildcard': 'CRITICAL' } }),
    );
    const cfg = loadConfig(tmpDir);
    expect(cfg.severity_overrides).toEqual({ 'CORS Wildcard': 'CRITICAL' });
  });

  test('loads notification settings from file', () => {
    fs.writeFileSync(
      path.join(tmpDir, CONFIG_FILE),
      JSON.stringify({ webhook_url: 'https://hooks.example.com/tdd', slack_webhook: 'https://hooks.slack.com/x', slack_channel: '#security' }),
    );
    const cfg = loadConfig(tmpDir);
    expect(cfg.webhook_url).toBe('https://hooks.example.com/tdd');
    expect(cfg.slack_webhook).toBe('https://hooks.slack.com/x');
    expect(cfg.slack_channel).toBe('#security');
  });

  test('loads workflow integration settings from file', () => {
    fs.writeFileSync(
      path.join(tmpDir, CONFIG_FILE),
      JSON.stringify({ open_pr: true, github_repo: 'owner/repo' }),
    );
    const cfg = loadConfig(tmpDir);
    expect(cfg.open_pr).toBe(true);
    expect(cfg.github_repo).toBe('owner/repo');
  });

  test('loads CI/scheduled mode settings from file', () => {
    fs.writeFileSync(
      path.join(tmpDir, CONFIG_FILE),
      JSON.stringify({ pr_mode: true, org_scan: 'my-org', schedule: '0 2 * * *' }),
    );
    const cfg = loadConfig(tmpDir);
    expect(cfg.pr_mode).toBe(true);
    expect(cfg.org_scan).toBe('my-org');
    expect(cfg.schedule).toBe('0 2 * * *');
  });

  test('loads output addition settings from file', () => {
    fs.writeFileSync(
      path.join(tmpDir, CONFIG_FILE),
      JSON.stringify({ sbom: true, report: true, watch: true, rotate_secrets: true }),
    );
    const cfg = loadConfig(tmpDir);
    expect(cfg.sbom).toBe(true);
    expect(cfg.report).toBe(true);
    expect(cfg.watch).toBe(true);
    expect(cfg.rotate_secrets).toBe(true);
  });

  test('CLI overrides win over file-based severity_overrides', () => {
    fs.writeFileSync(
      path.join(tmpDir, CONFIG_FILE),
      JSON.stringify({ severity_overrides: { 'CORS Wildcard': 'HIGH' } }),
    );
    const cfg = loadConfig(tmpDir, { severity_overrides: { 'CORS Wildcard': 'CRITICAL' } });
    expect(cfg.severity_overrides['CORS Wildcard']).toBe('CRITICAL');
  });
});

describe('loadConfig — explicit --config path', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-audit-cfg-'));
  });

  afterEach(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  test('loads from explicit configPath regardless of cwd', () => {
    const customPath = path.join(tmpDir, 'my-audit.json');
    fs.writeFileSync(customPath, JSON.stringify({ port: 7777, trustProxy: true }));
    const cfg = loadConfig('/tmp/some-other-dir', { configPath: customPath });
    expect(cfg.port).toBe(7777);
    expect(cfg.trustProxy).toBe(true);
  });

  test('configPath key is not leaked into result config', () => {
    const customPath = path.join(tmpDir, 'my-audit.json');
    fs.writeFileSync(customPath, JSON.stringify({ port: 1234 }));
    const cfg = loadConfig('/tmp', { configPath: customPath });
    expect(cfg).not.toHaveProperty('configPath');
  });

  test('missing explicit configPath returns DEFAULTS gracefully', () => {
    const cfg = loadConfig('/tmp', { configPath: '/tmp/no-such-file-xyz.json' });
    expect(cfg.port).toBe(3000);
  });
});

describe('loadConfig — apiKeyEnv resolution', () => {
  test('resolves apiKey from environment variable', () => {
    process.env._TEST_TDD_KEY = 'env-resolved-secret';
    const cfg = loadConfig('/tmp/nonexistent', { apiKeyEnv: '_TEST_TDD_KEY' });
    expect(cfg.apiKey).toBe('env-resolved-secret');
    delete process.env._TEST_TDD_KEY;
  });

  test('explicit apiKey takes precedence over apiKeyEnv', () => {
    process.env._TEST_TDD_KEY2 = 'from-env';
    const cfg = loadConfig('/tmp/nonexistent', { apiKey: 'explicit', apiKeyEnv: '_TEST_TDD_KEY2' });
    expect(cfg.apiKey).toBe('explicit');
    delete process.env._TEST_TDD_KEY2;
  });

  test('apiKey falls back to null when apiKeyEnv is set but env var is not defined', () => {
    delete process.env._TEST_UNSET_KEY_XYZ;
    const cfg = loadConfig('/tmp/nonexistent', { apiKeyEnv: '_TEST_UNSET_KEY_XYZ' });
    expect(cfg.apiKey).toBeNull();
  });
});

// ── parseCliOverrides ─────────────────────────────────────────────────────────

describe('parseCliOverrides', () => {
  test('parses --port', () => {
    expect(parseCliOverrides(['--port', '8080']).port).toBe(8080);
  });

  test('parses --provider', () => {
    expect(parseCliOverrides(['--provider', 'anthropic']).provider).toBe('anthropic');
  });

  test('parses --model', () => {
    expect(parseCliOverrides(['--model', 'gpt-4o-mini']).model).toBe('gpt-4o-mini');
  });

  test('parses --api-key', () => {
    expect(parseCliOverrides(['--api-key', 'sk-abc']).apiKey).toBe('sk-abc');
  });

  test('parses --base-url', () => {
    expect(parseCliOverrides(['--base-url', 'https://api.groq.com/openai/v1']).baseUrl)
      .toBe('https://api.groq.com/openai/v1');
  });

  test('parses --format sarif', () => {
    expect(parseCliOverrides(['--format', 'sarif']).output).toBe('sarif');
  });

  test('--json flag sets output to json', () => {
    expect(parseCliOverrides(['--json']).output).toBe('json');
  });

  test('parses --config path', () => {
    expect(parseCliOverrides(['--config', '/path/to/cfg.json']).configPath).toBe('/path/to/cfg.json');
  });

  test('returns empty object for unknown flags', () => {
    const overrides = parseCliOverrides(['--unknown', 'value']);
    expect(Object.keys(overrides).length).toBe(0);
  });

  test('--pr sets pr_mode to true', () => {
    expect(parseCliOverrides(['--pr']).pr_mode).toBe(true);
  });

  test('--org sets org_scan', () => {
    expect(parseCliOverrides(['--org', 'my-github-org']).org_scan).toBe('my-github-org');
  });

  test('--open-pr sets open_pr to true', () => {
    expect(parseCliOverrides(['--open-pr']).open_pr).toBe(true);
  });

  test('--sbom sets sbom to true', () => {
    expect(parseCliOverrides(['--sbom']).sbom).toBe(true);
  });

  test('--watch sets watch to true', () => {
    expect(parseCliOverrides(['--watch']).watch).toBe(true);
  });

  test('--report sets report to true', () => {
    expect(parseCliOverrides(['--report']).report).toBe(true);
  });

  test('--rotate-secrets sets rotate_secrets to true', () => {
    expect(parseCliOverrides(['--rotate-secrets']).rotate_secrets).toBe(true);
  });

  test('--threshold sets severityThreshold', () => {
    expect(parseCliOverrides(['--threshold', 'HIGH']).severityThreshold).toBe('HIGH');
  });

  test('--format report sets output to report', () => {
    expect(parseCliOverrides(['--format', 'report']).output).toBe('report');
  });
});

// ── writeInitConfig ───────────────────────────────────────────────────────────

describe('writeInitConfig', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-audit-init-'));
  });

  afterEach(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  test('creates .tdd-audit.json in the given directory', () => {
    const out = writeInitConfig(path.join(tmpDir, CONFIG_FILE));
    expect(fs.existsSync(out)).toBe(true);
  });

  test('written file contains valid JSON matching INIT_TEMPLATE keys', () => {
    const out = writeInitConfig(path.join(tmpDir, CONFIG_FILE));
    const parsed = JSON.parse(fs.readFileSync(out, 'utf8'));
    for (const key of Object.keys(INIT_TEMPLATE)) {
      expect(parsed).toHaveProperty(key);
    }
  });

  test('defaults to openai provider', () => {
    const out = writeInitConfig(path.join(tmpDir, CONFIG_FILE));
    const parsed = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(parsed.provider).toBe('openai');
    expect(parsed.model).toBe('gpt-4o');
    expect(parsed.apiKeyEnv).toBe('OPENAI_API_KEY');
  });

  test.each(Object.keys(PROVIDER_TEMPLATES))('scaffolds correct defaults for provider: %s', (provider) => {
    const dest = path.join(tmpDir, `${provider}.json`);
    const out  = writeInitConfig(dest, false, provider);
    const parsed = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(parsed.provider).toBe(provider);
    expect(parsed.model).toBe(PROVIDER_TEMPLATES[provider].model);
  });

  test('throws for unknown provider', () => {
    const dest = path.join(tmpDir, CONFIG_FILE);
    expect(() => writeInitConfig(dest, false, 'unknown-llm')).toThrow('Unknown provider');
  });

  test('throws if file already exists and force is false', () => {
    const dest = path.join(tmpDir, CONFIG_FILE);
    writeInitConfig(dest);
    expect(() => writeInitConfig(dest)).toThrow('already exists');
  });

  test('overwrites when force is true', () => {
    const dest = path.join(tmpDir, CONFIG_FILE);
    writeInitConfig(dest);
    expect(() => writeInitConfig(dest, true)).not.toThrow();
  });

  test('accepts a custom filename', () => {
    const dest = path.join(tmpDir, 'custom.json');
    const out = writeInitConfig(dest);
    expect(out).toBe(dest);
    expect(fs.existsSync(dest)).toBe(true);
  });

  test('uses cwd path when destPath is null (covers || fallback branch)', () => {
    // Covers `const target = destPath || path.join(process.cwd(), CONFIG_FILE)`
    const cwdConfigPath = path.join(process.cwd(), CONFIG_FILE);
    const alreadyExists = fs.existsSync(cwdConfigPath);
    if (alreadyExists) {
      // File exists → expect "already exists" error
      expect(() => writeInitConfig(null)).toThrow('already exists');
    } else {
      // File doesn't exist → will be created; clean up after
      try {
        const out = writeInitConfig(null);
        expect(out).toBe(cwdConfigPath);
      } finally {
        if (fs.existsSync(cwdConfigPath)) fs.unlinkSync(cwdConfigPath);
      }
    }
  });
});
