'use strict';

/**
 * Unit tests — lib/config.js
 * Covers: DEFAULTS, loadConfig (file/CLI/env merging), parseCliOverrides, writeInitConfig
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { loadConfig, parseCliOverrides, writeInitConfig, DEFAULTS, INIT_TEMPLATE, CONFIG_FILE } = require('../../lib/config');

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
});
