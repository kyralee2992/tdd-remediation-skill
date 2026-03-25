'use strict';

const fs   = require('fs');
const path = require('path');

const CONFIG_FILE = '.tdd-audit.json';

const DEFAULTS = {
  port:              3000,
  output:            'text',    // 'text' | 'json' | 'sarif'
  severityThreshold: 'LOW',     // minimum severity to include in output
  ignore:            [],        // path prefixes to skip
  provider:          null,      // 'anthropic' | 'openai' | 'gemini' | 'ollama'
  model:             null,
  apiKey:            null,
  baseUrl:           null,      // override base URL for OpenAI-compatible providers
  apiKeyEnv:         null,      // env var name to read the key from
  serverApiKey:      null,      // key required on REST API calls
  trustProxy:        false,     // trust X-Forwarded-For for rate limiting
};

// Template written by `tdd-audit init`
const INIT_TEMPLATE = {
  provider:          'openai',
  model:             'gpt-4o',
  apiKeyEnv:         'OPENAI_API_KEY',
  baseUrl:           null,
  output:            'text',
  severityThreshold: 'LOW',
  port:              3000,
  serverApiKey:      null,
  ignore:            ['node_modules', 'dist', 'build', 'coverage'],
};

/**
 * Load config from an explicit file path or from .tdd-audit.json in cwd.
 * CLI flags win over file config; file config wins over DEFAULTS.
 *
 * @param {string} [cwd=process.cwd()]
 * @param {object} [cliOverrides={}]  - may include { configPath: '/abs/path/to/file.json' }
 * @returns {object}
 */
function loadConfig(cwd = process.cwd(), cliOverrides = {}) {
  let fileConfig = {};

  // Explicit --config path wins over the cwd convention
  const filePath = cliOverrides.configPath
    ? path.resolve(cliOverrides.configPath)
    : path.join(cwd, CONFIG_FILE);

  if (fs.existsSync(filePath)) {
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      fileConfig = JSON.parse(raw);
    } catch (err) {
      process.stderr.write(`⚠️  Could not parse ${filePath}: ${err.message}\n`);
    }
  }

  const merged = { ...DEFAULTS, ...fileConfig };

  // Apply CLI overrides (skip internal keys like configPath)
  const INTERNAL = new Set(['configPath']);
  for (const [key, val] of Object.entries(cliOverrides)) {
    if (!INTERNAL.has(key) && val !== undefined && val !== null) merged[key] = val;
  }

  // Resolve apiKey from env var if apiKeyEnv is set and apiKey isn't already
  if (!merged.apiKey && merged.apiKeyEnv) {
    merged.apiKey = process.env[merged.apiKeyEnv] || null;
  }

  return merged;
}

/**
 * Parse relevant CLI args into an overrides object for loadConfig.
 * @param {string[]} args - process.argv.slice(2)
 * @returns {object}
 */
function parseCliOverrides(args) {
  const get = (flag) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };
  const overrides = {};
  const configPath = get('--config');    if (configPath) overrides.configPath = configPath;
  const port       = get('--port');      if (port)       overrides.port = Number(port);
  const provider   = get('--provider'); if (provider)   overrides.provider = provider;
  const model      = get('--model');    if (model)      overrides.model = model;
  const apiKey     = get('--api-key');  if (apiKey)     overrides.apiKey = apiKey;
  const baseUrl    = get('--base-url'); if (baseUrl)    overrides.baseUrl = baseUrl;
  const format     = get('--format');   if (format)     overrides.output = format;
  const srvKey     = get('--api-key');  if (srvKey)     overrides.serverApiKey = srvKey;
  if (args.includes('--json')) overrides.output = 'json';
  return overrides;
}

/**
 * Write a starter .tdd-audit.json to destPath (default: cwd/.tdd-audit.json).
 * Returns the path written, or throws if the file already exists and force is false.
 *
 * @param {string}  [destPath]
 * @param {boolean} [force=false]
 * @returns {string}
 */
function writeInitConfig(destPath, force = false) {
  const target = destPath || path.join(process.cwd(), CONFIG_FILE);
  if (fs.existsSync(target) && !force) {
    throw new Error(`${target} already exists. Pass --force to overwrite.`);
  }
  fs.writeFileSync(target, JSON.stringify(INIT_TEMPLATE, null, 2) + '\n', 'utf8');
  return target;
}

module.exports = { loadConfig, parseCliOverrides, writeInitConfig, DEFAULTS, INIT_TEMPLATE, CONFIG_FILE };
