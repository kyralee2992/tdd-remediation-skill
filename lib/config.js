'use strict';

const fs   = require('fs');
const path = require('path');

const CONFIG_FILE = '.tdd-audit.json';

const DEFAULTS = {
  port:             3000,
  output:           'text',     // 'text' | 'json' | 'sarif'
  severityThreshold:'LOW',      // minimum severity to include in output
  ignore:           [],         // path prefixes to skip
  provider:         null,       // 'anthropic' | 'openai' | 'gemini' | 'ollama'
  model:            null,
  apiKey:           null,
  apiKeyEnv:        null,       // env var name to read the key from
  serverApiKey:     null,       // key required on REST API calls
};

/**
 * Load .tdd-audit.json from cwd (or a given dir), merge with DEFAULTS.
 * CLI flags (passed as an object) win over file config.
 *
 * @param {string} [cwd=process.cwd()]
 * @param {object} [cliOverrides={}]
 * @returns {object}
 */
function loadConfig(cwd = process.cwd(), cliOverrides = {}) {
  let fileConfig = {};
  const filePath = path.join(cwd, CONFIG_FILE);
  if (fs.existsSync(filePath)) {
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      fileConfig = JSON.parse(raw);
    } catch (err) {
      process.stderr.write(`⚠️  Could not parse ${CONFIG_FILE}: ${err.message}\n`);
    }
  }

  const merged = { ...DEFAULTS, ...fileConfig };

  // CLI overrides — only set keys that were explicitly provided
  for (const [key, val] of Object.entries(cliOverrides)) {
    if (val !== undefined && val !== null) merged[key] = val;
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
  const port      = get('--port');      if (port)     overrides.port = Number(port);
  const provider  = get('--provider'); if (provider) overrides.provider = provider;
  const model     = get('--model');    if (model)    overrides.model = model;
  const apiKey    = get('--api-key');  if (apiKey)   overrides.apiKey = apiKey;
  const format    = get('--format');   if (format)   overrides.output = format;
  const srvKey    = get('--api-key');  if (srvKey)   overrides.serverApiKey = srvKey;
  if (args.includes('--json')) overrides.output = 'json';
  return overrides;
}

module.exports = { loadConfig, parseCliOverrides, DEFAULTS, CONFIG_FILE };
