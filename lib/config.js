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
  tdd_site:          null,      // custom URL for the README badge link; falls back to npm page

  // Branding — for wrapper/rebranded distributions
  org:               null,      // org name in reports, SECURITY.md, and pattern PRs
  project:           null,      // project name in reports and pattern contribution branch names
  badge_label:       null,      // badge label text; defaults to 'tdd-audit'
  security_name:     null,      // name of the security contact (stamped into SECURITY.md, compliance reports, and webhook payloads)
  security_email:    null,      // email of the security contact (used as the vulnerability reporting address in SECURITY.md)

  // Extensibility — both the CLI and the Claude Code skill honour these
  pattern_repos:     [],        // [{name, url, local_path, namespace}] — RAG-indexed at startup
  extra_skill_dirs:  [],        // relative paths to extra Claude Code skill directories
  extra_repos:       [],        // [{url, local_path}] — cloned/pulled for reference
  mcp_services:      [],        // [{name, cwd, command, args}] — started before first agent turn
  extra_domains:     [],        // [{name, prompt_file}] — custom audit domains

  // Policy as code — org-level severity overrides
  // e.g. { "CORS Wildcard": "CRITICAL", "Sensitive Log": "HIGH" }
  severity_overrides: {},

  // Notifications — fire on scan complete
  webhook_url:       null,      // POST findings JSON to this URL on scan complete
  slack_webhook:     null,      // Slack incoming webhook URL for findings summary
  slack_channel:     null,      // override default channel for the Slack webhook

  // Workflow integration
  open_pr:           false,     // open a GitHub PR per finding instead of committing directly
  github_token:      null,      // token for PR creation; falls back to GITHUB_TOKEN env var
  github_repo:       null,      // 'owner/repo' for PR creation; auto-detected from git remote if null

  // Scheduled / CI modes
  schedule:          null,      // cron expression — used by external schedulers, not the CLI itself
  pr_mode:           false,     // lightweight scan only (no agents, no RAG) — designed for CI PR gates
  org_scan:          null,      // GitHub org name — scan all repos in the org

  // Output additions
  sbom:              false,     // generate a CycloneDX SBOM alongside the audit report
  report:            false,     // generate a human-readable compliance report (PDF/markdown)
  watch:             false,     // re-scan affected files on change (watch mode)

  // Secret rotation — when a hardcoded key is found, offer to rotate via provider API
  rotate_secrets:    false,     // prompt to rotate detected secrets via provider API
};

// Provider-specific defaults for `tdd-audit init --provider <name>`
const PROVIDER_TEMPLATES = {
  openai: {
    provider:  'openai',
    model:     'gpt-4o',
    apiKeyEnv: 'OPENAI_API_KEY',
    baseUrl:   null,
  },
  anthropic: {
    provider:  'anthropic',
    model:     'claude-opus-4-6',
    apiKeyEnv: 'ANTHROPIC_API_KEY',
    baseUrl:   null,
  },
  gemini: {
    provider:  'gemini',
    model:     'gemini-2.0-flash',
    apiKeyEnv: 'GEMINI_API_KEY',
    baseUrl:   null,
  },
  ollama: {
    provider:  'ollama',
    model:     'llama3',
    apiKeyEnv: null,
    baseUrl:   'http://localhost:11434',
  },
};

// Template written by `tdd-audit init`
const INIT_TEMPLATE = {
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
  const threshold  = get('--threshold'); if (threshold) overrides.severityThreshold = threshold;
  const org        = get('--org');      if (org)        overrides.org_scan = org;
  if (args.includes('--json'))          overrides.output = 'json';
  if (args.includes('--pr'))            overrides.pr_mode = true;
  if (args.includes('--open-pr'))       overrides.open_pr = true;
  if (args.includes('--sbom'))          overrides.sbom = true;
  if (args.includes('--watch'))         overrides.watch = true;
  if (args.includes('--report'))        overrides.report = true;
  if (args.includes('--rotate-secrets')) overrides.rotate_secrets = true;
  return overrides;
}

/**
 * Write a starter .tdd-audit.json to destPath (default: cwd/.tdd-audit.json).
 * Returns the path written, or throws if the file already exists and force is false.
 *
 * @param {string}  [destPath]
 * @param {boolean} [force=false]
 * @param {string}  [provider='openai']
 * @returns {string}
 */
function writeInitConfig(destPath, force = false, provider = 'openai') {
  const providerDefaults = PROVIDER_TEMPLATES[provider];
  if (!providerDefaults) {
    throw new Error(
      `Unknown provider "${provider}". Valid options: ${Object.keys(PROVIDER_TEMPLATES).join(', ')}`
    );
  }
  const target = destPath || path.join(process.cwd(), CONFIG_FILE);
  if (fs.existsSync(target) && !force) {
    throw new Error(`${target} already exists. Pass --force to overwrite.`);
  }
  const template = { ...providerDefaults, ...INIT_TEMPLATE };
  fs.writeFileSync(target, JSON.stringify(template, null, 2) + '\n', 'utf8');
  return target;
}

module.exports = { loadConfig, parseCliOverrides, writeInitConfig, DEFAULTS, INIT_TEMPLATE, PROVIDER_TEMPLATES, CONFIG_FILE };
