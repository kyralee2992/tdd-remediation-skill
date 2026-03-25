'use strict';

const { version } = require('../package.json');

// ─── JSON ─────────────────────────────────────────────────────────────────────

/**
 * Return findings as a structured JSON-serialisable object.
 * @param {Array}    findings
 * @param {string[]} [exempted=[]]
 * @returns {object}
 */
function toJson(findings, exempted = []) {
  const real  = findings.filter(f => !f.likelyFalsePositive);
  const noisy = findings.filter(f =>  f.likelyFalsePositive);

  const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of real) summary[f.severity] = (summary[f.severity] || 0) + 1;

  return {
    version,
    summary,
    findings: real,
    likelyFalsePositives: noisy,
    exempted,
    scannedAt: new Date().toISOString(),
  };
}

// ─── SARIF ────────────────────────────────────────────────────────────────────

const SARIF_LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };

// Maps our vuln names to CWE IDs for richer GitHub annotations
const CWE_MAP = {
  'SQL Injection':             'CWE-89',
  'Command Injection':         'CWE-78',
  'Path Traversal':            'CWE-22',
  'XSS':                       'CWE-79',
  'IDOR':                      'CWE-639',
  'Broken Auth':               'CWE-287',
  'Hardcoded Secret':          'CWE-798',
  'SSRF':                      'CWE-918',
  'Open Redirect':             'CWE-601',
  'NoSQL Injection':           'CWE-943',
  'Mass Assignment':           'CWE-915',
  'Prototype Pollution':       'CWE-1321',
  'Weak Crypto':               'CWE-327',
  'Insecure Deserialization':  'CWE-502',
  'TLS Bypass':                'CWE-295',
  'Sensitive Storage':         'CWE-312',
  'JWT Alg None':              'CWE-347',
  'Secret Fallback':           'CWE-798',
  'eval() Injection':          'CWE-95',
  'Template Injection':        'CWE-94',
  'ReDoS':                     'CWE-1333',
  'XXE':                       'CWE-611',
  'CORS Wildcard':             'CWE-942',
  'Insecure Random':           'CWE-338',
  'Timing-Unsafe Comparison':  'CWE-208',
};

/**
 * Return findings as a SARIF 2.1.0 object (GitHub code scanning compatible).
 * @param {Array}  findings
 * @param {string} [projectDir='']  - used to build relative artifact URIs
 * @returns {object}
 */
function toSarif(findings, projectDir = '') {
  const rules = [];
  const ruleIndex = {};

  const results = findings.filter(f => !f.likelyFalsePositive).map(f => {
    if (ruleIndex[f.name] === undefined) {
      ruleIndex[f.name] = rules.length;
      const cwe = CWE_MAP[f.name];
      rules.push({
        id: f.name.replace(/\s+/g, '-').replace(/[()]/g, '').toLowerCase(),
        name: f.name,
        shortDescription: { text: f.name },
        fullDescription:  { text: `${f.name} detected — severity: ${f.severity}` },
        defaultConfiguration: { level: SARIF_LEVEL[f.severity] || 'warning' },
        ...(cwe && { relationships: [{ target: { id: cwe, toolComponent: { name: 'CWE' } } }] }),
        helpUri: `https://cwe.mitre.org/data/definitions/${cwe ? cwe.replace('CWE-', '') : '0'}.html`,
      });
    }

    return {
      ruleId:    rules[ruleIndex[f.name]].id,
      ruleIndex: ruleIndex[f.name],
      level:     SARIF_LEVEL[f.severity] || 'warning',
      message:   { text: f.snippet || f.name },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri:       f.file.replace(/\\/g, '/'),
            uriBaseId: '%SRCROOT%',
          },
          region: { startLine: f.line },
        },
      }],
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name:            '@lhi/tdd-audit',
          version,
          informationUri:  'https://www.npmjs.com/package/@lhi/tdd-audit',
          rules,
        },
      },
      results,
    }],
  };
}

// ─── Text (existing printFindings extracted for reuse) ────────────────────────

/**
 * Return a human-readable text report string (without printing it).
 * @param {Array}    findings
 * @param {string[]} [exempted=[]]
 * @returns {string}
 */
function toText(findings, exempted = []) {
  const lines = [];
  if (findings.length === 0) {
    lines.push('   ✅ No obvious vulnerability patterns detected.\n');
  } else {
    const real  = findings.filter(f => !f.likelyFalsePositive);
    const noisy = findings.filter(f =>  f.likelyFalsePositive);
    const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    for (const f of real) (bySeverity[f.severity] || bySeverity.LOW).push(f);
    const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };

    lines.push(`\n   Found ${real.length} potential issue(s)${noisy.length ? ` (+${noisy.length} in test files — see below)` : ''}:\n`);
    for (const [sev, list] of Object.entries(bySeverity)) {
      if (!list.length) continue;
      for (const f of list) {
        const badge = f.inTestFile ? ' [test file]' : '';
        lines.push(`   ${icons[sev]} [${sev}] ${f.name} — ${f.file}:${f.line}${badge}`);
        lines.push(`         ${f.snippet}`);
      }
    }
    if (noisy.length) {
      lines.push('\n   ⚪ Likely intentional (in test files — verify manually):');
      for (const f of noisy) lines.push(`      ${f.name} — ${f.file}:${f.line}`);
    }
    lines.push('\n   Run /tdd-audit in your agent to remediate.\n');
  }
  if (exempted.length) {
    lines.push('   ⚠️  Files skipped via audit_status:safe (verify these exemptions are intentional):');
    for (const p of exempted) lines.push(`      ${p}`);
    lines.push('');
  }
  return lines.join('\n');
}

module.exports = { toJson, toSarif, toText };
