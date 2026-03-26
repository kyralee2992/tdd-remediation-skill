'use strict';

/**
 * Coverage for the agentic loop paths in lib/auditor.js that require
 * multi-turn fetch mocks or module-level mocking:
 *
 *   Lines 427-434 — Anthropic tool_use multi-turn
 *   Lines 380-382 — logTool verbose output
 *   Lines 492-500 — OpenAI tool_calls multi-turn
 *   Lines 506-577 — Gemini functionCall loop
 *   Lines 598-600 — emitStructuredOutput JSON-extraction fallback
 *   Lines 598-600 — runFallbackAudit (ollama / unknown provider without baseUrl)
 *   Lines 699-703 — runAudit default switch: unknown provider + baseUrl (OpenAI-compat)
 *                   and unknown provider without baseUrl (fallback)
 */

jest.mock('../../lib/remediator', () => {
  const actual = jest.requireActual('../../lib/remediator');
  return {
    ...actual,
    callProvider: jest.fn().mockResolvedValue('Single-shot LLM analysis done.'),
  };
});

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { runAudit } = require('../../lib/auditor');

const PACKAGE_DIR = path.join(__dirname, '../..');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeTmpDir(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdd-loops-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return dir;
}

let tmpDir;
beforeEach(() => {
  tmpDir = makeTmpDir({ 'README.md': '# Project', 'src/index.js': 'const x = 1;' });
  jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
});
afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  jest.restoreAllMocks();
  delete global.fetch;
});

// ─── Anthropic tool_use multi-turn ────────────────────────────────────────────

describe('Anthropic agentic loop — tool_use multi-turn', () => {
  test('executes a tool call and continues to end_turn', async () => {
    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            content: [
              { type: 'tool_use', id: 'tu_1', name: 'read_file', input: { path: 'README.md' } },
            ],
            stop_reason: 'tool_use',
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          content:     [{ type: 'text', text: 'Analysis complete.' }],
          stop_reason: 'end_turn',
        }),
      };
    });

    const chunks = [];
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       (t) => chunks.push(t),
    });

    // fetch called twice: initial + tool result
    expect(fetchCount).toBe(2);
    // Second turn contained the text response
    expect(chunks.join('')).toContain('Analysis complete.');
  });

  test('verbose flag logs tool name to stderr during tool_use', async () => {
    const stderrLines = [];
    // Override the mock to capture stderr
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            content: [
              { type: 'tool_use', id: 'tu_v', name: 'list_files', input: { pattern: '*.md' } },
            ],
            stop_reason: 'tool_use',
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          content:     [{ type: 'text', text: 'Done.' }],
          stop_reason: 'end_turn',
        }),
      };
    });

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      verbose:      true,
      onText:       () => {},
    });

    const allStderr = stderrLines.join('');
    expect(allStderr).toMatch(/\[tool: list_files\]/);
  });

  test('Anthropic API error propagates as thrown Error', async () => {
    global.fetch = jest.fn(async () => ({
      ok:   false,
      status: 401,
      text: async () => 'Unauthorized',
    }));

    await expect(runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-bad',
      outputFormat: 'text',
      scanOnly:     true,
    })).rejects.toThrow(/Anthropic returned 401/);
  });
});

// ─── OpenAI tool_calls multi-turn ─────────────────────────────────────────────

describe('OpenAI agentic loop — tool_calls multi-turn', () => {
  test('executes a tool call and continues to stop', async () => {
    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            choices: [{
              message: {
                role:       'assistant',
                content:    null,
                tool_calls: [{
                  id:       'tc_1',
                  function: { name: 'read_file', arguments: '{"path":"README.md"}' },
                }],
              },
              finish_reason: 'tool_calls',
            }],
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          choices: [{
            message:       { role: 'assistant', content: 'OpenAI analysis done.' },
            finish_reason: 'stop',
          }],
        }),
      };
    });

    const chunks = [];
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'openai',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       (t) => chunks.push(t),
    });

    expect(fetchCount).toBe(2);
    expect(chunks.join('')).toContain('OpenAI analysis done.');
  });

  test('handles malformed tool_calls arguments gracefully', async () => {
    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            choices: [{
              message: {
                role:       'assistant',
                content:    null,
                tool_calls: [{
                  id:       'tc_bad',
                  function: { name: 'list_files', arguments: 'NOT_JSON{{' },
                }],
              },
              finish_reason: 'tool_calls',
            }],
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          choices: [{ message: { role: 'assistant', content: 'Recovered.' }, finish_reason: 'stop' }],
        }),
      };
    });

    // Should not throw even with malformed args
    await expect(runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'openai',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       () => {},
    })).resolves.toBeUndefined();
  });

  test('throws when OpenAI returns empty choices', async () => {
    global.fetch = jest.fn(async () => ({
      ok:   true,
      json: async () => ({ choices: [] }),
    }));

    await expect(runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'openai',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
    })).rejects.toThrow(/Empty response from OpenAI/);
  });

  test('OpenAI API error propagates as thrown Error', async () => {
    global.fetch = jest.fn(async () => ({
      ok:     false,
      status: 429,
      text:   async () => 'rate limited',
    }));

    await expect(runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'openai',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
    })).rejects.toThrow(/OpenAI returned 429/);
  });

  test('verbose flag logs tool name to stderr during tool_calls', async () => {
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            choices: [{
              message: {
                role:       'assistant',
                content:    null,
                tool_calls: [{
                  id:       'tc_v',
                  function: { name: 'search_in_files', arguments: '{"pattern":"const"}' },
                }],
              },
              finish_reason: 'tool_calls',
            }],
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          choices: [{ message: { role: 'assistant', content: 'Done.' }, finish_reason: 'stop' }],
        }),
      };
    });

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'openai',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      verbose:      true,
      onText:       () => {},
    });

    expect(stderrLines.join('')).toMatch(/\[tool: search_in_files\]/);
  });
});

// ─── Gemini functionCall loop ──────────────────────────────────────────────────

describe('Gemini agentic loop — functionCall multi-turn', () => {
  test('executes a functionCall and continues to STOP', async () => {
    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            candidates: [{
              content:      { parts: [{ functionCall: { name: 'read_file', args: { path: 'README.md' } } }] },
              finishReason: 'MAX_TOKENS',
            }],
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          candidates: [{
            content:      { parts: [{ text: 'Gemini audit finished.' }] },
            finishReason: 'STOP',
          }],
        }),
      };
    });

    const chunks = [];
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'gemini',
      apiKey:       'gm-test',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       (t) => chunks.push(t),
    });

    expect(fetchCount).toBe(2);
    expect(chunks.join('')).toContain('Gemini audit finished.');
  });

  test('breaks immediately when finishReason is STOP on first turn (no functionCall)', async () => {
    global.fetch = jest.fn(async () => ({
      ok:   true,
      json: async () => ({
        candidates: [{
          content:      { parts: [{ text: 'Quick answer.' }] },
          finishReason: 'STOP',
        }],
      }),
    }));

    const chunks = [];
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'gemini',
      apiKey:       'gm-test',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       (t) => chunks.push(t),
    });

    expect(chunks.join('')).toContain('Quick answer.');
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('verbose flag logs tool name to stderr during functionCall', async () => {
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            candidates: [{
              content:      { parts: [{ functionCall: { name: 'list_files', args: { pattern: '**/*.js' } } }] },
              finishReason: 'MAX_TOKENS',
            }],
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          candidates: [{
            content:      { parts: [{ text: 'Done.' }] },
            finishReason: 'STOP',
          }],
        }),
      };
    });

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'gemini',
      apiKey:       'gm-test',
      outputFormat: 'text',
      scanOnly:     true,
      verbose:      true,
      onText:       () => {},
    });

    expect(stderrLines.join('')).toMatch(/\[tool: list_files\]/);
  });

  test('Gemini API error propagates as thrown Error', async () => {
    global.fetch = jest.fn(async () => ({
      ok:     false,
      status: 403,
      text:   async () => 'Forbidden',
    }));

    await expect(runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'gemini',
      apiKey:       'gm-bad',
      outputFormat: 'text',
      scanOnly:     true,
    })).rejects.toThrow(/Gemini returned 403/);
  });

  test('throws when Gemini returns empty candidates', async () => {
    global.fetch = jest.fn(async () => ({
      ok:   true,
      json: async () => ({ candidates: [] }),
    }));

    await expect(runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'gemini',
      apiKey:       'gm-test',
      outputFormat: 'text',
      scanOnly:     true,
    })).rejects.toThrow(/Empty response from Gemini/);
  });
});

// ─── Default switch: unknown provider + baseUrl (OpenAI-compat path) ───────────

describe('runAudit() default switch — unknown provider with baseUrl', () => {
  test('routes an openai-compat provider through the OpenAI loop when baseUrl is provided', async () => {
    global.fetch = jest.fn(async () => ({
      ok:   true,
      json: async () => ({
        choices: [{ message: { role: 'assistant', content: 'groq done.' }, finish_reason: 'stop' }],
      }),
    }));

    const chunks = [];
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'groq',
      apiKey:       'gsk-test',
      baseUrl:      'https://api.groq.com/openai/v1',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       (t) => chunks.push(t),
    });

    expect(chunks.join('')).toContain('groq done.');
    // Should have called the OpenAI endpoint (groq baseUrl)
    const urls = global.fetch.mock.calls.map(([url]) => url);
    expect(urls[0]).toContain('groq.com');
  });
});

// ─── Fallback audit — unknown provider without baseUrl ───────────────────────

describe('runAudit() — fallback single-shot for providers without tool use', () => {
  const { callProvider } = require('../../lib/remediator');

  beforeEach(() => {
    callProvider.mockClear();
    callProvider.mockResolvedValue('Single-shot audit: no vulnerabilities found.');
  });

  test('calls callProvider with bundled project context for unknown provider', async () => {
    const chunks = [];
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'ollama',
      apiKey:       'ollama',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       (t) => chunks.push(t),
    });

    expect(callProvider).toHaveBeenCalledTimes(1);
    expect(callProvider).toHaveBeenCalledWith(
      'ollama',
      'ollama',
      undefined,        // model not provided → undefined
      expect.stringContaining('TDD Remediation Protocol'),
      undefined,        // baseUrl not provided
    );
    expect(chunks.join('')).toContain('no vulnerabilities found');
  });

  test('callProvider receives project file content in the prompt', async () => {
    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'custom-llm',
      apiKey:       'key',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       () => {},
    });

    const bundledPrompt = callProvider.mock.calls[0][3];
    // README.md content bundled into the prompt
    expect(bundledPrompt).toContain('README.md');
    expect(bundledPrompt).toContain('# Project');
  });
});

// ─── Anthropic mixed content (text + tool_use blocks) — covers line 429 branch ─

describe('Anthropic loop — mixed content array (text + tool_use blocks)', () => {
  test('skips text blocks in the tool_use processing loop (line 429 continue branch)', async () => {
    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            // Mix: one text block (should be skipped in tool processing) + one tool_use block
            content: [
              { type: 'text', text: 'Let me read the file.' },
              { type: 'tool_use', id: 'tu_mix', name: 'read_file', input: { path: 'README.md' } },
            ],
            stop_reason: 'tool_use',
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          content:     [{ type: 'text', text: 'Final.' }],
          stop_reason: 'end_turn',
        }),
      };
    });

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       () => {},
    });

    expect(fetchCount).toBe(2);
  });

  test('logTool handles null input (line 381 input || {} branch)', async () => {
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            content: [
              { type: 'tool_use', id: 'tu_nil', name: 'list_files', input: null },
            ],
            stop_reason: 'tool_use',
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          content:     [{ type: 'text', text: 'Done.' }],
          stop_reason: 'end_turn',
        }),
      };
    });

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      verbose:      true,
      onText:       () => {},
    });

    // logTool should not throw even with null input
    expect(stderrLines.join('')).toMatch(/\[tool: list_files\]/);
  });
});

// ─── OpenAI edge cases — covers line 492 branches ────────────────────────────

describe('OpenAI loop — edge cases for finish_reason handling', () => {
  test('tool_calls with empty tool_calls array skips the inner loop (line 492 false branch)', async () => {
    let fetchCount = 0;
    global.fetch = jest.fn(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return {
          ok:   true,
          json: async () => ({
            choices: [{
              message: {
                role:       'assistant',
                content:    'I will analyze...',
                tool_calls: [],   // empty array → message.tool_calls.length is 0 → if branch not taken
              },
              finish_reason: 'tool_calls',
            }],
          }),
        };
      }
      return {
        ok:   true,
        json: async () => ({
          choices: [{ message: { role: 'assistant', content: 'Done.' }, finish_reason: 'stop' }],
        }),
      };
    });

    await expect(runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'openai',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       () => {},
    })).resolves.toBeUndefined();
  });
});

// ─── runAudit — allowWrites=true branches (lines 671, 680) ───────────────────

describe('runAudit() — allowWrites=true covers ternary branches (lines 671, 680)', () => {
  test('uses "full + writes" mode text when allowWrites=true and scanOnly=false', async () => {
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    global.fetch = jest.fn(async () => ({
      ok:   true,
      json: async () => ({
        content:     [{ type: 'text', text: 'Done.' }],
        stop_reason: 'end_turn',
      }),
    }));

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     false,
      allowWrites:  true,
      onText:       () => {},
    });

    const allStderr = stderrLines.join('');
    expect(allStderr).toMatch(/full\/.+\+writes/);
  });

  test('user message includes "permission to write files" when allowWrites=true', async () => {
    const stderrLines = [];
    process.stderr.write.mockImplementation((s) => { stderrLines.push(s); });

    let capturedBody;
    global.fetch = jest.fn(async (_, init) => {
      capturedBody = JSON.parse(init.body);
      return {
        ok:   true,
        json: async () => ({
          content:     [{ type: 'text', text: 'Done.' }],
          stop_reason: 'end_turn',
        }),
      };
    });

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'anthropic',
      apiKey:       'sk-test',
      outputFormat: 'text',
      scanOnly:     false,
      allowWrites:  true,
      onText:       () => {},
    });

    const userMsg = capturedBody.messages[0].content;
    expect(userMsg).toMatch(/permission to write files/);
  });
});

// ─── runFallbackAudit — file sampling branches (lines 547-593) ───────────────

describe('runFallbackAudit() — file sampling edge cases', () => {
  const { callProvider } = require('../../lib/remediator');

  beforeEach(() => {
    callProvider.mockResolvedValue('Fallback analysis complete.');
  });

  test('skips binary files during project context bundling', async () => {
    // Write a binary file to the project
    const fs2 = require('fs');
    const path2 = require('path');
    fs2.writeFileSync(path2.join(tmpDir, 'binary.bin'), Buffer.from([0x00, 0x01, 0x02]));

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'custom-provider',
      apiKey:       'key',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       () => {},
    });

    // The binary file should not appear in the bundled prompt
    const bundledPrompt = callProvider.mock.calls[callProvider.mock.calls.length - 1][3];
    expect(bundledPrompt).not.toContain('binary.bin');
  });

  test('skips large files (> 8000 bytes) during project context bundling', async () => {
    const fs2 = require('fs');
    const path2 = require('path');
    fs2.writeFileSync(path2.join(tmpDir, 'huge.txt'), 'x'.repeat(9000));

    await runAudit({
      projectDir:   tmpDir,
      packageDir:   PACKAGE_DIR,
      provider:     'custom-provider2',
      apiKey:       'key2',
      outputFormat: 'text',
      scanOnly:     true,
      onText:       () => {},
    });

    const bundledPrompt = callProvider.mock.calls[callProvider.mock.calls.length - 1][3];
    expect(bundledPrompt).not.toContain('huge.txt');
  });
});

// ─── emitStructuredOutput — JSON extraction fallback ──────────────────────────

describe('emitStructuredOutput — JSON extraction fallback path', () => {
  test('writes raw LLM output to stderr/stdout when no JSON can be extracted', async () => {
    // Mock anthropic to return plain text with no JSON
    global.fetch = jest.fn(async () => ({
      ok:   true,
      json: async () => ({
        content:     [{ type: 'text', text: 'I found no issues. The code looks clean.' }],
        stop_reason: 'end_turn',
      }),
    }));

    const stderrChunks = [];
    process.stderr.write.mockImplementation((s) => { stderrChunks.push(s); });

    let captured = '';
    await runAudit({
      projectDir:    tmpDir,
      packageDir:    PACKAGE_DIR,
      provider:      'anthropic',
      apiKey:        'sk-test',
      outputFormat:  'json',
      scanOnly:      true,
      outputWriter:  (s) => { captured += s; },
    });

    // stderr should warn about the extraction failure
    expect(stderrChunks.join('')).toMatch(/Could not extract/);
    // The raw LLM output should be forwarded to the outputWriter
    expect(captured).toContain('The code looks clean');
  });
});
