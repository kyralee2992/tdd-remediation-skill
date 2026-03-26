'use strict';

/**
 * SEC-29 — Malformed tool-call arguments in the OpenAI agentic loop (LOW coverage gap).
 *
 * When the OpenAI provider returns a tool_call whose `arguments` field is not
 * valid JSON (e.g. prompt injection truncates the JSON mid-stream), the catch
 * branch at auditor.js:612 silently resets input to {} and continues the loop.
 *
 * That branch was never exercised by the test suite, leaving a blind spot:
 * a corrupt arguments payload could call executeToolCall with surprising input
 * without any test asserting the loop stays safe.
 *
 * Red phase: there is no existing test that hits the catch branch and asserts
 * the loop completes without throwing.  These tests FAIL (because they don't
 * exist) until we add them.  After adding them they exercise line 612's catch
 * and prove the loop is resilient to malformed tool-call arguments.
 */

const path = require('path');
const os   = require('os');
const { runAudit } = require('../../lib/auditor');

const PACKAGE_DIR = path.join(__dirname, '../..');
const PROJECT_DIR = os.tmpdir();

beforeEach(() => {
  jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
});

afterEach(() => {
  delete global.fetch;
  jest.restoreAllMocks();
});

describe('SEC-29: OpenAI loop — malformed tool-call arguments are handled safely', () => {
  test('audit completes without throwing when arguments is truncated JSON', async () => {
    let callCount = 0;
    global.fetch = async () => {
      callCount++;
      if (callCount === 1) {
        // First response: trigger a tool_call with malformed JSON arguments
        return {
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: null,
                tool_calls: [{
                  id: 'tc_bad',
                  function: { name: 'read_file', arguments: 'not-json{' },
                }],
              },
              finish_reason: 'tool_calls',
            }],
          }),
        };
      }
      // Second response: stop the loop
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: '{"findings":[]}' }, finish_reason: 'stop' }],
        }),
      };
    };

    // Must not throw even with malformed arguments
    await expect(
      runAudit({
        projectDir: PROJECT_DIR,
        packageDir: PACKAGE_DIR,
        provider:   'openai',
        apiKey:     'sk-test',
        model:      'gpt-4o',
        outputFormat: 'json',
      })
    ).resolves.toBeUndefined();
  });

  test('audit makes a second round-trip after the malformed call', async () => {
    let callCount = 0;
    global.fetch = async () => {
      callCount++;
      if (callCount === 1) {
        return {
          ok: true,
          json: async () => ({
            choices: [{
              message: {
                content: null,
                tool_calls: [{ id: 'tc_bad', function: { name: 'list_files', arguments: '{invalid' } }],
              },
              finish_reason: 'tool_calls',
            }],
          }),
        };
      }
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: '{"findings":[]}' }, finish_reason: 'stop' }],
        }),
      };
    };

    await runAudit({
      projectDir: PROJECT_DIR,
      packageDir: PACKAGE_DIR,
      provider:   'openai',
      apiKey:     'sk-test',
      model:      'gpt-4o',
      outputFormat: 'json',
    });

    // Loop must have made two round-trips: one with the bad tool call, one to stop
    expect(callCount).toBe(2);
  });

  test('malformed arguments fall back to empty object (no path traversal)', async () => {
    // If malformed args silently use {}, read_file gets path=undefined and returns an error,
    // NOT a file read from the filesystem.  The loop must not throw.
    const toolResults = [];
    global.fetch = async (_url, opts) => {
      const body = JSON.parse(opts.body);
      // Capture tool_results from the second call (messages include tool results)
      if (body.messages?.length > 2) {
        const last = body.messages[body.messages.length - 1];
        if (last.role === 'tool') toolResults.push(JSON.parse(last.content));
      }
      if (body.messages?.length > 2) {
        return {
          ok: true,
          json: async () => ({
            choices: [{ message: { content: '{}' }, finish_reason: 'stop' }],
          }),
        };
      }
      return {
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: null,
              tool_calls: [{ id: 'tc_x', function: { name: 'read_file', arguments: 'BROKEN' } }],
            },
            finish_reason: 'tool_calls',
          }],
        }),
      };
    };

    await runAudit({
      projectDir: PROJECT_DIR,
      packageDir: PACKAGE_DIR,
      provider:   'openai',
      apiKey:     'sk-test',
      outputFormat: 'json',
    });

    // The tool result for the malformed call must be an error, not file content
    expect(toolResults.length).toBeGreaterThan(0);
    expect(toolResults[0].error).toBeDefined();
  });
});
