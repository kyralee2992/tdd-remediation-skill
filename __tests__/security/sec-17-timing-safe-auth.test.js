'use strict';

/**
 * SEC-17 — Timing-unsafe API key comparison.
 *
 * Attack vector: `token === cfg.serverApiKey` short-circuits on the first
 * mismatched byte, leaking the correct prefix character-by-character via
 * response-time differences.
 *
 * Fix: normalise both values with HMAC then compare with crypto.timingSafeEqual.
 */

const fs   = require('fs');
const path = require('path');
const { authenticate } = require('../../lib/server');

describe('SEC-17: Timing-safe API key comparison', () => {
  test('authenticate is exported', () => {
    expect(typeof authenticate).toBe('function');
  });

  test('server.js uses crypto.timingSafeEqual', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../lib/server.js'), 'utf8');
    expect(src).toMatch(/timingSafeEqual/);
    expect(src).toMatch(/require\(['"]crypto['"]\)/);
  });

  test('correct key returns true', () => {
    const cfg = { serverApiKey: 'super-secret-key-abc' };
    const req = { headers: { authorization: 'Bearer super-secret-key-abc' } };
    expect(authenticate(req, cfg)).toBe(true);
  });

  test('wrong key returns false', () => {
    const cfg = { serverApiKey: 'super-secret-key-abc' };
    const req = { headers: { authorization: 'Bearer super-secret-key-xyz' } };
    expect(authenticate(req, cfg)).toBe(false);
  });

  test('key off by one character returns false', () => {
    const cfg = { serverApiKey: 'abcdefghij' };
    const req = { headers: { authorization: 'Bearer abcdefghiJ' } };
    expect(authenticate(req, cfg)).toBe(false);
  });

  test('empty token when key is configured returns false', () => {
    const cfg = { serverApiKey: 'required' };
    const req = { headers: {} };
    expect(authenticate(req, cfg)).toBe(false);
  });

  test('no serverApiKey configured returns true (open server)', () => {
    const cfg = { serverApiKey: null };
    const req = { headers: {} };
    expect(authenticate(req, cfg)).toBe(true);
  });
});
