'use strict';

/**
 * SEC-14 — Missing rate limiting on REST endpoints.
 *
 * Attack vector: an attacker floods /scan or /remediate to exhaust CPU/memory,
 * or brute-forces the API key via repeated unauthenticated requests.
 *
 * Fix: in-memory per-IP sliding window rate limiter exported as `rateLimiter`.
 * Returns false when the caller has exceeded RATE_LIMIT_MAX requests within
 * RATE_LIMIT_WINDOW_MS, causing the server to respond 429.
 */

describe('SEC-14: Rate limiting — per-IP request throttle', () => {
  let mod;

  beforeEach(() => {
    jest.resetModules();
    mod = require('../../lib/server');
    mod.rateLimiter.reset();
  });

  test('rateLimiter and RATE_LIMIT_MAX are exported', () => {
    expect(mod.rateLimiter).toBeDefined();
    expect(typeof mod.rateLimiter.check).toBe('function');
    expect(typeof mod.rateLimiter.reset).toBe('function');
    expect(typeof mod.RATE_LIMIT_MAX).toBe('number');
    expect(mod.RATE_LIMIT_MAX).toBeGreaterThan(0);
  });

  test('allows requests below the rate limit', () => {
    for (let i = 0; i < 10; i++) {
      expect(mod.rateLimiter.check('127.0.0.1')).toBe(true);
    }
  });

  test('blocks requests that exceed RATE_LIMIT_MAX in the window', () => {
    const { rateLimiter, RATE_LIMIT_MAX } = mod;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) rateLimiter.check('10.0.0.1');
    expect(rateLimiter.check('10.0.0.1')).toBe(false);
  });

  test('different IPs have independent counters', () => {
    const { rateLimiter, RATE_LIMIT_MAX } = mod;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) rateLimiter.check('192.168.0.1');
    // A different IP is unaffected
    expect(rateLimiter.check('192.168.0.2')).toBe(true);
  });

  test('reset() clears all counters', () => {
    const { rateLimiter, RATE_LIMIT_MAX } = mod;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) rateLimiter.check('1.2.3.4');
    expect(rateLimiter.check('1.2.3.4')).toBe(false);
    rateLimiter.reset();
    expect(rateLimiter.check('1.2.3.4')).toBe(true);
  });
});
