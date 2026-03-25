'use strict';

/**
 * SEC-13 — Unbounded job store.
 *
 * Attack vector: an attacker (or runaway client) makes repeated POST /remediate
 * calls. The jobs Map grows without limit, eventually exhausting process heap.
 *
 * Fix: cap at MAX_JOBS entries; evict TTL-expired jobs before each insert;
 * if still over cap after eviction, evict the oldest entry.
 */

describe('SEC-13: Job store — bounded size', () => {
  let mod;

  beforeEach(() => {
    jest.resetModules();
    mod = require('../../lib/server');
  });

  test('MAX_JOBS constant is exported', () => {
    expect(typeof mod.MAX_JOBS).toBe('number');
    expect(mod.MAX_JOBS).toBeGreaterThan(0);
    expect(mod.MAX_JOBS).toBeLessThanOrEqual(10_000);
  });

  test('job store never exceeds MAX_JOBS entries', () => {
    const { createJob, jobs, MAX_JOBS } = mod;
    for (let i = 0; i < MAX_JOBS + 20; i++) {
      createJob();
    }
    expect(jobs.size).toBeLessThanOrEqual(MAX_JOBS);
  });

  test('oldest jobs are evicted when cap is reached', () => {
    const { createJob, jobs, MAX_JOBS } = mod;
    // Fill to cap
    for (let i = 0; i < MAX_JOBS; i++) createJob();
    const firstKey = jobs.keys().next().value;
    // Add one more — oldest should be gone
    createJob();
    expect(jobs.has(firstKey)).toBe(false);
  });
});
