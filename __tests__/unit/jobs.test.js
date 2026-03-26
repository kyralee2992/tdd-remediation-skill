'use strict';

/**
 * Unit tests for lib/jobs.js
 * Covers: createJob, updateJob, subscribe/unsubscribe, evictJobs TTL
 */

const {
  jobs, createJob, updateJob, subscribe, evictJobs, MAX_JOBS, JOB_TTL_MS,
} = require('../../lib/jobs');

// Fresh slate between test groups to avoid cross-test pollution
beforeEach(() => { jobs.clear(); });

// ─── createJob ────────────────────────────────────────────────────────────────

describe('createJob()', () => {
  test('returns a unique id string', () => {
    const a = createJob();
    const b = createJob();
    expect(typeof a).toBe('string');
    expect(a).not.toBe(b);
  });

  test('new job has status: pending', () => {
    const id = createJob();
    expect(jobs.get(id).status).toBe('pending');
  });

  test('new job has createdAt ISO string', () => {
    const id = createJob();
    expect(() => new Date(jobs.get(id).createdAt)).not.toThrow();
  });
});

// ─── updateJob ────────────────────────────────────────────────────────────────

describe('updateJob()', () => {
  test('merges patch into job', () => {
    const id = createJob();
    updateJob(id, { status: 'running', startedAt: 'now' });
    expect(jobs.get(id).status).toBe('running');
    expect(jobs.get(id).startedAt).toBe('now');
  });

  test('no-ops for unknown id (does not throw)', () => {
    expect(() => updateJob('no-such-id', { status: 'done' })).not.toThrow();
  });

  test('preserves fields not in patch', () => {
    const id = createJob();
    const created = jobs.get(id).createdAt;
    updateJob(id, { status: 'done' });
    expect(jobs.get(id).createdAt).toBe(created);
  });
});

// ─── subscribe / unsubscribe ─────────────────────────────────────────────────

describe('subscribe() / unsubscribe()', () => {
  test('subscriber is called when updateJob fires', () => {
    const id = createJob();
    const received = [];
    subscribe(id, (job) => received.push(job.status));
    updateJob(id, { status: 'running' });
    updateJob(id, { status: 'done' });
    expect(received).toEqual(['running', 'done']);
  });

  test('unsubscribe return value stops future events', () => {
    const id = createJob();
    const received = [];
    const unsub = subscribe(id, (job) => received.push(job.status));
    updateJob(id, { status: 'running' });
    unsub();
    updateJob(id, { status: 'done' });
    expect(received).toEqual(['running']); // 'done' NOT received after unsub
  });

  test('multiple subscribers on the same job each receive updates', () => {
    const id = createJob();
    const a = [], b = [];
    subscribe(id, (j) => a.push(j.status));
    subscribe(id, (j) => b.push(j.status));
    updateJob(id, { status: 'scanning' });
    expect(a).toEqual(['scanning']);
    expect(b).toEqual(['scanning']);
  });

  test('subscriber on one job does not fire for another job', () => {
    const id1 = createJob();
    const id2 = createJob();
    const received = [];
    subscribe(id1, (j) => received.push(j.id));
    updateJob(id2, { status: 'done' });
    expect(received).toHaveLength(0);
  });
});

// ─── evictJobs ───────────────────────────────────────────────────────────────

describe('evictJobs()', () => {
  test('evicts jobs older than JOB_TTL_MS', () => {
    const id = createJob();
    // Back-date the job so it falls outside the TTL window
    const old = jobs.get(id);
    jobs.set(id, { ...old, createdAt: new Date(Date.now() - JOB_TTL_MS - 1_000).toISOString() });

    evictJobs();

    expect(jobs.has(id)).toBe(false);
  });

  test('keeps jobs within TTL', () => {
    const id = createJob();
    evictJobs();
    expect(jobs.has(id)).toBe(true);
  });

  test('createJob triggers eviction when over MAX_JOBS', () => {
    for (let i = 0; i < MAX_JOBS; i++) createJob();
    const firstId = jobs.keys().next().value;
    createJob(); // should evict oldest
    expect(jobs.has(firstId)).toBe(false);
    expect(jobs.size).toBeLessThanOrEqual(MAX_JOBS);
  });
});

// ─── constants ───────────────────────────────────────────────────────────────

describe('constants', () => {
  test('MAX_JOBS is a positive number ≤ 10 000', () => {
    expect(typeof MAX_JOBS).toBe('number');
    expect(MAX_JOBS).toBeGreaterThan(0);
    expect(MAX_JOBS).toBeLessThanOrEqual(10_000);
  });

  test('JOB_TTL_MS is a positive number', () => {
    expect(typeof JOB_TTL_MS).toBe('number');
    expect(JOB_TTL_MS).toBeGreaterThan(0);
  });
});
