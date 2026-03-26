'use strict';

const { EventEmitter } = require('events');

// ─── Job store (singleton, in-memory) ────────────────────────────────────────

const MAX_JOBS   = 1_000;
const JOB_TTL_MS = 60 * 60 * 1_000; // 1 hour

const jobs   = new Map();
let   jobSeq = 0;

// EventEmitter used to push job updates to SSE subscribers
const _emitter = new EventEmitter();
_emitter.setMaxListeners(500);

function evictJobs() {
  const cutoff = Date.now() - JOB_TTL_MS;
  for (const [id, job] of jobs) {
    if (new Date(job.createdAt).getTime() < cutoff) jobs.delete(id);
  }
  while (jobs.size >= MAX_JOBS) {
    jobs.delete(jobs.keys().next().value);
  }
}

function createJob() {
  evictJobs();
  const id = `job_${++jobSeq}_${Date.now()}`;
  jobs.set(id, { id, status: 'pending', createdAt: new Date().toISOString() });
  return id;
}

function updateJob(id, patch) {
  const job = jobs.get(id);
  if (!job) return;
  const updated = { ...job, ...patch };
  jobs.set(id, updated);
  _emitter.emit(id, updated);
}

/**
 * Subscribe to live updates for a job.
 * @param {string}   id  - job id
 * @param {Function} fn  - called with the updated job object on every change
 * @returns {Function}   - call to unsubscribe
 */
function subscribe(id, fn) {
  _emitter.on(id, fn);
  return () => _emitter.off(id, fn);
}

module.exports = { jobs, createJob, updateJob, subscribe, evictJobs, MAX_JOBS, JOB_TTL_MS };
