'use strict';

/**
 * Tests for the CI workflow templates — verifies that each template file
 * exists and contains the expected job structure.
 */

const fs = require('fs');
const path = require('path');

const WORKFLOWS_DIR = path.join(__dirname, '../../templates/workflows');

const CI_TEMPLATES = [
  'ci.node.yml',
  'ci.python.yml',
  'ci.go.yml',
  'ci.flutter.yml',
];

const SECURITY_TEMPLATES = [
  'security-tests.node.yml',
  'security-tests.python.yml',
  'security-tests.go.yml',
  'security-tests.flutter.yml',
];

describe('CI workflow templates', () => {
  test.each(CI_TEMPLATES)('%s exists', (name) => {
    expect(fs.existsSync(path.join(WORKFLOWS_DIR, name))).toBe(true);
  });

  test.each(CI_TEMPLATES)('%s contains a "test" or "Test" job', (name) => {
    const content = fs.readFileSync(path.join(WORKFLOWS_DIR, name), 'utf8');
    expect(content).toMatch(/jobs:/);
    expect(content.toLowerCase()).toMatch(/test/);
  });

  test.each(CI_TEMPLATES)('%s triggers on push and pull_request', (name) => {
    const content = fs.readFileSync(path.join(WORKFLOWS_DIR, name), 'utf8');
    expect(content).toContain('push:');
    expect(content).toContain('pull_request:');
  });

  test.each(CI_TEMPLATES)('%s includes a checkout step', (name) => {
    const content = fs.readFileSync(path.join(WORKFLOWS_DIR, name), 'utf8');
    expect(content).toContain('actions/checkout');
  });
});

describe('Security-test workflow templates', () => {
  test.each(SECURITY_TEMPLATES)('%s exists', (name) => {
    expect(fs.existsSync(path.join(WORKFLOWS_DIR, name))).toBe(true);
  });

  test.each(SECURITY_TEMPLATES)('%s triggers on push and pull_request', (name) => {
    const content = fs.readFileSync(path.join(WORKFLOWS_DIR, name), 'utf8');
    expect(content).toContain('push:');
    expect(content).toContain('pull_request:');
  });
});
