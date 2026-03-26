/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  forceExit: true,
  testMatch: [
    '**/__tests__/unit/**/*.test.js',
    '**/__tests__/security/**/*.test.js',
    '**/__tests__/e2e/**/*.test.js',
  ],
  coverageDirectory: 'coverage',
  collectCoverageFrom: ['lib/**/*.js', 'index.js'],
  testTimeout: 10000,
  workerIdleMemoryLimit: '512MB',
  testPathIgnorePatterns: [
    '/node_modules/',
    // Boilerplate templates — these are meant to be copied & filled in by the user
    'sample\\.exploit\\.test',
  ],
};
