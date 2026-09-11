/** @type {import('jest').Config} */
export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1'
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        module: 'es2022',
        target: 'es2022',
        moduleResolution: 'node'
      }
    }]
  },
  testMatch: [
    '**/tests/**/*.test.ts',
    '**/src/**/*.test.ts'
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/tests/**',
    '!src/**/index.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: [
    'text',
    'lcov',
    'html'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  testTimeout: 10000,

  // WORKAROUND -- remove once the leak below is fixed.
  //
  // PHIAuthorizationEngine's constructor starts an emergency-grant cleanup
  // timer (phi-authorization-engine.ts:36) and never clears it. The timer is
  // not .unref()'d, so every engine a test constructs keeps the node event
  // loop alive and jest reports "Jest did not exit one second after the test
  // run has completed" / "A worker process has failed to exit gracefully".
  //
  // That was invisible while the suite could not load at all. Without
  // forceExit the run hangs instead of finishing, which would make the CI gate
  // time out rather than report.
  //
  // This is a HARNESS workaround, not a fix. The real fix is to .unref() the
  // interval or expose a dispose() -- that file belongs to another lane.
  // Delete this option, and this comment, in the commit that fixes it.
  forceExit: true
};