// Jest setup file for FHIR-MCP server testing.
//
// This package is `"type": "module"` and jest.config.js sets
// `extensionsToTreatAsEsm: ['.ts']`, so this setup file is evaluated as an ES
// module. Under ESM there is no injected `jest` global -- every jest API must
// be imported explicitly from '@jest/globals'. Omitting these imports is what
// caused `ReferenceError: jest is not defined` and made both suites fail to
// load (0 tests executed).
import { jest, afterEach, beforeAll, afterAll } from '@jest/globals';

// Quieten console noise from the code under test.
//
// NOTE (important for any test that asserts on logging): we deliberately spy on
// the existing console methods rather than replacing `global.console` with a
// new object literal. Replacing the object breaks `jest.spyOn(console, 'warn')`
// inside a test -- the test would spy on the *replacement*, while the code under
// test may hold a reference to the original, so the spy silently records
// nothing. Spying keeps `console` identity stable, so a test-local spy layers
// on top of this one and observes real calls.
const silencedConsoleMethods = ['warn', 'error'];
for (const method of silencedConsoleMethods) {
  jest.spyOn(console, method).mockImplementation(() => {});
}

// Setup test environment variables
process.env.NODE_ENV = 'test';
process.env.PHI_MODE = 'safe';
process.env.ENABLE_AUDIT = 'true';

// Global test timeout for async operations
jest.setTimeout(10000);

// Setup global test utilities
globalThis.testUtils = {
  createMockFhirResource: (resourceType, overrides = {}) => ({
    resourceType,
    id: `test-${resourceType.toLowerCase()}-${Date.now()}`,
    meta: {
      versionId: '1',
      lastUpdated: new Date().toISOString()
    },
    ...overrides
  }),

  createMockSecurityContext: (overrides = {}) => ({
    sessionId: `test-session-${Date.now()}`,
    operation: 'fhir.search',
    resourceType: 'Patient',
    phiLevel: 'identifiable',
    ...overrides
  }),

  delay: (ms) => new Promise(resolve => setTimeout(resolve, ms))
};

// Setup test data cleanup
afterEach(() => {
  // Clears recorded calls but keeps the console spies installed for the next
  // test. (jest.restoreAllMocks() would un-silence console.)
  jest.clearAllMocks();
});

beforeAll(() => {
  // Setup test database or external services if needed
});

afterAll(() => {
  // Cleanup test database or external services if needed
});