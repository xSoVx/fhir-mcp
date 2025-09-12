// Jest setup file for FHIR-MCP server testing

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  // Uncomment the next line to disable console.log during tests
  // log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Setup test environment variables
process.env.NODE_ENV = 'test';
process.env.PHI_MODE = 'safe';
process.env.ENABLE_AUDIT = 'true';

// Global test timeout for async operations
jest.setTimeout(10000);

// Mock timers if needed
// jest.useFakeTimers();

// Setup global test utilities
global.testUtils = {
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
  // Clean up any test data or mocks
  jest.clearAllMocks();
});

beforeAll(() => {
  // Setup test database or external services if needed
  console.log('🧪 Setting up test environment...');
});

afterAll(() => {
  // Cleanup test database or external services if needed
  console.log('🧹 Cleaning up test environment...');
});