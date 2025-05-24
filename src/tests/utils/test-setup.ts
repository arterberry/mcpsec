// Global test setup
import { jest } from '@jest/globals';

// Setup global mocks
global.console = {
    ...console,
    log: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn()
};

// Mock environment variables
process.env.NODE_ENV = 'test';

// Setup test timeouts
jest.setTimeout(10000);

// Clean up after each test
afterEach(() => {
    jest.clearAllMocks();
});
