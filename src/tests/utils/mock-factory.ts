import { jest } from '@jest/globals';

export class MockFactory {
    static createFileSystemMock() {
        return {
            readFileSync: jest.fn(),
            writeFileSync: jest.fn(),
            existsSync: jest.fn(),
            readdirSync: jest.fn(),
            statSync: jest.fn()
        };
    }

    static createConfigManagerMock() {
        return {
            getInstance: jest.fn().mockReturnValue({
                loadConfig: jest.fn(),
                getConfig: jest.fn(),
                initializeConfig: jest.fn(),
                validateConfig: jest.fn()
            })
        };
    }

    static createAnalyzerMock() {
        return {
            analyze: jest.fn().mockResolvedValue([]),
            buildAnalysisContext: jest.fn()
        };
    }

    static createReporterMock() {
        return {
            generateReport: jest.fn().mockResolvedValue('mock report'),
            writeReport: jest.fn().mockResolvedValue(undefined)
        };
    }
}
