import { program } from '../../../cli/index';
import { MCPSecurityAnalyzer } from '../../../core/analyzer';
import { ConfigManager } from '../../../core/config';
import { SecurityReporter } from '../../../core/reporter';
import { TestHelpers } from '../../utils/test-helpers';

// Mock the modules before importing
jest.mock('../../../core/analyzer');
jest.mock('../../../core/config');
jest.mock('../../../core/reporter');
jest.mock('fs');

// Create proper mock types for singleton pattern
const mockAnalyzer = MCPSecurityAnalyzer as jest.MockedClass<typeof MCPSecurityAnalyzer>;
const mockReporter = SecurityReporter as jest.MockedClass<typeof SecurityReporter>;

// For ConfigManager, we need to mock the singleton differently
const mockConfigManager = ConfigManager as jest.Mocked<typeof ConfigManager>;

describe('CLI', () => {
    let consoleLogSpy: jest.SpyInstance;
    let processExitSpy: jest.SpyInstance;
    let mockConfigInstance: any;
    let mockAnalyzerInstance: any;
    let mockReporterInstance: any;

    beforeEach(() => {
        jest.clearAllMocks();
        consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
        processExitSpy = jest.spyOn(process, 'exit').mockImplementation((code) => {
            throw new Error(`Process exit called with code ${code}`);
        });

        // Setup mock for ConfigManager singleton
        mockConfigInstance = {
            loadConfig: jest.fn().mockReturnValue(TestHelpers.createMockConfig()),
            initializeConfig: jest.fn(),
            validateConfig: jest.fn().mockResolvedValue(true)
        };
        
        // Mock the getInstance static method
        mockConfigManager.getInstance = jest.fn().mockReturnValue(mockConfigInstance);

        // Setup mocks for constructable classes
        mockAnalyzerInstance = {
            analyze: jest.fn().mockResolvedValue([])
        };
        mockAnalyzer.mockImplementation(() => mockAnalyzerInstance);

        mockReporterInstance = {
            generateReport: jest.fn().mockResolvedValue('Test Report'),
            writeReport: jest.fn()
        };
        mockReporter.mockImplementation(() => mockReporterInstance);
    });

    afterEach(() => {
        consoleLogSpy.mockRestore();
        processExitSpy.mockRestore();
    });

    describe('analyze command', () => {
        it('should analyze project with default options', async () => {
            try {
                await program.parseAsync(['node', 'mcpsec', 'analyze', '/test/project']);
            } catch (error: any) {
                // Expect process.exit(0) to be called
                expect(error.message).toContain('Process exit called with code 0');
            }

            expect(mockAnalyzer).toHaveBeenCalledWith(expect.any(Object));
            expect(mockAnalyzerInstance.analyze).toHaveBeenCalledWith('/test/project');
            expect(mockReporter).toHaveBeenCalledWith(expect.any(Object));
            expect(mockReporterInstance.generateReport).toHaveBeenCalledWith([], 'text');
        });

        it('should handle violations and exit with code 1 on errors', async () => {
            const violations = [
                { ruleId: 'test-rule', severity: 'error', message: 'Test error' }
            ];

            mockAnalyzerInstance.analyze.mockResolvedValue(violations);

            try {
                await program.parseAsync(['node', 'mcpsec', 'analyze', '/test/project']);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 1');
            }

            expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Errors: 1'));
        });

        it('should exit with code 0 when no violations', async () => {
            mockAnalyzerInstance.analyze.mockResolvedValue([]);

            try {
                await program.parseAsync(['node', 'mcpsec', 'analyze', '/test/project']);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 0');
            }

            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('Security analysis completed successfully')
            );
        });

        it('should apply Fox Corp configuration when --fox-corp flag is used', async () => {
            try {
                await program.parseAsync(['node', 'mcpsec', 'analyze', '/test/project', '--fox-corp']);
            } catch (error: any) {
                // Expected to exit
            }

            expect(mockConfigInstance.loadConfig).toHaveBeenCalled();
            expect(mockAnalyzer).toHaveBeenCalledWith(
                expect.objectContaining({
                    foxCorp: expect.objectContaining({
                        streamingAssets: true
                    })
                })
            );
        });

        it('should write report to file when --output is specified', async () => {
            try {
                await program.parseAsync([
                    'node', 'mcpsec', 'analyze', '/test/project',
                    '--output', '/test/report.txt'
                ]);
            } catch (error: any) {
                // Expected to exit
            }

            expect(mockReporterInstance.writeReport).toHaveBeenCalledWith(
                'Test Report',
                '/test/report.txt'
            );
        });

        it('should generate report in specified format', async () => {
            try {
                await program.parseAsync([
                    'node', 'mcpsec', 'analyze', '/test/project',
                    '--format', 'json'
                ]);
            } catch (error: any) {
                // Expected to exit
            }

            expect(mockReporterInstance.generateReport).toHaveBeenCalledWith([], 'json');
        });

        it('should handle analysis errors gracefully', async () => {
            mockAnalyzerInstance.analyze.mockRejectedValue(new Error('Analysis failed'));

            try {
                await program.parseAsync(['node', 'mcpsec', 'analyze', '/test/project']);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 1');
            }

            expect(console.error).toHaveBeenCalledWith(
                expect.stringContaining('Analysis failed'),
                expect.any(String)
            );
        });

        it('should apply streaming-specific flags', async () => {
            try {
                await program.parseAsync([
                    'node', 'mcpsec', 'analyze', '/test/project',
                    '--streaming', '--conviva', '--har-validation'
                ]);
            } catch (error: any) {
                // Expected to exit
            }

            expect(mockAnalyzer).toHaveBeenCalledWith(
                expect.objectContaining({
                    foxCorp: expect.objectContaining({
                        streamingAssets: true,
                        convivaIntegration: true,
                        harValidation: true
                    })
                })
            );
        });

        it('should respect fail-on warning level', async () => {
            const violations = [
                { ruleId: 'test-rule', severity: 'warning', message: 'Test warning' }
            ];

            mockAnalyzerInstance.analyze.mockResolvedValue(violations);

            try {
                await program.parseAsync([
                    'node', 'mcpsec', 'analyze', '/test/project',
                    '--fail-on', 'warning'
                ]);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 1');
            }
        });
    });

    describe('init command', () => {
        it('should initialize configuration with default template', async () => {
            try {
                await program.parseAsync(['node', 'mcpsec', 'init']);
            } catch (error: any) {
                // May not exit, just complete
            }

            expect(mockConfigInstance.initializeConfig).toHaveBeenCalledWith('.', 'fox-corp');
            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('MCPSec configuration initialized')
            );
        });

        it('should initialize configuration with specified template', async () => {
            try {
                await program.parseAsync([
                    'node', 'mcpsec', 'init', '/custom/path',
                    '--template', 'strict'
                ]);
            } catch (error: any) {
                // May not exit
            }

            expect(mockConfigInstance.initializeConfig).toHaveBeenCalledWith('/custom/path', 'strict');
        });

        it('should handle initialization errors', async () => {
            mockConfigInstance.initializeConfig.mockRejectedValue(new Error('Init failed'));

            try {
                await program.parseAsync(['node', 'mcpsec', 'init']);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 1');
            }

            expect(console.error).toHaveBeenCalledWith(
                expect.stringContaining('Configuration initialization failed'),
                expect.any(String)
            );
        });
    });

    describe('rules command', () => {
        beforeEach(() => {
            // Mock the dynamic import
            jest.doMock('../../../rules', () => ({
                getAllRules: jest.fn().mockReturnValue([
                    {
                        id: 'test-rule-1',
                        name: 'Test Rule 1',
                        description: 'First test rule',
                        severity: 'error',
                        category: 'input-validation',
                        mandatory: true
                    },
                    {
                        id: 'test-rule-2',
                        name: 'Test Rule 2',
                        description: 'Second test rule',
                        severity: 'warning',
                        category: 'authentication',
                        mandatory: false
                    }
                ])
            }));
        });

        it('should list all rules by default', async () => {
            try {
                await program.parseAsync(['node', 'mcpsec', 'rules']);
            } catch (error: any) {
                // Command may not exit
            }

            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('Available Security Rules')
            );
            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('Test Rule 1')
            );
            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('Test Rule 2')
            );
        });

        it('should filter rules by category', async () => {
            try {
                await program.parseAsync(['node', 'mcpsec', 'rules', '--category', 'input-validation']);
            } catch (error: any) {
                // Command may not exit
            }

            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('Test Rule 1')
            );
        });

        it('should show only mandatory rules when flag is set', async () => {
            try {
                await program.parseAsync(['node', 'mcpsec', 'rules', '--mandatory-only']);
            } catch (error: any) {
                // Command may not exit
            }

            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('Test Rule 1')
            );
        });

        it('should handle rule listing errors', async () => {
            jest.doMock('../../../rules', () => {
                throw new Error('Failed to load rules');
            });

            try {
                await program.parseAsync(['node', 'mcpsec', 'rules']);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 1');
            }

            expect(console.error).toHaveBeenCalledWith(
                expect.stringContaining('Failed to list rules'),
                expect.any(String)
            );
        });
    });

    describe('validate-config command', () => {
        it('should validate correct configuration', async () => {
            mockConfigInstance.validateConfig.mockResolvedValue(true);

            try {
                await program.parseAsync(['node', 'mcpsec', 'validate-config', '.mcpsec.json']);
            } catch (error: any) {
                // May not exit on success
            }

            expect(mockConfigInstance.validateConfig).toHaveBeenCalledWith('.mcpsec.json');
            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('Configuration is valid')
            );
        });

        it('should handle invalid configuration', async () => {
            mockConfigInstance.validateConfig.mockResolvedValue(false);

            try {
                await program.parseAsync(['node', 'mcpsec', 'validate-config', '.mcpsec.json']);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 1');
            }

            expect(consoleLogSpy).toHaveBeenCalledWith(
                expect.stringContaining('Configuration is invalid')
            );
        });

        it('should handle validation errors', async () => {
            mockConfigInstance.validateConfig.mockRejectedValue(new Error('Validation error'));

            try {
                await program.parseAsync(['node', 'mcpsec', 'validate-config', '.mcpsec.json']);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 1');
            }

            expect(console.error).toHaveBeenCalledWith(
                expect.stringContaining('Configuration validation failed'),
                expect.any(String)
            );
        });
    });
});