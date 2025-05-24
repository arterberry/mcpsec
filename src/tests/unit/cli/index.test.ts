import { program } from '../../../src/cli/index';
import { MCPSecurityAnalyzer } from '../../../src/core/analyzer';
import { ConfigManager } from '../../../src/core/config';
import { SecurityReporter } from '../../../src/core/reporter';

jest.mock('../../../src/core/analyzer');
jest.mock('../../../src/core/config');
jest.mock('../../../src/core/reporter');
jest.mock('fs');

const mockAnalyzer = MCPSecurityAnalyzer as jest.MockedClass<typeof MCPSecurityAnalyzer>;
const mockConfigManager = ConfigManager as jest.MockedClass<typeof ConfigManager>;
const mockReporter = SecurityReporter as jest.MockedClass<typeof SecurityReporter>;

describe('CLI', () => {
    let consoleLogSpy: jest.SpyInstance;
    let processExitSpy: jest.SpyInstance;

    beforeEach(() => {
        jest.clearAllMocks();
        consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
        processExitSpy = jest.spyOn(process, 'exit').mockImplementation((code) => {
            throw new Error(`Process exit called with code ${code}`);
        });

        // Setup default mocks
        const mockConfigInstance = {
            loadConfig: jest.fn().mockReturnValue({}),
            initializeConfig: jest.fn(),
            validateConfig: jest.fn().mockResolvedValue(true)
        };
        mockConfigManager.getInstance.mockReturnValue(mockConfigInstance as any);

        const mockAnalyzerInstance = {
            analyze: jest.fn().mockResolvedValue([])
        };
        mockAnalyzer.mockImplementation(() => mockAnalyzerInstance as any);

        const mockReporterInstance = {
            generateReport: jest.fn().mockResolvedValue('Test Report'),
            writeReport: jest.fn()
        };
        mockReporter.mockImplementation(() => mockReporterInstance as any);
    });

    afterEach(() => {
        consoleLogSpy.mockRestore();
        processExitSpy.mockRestore();
    });

    describe('analyze command', () => {
        it('should analyze project with default options', async () => {
            const mockAnalyzerInstance = new mockAnalyzer();
            const mockReporterInstance = new mockReporter();

            try {
                await program.parseAsync(['node', 'mcpsec', 'analyze', '/test/project']);
            } catch (error: any) {
                // Expect process.exit(0) to be called
                expect(error.message).toContain('Process exit called with code 0');
            }

            expect(mockAnalyzerInstance.analyze).toHaveBeenCalledWith('/test/project');
            expect(mockReporterInstance.generateReport).toHaveBeenCalledWith([], 'text');
        });

        it('should handle violations and exit with code 1 on errors', async () => {
            const violations = [
                { ruleId: 'test-rule', severity: 'error', message: 'Test error' }
            ];

            const mockAnalyzerInstance = new mockAnalyzer();
            mockAnalyzerInstance.analyze.mockResolvedValue(violations);

            try {
                await program.parseAsync(['node', 'mcpsec', 'analyze', '/test/project']);
            } catch (error: any) {
                expect(error.message).toContain('Process exit called with code 1');
            }

            expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Errors: 1'));
        });

        it('should exit with code 0 when no violations', async () => {
            const mockAnalyzerInstance = new mockAnalyzer();
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
            const mockConfigInstance = mockConfigManager.getInstance();

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
            const mockReporterInstance = new mockReporter();

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
            const mockReporterInstance = new mockReporter();

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
            const mockAnalyzerInstance = new mockAnalyzer();
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

            const mockAnalyzerInstance = new mockAnalyzer();
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
            const mockConfigInstance = mockConfigManager.getInstance();

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
            const mockConfigInstance = mockConfigManager.getInstance();

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
            const mockConfigInstance = mockConfigManager.getInstance();
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
            jest.doMock('../../../src/rules', () => ({
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
            jest.doMock('../../../src/rules', () => {
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
            const mockConfigInstance = mockConfigManager.getInstance();
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
            const mockConfigInstance = mockConfigManager.getInstance();
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
            const mockConfigInstance = mockConfigManager.getInstance();
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
