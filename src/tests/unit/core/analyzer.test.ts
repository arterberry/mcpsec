import { MCPSecurityAnalyzer } from '../../../src/core/analyzer';
import { TestHelpers } from '../../utils/test-helpers';
import { MockFactory } from '../../utils/mock-factory';

jest.mock('fs');
jest.mock('../../../src/rules', () => ({
    getAllRules: jest.fn().mockReturnValue([
        {
            id: 'test-rule',
            name: 'Test Rule',
            description: 'A test rule',
            severity: 'error',
            category: 'input-validation',
            mandatory: true,
            check: jest.fn().mockResolvedValue([])
        }
    ])
}));

describe('MCPSecurityAnalyzer', () => {
    let analyzer: MCPSecurityAnalyzer;
    let mockConfig: any;

    beforeEach(() => {
        mockConfig = TestHelpers.createMockConfig();
        analyzer = new MCPSecurityAnalyzer(mockConfig);
    });

    describe('analyze', () => {
        it('should analyze project and return violations', async () => {
            const projectPath = '/test/project';
            const mockFs = require('fs');

            mockFs.readdirSync.mockReturnValue(['test.ts']);
            mockFs.statSync.mockReturnValue({ isDirectory: () => false });
            mockFs.readFileSync.mockReturnValue('const test = "hello";');

            const violations = await analyzer.analyze(projectPath);

            expect(violations).toBeInstanceOf(Array);
            expect(mockFs.readdirSync).toHaveBeenCalled();
        });

        it('should handle rule execution errors gracefully', async () => {
            const { getAllRules } = require('../../../src/rules');
            const mockRule = {
                id: 'failing-rule',
                name: 'Failing Rule',
                check: jest.fn().mockRejectedValue(new Error('Rule failed'))
            };

            getAllRules.mockReturnValue([mockRule]);

            const projectPath = '/test/project';
            const mockFs = require('fs');

            mockFs.readdirSync.mockReturnValue([]);
            mockFs.readFileSync.mockReturnValue('{}');

            const violations = await analyzer.analyze(projectPath);

            expect(violations).toContainEqual(
                expect.objectContaining({
                    ruleId: 'failing-rule',
                    severity: 'error',
                    message: expect.stringContaining('Rule execution failed')
                })
            );
        });

        it('should apply severity overrides from config', async () => {
            const configWithOverrides = TestHelpers.createMockConfig({
                rules: {
                    'test-rule': { enabled: true, severity: 'warning' }
                }
            });

            analyzer = new MCPSecurityAnalyzer(configWithOverrides);

            const { getAllRules } = require('../../../src/rules');
            const mockRule = {
                id: 'test-rule',
                check: jest.fn().mockResolvedValue([{
                    ruleId: 'test-rule',
                    severity: 'error',
                    message: 'Test violation'
                }])
            };

            getAllRules.mockReturnValue([mockRule]);

            const mockFs = require('fs');
            mockFs.readdirSync.mockReturnValue([]);
            mockFs.readFileSync.mockReturnValue('{}');

            const violations = await analyzer.analyze('/test/project');

            expect(violations[0].severity).toBe('warning');
        });
    });

    describe('file filtering', () => {
        it('should ignore files matching ignore patterns', async () => {
            const mockFs = require('fs');

            mockFs.readdirSync.mockReturnValue(['node_modules', 'src', 'dist']);
            mockFs.statSync.mockImplementation((path: string) => ({
                isDirectory: () => ['node_modules', 'src', 'dist'].some(dir => path.includes(dir))
            }));

            await analyzer.analyze('/test/project');

            // Should not read from ignored directories
            expect(mockFs.readdirSync).not.toHaveBeenCalledWith(
                expect.stringContaining('node_modules')
            );
        });

        it('should only analyze supported file types', async () => {
            const mockFs = require('fs');

            mockFs.readdirSync.mockReturnValue(['test.ts', 'test.js', 'test.json', 'test.txt']);
            mockFs.statSync.mockReturnValue({ isDirectory: () => false });
            mockFs.readFileSync.mockReturnValue('test content');

            await analyzer.analyze('/test/project');

            // Should only read supported file types
            expect(mockFs.readFileSync).toHaveBeenCalledTimes(4); // ts, js, json, package.json
        });
    });
});
