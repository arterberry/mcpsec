import { SecurityReporter } from '../../../../src/core/reporter';
import { TestHelpers } from '../../utils/test-helpers';

// Import or define RuleViolation type for test usage
import type { RuleViolation } from '../../../../src/core/reporter';

jest.mock('fs', () => ({
    promises: {
        writeFile: jest.fn()
    }
}));

describe('SecurityReporter', () => {
    let reporter: SecurityReporter;
    let mockConfig: any;
    let sampleViolations: any[];

    beforeEach(() => {
        mockConfig = TestHelpers.createMockConfig();
        reporter = new SecurityReporter(mockConfig);

        sampleViolations = [
            {
                ruleId: 'test-rule-1',
                severity: 'error',
                message: 'Test error violation',
                file: '/test/file.ts',
                line: 10,
                evidence: 'Test evidence',
                fix: 'Test fix'
            },
            {
                ruleId: 'test-rule-2',
                severity: 'warning',
                message: 'Test warning violation',
                file: '/test/other.ts',
                line: 20
            },
            {
                ruleId: 'test-rule-3',
                severity: 'info',
                message: 'Test info violation'
            }
        ];
    });

    describe('generateReport', () => {
        describe('text format', () => {
            it('should generate text report with no violations', async () => {
                const report = await reporter.generateReport([], 'text');

                expect(report).toContain('No security violations found');
                expect(report).toContain('✅');
            });

            it('should generate text report with violations grouped by severity', async () => {
                const report = await reporter.generateReport(sampleViolations, 'text');

                expect(report).toContain('ERRORS (1)');
                expect(report).toContain('WARNINGS (1)');
                expect(report).toContain('INFO (1)');
                expect(report).toContain('Test error violation');
                expect(report).toContain('Test warning violation');
                expect(report).toContain('Test info violation');
            });

            it('should include file locations and fixes when available', async () => {
                const report = await reporter.generateReport(sampleViolations, 'text');

                expect(report).toContain('/test/file.ts:10');
                expect(report).toContain('Test evidence');
                expect(report).toContain('Test fix');
            });
        });

        describe('json format', () => {
            it('should generate valid JSON report', async () => {
                const report = await reporter.generateReport(sampleViolations, 'json');

                const parsed = JSON.parse(report);
                expect(parsed).toHaveProperty('timestamp');
                expect(parsed).toHaveProperty('tool', 'MCPSec');
                expect(parsed).toHaveProperty('summary');
                expect(parsed).toHaveProperty('violations');

                expect(parsed.summary.total).toBe(3);
                expect(parsed.summary.errors).toBe(1);
                expect(parsed.summary.warnings).toBe(1);
                expect(parsed.summary.info).toBe(1);
            });
        });

        describe('junit format', () => {
            it('should generate valid JUnit XML', async () => {
                const report = await reporter.generateReport(sampleViolations, 'junit');

                expect(report).toContain('<?xml version="1.0" encoding="UTF-8"?>');
                expect(report).toContain('<testsuite');
                expect(report).toContain('tests="3"');
                expect(report).toContain('failures="1"');
                expect(report).toContain('skipped="1"');
                expect(report).toContain('<testcase name="test-rule-1"');
                expect(report).toContain('<failure message="Test error violation">');
            });

            it('should escape XML special characters', async () => {
                const violationsWithXML: RuleViolation[] = [{
                    ruleId: 'test-rule',
                    severity: 'error',
                    message: 'Error with <script> & "quotes"',
                    evidence: 'Evidence with & < > " \''
                }];

                const report = await reporter.generateReport(violationsWithXML, 'junit');

                expect(report).toContain('&lt;script&gt;');
                expect(report).toContain('&amp;');
                expect(report).toContain('&quot;');
                expect(report).toContain('&#39;');
            });
        });

        describe('sarif format', () => {
            it('should generate valid SARIF report', async () => {
                const report = await reporter.generateReport(sampleViolations, 'sarif');

                const parsed = JSON.parse(report);
                expect(parsed).toHaveProperty('version', '2.1.0');
                expect(parsed).toHaveProperty('$schema');
                expect(parsed).toHaveProperty('runs');

                const run = parsed.runs[0];
                expect(run).toHaveProperty('tool');
                expect(run).toHaveProperty('results');
                expect(run.tool.driver.name).toBe('MCPSec');
                expect(run.results).toHaveLength(3);
            });

            it('should map severity levels correctly', async () => {
                const report = await reporter.generateReport(sampleViolations, 'sarif');

                const parsed = JSON.parse(report);
                const results = parsed.runs[0].results;

                expect(results[0].level).toBe('error');
                expect(results[1].level).toBe('warning');
                expect(results[2].level).toBe('note');
            });
        });
    });

    describe('writeReport', () => {
        it('should write report to file', async () => {
            const { promises: fs } = require('fs');
            const report = 'test report content';
            const outputPath = '/test/output.txt';

            await reporter.writeReport(report, outputPath);

            expect(fs.writeFile).toHaveBeenCalledWith(outputPath, report, 'utf-8');
        });
    });
});
