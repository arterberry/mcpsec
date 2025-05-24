import { MCPSecurityAnalyzer } from '../../src/core/analyzer';
import { ConfigManager } from '../../src/core/config';
import { SecurityReporter } from '../../src/core/reporter';
import { TestHelpers } from '../utils/test-helpers';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

jest.mock('fs');
const mockFs = fs as jest.Mocked<typeof fs>;

describe('End-to-End Security Analysis', () => {
    let tempDir: string;
    let analyzer: MCPSecurityAnalyzer;
    let configManager: ConfigManager;
    let reporter: SecurityReporter;

    beforeEach(() => {
        tempDir = '/tmp/test-project';

        // Setup file system mocks
        mockFs.readdirSync.mockImplementation((dir: any) => {
            if (dir.includes('node_modules')) return [];
            return ['package.json', 'src'];
        });

        mockFs.statSync.mockImplementation((filepath: any) => ({
            isDirectory: () => filepath.includes('src'),
            isFile: () => !filepath.includes('src')
        } as any));

        mockFs.existsSync.mockReturnValue(true);

        configManager = ConfigManager.getInstance();
        const config = TestHelpers.createMockConfig();
        analyzer = new MCPSecurityAnalyzer(config);
        reporter = new SecurityReporter(config);
    });

    describe('complete analysis workflow', () => {
        it('should analyze a project with multiple security issues', async () => {
            // Mock a project with various security vulnerabilities
            const packageJson = {
                name: 'vulnerable-mcp-server',
                version: '1.0.0',
                dependencies: {
                    express: '^4.18.0'
                }
            };

            const vulnerableServerCode = `
        import express from 'express';
        import { exec } from 'child_process';
        
        const app = express();
        const API_KEY = "hardcoded_api_key_12345678901234567890";
        
        // Vulnerable tool without authentication
        async function executeTool(params) {
          // SQL injection vulnerability
          const query = "SELECT * FROM users WHERE id = " + params.userId;
          const result = await db.query(query);
          
          // Command injection vulnerability
          exec("ls " + params.directory);
          
          // No input validation
          return result;
        }
        
        // Tool without proper error handling
        async function processData(params) {
          return eval(params.code);
        }
      `;

            const mcpConfigCode = `
        export const mcpServer = {
          name: "vulnerable-server",
          version: "1.0.0",
          tools: [
            {
              name: "execute-tool",
              description: "Executes queries",
              inputSchema: {
                type: "object",
                properties: {
                  userId: { type: "string" },
                  directory: { type: "string" }
                }
              },
              implementation: "server.ts"
            },
            {
              name: "process-data",
              description: "Processes user data",
              inputSchema: {
                type: "object",
                properties: {
                  code: { type: "string" }
                }
              },
              implementation: "server.ts"
            }
          ],
          resources: [],
          prompts: []
        };
      `;

            // Setup file system responses
            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify(packageJson);
                }
                if (filepath.includes('server.ts')) {
                    return vulnerableServerCode;
                }
                if (filepath.includes('mcp-config.ts')) {
                    return mcpConfigCode;
                }
                return '';
            });

            // Run analysis
            const violations = await analyzer.analyze(tempDir);

            // Verify multiple types of violations are detected
            expect(violations.length).toBeGreaterThan(0);

            // Check for specific violation types
            const ruleIds = violations.map(v => v.ruleId);
            expect(ruleIds).toContain('injection-detection');
            expect(ruleIds).toContain('auth-required');
            expect(ruleIds).toContain('parameter-validation');

            // Verify severity levels
            const errorViolations = violations.filter(v => v.severity === 'error');
            expect(errorViolations.length).toBeGreaterThan(0);

            // Generate and verify report
            const textReport = await reporter.generateReport(violations, 'text');
            expect(textReport).toContain('Security Violations Found');
            expect(textReport).toContain('ERRORS');

            const jsonReport = await reporter.generateReport(violations, 'json');
            const parsedReport = JSON.parse(jsonReport);
            expect(parsedReport.summary.total).toBe(violations.length);
        });

        it('should pass analysis for a secure project', async () => {
            // Mock a secure project
            const packageJson = {
                name: 'secure-mcp-server',
                version: '1.0.0',
                dependencies: {
                    express: '^4.18.0',
                    joi: '^17.0.0',
                    bcrypt: '^5.0.0',
                    jsonwebtoken: '^9.0.0'
                }
            };

            const secureServerCode = `
        import express from 'express';
        import jwt from 'jsonwebtoken';
        import Joi from 'joi';
        import bcrypt from 'bcrypt';
        
        const app = express();
        
        // Secure authentication middleware
        function authenticate(token) {
          try {
            return jwt.verify(token, process.env.JWT_SECRET);
          } catch (error) {
            logger.error('Authentication failed', { error: error.message });
            throw new Error('Unauthorized');
          }
        }
        
        // Secure tool with proper validation
        async function executeTool(params) {
          // Authentication check
          if (!authenticate(params.token)) {
            throw new Error('Unauthorized');
          }
          
          // Input validation
          const schema = Joi.object({
            userId: Joi.string().uuid().required(),
            directory: Joi.string().alphanum().required()
          });
          
          const { error, value } = schema.validate(params);
          if (error) {
            logger.warn('Validation failed', { error: error.message });
            throw new Error('Invalid input');
          }
          
          // Parameterized query
          const query = "SELECT * FROM users WHERE id = $1";
          const result = await db.query(query, [value.userId]);
          
          logger.info('Tool executed successfully', { 
            userId: value.userId,
            timestamp: new Date().toISOString()
          });
          
          return result;
        }
      `;

            const secureConfigCode = `
        export const mcpServer = {
          name: "secure-server",
          version: "1.0.0",
          tools: [
            {
              name: "execute-tool",
              description: "Executes secure queries",
              inputSchema: {
                type: "object",
                properties: {
                  userId: { 
                    type: "string", 
                    format: "uuid",
                    maxLength: 36
                  },
                  directory: { 
                    type: "string",
                    pattern: "^[a-zA-Z0-9]+$",
                    maxLength: 50
                  token: {
                    type: "string",
                    maxLength: 1000
                  }
                },
                required: ["userId", "directory", "token"],
                additionalProperties: false
              },
              implementation: "server.ts",
              permissions: ["read:users"],
              authRequired: true,
              rateLimit: {
                requests: 100,
                window: 60000,
                scope: "user"
              }
            }
          ],
          resources: [],
          prompts: []
        };
      `;

            // Setup file system responses for secure project
            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify(packageJson);
                }
                if (filepath.includes('server.ts')) {
                    return secureServerCode;
                }
                if (filepath.includes('mcp-config.ts')) {
                    return secureConfigCode;
                }
                return '';
            });

            // Run analysis
            const violations = await analyzer.analyze(tempDir);

            // Should have minimal or no violations
            const errorViolations = violations.filter(v => v.severity === 'error');
            expect(errorViolations.length).toBe(0);

            // Generate success report
            const textReport = await reporter.generateReport(violations, 'text');
            if (violations.length === 0) {
                expect(textReport).toContain('No security violations found');
            } else {
                // Only warnings or info should remain
                const highSeverityViolations = violations.filter(v =>
                    v.severity === 'error'
                );
                expect(highSeverityViolations.length).toBe(0);
            }
        });
    });

    describe('Fox Corp specific analysis', () => {
        it('should enforce Fox Corp streaming protection rules', async () => {
            const foxConfig = TestHelpers.createMockConfig({
                foxCorp: {
                    streamingAssets: true,
                    convivaIntegration: true,
                    harValidation: true,
                    auditLevel: 'forensic'
                }
            });

            analyzer = new MCPSecurityAnalyzer(foxConfig);

            const streamingServerCode = `
        // Streaming tool without proper Fox Corp protections
        async function streamContent(params) {
          const streamUrl = "rtmp://stream.fox.com/live/" + params.channel;
          const customerKey = "fox_customer_key_12345";
          
          // No DRM protection
          // No geo-blocking
          // No watermarking
          
          return fetch(streamUrl, {
            headers: {
              'Authorization': customerKey
            }
          });
        }
        
        // HAR processing without security
        async function processHAR(params) {
          const harData = JSON.parse(params.harContent);
          
          // No size validation
          // No content filtering
          // Potential PII exposure
          
          return harData;
        }
      `;

            const foxMcpConfig = `
        export const mcpServer = {
          name: "fox-streaming-server",
          tools: [
            {
              name: "stream-content",
              description: "Streams Fox content",
              inputSchema: {
                type: "object",
                properties: {
                  channel: { type: "string" }
                }
              },
              implementation: "server.ts"
            },
            {
              name: "process-har",
              description: "Processes HAR files for analytics",
              inputSchema: {
                type: "object",
                properties: {
                  harContent: { type: "string" }
                }
              },
              implementation: "server.ts"
            }
          ]
        };
      `;

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'fox-server', version: '1.0.0' });
                }
                if (filepath.includes('server.ts')) {
                    return streamingServerCode;
                }
                if (filepath.includes('mcp-config.ts')) {
                    return foxMcpConfig;
                }
                return '';
            });

            const violations = await analyzer.analyze(tempDir);

            // Should detect Fox Corp specific violations
            const foxViolations = violations.filter(v =>
                v.ruleId.includes('fox-') ||
                v.ruleId.includes('conviva') ||
                v.ruleId.includes('har')
            );

            expect(foxViolations.length).toBeGreaterThan(0);

            // Check for specific Fox Corp violations
            expect(violations.some(v =>
                v.message.includes('streaming permissions')
            )).toBe(true);

            expect(violations.some(v =>
                v.message.includes('HAR') || v.message.includes('har')
            )).toBe(true);
        });
    });

    describe('configuration-driven analysis', () => {
        it('should respect rule enablement configuration', async () => {
            const customConfig = TestHelpers.createMockConfig({
                rules: {
                    'auth-required': { enabled: false },
                    'injection-detection': { enabled: true, severity: 'warning' },
                    'parameter-validation': { enabled: true, severity: 'error' }
                }
            });

            analyzer = new MCPSecurityAnalyzer(customConfig);

            const testCode = `
        // Missing authentication (should be ignored)
        async function publicTool(params) {
          // SQL injection (should be warning)
          const query = "SELECT * FROM data WHERE id = " + params.id;
          return db.query(query);
        }
      `;

            const testConfig = `
        export const mcpServer = {
          tools: [{
            name: "public-tool",
            inputSchema: { type: "object" },
            implementation: "server.ts"
          }]
        };
      `;

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'test', version: '1.0.0' });
                }
                if (filepath.includes('server.ts')) {
                    return testCode;
                }
                if (filepath.includes('mcp-config.ts')) {
                    return testConfig;
                }
                return '';
            });

            const violations = await analyzer.analyze(tempDir);

            // Should not have auth-required violations (disabled)
            expect(violations.filter(v => v.ruleId === 'auth-required')).toHaveLength(0);

            // Should have injection-detection violations with warning severity
            const injectionViolations = violations.filter(v => v.ruleId === 'injection-detection');
            expect(injectionViolations.length).toBeGreaterThan(0);
            expect(injectionViolations[0].severity).toBe('warning');
        });

        it('should apply ignore patterns correctly', async () => {
            const configWithIgnores = TestHelpers.createMockConfig({
                ignorePatterns: [
                    'test/**',
                    '*.test.ts',
                    'legacy/**'
                ]
            });

            analyzer = new MCPSecurityAnalyzer(configWithIgnores);

            // Mock file system with ignored files
            mockFs.readdirSync.mockImplementation((dir: any) => {
                if (dir === tempDir) {
                    return ['src', 'test', 'legacy', 'package.json'];
                }
                if (dir.includes('test')) {
                    return ['vulnerable.test.ts'];
                }
                if (dir.includes('legacy')) {
                    return ['old-code.ts'];
                }
                if (dir.includes('src')) {
                    return ['server.ts'];
                }
                return [];
            });

            mockFs.statSync.mockImplementation((filepath: any) => ({
                isDirectory: () => ['src', 'test', 'legacy'].some(dir => filepath.includes(dir)),
                isFile: () => !['src', 'test', 'legacy'].some(dir => filepath.includes(dir))
            } as any));

            const violations = await analyzer.analyze(tempDir);

            // Should only analyze files in src/, not test/ or legacy/
            // This is verified by checking that readFileSync is not called for ignored paths
            const readFileCalls = (mockFs.readFileSync as jest.Mock).mock.calls;
            const ignoredFileCalls = readFileCalls.filter((call: any) =>
                call[0].includes('test/') ||
                call[0].includes('legacy/') ||
                call[0].includes('.test.ts')
            );

            expect(ignoredFileCalls.length).toBe(0);
        });
    });

    describe('report generation', () => {
        it('should generate reports in all supported formats', async () => {
            const sampleViolations = [
                {
                    ruleId: 'test-rule',
                    severity: 'error' as const,
                    message: 'Test violation',
                    file: '/test/file.ts',
                    line: 10,
                    evidence: 'Test evidence',
                    fix: 'Test fix'
                }
            ];

            // Test text format
            const textReport = await reporter.generateReport(sampleViolations, 'text');
            expect(textReport).toContain('Security Violations Found');
            expect(textReport).toContain('Test violation');
            expect(textReport).toContain('/test/file.ts:10');

            // Test JSON format
            const jsonReport = await reporter.generateReport(sampleViolations, 'json');
            const jsonData = JSON.parse(jsonReport);
            expect(jsonData.violations).toHaveLength(1);
            expect(jsonData.summary.errors).toBe(1);

            // Test JUnit format
            const junitReport = await reporter.generateReport(sampleViolations, 'junit');
            expect(junitReport).toContain('<?xml version="1.0"');
            expect(junitReport).toContain('<testsuite');
            expect(junitReport).toContain('<failure');

            // Test SARIF format
            const sarifReport = await reporter.generateReport(sampleViolations, 'sarif');
            const sarifData = JSON.parse(sarifReport);
            expect(sarifData.version).toBe('2.1.0');
            expect(sarifData.runs[0].results).toHaveLength(1);
        });

        it('should handle empty violation list', async () => {
            const textReport = await reporter.generateReport([], 'text');
            expect(textReport).toContain('No security violations found');

            const jsonReport = await reporter.generateReport([], 'json');
            const jsonData = JSON.parse(jsonReport);
            expect(jsonData.summary.total).toBe(0);
        });
    });

    describe('error handling and edge cases', () => {
        it('should handle missing package.json gracefully', async () => {
            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    throw new Error('ENOENT: no such file or directory');
                }
                return 'const test = "hello";';
            });

            // Should not throw an error
            const violations = await analyzer.analyze(tempDir);
            expect(Array.isArray(violations)).toBe(true);
        });

        it('should handle malformed JSON files gracefully', async () => {
            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return 'invalid json content';
                }
                return 'const test = "hello";';
            });

            // Should not throw an error
            const violations = await analyzer.analyze(tempDir);
            expect(Array.isArray(violations)).toBe(true);
        });

        it('should handle files that cannot be parsed as TypeScript', async () => {
            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'test', version: '1.0.0' });
                }
                return 'completely invalid typescript syntax }}}';
            });

            // Should not throw an error
            const violations = await analyzer.analyze(tempDir);
            expect(Array.isArray(violations)).toBe(true);
        });

        it('should handle rule execution failures gracefully', async () => {
            // Create an analyzer with a rule that will fail
            const configWithFailingRule = TestHelpers.createMockConfig();

            // Mock getAllRules to return a failing rule
            jest.doMock('../../src/rules', () => ({
                getAllRules: () => [{
                    id: 'failing-rule',
                    name: 'Failing Rule',
                    description: 'A rule that always fails',
                    severity: 'error',
                    category: 'test',
                    mandatory: true,
                    check: jest.fn().mockRejectedValue(new Error('Rule execution failed'))
                }]
            }));

            const { MCPSecurityAnalyzer } = await import('../../src/core/analyzer');
            const failingAnalyzer = new MCPSecurityAnalyzer(configWithFailingRule);

            mockFs.readFileSync.mockReturnValue('const test = "hello";');

            const violations = await failingAnalyzer.analyze(tempDir);

            // Should include a violation about the rule failure
            expect(violations.some(v =>
                v.message.includes('Rule execution failed')
            )).toBe(true);
        });
    });

    describe('performance and scalability', () => {
        it('should handle large projects efficiently', async () => {
            // Mock a large project structure
            const largeFileList = Array.from({ length: 100 }, (_, i) => `file${i}.ts`);

            mockFs.readdirSync.mockImplementation((dir: any) => {
                if (dir === tempDir) {
                    return ['src', 'package.json'];
                }
                if (dir.includes('src')) {
                    return largeFileList;
                }
                return [];
            });

            mockFs.statSync.mockImplementation((filepath: any) => ({
                isDirectory: () => filepath.includes('src'),
                isFile: () => !filepath.includes('src')
            } as any));

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'large-project', version: '1.0.0' });
                }
                return 'const test = "hello world";';
            });

            const startTime = Date.now();
            const violations = await analyzer.analyze(tempDir);
            const endTime = Date.now();

            // Should complete within reasonable time (adjust threshold as needed)
            expect(endTime - startTime).toBeLessThan(5000); // 5 seconds

            // Should have processed all files
            expect(Array.isArray(violations)).toBe(true);
        });
    });
});
