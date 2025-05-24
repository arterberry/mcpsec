import { MCPSecurityAnalyzer } from '../../src/core/analyzer';
import { TestHelpers } from '../utils/test-helpers';
import * as fs from 'fs';

jest.mock('fs');
const mockFs = fs as jest.Mocked<typeof fs>;

describe('Rule Combinations and Interactions', () => {
    let analyzer: MCPSecurityAnalyzer;
    let mockContext: any;

    beforeEach(() => {
        const config = TestHelpers.createMockConfig();
        analyzer = new MCPSecurityAnalyzer(config);
        mockContext = TestHelpers.createMockAnalysisContext();

        // Setup default file system mocks
        mockFs.readdirSync.mockReturnValue(['package.json', 'server.ts']);
        mockFs.statSync.mockReturnValue({ isDirectory: () => false } as any);
        mockFs.existsSync.mockReturnValue(true);
    });

    describe('authentication and authorization integration', () => {
        it('should detect missing authentication AND authorization', async () => {
            const vulnerableCode = `
        // Tool missing both auth and authz
        async function adminTool(params) {
          // No authentication check
          // No authorization check
          return await deleteUser(params.userId);
        }
      `;

            const toolConfig = {
                name: 'admin-tool',
                description: 'Administrative tool',
                inputSchema: { type: 'object' },
                implementation: 'server.ts'
                // No authRequired, no permissions, no roles
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'test', version: '1.0.0' });
                }
                return vulnerableCode;
            });

            mockContext.mcpServer.tools = [toolConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(vulnerableCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should detect violations from multiple rules
            const ruleIds = violations.map(v => v.ruleId);
            expect(ruleIds).toContain('auth-required');
            expect(ruleIds).toContain('permission-checks');
            expect(ruleIds).toContain('role-validation');
        });

        it('should validate consistent auth/authz implementation', async () => {
            const inconsistentCode = `
        async function protectedTool(params) {
          // Has auth check but wrong permission validation
          if (!authenticate(params.token)) {
            throw new Error('Unauthorized');
          }
          
          // Checking wrong permission
          if (!hasPermission(params.user, 'wrong:permission')) {
            throw new Error('Forbidden');
          }
          
          return sensitiveData;
        }
      `;

            const toolConfig = {
                name: 'protected-tool',
                description: 'Protected tool',
                authRequired: true,
                permissions: ['correct:permission'],
                roles: ['user'],
                inputSchema: { type: 'object' },
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'test', version: '1.0.0' });
                }
                return inconsistentCode;
            });

            mockContext.mcpServer.tools = [toolConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(inconsistentCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should detect inconsistency between declared and implemented permissions
            expect(violations.some(v =>
                v.message.includes('permission') &&
                (v.message.includes('inconsistent') || v.message.includes('mismatch'))
            )).toBe(true);
        });
    });

    describe('input validation and injection prevention', () => {
        it('should detect both missing validation AND injection vulnerabilities', async () => {
            const vulnerableCode = `
        async function queryTool(params) {
          // No input validation
          // Direct SQL injection vulnerability
          const query = "SELECT * FROM users WHERE name = '" + params.name + "'";
          return db.query(query);
        }
      `;

            const toolConfig = {
                name: 'query-tool',
                description: 'Database query tool',
                inputSchema: {
                    type: 'object',
                    properties: {
                        name: { type: 'string' }
                        // Missing validation constraints
                    }
                },
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'test', version: '1.0.0' });
                }
                return vulnerableCode;
            });

            mockContext.mcpServer.tools = [toolConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(vulnerableCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should detect both parameter validation and injection issues
            const ruleIds = violations.map(v => v.ruleId);
            expect(ruleIds).toContain('parameter-validation');
            expect(ruleIds).toContain('injection-detection');
            expect(ruleIds).toContain('input-sanitization');
        });

        it('should validate sanitization prevents injection', async () => {
            const partiallySecureCode = `
        async function queryTool(params) {
          // Has some validation but not injection-proof
          if (typeof params.name !== 'string') {
            throw new Error('Invalid input');
          }
          
          // Still vulnerable to SQL injection
          const query = "SELECT * FROM users WHERE name = '" + params.name + "'";
          return db.query(query);
        }
      `;

            const toolConfig = {
                name: 'query-tool',
                inputSchema: {
                    type: 'object',
                    properties: {
                        name: { type: 'string', maxLength: 100 }
                    },
                    required: ['name']
                },
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'test', version: '1.0.0' });
                }
                return partiallySecureCode;
            });

            mockContext.mcpServer.tools = [toolConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(partiallySecureCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should still detect injection despite basic validation
            expect(violations.some(v => v.ruleId === 'injection-detection')).toBe(true);

            // May pass parameter validation but fail sanitization
            const sanitizationViolations = violations.filter(v => v.ruleId === 'input-sanitization');
            expect(sanitizationViolations.length).toBeGreaterThan(0);
        });
    });

    describe('Fox Corp streaming rules interaction', () => {
        it('should enforce comprehensive streaming protection', async () => {
            const streamingCode = `
        async function streamTool(params) {
          // Missing streaming-specific validation
          const streamUrl = "rtmp://stream.fox.com/" + params.channel;
          const customerKey = "hardcoded_conviva_key_12345";
          
          // No HAR validation for analytics
          const harData = JSON.parse(params.harContent);
          
          return {
            stream: fetch(streamUrl),
            analytics: processConvivaData(harData, customerKey)
          };
        }
      `;

            const streamingConfig = {
                name: 'stream-tool',
                description: 'Streaming content tool',
                inputSchema: {
                    type: 'object',
                    properties: {
                        channel: { type: 'string' },
                        harContent: { type: 'string' }
                    }
                },
                implementation: 'server.ts'
                // Missing streaming permissions, rate limits, etc.
            };

            const foxCorpConfig = TestHelpers.createMockConfig({
                foxCorp: {
                    streamingAssets: true,
                    convivaIntegration: true,
                    harValidation: true,
                    auditLevel: 'forensic'
                }
            });

            analyzer = new MCPSecurityAnalyzer(foxCorpConfig);

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'fox-streaming-server', version: '1.0.0' });
                }
                return streamingCode;
            });

            mockContext.mcpServer.tools = [streamingConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(streamingCode)];
            mockContext.config = foxCorpConfig;

            const violations = await analyzer.analyze('/test/project');

            // Should detect violations from all Fox Corp streaming rules
            const foxRuleIds = violations.filter(v =>
                v.ruleId.includes('fox-') ||
                v.ruleId.includes('conviva') ||
                v.ruleId.includes('har')
            ).map(v => v.ruleId);

            expect(foxRuleIds).toContain('fox-streaming-protection');
            expect(foxRuleIds).toContain('conviva-validation');
            expect(foxRuleIds).toContain('har-security');

            // Should also detect general security issues
            const generalRuleIds = violations.map(v => v.ruleId);
            expect(generalRuleIds).toContain('parameter-validation');
            expect(generalRuleIds).toContain('injection-detection');
        });

        it('should validate streaming security layers work together', async () => {
            const compliantStreamingCode = `
        async function streamTool(params) {
          // Proper authentication
          const user = await authenticate(params.token);
          if (!user) throw new Error('Unauthorized');
          
          // Streaming-specific authorization
          if (!hasStreamingPermission(user, 'streaming:read')) {
            throw new Error('Insufficient permissions');
          }
          
          // Input validation with streaming constraints
          const schema = Joi.object({
            streamId: Joi.string().pattern(/^fox-[a-zA-Z0-9-]+$/).required(),
            contentType: Joi.string().valid('live', 'vod', 'sports').required()
          });
          
          const { error, value } = schema.validate(params);
          if (error) throw new Error('Invalid input');
          
          // Secure streaming URL construction
          const streamUrl = buildSecureStreamUrl(value.streamId, value.contentType);
          
          // Rate limiting
          await rateLimiter.checkLimit(user.id, 'streaming');
          
          // Audit logging
          logger.info('Stream access', {
            userId: user.id,
            streamId: value.streamId,
            contentType: value.contentType,
            timestamp: new Date().toISOString()
          });
          
          return { streamUrl };
        }
      `;

            const compliantConfig = {
                name: 'stream-tool',
                description: 'Compliant streaming tool',
                authRequired: true,
                permissions: ['streaming:read'],
                roles: ['stream_operator'],
                rateLimit: {
                    requests: 50,
                    window: 60000,
                    scope: 'user'
                },
                inputSchema: {
                    type: 'object',
                    properties: {
                        streamId: {
                            type: 'string',
                            pattern: '^fox-[a-zA-Z0-9-]+$',
                            maxLength: 50
                        },
                        contentType: {
                            type: 'string',
                            enum: ['live', 'vod', 'sports']
                        },
                        token: {
                            type: 'string',
                            maxLength: 1000
                        }
                    },
                    required: ['streamId', 'contentType', 'token'],
                    additionalProperties: false
                },
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({
                        name: 'compliant-streaming-server',
                        version: '1.0.0',
                        dependencies: {
                            joi: '^17.0.0',
                            winston: '^3.0.0'
                        }
                    });
                }
                return compliantStreamingCode;
            });

            mockContext.mcpServer.tools = [compliantConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(compliantStreamingCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should have minimal violations for compliant streaming implementation
            const errorViolations = violations.filter(v => v.severity === 'error');
            expect(errorViolations.length).toBe(0);

            // Any remaining violations should be low severity
            violations.forEach(violation => {
                expect(['warning', 'info']).toContain(violation.severity);
            });
        });
    });

    describe('rate limiting and resource protection', () => {
        it('should coordinate rate limiting with other security measures', async () => {
            const resourceIntensiveCode = `
        async function dataProcessingTool(params) {
          // Expensive operation without proper protection
          const largeDataset = await loadEntireDatabase();
          const results = await processComplexAnalytics(largeDataset, params.query);
          
          // Potential resource exhaustion
          for (let i = 0; i < params.iterations; i++) {
            await heavyComputation(results);
          }
          
          return results;
        }
      `;

            const resourceIntensiveConfig = {
                name: 'data-processing-tool',
                description: 'Data processing and analytics',
                inputSchema: {
                    type: 'object',
                    properties: {
                        query: { type: 'string' },
                        iterations: { type: 'number' }
                        // Missing constraints on iterations
                    }
                },
                // Missing rate limiting
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'analytics-server', version: '1.0.0' });
                }
                return resourceIntensiveCode;
            });

            mockContext.mcpServer.tools = [resourceIntensiveConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(resourceIntensiveCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should detect multiple resource protection issues
            const ruleIds = violations.map(v => v.ruleId);
            expect(ruleIds).toContain('rate-limit-enforcement');
            expect(ruleIds).toContain('parameter-validation'); // Missing iteration limits
            expect(ruleIds).toContain('auth-required'); // Resource-intensive tools need auth
        });
    });

    describe('audit logging integration', () => {
        it('should ensure audit logging covers all security events', async () => {
            const partiallyLoggedCode = `
        async function sensitiveOperationTool(params) {
          try {
            // Authentication with logging
            const user = await authenticate(params.token);
            logger.info('User authenticated', { userId: user.id });
            
            // Authorization without logging
            if (!hasPermission(user, 'sensitive:operation')) {
              throw new Error('Forbidden');
            }
            
            // Sensitive operation without comprehensive logging
            const result = await performSensitiveOperation(params.data);
            
            return result;
          } catch (error) {
            // Error without security context logging
            throw error;
          }
        }
      `;

            const sensitiveConfig = {
                name: 'sensitive-operation-tool',
                description: 'Performs sensitive operations',
                authRequired: true,
                permissions: ['sensitive:operation'],
                inputSchema: { type: 'object' },
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'sensitive-server', version: '1.0.0' });
                }
                return partiallyLoggedCode;
            });

            mockContext.mcpServer.tools = [sensitiveConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(partiallyLoggedCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should detect incomplete audit logging
            const auditViolations = violations.filter(v => v.ruleId === 'audit-logging');
            expect(auditViolations.length).toBeGreaterThan(0);

            // Should identify missing security event logging
            expect(auditViolations.some(v =>
                v.message.includes('authorization') ||
                v.message.includes('error')
            )).toBe(true);
        });
    });

    describe('cross-cutting security concerns', () => {
        it('should detect when multiple security layers are missing', async () => {
            const comprehensivelyVulnerableCode = `
        // Tool with multiple security issues across all categories
        async function multiVulnerableTool(params) {
          // 1. No authentication
          // 2. No input validation
          // 3. SQL injection vulnerability
          const query = "SELECT * FROM sensitive_data WHERE filter = '" + params.filter + "'";
          
          // 4. Command injection
          exec("grep " + params.pattern + " /var/log/app.log");
          
          // 5. Hardcoded secret
          const apiKey = "sk_live_hardcoded_secret_key_12345678901234567890";
          
          // 6. No rate limiting protection
          // 7. No audit logging
          // 8. Eval usage
          const code = params.dynamicCode;
          return eval(code);
        }
      `;

            const vulnerableConfig = {
                name: 'multi-vulnerable-tool',
                description: 'Tool with comprehensive vulnerabilities',
                inputSchema: {
                    type: 'object'
                    // No property definitions or validation
                },
                implementation: 'server.ts'
                // Missing: authRequired, permissions, roles, rateLimit
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'vulnerable-server', version: '1.0.0' });
                }
                return comprehensivelyVulnerableCode;
            });

            mockContext.mcpServer.tools = [vulnerableConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(comprehensivelyVulnerableCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should detect violations across all security categories
            const ruleIds = violations.map(v => v.ruleId);

            // Authentication category
            expect(ruleIds).toContain('auth-required');

            // Authorization category  
            expect(ruleIds).toContain('permission-checks');
            expect(ruleIds).toContain('role-validation');

            // Input validation category
            expect(ruleIds).toContain('parameter-validation');
            expect(ruleIds).toContain('input-sanitization');
            expect(ruleIds).toContain('injection-detection');

            // Rate limiting category
            expect(ruleIds).toContain('rate-limit-enforcement');

            // Audit logging category
            expect(ruleIds).toContain('audit-logging');

            // Should have multiple high-severity violations
            const errorViolations = violations.filter(v => v.severity === 'error');
            expect(errorViolations.length).toBeGreaterThan(5);
        });

        it('should validate defense-in-depth implementation', async () => {
            const defenseInDepthCode = `
        async function secureMultiLayerTool(params) {
          // Layer 1: Authentication
          const user = await authenticateWithMFA(params.token, params.mfaCode);
          if (!user) {
            await auditLogger.logSecurityEvent('auth_failure', { 
              ip: params.clientIP, 
              timestamp: new Date().toISOString() 
            });
            throw new Error('Authentication failed');
          }
          
          // Layer 2: Authorization with multiple checks
          if (!hasRole(user, 'admin') || !hasPermission(user, 'sensitive:read')) {
            await auditLogger.logSecurityEvent('authz_failure', { 
              userId: user.id, 
              attemptedAction: 'sensitive:read',
              timestamp: new Date().toISOString()
            });
            throw new Error('Insufficient permissions');
          }
          
          // Layer 3: Rate limiting
          await rateLimiter.checkAndRecord(user.id, 'sensitive-operations');
          
          // Layer 4: Input validation with multiple layers
          const schema = Joi.object({
            query: Joi.string().max(1000).pattern(/^[a-zA-Z0-9\s\-_]+$/).required(),
            limit: Joi.number().min(1).max(100).required()
          });
          
          const { error, value } = schema.validate(params);
          if (error) {
            await auditLogger.logSecurityEvent('validation_failure', { 
              userId: user.id, 
              error: error.message,
              timestamp: new Date().toISOString()
            });
            throw new Error('Invalid input');
          }
          
          // Layer 5: Additional sanitization
          const sanitizedQuery = sanitizeForDatabase(value.query);
          
          // Layer 6: Parameterized query (injection protection)
          const query = "SELECT id, name FROM public_data WHERE description LIKE $1 LIMIT $2";
          const result = await db.query(query, [\`%\${sanitizedQuery}%\`, value.limit]);
          
          // Layer 7: Output sanitization
          const sanitizedResult = result.map(row => ({
            id: row.id,
            name: sanitizeForOutput(row.name)
          }));
          
          // Layer 8: Comprehensive audit logging
          await auditLogger.logBusinessEvent('data_access', {
            userId: user.id,
            action: 'query_data',
            query: sanitizedQuery,
            resultCount: sanitizedResult.length,
            timestamp: new Date().toISOString(),
            clientIP: params.clientIP,
            userAgent: params.userAgent
          });
          
          return sanitizedResult;
        }
      `;

            const secureConfig = {
                name: 'secure-multi-layer-tool',
                description: 'Tool with comprehensive security layers',
                authRequired: true,
                permissions: ['sensitive:read'],
                roles: ['admin'],
                rateLimit: {
                    requests: 10,
                    window: 60000,
                    scope: 'user'
                },
                inputSchema: {
                    type: 'object',
                    properties: {
                        query: {
                            type: 'string',
                            maxLength: 1000,
                            pattern: '^[a-zA-Z0-9\\s\\-_]+$'
                        },
                        limit: {
                            type: 'number',
                            minimum: 1,
                            maximum: 100
                        },
                        token: { type: 'string', maxLength: 1000 },
                        mfaCode: { type: 'string', pattern: '^[0-9]{6}$' },
                        clientIP: { type: 'string', format: 'ipv4' },
                        userAgent: { type: 'string', maxLength: 500 }
                    },
                    required: ['query', 'limit', 'token', 'mfaCode'],
                    additionalProperties: false
                },
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({
                        name: 'secure-server',
                        version: '1.0.0',
                        dependencies: {
                            joi: '^17.0.0',
                            winston: '^3.0.0',
                            bcrypt: '^5.0.0',
                            jsonwebtoken: '^9.0.0'
                        }
                    });
                }
                return defenseInDepthCode;
            });

            mockContext.mcpServer.tools = [secureConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(defenseInDepthCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should have minimal violations for well-secured implementation
            const errorViolations = violations.filter(v => v.severity === 'error');
            expect(errorViolations.length).toBe(0);

            // Any warnings should be minor improvements
            const warningViolations = violations.filter(v => v.severity === 'warning');
            warningViolations.forEach(violation => {
                expect(violation.message).not.toContain('missing');
                expect(violation.message).not.toContain('lacks');
            });
        });
    });

    describe('rule precedence and conflicts', () => {
        it('should handle conflicting rule recommendations appropriately', async () => {
            // Some security rules might have conflicting recommendations
            // e.g., strict validation vs. usability, logging detail vs. privacy
            const conflictingCode = `
        async function userDataTool(params) {
          // Authentication with detailed logging (privacy concern)
          const user = await authenticate(params.token);
          logger.info('User authenticated', { 
            userId: user.id, 
            email: user.email,  // PII in logs
            ipAddress: params.clientIP 
          });
          
          // Very strict validation (usability concern)
          if (params.searchTerm.length < 3) {
            throw new Error('Search term too short');
          }
          
          // Conservative rate limiting (performance concern)
          await rateLimiter.checkLimit(user.id, 'search', { requests: 1, window: 60000 });
          
          return searchResults;
        }
      `;

            const balancedConfig = {
                name: 'user-data-tool',
                description: 'User data search tool',
                authRequired: true,
                permissions: ['user:search'],
                rateLimit: {
                    requests: 1,  // Very conservative
                    window: 60000,
                    scope: 'user'
                },
                inputSchema: {
                    type: 'object',
                    properties: {
                        searchTerm: {
                            type: 'string',
                            minLength: 3,  // Strict validation
                            maxLength: 100
                        },
                        token: { type: 'string' },
                        clientIP: { type: 'string', format: 'ipv4' }
                    },
                    required: ['searchTerm', 'token'],
                    additionalProperties: false
                },
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'balanced-server', version: '1.0.0' });
                }
                return conflictingCode;
            });

            mockContext.mcpServer.tools = [balancedConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(conflictingCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should provide balanced recommendations
            const auditViolations = violations.filter(v => v.ruleId === 'audit-logging');

            // Might warn about PII in logs but recognize the security value
            if (auditViolations.some(v => v.message.includes('PII'))) {
                expect(auditViolations.some(v =>
                    v.severity === 'warning' // Not error, acknowledging the balance
                )).toBe(true);
            }
        });
    });

    describe('progressive security hardening', () => {
        it('should provide graduated recommendations for security improvement', async () => {
            const partiallySecureCode = `
        async function improvingTool(params) {
          // Has basic auth but could be stronger
          const user = await authenticate(params.token);
          if (!user) throw new Error('Unauthorized');
          
          // Has some validation but incomplete
          if (!params.data || typeof params.data !== 'string') {
            throw new Error('Invalid data');
          }
          
          // Has basic logging but could be more comprehensive
          logger.info('Tool executed', { userId: user.id });
          
          // Parameterized query (good) but no additional sanitization
          const result = await db.query("SELECT * FROM items WHERE category = $1", [params.data]);
          
          return result;
        }
      `;

            const improvingConfig = {
                name: 'improving-tool',
                description: 'Tool with partial security measures',
                authRequired: true,
                inputSchema: {
                    type: 'object',
                    properties: {
                        data: { type: 'string' }
                        // Missing additional constraints
                    },
                    required: ['data']
                    // Missing additionalProperties: false
                },
                // Missing: permissions, roles, rateLimit
                implementation: 'server.ts'
            };

            mockFs.readFileSync.mockImplementation((filepath: any) => {
                if (filepath.includes('package.json')) {
                    return JSON.stringify({ name: 'improving-server', version: '1.0.0' });
                }
                return partiallySecureCode;
            });

            mockContext.mcpServer.tools = [improvingConfig];
            mockContext.sourceFiles = [TestHelpers.createMockSourceFile(partiallySecureCode)];

            const violations = await analyzer.analyze('/test/project');

            // Should have a mix of severities, prioritizing the most critical issues
            const errorViolations = violations.filter(v => v.severity === 'error');
            const warningViolations = violations.filter(v => v.severity === 'warning');
            const infoViolations = violations.filter(v => v.severity === 'info');

            // Should have some violations but not overwhelming
            expect(violations.length).toBeGreaterThan(0);
            expect(violations.length).toBeLessThan(10); // Not overwhelming

            // Errors should be for critical missing pieces
            errorViolations.forEach(violation => {
                expect(['permission-checks', 'role-validation', 'parameter-validation'])
                    .toContain(violation.ruleId);
            });

            // Warnings should be for improvements
            warningViolations.forEach(violation => {
                expect(['rate-limit-enforcement', 'audit-logging', 'input-sanitization'])
                    .toContain(violation.ruleId);
            });
        });
    });
});
