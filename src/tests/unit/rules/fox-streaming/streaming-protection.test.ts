import { foxStreamingProtection } from '../../../../../src/rules/fox-streaming/streaming-protection';
import { TestHelpers } from '../../../utils/test-helpers';

describe('fox-streaming-protection rule', () => {
    let mockContext: any;

    beforeEach(() => {
        mockContext = TestHelpers.createMockAnalysisContext({
            config: TestHelpers.createMockConfig({
                foxCorp: {
                    streamingAssets: true,
                    convivaIntegration: true,
                    harValidation: true,
                    auditLevel: 'comprehensive'
                }
            })
        });
    });

    describe('streaming tool detection', () => {
        it('should identify streaming tools by name', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'video-stream-tool',
                description: 'Handles video streaming'
            });

            mockContext.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(mockContext);

            expect(violations.length).toBeGreaterThan(0);
            expect(violations[0].ruleId).toBe('fox-streaming-protection');
        });

        it('should identify streaming tools by description', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'content-tool',
                description: 'Tool for managing media content and streaming'
            });

            mockContext.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(mockContext);

            expect(violations.length).toBeGreaterThan(0);
        });

        it('should skip non-streaming tools', async () => {
            const regularTool = TestHelpers.createMockTool({
                name: 'database-tool',
                description: 'Database operations'
            });

            mockContext.mcpServer.tools = [regularTool];

            const violations = await foxStreamingProtection.check(mockContext);

            TestHelpers.expectNoViolations(violations, 'fox-streaming-protection');
        });
    });

    describe('streaming permissions validation', () => {
        it('should require streaming permissions for streaming tools', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                description: 'Video streaming tool',
                permissions: ['general:read']
            });

            mockContext.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'fox-streaming-protection', 'error');
            expect(violations[0].message).toContain('must have explicit streaming permissions');
        });

        it('should pass for tools with streaming:read permission', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                description: 'Video streaming tool',
                permissions: ['streaming:read']
            });

            mockContext.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(mockContext);

            TestHelpers.expectNoViolations(violations.filter(v =>
                v.message.includes('streaming permissions')
            ));
        });

        it('should pass for tools with streaming:admin permission', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-admin-tool',
                description: 'Stream administration',
                permissions: ['streaming:admin']
            });

            mockContext.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(mockContext);

            TestHelpers.expectNoViolations(violations.filter(v =>
                v.message.includes('streaming permissions')
            ));
        });
    });

    describe('rate limiting requirements', () => {
        it('should warn about missing rate limiting', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                description: 'Video streaming tool',
                permissions: ['streaming:read'],
                rateLimit: undefined
            });

            mockContext.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'fox-streaming-protection', 'warning');
            expect(violations[0].message).toContain('should have rate limiting');
        });

        it('should pass for tools with rate limiting', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                description: 'Video streaming tool',
                permissions: ['streaming:read'],
                rateLimit: {
                    requests: 100,
                    window: 60000,
                    scope: 'user'
                }
            });

            mockContext.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(mockContext);

            TestHelpers.expectNoViolations(violations.filter(v =>
                v.message.includes('rate limiting')
            ));
        });
    });

    describe('streaming implementation analysis', () => {
        it('should detect hardcoded streaming URLs', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                permissions: ['streaming:read']
            });

            const implementationCode = `
        function streamTool(params) {
          const streamUrl = "rtmp://stream.fox.com/live/channel1";
          return fetch(streamUrl);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(implementationCode, 'stream-tool.ts');
            mockContext.mcpServer.tools = [streamingTool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await foxStreamingProtection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'fox-streaming-protection', 'error');
            expect(violations[0].message).toContain('URLs must be validated');
        });

        it('should detect hardcoded credentials', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                permissions: ['streaming:read']
            });

            const implementationCode = `
        function streamTool(params) {
          const apiKey = "fox_api_key_12345678901234567890";
          return authenticate(apiKey);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(implementationCode, 'stream-tool.ts');
            mockContext.mcpServer.tools = [streamingTool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await foxStreamingProtection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'fox-streaming-protection', 'error');
            expect(violations[0].message).toContain('Hardcoded credentials');
        });

        it('should pass for properly validated streaming URLs', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                permissions: ['streaming:read']
            });

            const implementationCode = `
        function streamTool(params) {
          const streamUrl = params.url;
          if (!validateUrl(streamUrl)) {
            throw new Error('Invalid URL');
          }
          return fetch(streamUrl);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(implementationCode, 'stream-tool.ts');
            mockContext.mcpServer.tools = [streamingTool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await foxStreamingProtection.check(mockContext);

            TestHelpers.expectNoViolations(violations.filter(v =>
                v.message.includes('URLs must be validated')
            ));
        });
    });

    describe('Fox Corp configuration', () => {
        it('should skip analysis when Fox Corp streaming is disabled', async () => {
            const contextWithoutFox = TestHelpers.createMockAnalysisContext({
                config: TestHelpers.createMockConfig({
                    foxCorp: {
                        streamingAssets: false
                    }
                })
            });

            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                description: 'Video streaming tool'
            });

            contextWithoutFox.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(contextWithoutFox);

            expect(violations).toHaveLength(0);
        });

        it('should analyze streaming tools when Fox Corp streaming is enabled', async () => {
            const streamingTool = TestHelpers.createMockTool({
                name: 'stream-tool',
                description: 'Video streaming tool',
                permissions: []
            });

            mockContext.mcpServer.tools = [streamingTool];

            const violations = await foxStreamingProtection.check(mockContext);

            expect(violations.length).toBeGreaterThan(0);
        });
    });

    describe('streaming URL validation', () => {
        it('should detect various streaming URL patterns', async () => {
            const urlPatterns = [
                'rtmp://example.com/live',
                'hls://example.com/playlist.m3u8',
                'dash://example.com/manifest.mpd',
                'https://media.fox.com/stream'
            ];

            for (const url of urlPatterns) {
                const streamingTool = TestHelpers.createMockTool({
                    name: 'stream-tool',
                    permissions: ['streaming:read']
                });

                const implementationCode = `
          function streamTool() {
            const url = "${url}";
            return fetch(url);
          }
        `;

                const sourceFile = TestHelpers.createMockSourceFile(implementationCode);
                const context = TestHelpers.createMockAnalysisContext({
                    mcpServer: { ...mockContext.mcpServer, tools: [streamingTool] },
                    sourceFiles: [sourceFile],
                    config: mockContext.config
                });

                const violations = await foxStreamingProtection.check(context);

                expect(violations.some(v =>
                    v.ruleId === 'fox-streaming-protection' &&
                    v.message.includes('URLs must be validated')
                )).toBe(true);
            }
        });
    });

    describe('credential detection patterns', () => {
        it('should detect various credential patterns', async () => {
            const credentialPatterns = [
                'api_key_1234567890123456',
                'secret_token_abcdefghijk',
                'fox_auth_key_xyz123',
                'streaming_password_test'
            ];

            for (const credential of credentialPatterns) {
                const streamingTool = TestHelpers.createMockTool({
                    name: 'stream-tool',
                    permissions: ['streaming:read']
                });

                const implementationCode = `
          function streamTool() {
            const cred = "${credential}";
            return authenticate(cred);
          }
        `;

                const sourceFile = TestHelpers.createMockSourceFile(implementationCode);
                const context = TestHelpers.createMockAnalysisContext({
                    mcpServer: { ...mockContext.mcpServer, tools: [streamingTool] },
                    sourceFiles: [sourceFile],
                    config: mockContext.config
                });

                const violations = await foxStreamingProtection.check(context);

                expect(violations.some(v =>
                    v.ruleId === 'fox-streaming-protection' &&
                    v.message.includes('Hardcoded credentials')
                )).toBe(true);
            }
        });
    });
});
