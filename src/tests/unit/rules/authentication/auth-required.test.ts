import { authRequired } from '../../../../../src/rules/authentication/auth-required';
import { TestHelpers } from '../../../utils/test-helpers';

describe('auth-required rule', () => {
    let mockContext: any;

    beforeEach(() => {
        mockContext = TestHelpers.createMockAnalysisContext();
    });

    describe('tool authentication requirements', () => {
        it('should require authentication for all tools', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: undefined
            });

            mockContext.mcpServer.tools = [tool];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('lacks authentication requirement');
        });

        it('should pass for tools with authRequired: true', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            mockContext.mcpServer.tools = [tool];

            const violations = await authRequired.check(mockContext);

            TestHelpers.expectNoViolations(violations, 'auth-required');
        });

        it('should pass for tools with authentication property', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authentication: 'required'
            });

            mockContext.mcpServer.tools = [tool];

            const violations = await authRequired.check(mockContext);

            TestHelpers.expectNoViolations(violations, 'auth-required');
        });

        it('should pass for tools with permissions', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                permissions: ['read:data']
            });

            mockContext.mcpServer.tools = [tool];

            const violations = await authRequired.check(mockContext);

            TestHelpers.expectNoViolations(violations, 'auth-required');
        });
    });

    describe('authentication implementation checks', () => {
        it('should detect missing authentication checks in implementation', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const implementationCode = `
        async function testTool(params) {
          // No authentication check
          return { result: 'data' };
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(implementationCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('lacks authentication validation');
        });

        it('should pass for implementations with authentication checks', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const implementationCode = `
        async function testTool(params) {
          if (!authenticate(params.token)) {
            throw new Error('Unauthorized');
          }
          return { result: 'data' };
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(implementationCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            TestHelpers.expectNoViolations(violations);
        });
    });

    describe('token validation checks', () => {
        it('should detect missing token validation', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const implementationCode = `
        async function testTool(params) {
          const token = params.authorization;
          // No token validation
          return { result: 'data' };
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(implementationCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('lacks proper token validation');
        });

        it('should pass for proper token validation', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const implementationCode = `
        async function testTool(params) {
          const token = params.authorization;
          const verified = jwt.verify(token, secret);
          if (!verified) {
            throw new Error('Invalid token');
          }
          return { result: 'data' };
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(implementationCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            TestHelpers.expectNoViolations(violations);
        });
    });

    describe('high-risk tool authentication', () => {
        it('should require strong authentication for admin tools', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'admin-tool',
                description: 'Administrative functions',
                authRequired: true,
                authentication: 'basic'
            });

            mockContext.mcpServer.tools = [tool];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('requires strong authentication');
        });

        it('should pass for high-risk tools with strong authentication', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'admin-tool',
                description: 'Administrative functions',
                authRequired: true,
                authentication: 'mfa'
            });

            mockContext.mcpServer.tools = [tool];

            const violations = await authRequired.check(mockContext);

            TestHelpers.expectNoViolations(violations);
        });

        it('should require additional authorization for system tools', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'system-tool',
                description: 'System operations',
                authRequired: true,
                strongAuth: true
            });

            mockContext.mcpServer.tools = [tool];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('requires additional authorization');
        });
    });

    describe('global authentication middleware', () => {
        it('should detect missing global authentication middleware', async () => {
            mockContext.sourceFiles = [];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('No global authentication middleware');
        });

        it('should pass when authentication middleware is present', async () => {
            const middlewareCode = `
        function authMiddleware(req, res, next) {
          if (!authenticate(req.headers.authorization)) {
            return res.status(401).send('Unauthorized');
          }
          next();
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(middlewareCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            TestHelpers.expectNoViolations(violations.filter(v =>
                v.message.includes('global authentication middleware')
            ));
        });
    });

    describe('weak authentication patterns', () => {
        it('should detect plain text password comparison', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const weakCode = `
        function authenticate(password) {
          return password === 'hardcoded_password';
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(weakCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('Weak password comparison');
        });

        it('should detect hardcoded credentials', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const weakCode = `
        function authenticate() {
          const secret = 'hardcoded_secret_key_12345';
          return jwt.sign(payload, secret);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(weakCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('Hardcoded credentials');
        });

        it('should detect weak JWT secrets', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const weakCode = `
        function generateToken() {
          const secret = 'weak';
          return jwt.sign(payload, secret);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(weakCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('Weak JWT secret');
        });
    });

    describe('authentication bypass detection', () => {
        it('should detect authentication bypass conditions', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const bypassCode = `
        function authenticate(req) {
          if (skipAuth || bypassAuth) {
            return true;
          }
          return verifyToken(req.token);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(bypassCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('Authentication bypass condition');
        });

        it('should detect debug mode bypasses', async () => {
            const tool = TestHelpers.createMockTool({
                name: 'test-tool',
                authRequired: true
            });

            const debugCode = `
        function authenticate(req) {
          if (process.env.NODE_ENV === 'development') {
            return true;
          }
          return verifyToken(req.token);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(debugCode);
            mockContext.mcpServer.tools = [tool];
            mockContext.sourceFiles = [sourceFile];

            const violations = await authRequired.check(mockContext);

            await TestHelpers.expectViolation(violations, 'auth-required', 'error');
            expect(violations[0].message).toContain('Debug authentication bypass');
        });
    });
});
