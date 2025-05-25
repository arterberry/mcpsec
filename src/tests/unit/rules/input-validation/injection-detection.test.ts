import { injectionDetection } from '../../../../../src/rules/input-validation/injection-detection';
import { TestHelpers } from '../../../utils/test-helpers';

describe('injection-detection rule', () => {
    let mockContext: any;

    beforeEach(() => {
        mockContext = TestHelpers.createMockAnalysisContext();
    });

    describe('SQL injection detection', () => {
        it('should detect SQL injection in query calls', async () => {
            const vulnerableCode = `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = " + userId;
          return db.query(query);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'error');
            expect(violations[0].message).toContain('SQL injection vulnerability');
        });

        it('should not detect SQL injection with parameterized queries', async () => {
            const secureCode = `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = $1";
          return db.query(query, [userId]);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(secureCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            TestHelpers.expectNoViolations(violations, 'injection-detection');
        });

        it('should detect SQL injection in exec calls', async () => {
            const vulnerableCode = `
        function executeQuery(userInput) {
          return db.exec("DELETE FROM logs WHERE id = " + userInput);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'error');
        });
    });

    describe('Command injection detection', () => {
        it('should detect command injection in exec calls', async () => {
            const vulnerableCode = `
        function runCommand(userInput) {
          return exec("ls " + userInput);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'error');
            expect(violations[0].message).toContain('command injection vulnerability');
        });

        it('should detect command injection in spawn calls', async () => {
            const vulnerableCode = `
        function executeCommand(command) {
          return spawn('sh', ['-c', command]);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'error');
        });

        it('should not detect command injection with sanitized input', async () => {
            const secureCode = `
        function executeCommand(userInput) {
          const sanitized = sanitizeInput(userInput);
          return exec(sanitized);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(secureCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            TestHelpers.expectNoViolations(violations, 'injection-detection');
        });
    });

    describe('Eval injection detection', () => {
        it('should detect dangerous eval usage', async () => {
            const vulnerableCode = `
        function processUserCode(code) {
          return eval(code);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'error');
            expect(violations[0].message).toContain('eval-like function usage');
        });

        it('should detect Function constructor usage', async () => {
            const vulnerableCode = `
        function createFunction(code) {
          return new Function(code);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'error');
        });

        it('should detect setTimeout with string argument', async () => {
            const vulnerableCode = `
        function delayedExecution(code) {
          setTimeout(code, 1000);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'error');
        });
    });

    describe('Template literal injection detection', () => {
        it('should detect SQL-like template literals with unsanitized input', async () => {
            const vulnerableCode = `
        function buildQuery(userId) {
          return \`SELECT * FROM users WHERE id = \${userId}\`;
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'warning');
            expect(violations[0].message).toContain('Template literal with potential injection risk');
        });

        it('should detect command-like template literals with unsanitized input', async () => {
            const vulnerableCode = `
        function buildCommand(filename) {
          return \`rm \${filename}\`;
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(vulnerableCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            await TestHelpers.expectViolation(violations, 'injection-detection', 'warning');
        });

        it('should not flag template literals with sanitized input', async () => {
            const secureCode = `
        function buildQuery(userId) {
          const sanitized = sanitizeInput(userId);
          return \`SELECT * FROM users WHERE id = \${sanitized}\`;
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(secureCode);
            mockContext.sourceFiles = [sourceFile];

            const violations = await injectionDetection.check(mockContext);

            TestHelpers.expectNoViolations(violations, 'injection-detection');
        });
    });

    describe('containsUnsanitizedInput helper', () => {
        it('should identify various user input patterns', async () => {
            const testCases = [
                'params.userId',
                'request.body.data',
                'input.filename',
                'args[0]',
                'arguments[1]',
                'process.argv[2]'
            ];

            for (const testCase of testCases) {
                const code = `function test() { return db.query("SELECT * FROM users WHERE id = " + ${testCase}); }`;
                const sourceFile = TestHelpers.createMockSourceFile(code);
                mockContext.sourceFiles = [sourceFile];

                const violations = await injectionDetection.check(mockContext);

                expect(violations.length).toBeGreaterThan(0);
                expect(violations[0].ruleId).toBe('injection-detection');
            }
        });

        it('should recognize sanitization patterns', async () => {
            const testCases = [
                'sanitize(params.userId)',
                'escape(request.body.data)',
                'validate(input.filename)',
                'clean(args[0])'
            ];

            for (const testCase of testCases) {
                const code = `function test() { return db.query("SELECT * FROM users WHERE id = " + ${testCase}); }`;
                const sourceFile = TestHelpers.createMockSourceFile(code);
                mockContext.sourceFiles = [sourceFile];

                const violations = await injectionDetection.check(mockContext);

                TestHelpers.expectNoViolations(violations, 'injection-detection');
            }
        });
    });
});

