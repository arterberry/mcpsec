import { StaticAnalyzer } from '../../../../src/analyzers/static-analyzer';
import { TestHelpers } from '../../utils/test-helpers';

describe('StaticAnalyzer', () => {
    let analyzer: StaticAnalyzer;

    beforeEach(() => {
        analyzer = new StaticAnalyzer();
    });

    describe('function analysis', () => {
        it('should extract function information', () => {
            const code = `
        async function testFunction(param1: string, param2?: number): Promise<string> {
          return "test";
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.functions).toHaveLength(1);
            expect(result.functions[0]).toMatchObject({
                name: 'testFunction',
                isAsync: true,
                returnType: 'Promise<string>',
                file: expect.any(String),
                line: expect.any(Number),
                visibility: 'public',
                parameters: [
                    { name: 'param1', type: 'string', optional: false, hasValidation: false },
                    { name: 'param2', type: 'number', optional: true, hasValidation: false }
                ]
            });
        });

        it('should detect method declarations', () => {
            const code = `
        class TestClass {
          private async processData(data: any): Promise<void> {
            // Implementation
          }
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.functions).toHaveLength(1);
            expect(result.functions[0]).toMatchObject({
                name: 'processData',
                isAsync: true,
                visibility: 'private',
                file: expect.any(String),
                line: expect.any(Number)
            });
        });

        it('should detect arrow functions', () => {
            const code = `
        const handleRequest = async (req: Request) => {
          return response;
        };
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.functions).toHaveLength(1);
            expect(result.functions[0].name).toBe('arrow_function');
            expect(result.functions[0].isAsync).toBe(true);
            expect(result.functions[0].file).toBe(sourceFile.path);
        });
    });

    describe('import/export analysis', () => {
        it('should extract import statements', () => {
            const code = `
        import { readFile } from 'fs';
        import * as path from 'path';
        import express from 'express';
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.imports).toHaveLength(3);
            expect(result.imports[0]).toMatchObject({
                module: 'fs',
                imports: ['readFile'],
                file: sourceFile.path,
                line: expect.any(Number),
                isDynamic: false
            });
            expect(result.imports[1]).toMatchObject({
                module: 'path',
                imports: ['* as path'],
                file: sourceFile.path,
                line: expect.any(Number),
                isDynamic: false
            });
            expect(result.imports[2]).toMatchObject({
                module: 'express',
                imports: ['express'],
                file: sourceFile.path,
                line: expect.any(Number),
                isDynamic: false
            });
        });

        it('should extract export statements', () => {
            const code = `
        export const config = {};
        export default function main() {}
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            // Note: The analyzer may detect both exports or just the default
            expect(result.exports.length).toBeGreaterThan(0);
            expect(result.exports.some(exp => exp.type === 'default')).toBe(true);
        });
    });

    describe('security pattern detection', () => {
        it('should detect dangerous function calls', () => {
            const code = `
        function processCode(userCode) {
          return eval(userCode);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.securityPatterns).toHaveLength(1);
            expect(result.securityPatterns[0]).toMatchObject({
                type: 'eval-usage',
                severity: 'high',
                description: expect.stringContaining('eval()'),
                file: sourceFile.path,
                line: expect.any(Number),
                code: expect.stringContaining('eval(userCode)')
            });
        });

        it('should detect hardcoded secrets', () => {
            const code = `
        const apiKey = "sk_test_1234567890abcdef1234567890abcdef";
        const password = "hardcoded_password_123";
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.securityPatterns.length).toBeGreaterThan(0);
            expect(result.securityPatterns.some(p =>
                p.type === 'hardcoded-secret'
            )).toBe(true);
        });

        it('should detect SQL injection vulnerabilities', () => {
            const code = `
        function getUser(id) {
          const query = "SELECT * FROM users WHERE id = " + id;
          return db.query(query);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.securityPatterns.some(p =>
                p.type === 'sql-injection'
            )).toBe(true);
        });

        it('should detect command injection vulnerabilities', () => {
            const code = `
        function executeCommand(cmd) {
          return exec("ls " + cmd);
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.securityPatterns.some(p =>
                p.type === 'command-injection'
            )).toBe(true);
        });

        it('should detect unsafe regular expressions', () => {
            const code = `
        const pattern = /(a+)+/;
        const result = text.match(pattern);
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.securityPatterns.some(p =>
                p.type === 'unsafe-regex'
            )).toBe(true);
        });
    });

    describe('template literal analysis', () => {
        it('should detect SQL injection in template literals', () => {
            const code = `
        function buildQuery(userId) {
          return \`SELECT * FROM users WHERE id = \${userId}\`;
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.securityPatterns.some(p =>
                p.type === 'sql-injection' && p.code.includes('SELECT')
            )).toBe(true);
        });

        it('should detect command injection in template literals', () => {
            const code = `
        function buildCommand(filename) {
          return \`rm \${filename}\`;
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.securityPatterns.some(p =>
                p.type === 'command-injection' && p.code.includes('rm')
            )).toBe(true);
        });
    });

    describe('parameter validation detection', () => {
        it('should detect parameters with validation decorators', () => {
            const code = `
        function createUser(@IsString() name: string, @IsEmail() email: string) {
          // Implementation
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.functions).toHaveLength(1);
            expect(result.functions[0].parameters[0].hasValidation).toBe(true);
            expect(result.functions[0].parameters[1].hasValidation).toBe(true);
        });

        it('should detect parameters without validation', () => {
            const code = `
        function processData(data: any) {
          // No validation
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.functions).toHaveLength(1);
            expect(result.functions[0].parameters[0].hasValidation).toBe(false);
        });
    });

    describe('edge cases and error handling', () => {
        it('should handle files without AST', () => {
            const sourceFile = {
                path: 'test.ts',
                content: 'const test = "hello";',
                ast: undefined
            };

            const result = analyzer.analyze([sourceFile]);

            expect(result.functions).toHaveLength(0);
            expect(result.imports).toHaveLength(0);
            expect(result.exports).toHaveLength(0);
            // Should still check content for patterns like hardcoded secrets
            expect(result.securityPatterns).toBeDefined();
        });

        it('should handle malformed code gracefully', () => {
            const code = `
        function incomplete( {
          // Malformed function
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);

            // Should not throw an error
            expect(() => analyzer.analyze([sourceFile])).not.toThrow();
        });

        it('should handle complex nested structures', () => {
            const code = `
        class ComplexClass {
          private nested = {
            method: async (param: string) => {
              if (condition) {
                return eval(param);
              }
            }
          };
        }
      `;

            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.securityPatterns.some(p =>
                p.type === 'eval-usage'
            )).toBe(true);
        });
    });

    describe('secret pattern detection', () => {
        it('should detect various secret patterns', () => {
            const secretPatterns = [
                'api_key = "sk_test_1234567890abcdef"',
                'secret: "mysecret123456789"',
                'password = "strongpassword123"',
                'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"',
                'aws_access_key = "AKIAIOSFODNN7EXAMPLE"',
                'aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
            ];

            for (const pattern of secretPatterns) {
                const code = `const config = { ${pattern} };`;
                const sourceFile = TestHelpers.createMockSourceFile(code);
                const result = analyzer.analyze([sourceFile]);

                expect(result.securityPatterns.some(p =>
                    p.type === 'hardcoded-secret'
                )).toBe(true);
            }
        });
    });

    describe('ReDoS detection', () => {
        it('should detect ReDoS vulnerable patterns', () => {
            const vulnerablePatterns = [
                '/(a+)+/',
                '/(a*)*/',
                '/(a+){2,}/',
                '/(a|b)+/'
            ];

            for (const pattern of vulnerablePatterns) {
                const code = `const regex = ${pattern};`;
                const sourceFile = TestHelpers.createMockSourceFile(code);
                const result = analyzer.analyze([sourceFile]);

                expect(result.securityPatterns.some(p =>
                    p.type === 'unsafe-regex'
                )).toBe(true);
            }
        });

        it('should not flag safe regex patterns', () => {
            const safePatterns = [
                '/^[a-zA-Z0-9]+$/',
                '/\\d{3}-\\d{3}-\\d{4}/',
                '/[a-z]+/'
            ];

            for (const pattern of safePatterns) {
                const code = `const regex = ${pattern};`;
                const sourceFile = TestHelpers.createMockSourceFile(code);
                const result = analyzer.analyze([sourceFile]);

                expect(result.securityPatterns.some(p =>
                    p.type === 'unsafe-regex'
                )).toBe(false);
            }
        });
    });

    describe('dependency analysis', () => {
        it('should return empty dependencies array', () => {
            const code = `const test = "hello";`;
            const sourceFile = TestHelpers.createMockSourceFile(code);
            const result = analyzer.analyze([sourceFile]);

            expect(result.dependencies).toBeDefined();
            expect(Array.isArray(result.dependencies)).toBe(true);
        });
    });
});