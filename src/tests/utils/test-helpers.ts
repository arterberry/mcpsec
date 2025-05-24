import * as ts from 'typescript';
import { AnalysisContext, MCPServerInfo, SourceFile, MCPSecConfig } from '../../src/core/types';

export interface TestFixture {
  name: string;
  sourceFiles: SourceFile[];
  mcpServer: MCPServerInfo;
  config: MCPSecConfig;
  packageJson: any;
}

export class TestHelpers {
  static createMockSourceFile(content: string, path: string = 'test.ts'): SourceFile {
    const ast = ts.createSourceFile(
      path,
      content,
      ts.ScriptTarget.Latest,
      true
    );

    return {
      path,
      content,
      ast
    };
  }

  static createMockAnalysisContext(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
    const defaultContext: AnalysisContext = {
      projectPath: '/test/project',
      mcpServer: this.createMockMCPServer(),
      sourceFiles: [],
      packageJson: { name: 'test-project', version: '1.0.0', dependencies: {} },
      config: this.createMockConfig()
    };

    return { ...defaultContext, ...overrides };
  }

  static createMockMCPServer(overrides: Partial<MCPServerInfo> = {}): MCPServerInfo {
    const defaultServer: MCPServerInfo = {
      name: 'test-server',
      version: '1.0.0',
      tools: [],
      resources: [],
      prompts: []
    };

    return { ...defaultServer, ...overrides };
  }

  static createMockConfig(overrides: Partial<MCPSecConfig> = {}): MCPSecConfig {
    const defaultConfig: MCPSecConfig = {
      rules: {
        'auth-required': { enabled: true, severity: 'error' },
        'role-validation': { enabled: true, severity: 'error' },
        'input-sanitization': { enabled: true, severity: 'error' },
        'parameter-validation': { enabled: true, severity: 'error' },
        'injection-detection': { enabled: true, severity: 'error' },
        'permission-checks': { enabled: true, severity: 'error' },
        'resource-access': { enabled: true, severity: 'warning' },
        'rate-limit-enforcement': { enabled: true, severity: 'warning' },
        'audit-logging': { enabled: true, severity: 'error' },
        'fox-streaming-protection': { enabled: true, severity: 'error' },
        'conviva-validation': { enabled: true, severity: 'warning' },
        'har-security': { enabled: true, severity: 'error' }
      },
      foxCorp: {
        streamingAssets: true,
        convivaIntegration: true,
        harValidation: true,
        auditLevel: 'comprehensive'
      },
      ignorePatterns: ['node_modules/**', 'dist/**'],
      severity: { error: 2, warning: 1 }
    };

    return { ...defaultConfig, ...overrides };
  }

  static createMockTool(overrides: any = {}) {
    return {
      name: 'test-tool',
      description: 'A test tool',
      inputSchema: {
        type: 'object',
        properties: {
          input: { type: 'string' }
        }
      },
      implementation: 'test.ts',
      permissions: ['test:read'],
      authRequired: true,
      ...overrides
    };
  }

  static createMockResource(overrides: any = {}) {
    return {
      name: 'test-resource',
      uri: 'file:///test/resource',
      type: 'file',
      ...overrides
    };
  }

  static createVulnerableCode(type: 'sql' | 'command' | 'xss' | 'path-traversal'): string {
    const vulnerabilities = {
      sql: `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = " + userId;
          return db.query(query);
        }
      `,
      command: `
        function executeCommand(userInput) {
          const cmd = "ls " + userInput;
          return exec(cmd);
        }
      `,
      xss: `
        function renderUserContent(content) {
          document.innerHTML = content;
        }
      `,
      'path-traversal': `
        function readFile(filename) {
          return fs.readFileSync(filename);
        }
      `
    };

    return vulnerabilities[type];
  }

  static createSecureCode(type: 'sql' | 'command' | 'xss' | 'path-traversal'): string {
    const secureCode = {
      sql: `
        function getUserData(userId) {
          const query = "SELECT * FROM users WHERE id = $1";
          return db.query(query, [userId]);
        }
      `,
      command: `
        function executeCommand(userInput) {
          const sanitized = sanitizeInput(userInput);
          if (!isAllowedCommand(sanitized)) {
            throw new Error('Command not allowed');
          }
          return exec(sanitized);
        }
      `,
      xss: `
        function renderUserContent(content) {
          const sanitized = DOMPurify.sanitize(content);
          document.innerHTML = sanitized;
        }
      `,
      'path-traversal': `
        function readFile(filename) {
          const sanitized = path.normalize(filename);
          if (!sanitized.startsWith('/safe/directory/')) {
            throw new Error('Path not allowed');
          }
          return fs.readFileSync(sanitized);
        }
      `
    };

    return secureCode[type];
  }

  static async expectViolation(violations: any[], ruleId: string, severity: string = 'error') {
    const violation = violations.find(v => v.ruleId === ruleId && v.severity === severity);
    expect(violation).toBeDefined();
    return violation;
  }

  static expectNoViolations(violations: any[], ruleId?: string) {
    if (ruleId) {
      const ruleViolations = violations.filter(v => v.ruleId === ruleId);
      expect(ruleViolations).toHaveLength(0);
    } else {
      expect(violations).toHaveLength(0);
    }
  }
}
