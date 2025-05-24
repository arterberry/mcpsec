import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

interface LoggingCall {
  line: number;
  args: ts.Node[];
}

export const auditLoggingRequirements = {
  id: 'audit-logging',
  name: 'Audit Logging Requirements',
  description: 'Ensures comprehensive audit logging for Fox Corp compliance',
  severity: 'error' as const,
  category: 'audit-logging' as const,
  mandatory: true,

  async check(context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    // Check each MCP tool for proper logging
    for (const tool of context.mcpServer.tools) {
      const toolViolations = await this.checkToolLogging(tool, context);
      violations.push(...toolViolations);
    }

    // Check for global audit configuration
    const globalViolations = this.checkGlobalAuditConfig(context);
    violations.push(...globalViolations);

    return violations;
  },

  async checkToolLogging(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    // Find tool implementation
    const implFile = context.sourceFiles.find(file =>
      file.content.includes(tool.name) &&
      file.content.includes('async') &&
      file.content.includes('function')
    );

    if (!implFile || !implFile.ast) {
      violations.push({
        ruleId: 'audit-logging',
        severity: 'warning',
        message: `Cannot analyze logging for tool '${tool.name}' - implementation not found`,
        evidence: `Tool: ${tool.name}`
      });
      return violations;
    }

    const hasLogging = this.checkForLoggingStatements(implFile);
    const hasErrorLogging = this.checkForErrorLogging(implFile);
    const hasSecurityLogging = this.checkForSecurityEventLogging(implFile);

    if (!hasLogging.found) {
      violations.push({
        ruleId: 'audit-logging',
        severity: 'error',
        message: `Tool '${tool.name}' lacks required audit logging`,
        file: implFile.path,
        fix: 'Add comprehensive audit logging for all tool operations'
      });
    }

    if (!hasErrorLogging.found) {
      violations.push({
        ruleId: 'audit-logging',
        severity: 'error',
        message: `Tool '${tool.name}' lacks error logging`,
        file: implFile.path,
        fix: 'Add error logging with appropriate detail level'
      });
    }

    if (this.isHighRiskTool(tool) && !hasSecurityLogging.found) {
      violations.push({
        ruleId: 'audit-logging',
        severity: 'error',
        message: `High-risk tool '${tool.name}' requires security event logging`,
        file: implFile.path,
        fix: 'Add security event logging for sensitive operations'
      });
    }

    // Check Fox Corp specific logging requirements
    if (context.config.foxCorp?.auditLevel === 'comprehensive' ||
      context.config.foxCorp?.auditLevel === 'forensic') {

      const foxViolations = this.checkFoxCorpLoggingRequirements(tool, implFile, context);
      violations.push(...foxViolations);
    }

    return violations;
  },

  checkForLoggingStatements(file: any): { found: boolean; locations: number[] } {
    const locations: number[] = [];
    let found = false;

    if (!file.ast) return { found, locations };

    const visitor = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const obj = node.expression.expression;
        const method = node.expression.name.text;

        if ((ts.isIdentifier(obj) && obj.text === 'logger') ||
          (ts.isIdentifier(obj) && obj.text === 'console' &&
            ['log', 'info', 'warn', 'error'].includes(method))) {
          found = true;
          locations.push(this.getLineNumber(file.ast, node));
        }
      }
      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return { found, locations };
  },

  checkForErrorLogging(file: any): { found: boolean; locations: number[] } {
    const locations: number[] = [];
    let found = false;

    if (!file.ast) return { found, locations };

    const visitor = (node: ts.Node): void => {
      if (ts.isTryStatement(node) && node.catchClause) {
        const catchBlock = node.catchClause.block;

        // Check if catch block contains logging
        const hasLoggingInCatch = this.containsLoggingInBlock(catchBlock);
        if (hasLoggingInCatch) {
          found = true;
          locations.push(this.getLineNumber(file.ast, node));
        }
      }
      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return { found, locations };
  },

  checkForSecurityEventLogging(file: any): { found: boolean; locations: number[] } {
    const locations: number[] = [];
    let found = false;

    if (!file.ast) return { found, locations };

    const securityKeywords = [
      'security',
      'auth',
      'permission',
      'access',
      'violation',
      'breach',
      'unauthorized'
    ];

    const visitor = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const args = node.arguments;
        if (args.length > 0 && ts.isStringLiteral(args[0])) {
          const message = args[0].text.toLowerCase();
          if (securityKeywords.some(keyword => message.includes(keyword))) {
            found = true;
            locations.push(this.getLineNumber(file.ast, node));
          }
        }
      }
      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return { found, locations };
  },

  checkFoxCorpLoggingRequirements(tool: any, file: any, context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Fox Corp requires specific fields in audit logs
    const requiredFields = [
      'timestamp',
      'userId',
      'toolName',
      'action',
      'result',
      'ipAddress',
      'userAgent'
    ];

    if (context.config.foxCorp?.streamingAssets) {
      requiredFields.push('streamId', 'assetId', 'contentType');
    }

    const loggingCalls = this.findLoggingCalls(file);

    for (const call of loggingCalls) {
      const missingFields = this.checkRequiredFields(call, requiredFields, file);
      if (missingFields.length > 0) {
        violations.push({
          ruleId: 'audit-logging',
          severity: 'warning',
          message: `Fox Corp audit logging missing required fields: ${missingFields.join(', ')}`,
          file: file.path,
          line: call.line,
          fix: `Add missing fields to audit log: ${missingFields.join(', ')}`
        });
      }
    }

    // Check for PII handling in logs
    const piiViolations = this.checkPIIInLogs(file, context);
    violations.push(...piiViolations);

    // Check for streaming content protection
    if (this.isStreamingRelatedTool(tool)) {
      const streamingViolations = this.checkStreamingContentLogging(file, context);
      violations.push(...streamingViolations);
    }

    return violations;
  },

  findLoggingCalls(file: any): LoggingCall[] {
    const calls: LoggingCall[] = [];

    if (!file.ast) return calls;

    const visitor = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const obj = node.expression.expression;
        const method = node.expression.name.text;

        if ((ts.isIdentifier(obj) && obj.text === 'logger') ||
          (ts.isIdentifier(obj) && obj.text === 'console')) {
          calls.push({
            line: this.getLineNumber(file.ast, node),
            args: Array.from(node.arguments)
          });
        }
      }
      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return calls;
  },

  checkRequiredFields(call: LoggingCall, requiredFields: string[], file: any): string[] {
    const missingFields: string[] = [];

    // Simple heuristic: check if the logging call includes the required fields
    const callText = call.args.map((arg: ts.Node) => arg.getText(file.ast)).join(' ');

    for (const field of requiredFields) {
      if (!callText.includes(field)) {
        missingFields.push(field);
      }
    }

    return missingFields;
  },

  checkPIIInLogs(file: any, context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    if (!file.ast) return violations;

    const piiPatterns = [
      /email/i,
      /phone/i,
      /ssn/i,
      /credit.*card/i,
      /password/i,
      /personal.*info/i
    ];

    const visitor = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && this.isLoggingCall(node)) {
        const args = node.arguments;
        for (const arg of args) {
          const argText = arg.getText(file.ast);
          if (piiPatterns.some(pattern => pattern.test(argText))) {
            violations.push({
              ruleId: 'audit-logging',
              severity: 'error',
              message: 'Potential PII in audit logs detected',
              file: file.path,
              line: this.getLineNumber(file.ast, node),
              evidence: 'Log statement may contain personally identifiable information',
              fix: 'Remove or mask PII before logging'
            });
          }
        }
      }
      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return violations;
  },

  checkStreamingContentLogging(file: any, context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    if (!file.ast) return violations;

    // Streaming content access should be logged with specific details
    const streamingPatterns = [
      /stream/i,
      /video/i,
      /media/i,
      /content/i,
      /asset/i
    ];

    const visitor = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const callText = node.getText(file.ast);
        if (streamingPatterns.some(pattern => pattern.test(callText))) {
          // Check if this streaming operation has proper logging
          if (!this.hasNearbyLogging(node, file)) {
            violations.push({
              ruleId: 'audit-logging',
              severity: 'error',
              message: 'Streaming content access requires audit logging',
              file: file.path,
              line: this.getLineNumber(file.ast, node),
              fix: 'Add audit logging for streaming content access'
            });
          }
        }
      }
      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return violations;
  },

  isHighRiskTool(tool: any): boolean {
    const highRiskPatterns = [
      /admin/i,
      /system/i,
      /execute/i,
      /command/i,
      /file/i,
      /database/i,
      /stream/i,
      /media/i
    ];

    return highRiskPatterns.some(pattern =>
      pattern.test(tool.name) || pattern.test(tool.description)
    );
  },

  isStreamingRelatedTool(tool: any): boolean {
    const streamingPatterns = [
      /stream/i,
      /video/i,
      /media/i,
      /conviva/i,
      /har/i
    ];

    return streamingPatterns.some(pattern =>
      pattern.test(tool.name) || pattern.test(tool.description)
    );
  },

  containsLoggingInBlock(block: ts.Block): boolean {
    let hasLogging = false;

    const visitor = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && this.isLoggingCall(node)) {
        hasLogging = true;
      }
      if (!hasLogging) {
        ts.forEachChild(node, visitor);
      }
    };

    visitor(block);
    return hasLogging;
  },

  isLoggingCall(node: ts.CallExpression): boolean {
    if (ts.isPropertyAccessExpression(node.expression)) {
      const obj = node.expression.expression;
      const method = node.expression.name.text;

      return (ts.isIdentifier(obj) && obj.text === 'logger') ||
        (ts.isIdentifier(obj) && obj.text === 'console' &&
          ['log', 'info', 'warn', 'error'].includes(method));
    }
    return false;
  },

  hasNearbyLogging(node: ts.Node, file: any): boolean {
    // Simple heuristic: check if there's a logging call within 5 lines
    const nodeLineNumber = this.getLineNumber(file.ast, node);
    const loggingCalls = this.findLoggingCalls(file);

    return loggingCalls.some((call: LoggingCall) =>
      Math.abs(call.line - nodeLineNumber) <= 5
    );
  },

  checkGlobalAuditConfig(context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for audit configuration file
    const configFiles = context.sourceFiles.filter(file =>
      file.path.includes('config') ||
      file.path.includes('audit') ||
      file.path.includes('logging')
    );

    if (configFiles.length === 0) {
      violations.push({
        ruleId: 'audit-logging',
        severity: 'warning',
        message: 'No audit configuration files found',
        fix: 'Create audit configuration to standardize logging across tools'
      });
    }

    // Check package.json for required logging dependencies
    const requiredDeps = ['winston', 'pino', 'bunyan'];
    const hasDep = requiredDeps.some(dep =>
      context.packageJson.dependencies?.[dep] ||
      context.packageJson.devDependencies?.[dep]
    );

    if (!hasDep) {
      violations.push({
        ruleId: 'audit-logging',
        severity: 'warning',
        message: 'No structured logging library found in dependencies',
        fix: `Add a structured logging library (${requiredDeps.join(', ')})`
      });
    }

    return violations;
  },

  getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  }
} as MCPSecurityRule;