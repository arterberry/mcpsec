import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

export const injectionDetection = {
  id: 'injection-detection',
  name: 'Injection Attack Detection',
  description: 'Detects potential injection vulnerabilities in MCP tool implementations',
  severity: 'error',
  category: 'input-validation',
  mandatory: true,

  async check(context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    for (const file of context.sourceFiles) {
      if (!file.ast) continue;

      const fileViolations = this.analyzeFileForInjections(file, context);
      violations.push(...fileViolations);
    }

    return violations;
  },
  analyzeFileForInjections(file: any, context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];
    
    const visitor = (node: ts.Node) => {
      // Check for SQL injection patterns
      if (ts.isCallExpression(node)) {
        this.checkSQLInjection(node, file, violations);
        this.checkCommandInjection(node, file, violations);
        this.checkEvalInjection(node, file, violations);
      }

      // Check for template literal injections
      if (ts.isTemplateExpression(node)) {
        this.checkTemplateLiteralInjection(node, file, violations);
      }

      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return violations;
  },
  checkSQLInjection(node: ts.CallExpression, file: any, violations: RuleViolation[]) {
    const expression = node.expression;
    
    if (ts.isPropertyAccessExpression(expression) && 
        (expression.name.text === 'query' || expression.name.text === 'exec')) {
      
      // Check if SQL query uses unsanitized input
      const args = node.arguments;
      if (args.length > 0) {
        const queryArg = args[0];
        
        if (this.containsUnsanitizedInput(queryArg, file)) {
          violations.push({
            ruleId: 'injection-detection',
            severity: 'error',
            message: 'Potential SQL injection vulnerability detected',
            file: file.path,
            line: this.getLineNumber(file.ast, node),
            evidence: 'SQL query appears to use unsanitized user input',
            fix: 'Use parameterized queries or input sanitization'
          });
        }
      }
    }
  },
  checkCommandInjection(node: ts.CallExpression, file: any, violations: RuleViolation[]) {
    const expression = node.expression;
    
    if (ts.isIdentifier(expression) && 
        ['exec', 'spawn', 'execSync', 'spawnSync'].includes(expression.text)) {
      
      const args = node.arguments;
      if (args.length > 0 && this.containsUnsanitizedInput(args[0], file)) {
        violations.push({
          ruleId: 'injection-detection',
          severity: 'error',
          message: 'Potential command injection vulnerability detected',
          file: file.path,
          line: this.getLineNumber(file.ast, node),
          evidence: 'System command execution with unsanitized input',
          fix: 'Sanitize command arguments and use allowlists'
        });
      }
    }
  },
  checkEvalInjection(node: ts.CallExpression, file: any, violations: RuleViolation[]) {
    const expression = node.expression;
    
    if (ts.isIdentifier(expression) && 
        ['eval', 'Function', 'setTimeout', 'setInterval'].includes(expression.text)) {
      
      violations.push({
        ruleId: 'injection-detection',
        severity: 'error',
        message: 'Dangerous eval-like function usage detected',
        file: file.path,
        line: this.getLineNumber(file.ast, node),
        evidence: `Usage of ${expression.text} function`,
        fix: 'Avoid eval-like functions or use safer alternatives'
      });
    }
  },
  checkTemplateLiteralInjection(node: ts.TemplateExpression, file: any, violations: RuleViolation[]) {
    // Check if template literal contains SQL-like or command-like patterns
    const spans = node.templateSpans;
    
    for (const span of spans) {
      if (this.containsUnsanitizedInput(span.expression, file)) {
        const template = this.getTemplateContext(node, file);
        
        if (this.looksLikeSQLOrCommand(template)) {
          violations.push({
            ruleId: 'injection-detection',
            severity: 'warning',
            message: 'Template literal with potential injection risk',
            file: file.path,
            line: this.getLineNumber(file.ast, node),
            evidence: 'Template literal contains unsanitized user input',
            fix: 'Sanitize template literal inputs'
          });
        }
      }
    }
  },
  containsUnsanitizedInput(node: ts.Node, file: any): boolean {
    // Simple heuristic: check if the node references user input without sanitization
    const text = node.getText(file.ast);
    
    const userInputPatterns = [
      /params\./,
      /request\./,
      /input\./,
      /args\./,
      /arguments\[/,
      /process\.argv/
    ];

    const sanitizationPatterns = [
      /sanitize/i,
      /escape/i,
      /validate/i,
      /clean/i
    ];

    const hasUserInput = userInputPatterns.some(pattern => pattern.test(text));
    const hasSanitization = sanitizationPatterns.some(pattern => pattern.test(text));

    return hasUserInput && !hasSanitization;
  },
  getTemplateContext(node: ts.TemplateExpression, file: any): string {
    return node.getText(file.ast);
  },
  looksLikeSQLOrCommand(template: string): boolean {
    const sqlPatterns = [
      /SELECT\s+.*\s+FROM/i,
      /INSERT\s+INTO/i,
      /UPDATE\s+.*\s+SET/i,
      /DELETE\s+FROM/i
    ];

    const commandPatterns = [
      /rm\s+/i,
      /del\s+/i,
      /cat\s+/i,
      /ls\s+/i,
      /dir\s+/i
    ];

    return [...sqlPatterns, ...commandPatterns].some(pattern => pattern.test(template));
  },
  getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  }
} as MCPSecurityRule;
