import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

export const sanitizationRequired = {
    id: 'input-sanitization',
    name: 'Input Sanitization Required',
    description: 'Ensures all user inputs are properly sanitized before processing',
    severity: 'error',
    category: 'input-validation',
    mandatory: true,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check each tool for input sanitization
        for (const tool of context.mcpServer.tools) {
            const toolViolations = await this.checkToolSanitization(tool, context);
            violations.push(...toolViolations);
        }

        // Check for global sanitization middleware
        const globalViolations = this.checkGlobalSanitization(context);
        violations.push(...globalViolations);

        // Check for sanitization library usage
        const libraryViolations = this.checkSanitizationLibraries(context);
        violations.push(...libraryViolations);

        return violations;
    },
  async checkToolSanitization(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Find tool implementation
        const implFile = context.sourceFiles.find(file =>
            file.content.includes(tool.name) &&
            (file.content.includes('function') || file.content.includes('=>'))
        );

        if (!implFile || !implFile.ast) {
            violations.push({
                ruleId: 'input-sanitization',
                severity: 'warning',
                message: `Cannot analyze input sanitization for tool '${tool.name}' - implementation not found`
            });
            return violations;
        }

        // Check for input parameters
        const inputParams = this.extractInputParameters(implFile, tool);

        for (const param of inputParams) {
            // Check if parameter is sanitized
            const isSanitized = this.isParameterSanitized(param, implFile);
            if (!isSanitized) {
                violations.push({
                    ruleId: 'input-sanitization',
                    severity: 'error',
                    message: `Tool '${tool.name}' parameter '${param.name}' lacks sanitization`,
                    file: implFile.path,
                    line: param.line,
                    evidence: `Unsanitized parameter: ${param.name}`,
                    fix: 'Add input sanitization before using parameter'
                });
            }

            // Check for specific sanitization requirements
            const specificViolations = this.checkSpecificSanitization(param, tool, implFile, context);
            violations.push(...specificViolations);
        }

        // Check for direct user input usage
        const directUsageViolations = this.checkDirectInputUsage(implFile, tool);
        violations.push(...directUsageViolations);

        // Check for output sanitization
        const outputViolations = this.checkOutputSanitization(implFile, tool);
        violations.push(...outputViolations);

        return violations;
    },
  extractInputParameters(file: any, tool: any): Array<{ name: string, type: string, line: number }> {
        const parameters: Array<{ name: string, type: string, line: number }> = [];

        if (!file.ast) return parameters;

        const visitor = (node: ts.Node) => {
            // Look for function parameters
            if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isArrowFunction(node)) {
                const functionName = this.getFunctionName(node);
                if (functionName && functionName.includes(tool.name)) {
                    if ('parameters' in node && node.parameters) {
                        for (const param of node.parameters) {
                            if (ts.isIdentifier(param.name)) {
                                parameters.push({
                                    name: param.name.text,
                                    type: param.type?.getText(file.ast) || 'any',
                                    line: this.getLineNumber(file.ast, param)
                                });
                            }
                        }
                    }
                }
            }

            // Look for destructuring parameters
            if (ts.isObjectBindingPattern(node)) {
                for (const element of node.elements) {
                    if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
                        parameters.push({
                            name: element.name.text,
                            type: 'unknown',
                            line: this.getLineNumber(file.ast, element)
                        });
                    }
                }
            }

            ts.forEachChild(node, visitor);
        };

        visitor(file.ast);
        return parameters;
    },
  getFunctionName(node: ts.FunctionDeclaration | ts.MethodDeclaration | ts.ArrowFunction): string | null {
        if (ts.isFunctionDeclaration(node) && node.name) {
            return node.name.text;
        }
        if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) {
            return node.name.text;
        }
        return null;
    },
  isParameterSanitized(param: { name: string, type: string, line: number }, file: any): boolean {
        const content = file.content;

        // Look for sanitization calls near the parameter usage
        const sanitizationPatterns = [
            new RegExp(`sanitize.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*sanitize`, 'i'),
            new RegExp(`clean.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*clean`, 'i'),
            new RegExp(`validate.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*validate`, 'i'),
            new RegExp(`escape.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*escape`, 'i')
        ];

        return sanitizationPatterns.some(pattern => pattern.test(content));
    },
  checkSpecificSanitization(
        param: { name: string, type: string, line: number },
        tool: any,
        file: any,
        context: AnalysisContext
    ): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for HTML sanitization
        if (this.needsHTMLSanitization(param, file)) {
            if (!this.hasHTMLSanitization(param, file)) {
                violations.push({
                    ruleId: 'input-sanitization',
                    severity: 'error',
                    message: `Parameter '${param.name}' in tool '${tool.name}' needs HTML sanitization`,
                    file: file.path,
                    line: param.line,
                    evidence: 'Parameter used in HTML context without sanitization',
                    fix: 'Use HTML sanitization library (e.g., DOMPurify, sanitize-html)'
                });
            }
        }

        // Check for SQL injection protection
        if (this.needsSQLSanitization(param, file)) {
            if (!this.hasSQLSanitization(param, file)) {
                violations.push({
                    ruleId: 'input-sanitization',
                    severity: 'error',
                    message: `Parameter '${param.name}' in tool '${tool.name}' needs SQL sanitization`,
                    file: file.path,
                    line: param.line,
                    evidence: 'Parameter used in SQL context without proper sanitization',
                    fix: 'Use parameterized queries or SQL sanitization'
                });
            }
        }

        // Check for file path sanitization
        if (this.needsPathSanitization(param, file)) {
            if (!this.hasPathSanitization(param, file)) {
                violations.push({
                    ruleId: 'input-sanitization',
                    severity: 'error',
                    message: `Parameter '${param.name}' in tool '${tool.name}' needs path sanitization`,
                    file: file.path,
                    line: param.line,
                    evidence: 'Parameter used as file path without sanitization',
                    fix: 'Use path sanitization to prevent directory traversal'
                });
            }
        }

        // Check for URL sanitization
        if (this.needsURLSanitization(param, file)) {
            if (!this.hasURLSanitization(param, file)) {
                violations.push({
                    ruleId: 'input-sanitization',
                    severity: 'error',
                    message: `Parameter '${param.name}' in tool '${tool.name}' needs URL sanitization`,
                    file: file.path,
                    line: param.line,
                    evidence: 'Parameter used as URL without validation',
                    fix: 'Validate and sanitize URLs to prevent SSRF attacks'
                });
            }
        }

        // Fox Corp specific: streaming content sanitization
        if (context.config.foxCorp?.streamingAssets && this.isStreamingParameter(param, file)) {
            if (!this.hasStreamingSanitization(param, file)) {
                violations.push({
                    ruleId: 'input-sanitization',
                    severity: 'error',
                    message: `Streaming parameter '${param.name}' requires Fox Corp sanitization`,
                    file: file.path,
                    line: param.line,
                    evidence: 'Streaming content parameter without proper sanitization',
                    fix: 'Apply Fox Corp streaming content sanitization rules'
                });
            }
        }

        return violations;
    },
  needsHTMLSanitization(param: { name: string, type: string }, file: any): boolean {
        const content = file.content;
        const htmlPatterns = [
            new RegExp(`${param.name}.*innerHTML`, 'i'),
            new RegExp(`innerHTML.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*html`, 'i'),
            new RegExp(`render.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*render`, 'i'),
            new RegExp(`document.*${param.name}`, 'i')
        ];

        return htmlPatterns.some(pattern => pattern.test(content));
    },
  hasHTMLSanitization(param: { name: string, type: string }, file: any): boolean {
        const content = file.content;
        const sanitizationPatterns = [
            /dompurify/i,
            /sanitize-html/i,
            /xss/i,
            /escape.*html/i,
            /html.*escape/i
        ];

        const paramContext = this.getParameterContext(param.name, file);
        return sanitizationPatterns.some(pattern => pattern.test(paramContext));
    },
  needsSQLSanitization(param: { name: string, type: string }, file: any): boolean {
        const content = file.content;
        const sqlPatterns = [
            new RegExp(`query.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*query`, 'i'),
            new RegExp(`SELECT.*${param.name}`, 'i'),
            new RegExp(`INSERT.*${param.name}`, 'i'),
            new RegExp(`UPDATE.*${param.name}`, 'i'),
            new RegExp(`DELETE.*${param.name}`, 'i'),
            new RegExp(`WHERE.*${param.name}`, 'i')
        ];

        return sqlPatterns.some(pattern => pattern.test(content));
    },
  hasSQLSanitization(param: { name: string, type: string }, file: any): boolean {
        const paramContext = this.getParameterContext(param.name, file);

        // Check for parameterized queries
        const parameterizedPatterns = [
            /\$\d+/,  // PostgreSQL
            /\?/,     // MySQL/SQLite
            /:\w+/    // Named parameters
        ];

        // Check for SQL escape functions
        const escapePatterns = [
            /escape.*sql/i,
            /sql.*escape/i,
            /quote/i,
            /sanitize.*sql/i
        ];

        return parameterizedPatterns.some(pattern => pattern.test(paramContext)) ||
            escapePatterns.some(pattern => pattern.test(paramContext));
    },
  needsPathSanitization(param: { name: string, type: string }, file: any): boolean {
        const content = file.content;
        const pathPatterns = [
            new RegExp(`readFile.*${param.name}`, 'i'),
            new RegExp(`writeFile.*${param.name}`, 'i'),
            new RegExp(`path.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*path`, 'i'),
            new RegExp(`fs\..*${param.name}`, 'i'),
            new RegExp(`require.*${param.name}`, 'i')
        ];

        return pathPatterns.some(pattern => pattern.test(content));
    },
  hasPathSanitization(param: { name: string, type: string }, file: any): boolean {
        const paramContext = this.getParameterContext(param.name, file);
        const sanitizationPatterns = [
            /path\.normalize/i,
            /path\.resolve/i,
            /sanitize.*path/i,
            /clean.*path/i,
            /validate.*path/i,
            /allowlist/i,
            /whitelist/i
        ];

        return sanitizationPatterns.some(pattern => pattern.test(paramContext));
    },
  needsURLSanitization(param: { name: string, type: string }, file: any): boolean {
        const content = file.content;
        const urlPatterns = [
            new RegExp(`fetch.*${param.name}`, 'i'),
            new RegExp(`request.*${param.name}`, 'i'),
            new RegExp(`${param.name}.*url`, 'i'),
            new RegExp(`url.*${param.name}`, 'i'),
            new RegExp(`href.*${param.name}`, 'i'),
            new RegExp(`axios.*${param.name}`, 'i')
        ];

        return urlPatterns.some(pattern => pattern.test(content));
    },
  hasURLSanitization(param: { name: string, type: string }, file: any): boolean {
        const paramContext = this.getParameterContext(param.name, file);
        const sanitizationPatterns = [
            /url.*parse/i,
            /validate.*url/i,
            /sanitize.*url/i,
            /allowlist.*url/i,
            /whitelist.*url/i,
            /new.*url/i
        ];

        return sanitizationPatterns.some(pattern => pattern.test(paramContext));
    },
  isStreamingParameter(param: { name: string, type: string }, file: any): boolean {
        const streamingPatterns = [
            /stream/i,
            /video/i,
            /media/i,
            /content/i,
            /asset/i,
            /manifest/i,
            /playlist/i
        ];

        return streamingPatterns.some(pattern => pattern.test(param.name)) ||
            streamingPatterns.some(pattern => pattern.test(param.type));
    },
  hasStreamingSanitization(param: { name: string, type: string }, file: any): boolean {
        const paramContext = this.getParameterContext(param.name, file);
        const sanitizationPatterns = [
            /validate.*stream/i,
            /sanitize.*stream/i,
            /clean.*stream/i,
            /stream.*validate/i,
            /content.*validate/i,
            /media.*validate/i
        ];

        return sanitizationPatterns.some(pattern => pattern.test(paramContext));
    },
  getParameterContext(paramName: string, file: any): string {
        const content = file.content;
        const lines = content.split('\n');
        const contextLines: string[] = [];

        for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes(paramName)) {
                // Get context: 3 lines before and after
                const start = Math.max(0, i - 3);
                const end = Math.min(lines.length, i + 4);
                contextLines.push(...lines.slice(start, end));
            }
        }

        return contextLines.join('\n');
    },
  checkDirectInputUsage(file: any, tool: any): RuleViolation[] {
        const violations: RuleViolation[] = [];

        if (!file.ast) return violations;

        const visitor = (node: ts.Node) => {
            // Check for direct user input usage
            if (ts.isPropertyAccessExpression(node)) {
                const propertyAccess = node.getText(file.ast);

                if (this.isDirectUserInput(propertyAccess)) {
                    // Check if this input is used without sanitization
                    const parent = node.parent;
                    if (parent && !this.isInSanitizationContext(parent, file.ast)) {
                        violations.push({
                            ruleId: 'input-sanitization',
                            severity: 'error',
                            message: `Tool '${tool.name}' uses unsanitized user input directly`,
                            file: file.path,
                            line: this.getLineNumber(file.ast, node),
                            evidence: `Direct input usage: ${propertyAccess}`,
                            fix: 'Sanitize user input before processing'
                        });
                    }
                }
            }

            ts.forEachChild(node, visitor);
        };

        visitor(file.ast);
        return violations;
    },
  isDirectUserInput(propertyAccess: string): boolean {
        const inputPatterns = [
            /req\.body/,
            /req\.query/,
            /req\.params/,
            /request\.body/,
            /request\.query/,
            /request\.params/,
            /params\./,
            /args\./,
            /input\./,
            /userInput/,
            /process\.argv/
        ];

        return inputPatterns.some(pattern => pattern.test(propertyAccess));
    },
  isInSanitizationContext(node: ts.Node, sourceFile: ts.SourceFile): boolean {
        // Check if the node is within a sanitization function call
        let current = node.parent;

        while (current) {
            if (ts.isCallExpression(current)) {
                const callText = current.getText(sourceFile);
                if (this.isSanitizationCall(callText)) {
                    return true;
                }
            }
            current = current.parent;
        }

        return false;
    },
  isSanitizationCall(callText: string): boolean {
        const sanitizationPatterns = [
            /sanitize/i,
            /clean/i,
            /escape/i,
            /validate/i,
            /normalize/i,
            /filter/i,
            /purify/i
        ];

        return sanitizationPatterns.some(pattern => pattern.test(callText));
    },
  checkOutputSanitization(file: any, tool: any): RuleViolation[] {
        const violations: RuleViolation[] = [];

        if (!file.ast) return violations;

        const visitor = (node: ts.Node) => {
            // Check for return statements
            if (ts.isReturnStatement(node) && node.expression) {
                const returnValue = node.expression.getText(file.ast);

                // Check if return value contains user input without sanitization
                if (this.containsUnsanitizedInput(returnValue, file)) {
                    violations.push({
                        ruleId: 'input-sanitization',
                        severity: 'warning',
                        message: `Tool '${tool.name}' may return unsanitized user input`,
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `Return value: ${returnValue}`,
                        fix: 'Sanitize output before returning to prevent data leakage'
                    });
                }
            }

            // Check for response sending
            if (ts.isCallExpression(node)) {
                const callText = node.getText(file.ast);

                if (this.isResponseCall(callText) && this.containsUnsanitizedInput(callText, file)) {
                    violations.push({
                        ruleId: 'input-sanitization',
                        severity: 'warning',
                        message: `Tool '${tool.name}' may send unsanitized data in response`,
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `Response call: ${callText}`,
                        fix: 'Sanitize response data before sending'
                    });
                }
            }

            ts.forEachChild(node, visitor);
        };

        visitor(file.ast);
        return violations;
    },
  containsUnsanitizedInput(text: string, file: any): boolean {
        const inputPatterns = [
            /req\./,
            /request\./,
            /params\./,
            /args\./,
            /input\./,
            /userInput/
        ];

        const sanitizationPatterns = [
            /sanitize/i,
            /clean/i,
            /escape/i,
            /validate/i
        ];

        const hasInput = inputPatterns.some(pattern => pattern.test(text));
        const hasSanitization = sanitizationPatterns.some(pattern => pattern.test(text));

        return hasInput && !hasSanitization;
    },
  isResponseCall(callText: string): boolean {
        const responsePatterns = [
            /res\.send/,
            /res\.json/,
            /response\.send/,
            /response\.json/,
            /return.*response/,
            /send.*response/
        ];

        return responsePatterns.some(pattern => pattern.test(callText));
    },
  checkGlobalSanitization(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for sanitization middleware
        const hasSanitizationMiddleware = context.sourceFiles.some(file =>
            this.hasSanitizationMiddleware(file)
        );

        if (!hasSanitizationMiddleware) {
            violations.push({
                ruleId: 'input-sanitization',
                severity: 'warning',
                message: 'No global input sanitization middleware detected',
                fix: 'Implement global sanitization middleware for all inputs'
            });
        }

        return violations;
    },
  hasSanitizationMiddleware(file: any): boolean {
        const content = file.content.toLowerCase();
        const middlewarePatterns = [
            /sanitize.*middleware/,
            /middleware.*sanitize/,
            /input.*validation.*middleware/,
            /validation.*middleware/
        ];

        return middlewarePatterns.some(pattern => pattern.test(content));
    },
  checkSanitizationLibraries(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        const sanitizationLibs = [
            'validator',
            'sanitize-html',
            'dompurify',
            'xss',
            'joi',
            'yup',
            'express-validator'
        ];

        const hasLibrary = sanitizationLibs.some(lib =>
            context.packageJson.dependencies?.[lib] ||
            context.packageJson.devDependencies?.[lib]
        );

        if (!hasLibrary) {
            violations.push({
                ruleId: 'input-sanitization',
                severity: 'info',
                message: 'No input sanitization library found in dependencies',
                fix: `Consider adding a sanitization library: ${sanitizationLibs.slice(0, 3).join(', ')}`
            });
        }

        return violations;
    },
  getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
        return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    }
} as MCPSecurityRule;
