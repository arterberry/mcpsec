import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

export const authRequired: MCPSecurityRule = {
    id: 'auth-required',
    name: 'Authentication Required',
    description: 'Ensures all MCP tools require proper authentication before execution',
    severity: 'error',
    category: 'authentication',
    mandatory: true,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check each tool for authentication requirements
        for (const tool of context.mcpServer.tools) {
            const toolViolations = await this.checkToolAuthentication(tool, context);
            violations.push(...toolViolations);
        }

        // Check for global authentication middleware
        const globalViolations = this.checkGlobalAuthentication(context);
        violations.push(...globalViolations);

        // Check authentication implementation quality
        const implViolations = this.checkAuthenticationImplementation(context);
        violations.push(...implViolations);

        return violations;
    }

  private async checkToolAuthentication(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check if tool explicitly requires authentication
        if (!this.hasAuthenticationRequirement(tool)) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'error',
                message: `Tool '${tool.name}' lacks authentication requirement`,
                evidence: `Tool: ${tool.name}, Auth required: ${tool.authRequired || 'undefined'}`,
                fix: 'Add authRequired: true to tool configuration'
            });
        }

        // Check tool implementation for authentication checks
        const implViolations = await this.checkToolAuthImplementation(tool, context);
        violations.push(...implViolations);

        // Special checks for high-risk tools
        if (this.isHighRiskTool(tool)) {
            const highRiskViolations = this.checkHighRiskToolAuth(tool, context);
            violations.push(...highRiskViolations);
        }

        return violations;
    }

  private hasAuthenticationRequirement(tool: any): boolean {
        return tool.authRequired === true ||
            tool.authentication === 'required' ||
            (tool.permissions && tool.permissions.length > 0);
    }

  private async checkToolAuthImplementation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Find tool implementation file
        const implFile = context.sourceFiles.find(file =>
            file.content.includes(tool.name) &&
            (file.content.includes('function') || file.content.includes('=>'))
        );

        if (!implFile || !implFile.ast) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'warning',
                message: `Cannot analyze authentication for tool '${tool.name}' - implementation not found`,
                evidence: `Tool: ${tool.name}`
            });
            return violations;
        }

        // Check for authentication validation in implementation
        const hasAuthCheck = this.hasAuthenticationCheck(implFile);
        if (!hasAuthCheck) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'error',
                message: `Tool '${tool.name}' implementation lacks authentication validation`,
                file: implFile.path,
                fix: 'Add authentication check at the beginning of tool function'
            });
        }

        // Check for proper token validation
        const hasTokenValidation = this.hasTokenValidation(implFile);
        if (!hasTokenValidation && this.usesTokenAuth(implFile)) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'error',
                message: `Tool '${tool.name}' uses tokens but lacks proper token validation`,
                file: implFile.path,
                fix: 'Implement proper token validation (signature, expiration, issuer)'
            });
        }

        // Check for session management
        const hasSessionCheck = this.hasSessionValidation(implFile);
        if (!hasSessionCheck && this.usesSessionAuth(implFile)) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'error',
                message: `Tool '${tool.name}' uses sessions but lacks session validation`,
                file: implFile.path,
                fix: 'Add session validation (active, not expired, valid user)'
            });
        }

        return violations;
    }

  private hasAuthenticationCheck(file: any): boolean {
        const content = file.content.toLowerCase();
        const authPatterns = [
            /authenticate/,
            /auth.*check/,
            /verify.*auth/,
            /check.*auth/,
            /is.*authenticated/,
            /require.*auth/,
            /token.*valid/,
            /session.*valid/,
            /user.*authenticated/
        ];

        return authPatterns.some(pattern => pattern.test(content));
    }

  private hasTokenValidation(file: any): boolean {
        const content = file.content.toLowerCase();
        const tokenPatterns = [
            /jwt\.verify/,
            /token\.verify/,
            /verify.*token/,
            /decode.*token/,
            /validate.*token/,
            /check.*token.*expir/,
            /token.*signature/
        ];

        return tokenPatterns.some(pattern => pattern.test(content));
    }

  private usesTokenAuth(file: any): boolean {
        const content = file.content.toLowerCase();
        const tokenUsagePatterns = [
            /bearer.*token/,
            /authorization.*token/,
            /jwt/,
            /access.*token/,
            /auth.*token/
        ];

        return tokenUsagePatterns.some(pattern => pattern.test(content));
    }

  private hasSessionValidation(file: any): boolean {
        const content = file.content.toLowerCase();
        const sessionPatterns = [
            /session\.check/,
            /validate.*session/,
            /session.*valid/,
            /session.*active/,
            /session.*expired/
        ];

        return sessionPatterns.some(pattern => pattern.test(content));
    }

  private usesSessionAuth(file: any): boolean {
        const content = file.content.toLowerCase();
        const sessionUsagePatterns = [
            /req\.session/,
            /session\.user/,
            /session\.id/,
            /cookie.*session/
        ];

        return sessionUsagePatterns.some(pattern => pattern.test(content));
    }

  private isHighRiskTool(tool: any): boolean {
        const highRiskPatterns = [
            /admin/i,
            /system/i,
            /execute/i,
            /command/i,
            /file/i,
            /database/i,
            /delete/i,
            /modify/i,
            /stream/i,
            /media/i,
            /user/i,
            /config/i
        ];

        return highRiskPatterns.some(pattern =>
            pattern.test(tool.name) || pattern.test(tool.description || '')
        );
    }

  private checkHighRiskToolAuth(tool: any, context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // High-risk tools should require strong authentication
        if (!this.hasStrongAuthentication(tool)) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'error',
                message: `High-risk tool '${tool.name}' requires strong authentication`,
                evidence: `Tool category: ${this.getToolCategory(tool)}`,
                fix: 'Implement multi-factor authentication or certificate-based auth'
            });
        }

        // High-risk tools should have additional authorization
        if (!this.hasAdditionalAuthorization(tool)) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'error',
                message: `High-risk tool '${tool.name}' requires additional authorization`,
                evidence: `Tool: ${tool.name}`,
                fix: 'Add role-based or permission-based authorization'
            });
        }

        return violations;
    }

  private hasStrongAuthentication(tool: any): boolean {
        return tool.authentication === 'mfa' ||
            tool.authentication === 'certificate' ||
            tool.strongAuth === true;
    }

  private hasAdditionalAuthorization(tool: any): boolean {
        return (tool.permissions && tool.permissions.length > 0) ||
            tool.roles ||
            tool.authorization;
    }

  private getToolCategory(tool: any): string {
        if (tool.name.toLowerCase().includes('admin')) return 'Administrative';
        if (tool.name.toLowerCase().includes('system')) return 'System';
        if (tool.name.toLowerCase().includes('stream')) return 'Streaming';
        if (tool.name.toLowerCase().includes('file')) return 'File System';
        if (tool.name.toLowerCase().includes('database')) return 'Database';
        return 'General';
    }

  private checkGlobalAuthentication(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for authentication middleware
        const hasAuthMiddleware = context.sourceFiles.some(file =>
            this.isAuthenticationMiddleware(file)
        );

        if (!hasAuthMiddleware) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'error',
                message: 'No global authentication middleware detected',
                fix: 'Implement authentication middleware to protect all MCP endpoints'
            });
        }

        // Check for authentication configuration
        const hasAuthConfig = context.sourceFiles.some(file =>
            this.hasAuthenticationConfig(file)
        );

        if (!hasAuthConfig) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'warning',
                message: 'No authentication configuration found',
                fix: 'Create authentication configuration file with proper settings'
            });
        }

        // Check for required authentication dependencies
        // Check for required authentication dependencies
        const authDeps = [
            'passport',
            'jsonwebtoken',
            'express-session',
            'bcrypt',
            'bcryptjs',
            'argon2',
            'jose'
        ];

        const hasAuthDep = authDeps.some(dep =>
            context.packageJson.dependencies?.[dep] ||
            context.packageJson.devDependencies?.[dep]
        );

        if (!hasAuthDep) {
            violations.push({
                ruleId: 'auth-required',
                severity: 'warning',
                message: 'No authentication library found in dependencies',
                fix: `Add an authentication library: ${authDeps.slice(0, 3).join(', ')}`
            });
        }

        return violations;
    }

 private isAuthenticationMiddleware(file: any): boolean {
        const content = file.content.toLowerCase();
        const middlewarePatterns = [
            /auth.*middleware/,
            /middleware.*auth/,
            /passport\./,
            /authenticate.*function/,
            /verify.*token.*function/,
            /check.*auth.*function/
        ];

        return middlewarePatterns.some(pattern => pattern.test(content)) &&
            (content.includes('function') || content.includes('=>'));
    }

 private hasAuthenticationConfig(file: any): boolean {
        const content = file.content.toLowerCase();
        const configPatterns = [
            /auth.*config/,
            /jwt.*secret/,
            /session.*secret/,
            /auth.*strategy/,
            /passport.*config/
        ];

        return configPatterns.some(pattern => pattern.test(content));
    }

 private checkAuthenticationImplementation(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        for (const file of context.sourceFiles) {
            if (!file.ast) continue;

            // Check for weak authentication patterns
            const weakAuthViolations = this.checkWeakAuthentication(file);
            violations.push(...weakAuthViolations);

            // Check for authentication bypass vulnerabilities
            const bypassViolations = this.checkAuthenticationBypass(file);
            violations.push(...bypassViolations);

            // Check for secure credential handling
            const credentialViolations = this.checkCredentialHandling(file);
            violations.push(...credentialViolations);
        }

        return violations;
    }

 private checkWeakAuthentication(file: any): RuleViolation[] {
        const violations: RuleViolation[] = [];

        if (!file.ast) return violations;

        const visitor = (node: ts.Node) => {
            // Check for weak password validation
            if (ts.isCallExpression(node)) {
                const callText = node.getText(file.ast);

                if (this.isPasswordComparison(callText) && this.isWeakPasswordCheck(callText)) {
                    violations.push({
                        ruleId: 'auth-required',
                        severity: 'error',
                        message: 'Weak password comparison detected',
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: 'Plain text password comparison',
                        fix: 'Use bcrypt or argon2 for password hashing and comparison'
                    });
                }

                // Check for hardcoded credentials
                if (this.hasHardcodedCredentials(callText)) {
                    violations.push({
                        ruleId: 'auth-required',
                        severity: 'error',
                        message: 'Hardcoded credentials detected in authentication',
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: 'Hardcoded authentication credentials',
                        fix: 'Move credentials to environment variables or secure configuration'
                    });
                }

                // Check for weak JWT secrets
                if (this.hasWeakJWTSecret(callText)) {
                    violations.push({
                        ruleId: 'auth-required',
                        severity: 'error',
                        message: 'Weak JWT secret detected',
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: 'JWT secret appears to be weak or hardcoded',
                        fix: 'Use strong, randomly generated JWT secrets from environment variables'
                    });
                }
            }

            ts.forEachChild(node, visitor);
        };

        visitor(file.ast);
        return violations;
    }

 private isPasswordComparison(callText: string): boolean {
        const passwordPatterns = [
            /password.*===/,
            /password.*==/,
            /===.*password/,
            /==.*password/,
            /compare.*password/,
            /password.*compare/
        ];

        return passwordPatterns.some(pattern => pattern.test(callText));
    }

 private isWeakPasswordCheck(callText: string): boolean {
        // Check if it's NOT using proper hashing
        const strongHashPatterns = [
            /bcrypt/i,
            /argon2/i,
            /scrypt/i,
            /pbkdf2/i
        ];

        return !strongHashPatterns.some(pattern => pattern.test(callText));
    }

 private hasHardcodedCredentials(callText: string): boolean {
        const credentialPatterns = [
            /password.*=.*["'][^"']{8,}["']/,
            /secret.*=.*["'][^"']{16,}["']/,
            /key.*=.*["'][^"']{16,}["']/,
            /token.*=.*["'][^"']{20,}["']/
        ];

        return credentialPatterns.some(pattern => pattern.test(callText));
    }

 private hasWeakJWTSecret(callText: string): boolean {
        if (!callText.toLowerCase().includes('jwt')) return false;

        const weakSecretPatterns = [
            /secret.*=.*["'][^"']{1,15}["']/,  // Too short
            /["']secret["']/,                  // Literal "secret"
            /["']password["']/,                // Literal "password"
            /["']123/,                         // Starts with numbers
            /["']test/,                        // Test secrets
            /["']dev/                          // Dev secrets
        ];

        return weakSecretPatterns.some(pattern => pattern.test(callText));
    }

 private checkAuthenticationBypass(file: any): RuleViolation[] {
        const violations: RuleViolation[] = [];

        if (!file.ast) return violations;

        const visitor = (node: ts.Node) => {
            // Check for authentication bypass conditions
            if (ts.isIfStatement(node)) {
                const condition = node.expression.getText(file.ast);

                if (this.isAuthBypassCondition(condition)) {
                    violations.push({
                        ruleId: 'auth-required',
                        severity: 'error',
                        message: 'Authentication bypass condition detected',
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `Bypass condition: ${condition}`,
                        fix: 'Remove authentication bypasses or ensure they are properly secured'
                    });
                }

                // Check for debug/development bypasses
                if (this.isDebugBypass(condition)) {
                    violations.push({
                        ruleId: 'auth-required',
                        severity: 'error',
                        message: 'Debug authentication bypass detected',
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `Debug bypass: ${condition}`,
                        fix: 'Remove debug authentication bypasses from production code'
                    });
                }
            }

            // Check for commented-out authentication
            if (ts.isBlock(node) || ts.isSourceFile(node)) {
                const commentViolations = this.checkCommentedAuth(node, file);
                violations.push(...commentViolations);
            }

            ts.forEachChild(node, visitor);
        };

        visitor(file.ast);
        return violations;
    }

 private isAuthBypassCondition(condition: string): boolean {
        const bypassPatterns = [
            /skip.*auth/i,
            /bypass.*auth/i,
            /no.*auth/i,
            /auth.*false/i,
            /!.*auth/i,
            /auth.*disabled/i
        ];

        return bypassPatterns.some(pattern => pattern.test(condition));
    }

 private isDebugBypass(condition: string): boolean {
        const debugPatterns = [
            /debug.*mode/i,
            /dev.*mode/i,
            /test.*mode/i,
            /development/i,
            /node_env.*dev/i,
            /process\.env\.debug/i
        ];

        return debugPatterns.some(pattern => pattern.test(condition));
    }

 private checkCommentedAuth(node: ts.Node, file: any): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Get comments in the node range
        const sourceFile = file.ast;
        const comments = ts.getLeadingCommentRanges(file.content, node.getFullStart()) || [];

        for (const comment of comments) {
            const commentText = file.content.substring(comment.pos, comment.end);

            if (this.isCommentedAuthentication(commentText)) {
                violations.push({
                    ruleId: 'auth-required',
                    severity: 'warning',
                    message: 'Commented-out authentication code detected',
                    file: file.path,
                    line: this.getLineFromPosition(file.content, comment.pos),
                    evidence: 'Authentication code appears to be commented out',
                    fix: 'Remove commented authentication code or restore if needed'
                });
            }
        }

        return violations;
    }

 private isCommentedAuthentication(commentText: string): boolean {
        const authPatterns = [
            /\/\/.*auth/i,
            /\/\*.*auth.*\*\//i,
            /\/\/.*login/i,
            /\/\/.*token/i,
            /\/\/.*verify/i
        ];

        return authPatterns.some(pattern => pattern.test(commentText));
    }

 private checkCredentialHandling(file: any): RuleViolation[] {
        const violations: RuleViolation[] = [];

        if (!file.ast) return violations;

        const visitor = (node: ts.Node) => {
            if (ts.isVariableDeclaration(node) || ts.isPropertyAssignment(node)) {
                const nodeText = node.getText(file.ast);

                // Check for credentials in variables
                if (this.isCredentialVariable(nodeText)) {
                    if (this.isInsecureCredentialHandling(nodeText)) {
                        violations.push({
                            ruleId: 'auth-required',
                            severity: 'error',
                            message: 'Insecure credential handling detected',
                            file: file.path,
                            line: this.getLineNumber(file.ast, node),
                            evidence: 'Credentials handled insecurely',
                            fix: 'Use environment variables and secure storage for credentials'
                        });
                    }
                }
            }

            // Check for credential logging
            if (ts.isCallExpression(node)) {
                const callText = node.getText(file.ast);
                if (this.isLoggingCall(callText) && this.mayLogCredentials(callText)) {
                    violations.push({
                        ruleId: 'auth-required',
                        severity: 'error',
                        message: 'Potential credential logging detected',
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: 'Logging call may expose credentials',
                        fix: 'Ensure credentials are not logged or exposed in error messages'
                    });
                }
            }

            ts.forEachChild(node, visitor);
        };

        visitor(file.ast);
        return violations;
    }

 private isCredentialVariable(nodeText: string): boolean {
        const credentialPatterns = [
            /password/i,
            /secret/i,
            /key/i,
            /token/i,
            /credential/i,
            /auth/i
        ];

        return credentialPatterns.some(pattern => pattern.test(nodeText));
    }

 private isInsecureCredentialHandling(nodeText: string): boolean {
        const insecurePatterns = [
            /=.*["'][^"']+["']/,  // Direct assignment of string literals
            /console\./,          // Console output
            /alert\(/,            // Alert dialogs
            /document\./,         // DOM manipulation
            /localStorage/,       // Local storage
            /sessionStorage/      // Session storage
        ];

        return insecurePatterns.some(pattern => pattern.test(nodeText));
    }

 private isLoggingCall(callText: string): boolean {
        const loggingPatterns = [
            /console\./,
            /log\./,
            /logger\./,
            /print/,
            /debug/,
            /info/,
            /warn/,
            /error/
        ];

        return loggingPatterns.some(pattern => pattern.test(callText));
    }

 private mayLogCredentials(callText: string): boolean {
        const credentialPatterns = [
            /password/i,
            /secret/i,
            /token/i,
            /key/i,
            /credential/i,
            /auth/i
        ];

        return credentialPatterns.some(pattern => pattern.test(callText));
    }

 private getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
        return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    }

 private getLineFromPosition(content: string, position: number): number {
        return content.substring(0, position).split('\n').length;
    }
};