import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

export const permissionChecks: MCPSecurityRule = {
    id: 'permission-checks',
    name: 'Permission Checks',
    description: 'Ensures proper permission validation before tool execution',
    severity: 'error',
    category: 'authorization',
    mandatory: true,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check each tool for permission requirements and validation
        for (const tool of context.mcpServer.tools) {
            const toolViolations = await this.checkToolPermissions(tool, context);
            violations.push(...toolViolations);
        }

        // Check for permission system implementation
        const systemViolations = this.checkPermissionSystem(context);
        violations.push(...systemViolations);

        return violations;
    }

  private async checkToolPermissions(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check if tool has defined permissions
        if (!tool.permissions || tool.permissions.length === 0) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'error',
                message: `Tool '${tool.name}' lacks permission definitions`,
                evidence: `Tool: ${tool.name}, Permissions: ${tool.permissions || 'undefined'}`,
                fix: 'Define required permissions array for this tool'
            });
        } else {
            // Validate permission format and naming
            const permViolations = this.validatePermissionFormat(tool, context);
            violations.push(...permViolations);
        }

        // Check implementation for permission validation
        const implViolations = await this.checkPermissionImplementation(tool, context);
        violations.push(...implViolations);

        // Check for privilege escalation vulnerabilities
        const escalationViolations = await this.checkPrivilegeEscalation(tool, context);
        violations.push(...escalationViolations);

        return violations;
    }

  private validatePermissionFormat(tool: any, context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        for (const permission of tool.permissions) {
            // Check permission naming convention
            if (!this.isValidPermissionFormat(permission)) {
                violations.push({
                    ruleId: 'permission-checks',
                    severity: 'warning',
                    message: `Tool '${tool.name}' has invalid permission format: '${permission}'`,
                    evidence: `Expected format: 'resource:action' (e.g., 'stream:read')`,
                    fix: 'Use standard permission format: resource:action'
                });
            }

            // Check for overly broad permissions
            if (this.isOverlyBroadPermission(permission)) {
                violations.push({
                    ruleId: 'permission-checks',
                    severity: 'error',
                    message: `Tool '${tool.name}' requests overly broad permission: '${permission}'`,
                    evidence: `Broad permission: ${permission}`,
                    fix: 'Use more specific permissions instead of wildcard or admin permissions'
                });
            }

            // Fox Corp specific: streaming permissions validation
            if (context.config.foxCorp?.streamingAssets && this.isStreamingPermission(permission)) {
                const streamingViolations = this.validateStreamingPermission(tool, permission, context);
                violations.push(...streamingViolations);
            }
        }

        return violations;
    }

  private isValidPermissionFormat(permission: string): boolean {
        // Standard format: resource:action
        const permissionPattern = /^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$/;
        return permissionPattern.test(permission);
    }

  private isOverlyBroadPermission(permission: string): boolean {
        const broadPatterns = [
            /.*:\*/,      // Any action wildcard
            /\*:.*/,      // Any resource wildcard
            /admin/i,     // Admin permissions
            /root/i,      // Root permissions
            /superuser/i, // Superuser permissions
            /.*:all$/i    // All actions
        ];

        return broadPatterns.some(pattern => pattern.test(permission));
    }

  private isStreamingPermission(permission: string): boolean {
        const streamingPatterns = [
            /stream/i,
            /media/i,
            /video/i,
            /content/i,
            /asset/i
        ];

        return streamingPatterns.some(pattern => pattern.test(permission));
    }

  private validateStreamingPermission(tool: any, permission: string, context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Fox Corp streaming permissions must be specific
        const requiredStreamingActions = ['read', 'write', 'delete', 'admin'];
        const [resource, action] = permission.split(':');

        if (!requiredStreamingActions.includes(action)) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'error',
                message: `Tool '${tool.name}' uses non-standard streaming permission action: '${action}'`,
                evidence: `Permission: ${permission}, Valid actions: ${requiredStreamingActions.join(', ')}`,
                fix: 'Use standard Fox Corp streaming permission actions'
            });
        }

        // Streaming write/delete permissions require additional validation
        if (['write', 'delete', 'admin'].includes(action)) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'warning',
                message: `Tool '${tool.name}' requests high-privilege streaming permission: '${permission}'`,
                evidence: `High-privilege streaming permission: ${permission}`,
                fix: 'Ensure this tool truly requires write/delete access to streaming assets'
            });
        }

        return violations;
    }

  private async checkPermissionImplementation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Find tool implementation
        const implFile = context.sourceFiles.find(file =>
            file.content.includes(tool.name) &&
            (file.content.includes('function') || file.content.includes('=>'))
        );

        if (!implFile || !implFile.ast) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'warning',
                message: `Cannot analyze permission implementation for tool '${tool.name}'`,
                evidence: 'Implementation file not found or not parseable'
            });
            return violations;
        }

        // Check for permission validation in implementation
        const hasPermissionCheck = this.hasPermissionValidation(implFile);
        if (!hasPermissionCheck) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'error',
                message: `Tool '${tool.name}' implementation lacks permission validation`,
                file: implFile.path,
                fix: 'Add permission validation at the beginning of tool function'
            });
        }

        // Check for proper permission error handling
        const hasPermissionErrorHandling = this.hasPermissionErrorHandling(implFile);
        if (!hasPermissionErrorHandling) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'warning',
                message: `Tool '${tool.name}' lacks proper permission error handling`,
                file: implFile.path,
                fix: 'Add proper error responses for permission denied scenarios'
            });
        }

        // Check for context-based permission validation
        const hasContextValidation = this.hasContextBasedValidation(implFile);
        if (!hasContextValidation && this.requiresContextValidation(tool)) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'error',
                message: `Tool '${tool.name}' requires context-based permission validation`,
                file: implFile.path,
                evidence: 'Tool accesses resources that require context validation',
                fix: 'Implement context-aware permission checking (user, resource, action)'
            });
        }

        return violations;
    }

  private hasPermissionValidation(file: any): boolean {
        const content = file.content.toLowerCase();
        const permissionPatterns = [
            /check.*permission/,
            /validate.*permission/,
            /has.*permission/,
            /permission.*check/,
            /authorize/,
            /can.*access/,
            /allowed/,
            /hasaccess/
        ];

        return permissionPatterns.some(pattern => pattern.test(content));
    }

  private hasPermissionErrorHandling(file: any): boolean {
        const content = file.content.toLowerCase();
        const errorPatterns = [
            /403/,  // Forbidden status code
            /forbidden/,
            /permission.*denied/,
            /access.*denied/,
            /unauthorized/,
            /not.*allowed/,
            /insufficient.*permission/
        ];

        return errorPatterns.some(pattern => pattern.test(content));
    }

  private hasContextBasedValidation(file: any): boolean {
        const content = file.content.toLowerCase();
        const contextPatterns = [
            /user.*permission/,
            /resource.*permission/,
            /context.*permission/,
            /role.*based/,
            /rbac/,
            /attribute.*based/,
            /abac/
        ];

        return contextPatterns.some(pattern => pattern.test(content));
    }

  private requiresContextValidation(tool: any): boolean {
        // Tools that modify data or access sensitive resources need context validation
        const sensitivePatterns = [
            /write/i,
            /delete/i,
            /modify/i,
            /update/i,
            /admin/i,
            /manage/i,
            /stream/i,
            /media/i,
            /user/i,
            /account/i
        ];

        return sensitivePatterns.some(pattern =>
            pattern.test(tool.name) ||
            pattern.test(tool.description || '') ||
            (tool.permissions && tool.permissions.some((perm: string) => pattern.test(perm)))
        );
    }

  private async checkPrivilegeEscalation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        const implFile = context.sourceFiles.find(file =>
            file.content.includes(tool.name)
        );

        if (!implFile || !implFile.ast) {
            return violations;
        }

        const visitor = (node: ts.Node) => {
            // Check for potential privilege escalation patterns
            if (ts.isCallExpression(node)) {
                const callText = node.getText(implFile.ast);

                // Check for role/permission modification
                if (this.isPermissionModification(callText)) {
                    violations.push({
                        ruleId: 'permission-checks',
                        severity: 'error',
                        message: `Tool '${tool.name}' contains permission modification logic`,
                        file: implFile.path,
                        line: this.getLineNumber(implFile.ast, node),
                        evidence: `Function call: ${callText}`,
                        fix: 'Remove permission modification from tool or require admin privileges'
                    });
                }

                // Check for sudo/elevation patterns
                if (this.isSudoCall(callText)) {
                    violations.push({
                        ruleId: 'permission-checks',
                        severity: 'error',
                        message: `Tool '${tool.name}' attempts privilege elevation`,
                        file: implFile.path,
                        line: this.getLineNumber(implFile.ast, node),
                        evidence: `Elevation attempt: ${callText}`,
                        fix: 'Remove privilege elevation or implement proper authorization'
                    });
                }
            }

            // Check for bypass patterns
            if (ts.isIfStatement(node)) {
                const condition = node.expression.getText(implFile.ast);
                if (this.isPermissionBypass(condition)) {
                    violations.push({
                        ruleId: 'permission-checks',
                        severity: 'error',
                        message: `Tool '${tool.name}' contains permission bypass logic`,
                        file: implFile.path,
                        line: this.getLineNumber(implFile.ast, node),
                        evidence: `Bypass condition: ${condition}`,
                        fix: 'Remove permission bypasses or implement proper admin checks'
                    });
                }
            }

            ts.forEachChild(node, visitor);
        };

        visitor(implFile.ast);
        return violations;
    }

  private isPermissionModification(callText: string): boolean {
        const modificationPatterns = [
            /set.*permission/i,
            /grant.*permission/i,
            /revoke.*permission/i,
            /add.*role/i,
            /remove.*role/i,
            /promote/i,
            /demote/i,
            /elevate/i
        ];

        return modificationPatterns.some(pattern => pattern.test(callText));
    }

  private isSudoCall(callText: string): boolean {
        const sudoPatterns = [
            /sudo/i,
            /runas/i,
            /elevate/i,
            /impersonate/i,
            /become.*admin/i,
            /switch.*user/i
        ];

        return sudoPatterns.some(pattern => pattern.test(callText));
    }

  private isPermissionBypass(condition: string): boolean {
        const bypassPatterns = [
            /skip.*permission/i,
            /bypass.*auth/i,
            /ignore.*permission/i,
            /debug.*mode/i,
            /dev.*mode/i,
            /test.*mode/i
        ];

        return bypassPatterns.some(pattern => pattern.test(condition));
    }

  private checkPermissionSystem(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for permission system implementation
        const hasPermissionSystem = context.sourceFiles.some(file =>
            this.hasPermissionValidation(file) &&
            file.content.toLowerCase().includes('role')
        );

        if (!hasPermissionSystem) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'error',
                message: 'No permission system implementation detected',
                fix: 'Implement a role-based or attribute-based permission system'
            });
        }

        // Check for permission management endpoints
        const hasPermissionManagement = context.sourceFiles.some(file =>
            file.content.toLowerCase().includes('permission') &&
            (file.content.toLowerCase().includes('create') ||
                file.content.toLowerCase().includes('update') ||
                file.content.toLowerCase().includes('delete'))
        );

        if (hasPermissionManagement) {
            violations.push({
                ruleId: 'permission-checks',
                severity: 'warning',
                message: 'Permission management endpoints detected - ensure they are properly secured',
                fix: 'Verify permission management endpoints require admin privileges'
            });
        }

        return violations;
    }

  private getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
        return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    }
};