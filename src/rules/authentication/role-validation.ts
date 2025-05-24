import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

export const roleValidation = {
    id: 'role-validation',
    name: 'Role-Based Access Validation',
    description: 'Ensures proper role-based access control implementation in MCP tools',
    severity: 'error',
    category: 'authentication',
    mandatory: true,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check role system implementation
        const roleSystemViolations = this.checkRoleSystem(context);
        violations.push(...roleSystemViolations);

        // Check each tool for role validation
        for (const tool of context.mcpServer.tools) {
            const toolViolations = await this.checkToolRoleValidation(tool, context);
            violations.push(...toolViolations);
        }

        // Check for role-based resource access
        const resourceViolations = this.checkRoleBasedResourceAccess(context);
        violations.push(...resourceViolations);

        // Fox Corp specific role checks
        if (context.config.foxCorp) {
            const foxViolations = this.checkFoxCorpRoles(context);
            violations.push(...foxViolations);
        }

        return violations;
    },
  checkRoleSystem(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for role definition
        const hasRoleDefinition = context.sourceFiles.some(file =>
            this.hasRoleDefinitions(file)
        );

        if (!hasRoleDefinition) {
            violations.push({
                ruleId: 'role-validation',
                severity: 'error',
                message: 'No role system implementation detected',
                fix: 'Implement role definitions and role-based access control'
            });
        }

        // Check for role assignment mechanism
        const hasRoleAssignment = context.sourceFiles.some(file =>
            this.hasRoleAssignment(file)
        );

        if (!hasRoleAssignment) {
            violations.push({
                ruleId: 'role-validation',
                severity: 'warning',
                message: 'No role assignment mechanism found',
                fix: 'Implement user role assignment and management'
            });
        }

        // Check for role inheritance/hierarchy
        const hasRoleHierarchy = context.sourceFiles.some(file =>
            this.hasRoleHierarchy(file)
        );

        if (!hasRoleHierarchy) {
            violations.push({
                ruleId: 'role-validation',
                severity: 'info',
                message: 'No role hierarchy system detected',
                fix: 'Consider implementing role hierarchy for better access management'
            });
        }

        return violations;
    },
  hasRoleDefinitions(file: any): boolean {
        const content = file.content.toLowerCase();
        const rolePatterns = [
            /role.*=.*{/,
            /roles.*=.*\[/,
            /enum.*role/,
            /interface.*role/,
            /type.*role/,
            /const.*roles/,
            /define.*role/
        ];

        return rolePatterns.some(pattern => pattern.test(content));
    },
  hasRoleAssignment(file: any): boolean {
        const content = file.content.toLowerCase();
        const assignmentPatterns = [
            /assign.*role/,
            /add.*role/,
            /user.*role/,
            /set.*role/,
            /grant.*role/,
            /role.*assignment/
        ];

        return assignmentPatterns.some(pattern => pattern.test(content));
    },
  hasRoleHierarchy(file: any): boolean {
        const content = file.content.toLowerCase();
        const hierarchyPatterns = [
            /role.*inherit/,
            /parent.*role/,
            /child.*role/,
            /role.*hierarchy/,
            /super.*role/,
            /extends.*role/
        ];

        return hierarchyPatterns.some(pattern => pattern.test(content));
    },
  async checkToolRoleValidation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check if tool defines required roles
        if (!this.hasRequiredRoles(tool)) {
            const severity = this.isHighPrivilegeTool(tool) ? 'error' : 'warning';
            violations.push({
                ruleId: 'role-validation',
                severity,
                message: `Tool '${tool.name}' lacks required role definitions`,
                evidence: `Tool: ${tool.name}, Roles: ${tool.roles || 'undefined'}`,
                fix: 'Define required roles for tool access'
            });
        } else {
            // Validate role definitions
            const roleViolations = this.validateToolRoles(tool, context);
            violations.push(...roleViolations);
        }

        // Check implementation for role validation
        const implViolations = await this.checkRoleImplementation(tool, context);
        violations.push(...implViolations);

        return violations;
    },
  hasRequiredRoles(tool: any): boolean {
        return tool.roles &&
            (Array.isArray(tool.roles) ? tool.roles.length > 0 : typeof tool.roles === 'string');
    },
  isHighPrivilegeTool(tool: any): boolean {
        const highPrivilegePatterns = [
            /admin/i,
            /system/i,
            /root/i,
            /super/i,
            /manage/i,
            /delete/i,
            /modify/i,
            /config/i,
            /user/i,
            /role/i
        ];

        return highPrivilegePatterns.some(pattern =>
            pattern.test(tool.name) || pattern.test(tool.description || '')
        );
    },
  validateToolRoles(tool: any, context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];
        const roles = Array.isArray(tool.roles) ? tool.roles : [tool.roles];

        for (const role of roles) {
            // Check role naming convention
            if (!this.isValidRoleName(role)) {
                violations.push({
                    ruleId: 'role-validation',
                    severity: 'warning',
                    message: `Tool '${tool.name}' uses invalid role name: '${role}'`,
                    evidence: `Invalid role: ${role}`,
                    fix: 'Use standard role naming convention (lowercase, underscores)'
                });
            }

            // Check for overly broad roles
            if (this.isOverlyBroadRole(role)) {
                violations.push({
                    ruleId: 'role-validation',
                    severity: 'error',
                    message: `Tool '${tool.name}' uses overly broad role: '${role}'`,
                    evidence: `Broad role: ${role}`,
                    fix: 'Use more specific roles instead of admin or superuser roles'
                });
            }

            // Check for standard role compliance
            if (context.config.foxCorp && !this.isFoxCorpCompliantRole(role)) {
                violations.push({
                    ruleId: 'role-validation',
                    severity: 'warning',
                    message: `Tool '${tool.name}' uses non-standard Fox Corp role: '${role}'`,
                    evidence: `Non-standard role: ${role}`,
                    fix: 'Use Fox Corp standard roles or get approval for custom roles'
                });
            }
        }

        return violations;
    },
  isValidRoleName(role: string): boolean {
        // Standard role naming: lowercase, underscores, no spaces
        const rolePattern = /^[a-z][a-z0-9_]*$/;
        return rolePattern.test(role);
    },
  isOverlyBroadRole(role: string): boolean {
        const broadRoles = [
            'admin',
            'administrator',
            'root',
            'superuser',
            'super_admin',
            'god',
            'all',
            '*'
        ];

        return broadRoles.includes(role.toLowerCase());
    },
  isFoxCorpCompliantRole(role: string): boolean {
        const foxCorpStandardRoles = [
            'viewer',
            'editor',
            'moderator',
            'content_manager',
            'stream_operator',
            'analytics_viewer',
            'tech_support',
            'system_admin'
        ];

        return foxCorpStandardRoles.includes(role.toLowerCase()) ||
            role.startsWith('fox_') ||
            role.startsWith('content_');
    },
  async checkRoleImplementation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Find tool implementation
        const implFile = context.sourceFiles.find(file =>
            file.content.includes(tool.name) &&
            (file.content.includes('function') || file.content.includes('=>'))
        );

        if (!implFile || !implFile.ast) {
            violations.push({
                ruleId: 'role-validation',
                severity: 'warning',
                message: `Cannot analyze role validation for tool '${tool.name}' - implementation not found`
            });
            return violations;
        }

        // Check for role validation in implementation
        const hasRoleCheck = this.hasRoleValidationCode(implFile);
        if (!hasRoleCheck && tool.roles) {
            violations.push({
                ruleId: 'role-validation',
                severity: 'error',
                message: `Tool '${tool.name}' implementation lacks role validation`,
                file: implFile.path,
                fix: 'Add role validation check in tool implementation'
            });
        }

        // Check for proper role error handling
        const hasRoleErrorHandling = this.hasRoleErrorHandling(implFile);
        if (!hasRoleErrorHandling && tool.roles) {
            violations.push({
                ruleId: 'role-validation',
                severity: 'warning',
                message: `Tool '${tool.name}' lacks proper role-based error handling`,
                file: implFile.path,
                fix: 'Add appropriate error responses for role validation failures'
            });
        }

        // Check for role escalation vulnerabilities
        const escalationViolations = this.checkRoleEscalation(implFile, tool);
        violations.push(...escalationViolations);

        return violations;
    },
  hasRoleValidationCode(file: any): boolean {
        const content = file.content.toLowerCase();
        const roleValidationPatterns = [
            /check.*role/,
            /validate.*role/,
            /has.*role/,
            /user.*role/,
            /role.*check/,
            /role.*validation/,
            /is.*role/,
            /can.*access/
        ];

        return roleValidationPatterns.some(pattern => pattern.test(content));
    },
  hasRoleErrorHandling(file: any): boolean {
        const content = file.content.toLowerCase();
        const errorPatterns = [
            /role.*error/,
            /access.*denied/,
            /forbidden/,
            /403/,
            /insufficient.*role/,
            /role.*required/,
            /unauthorized.*role/
        ];

        return errorPatterns.some(pattern => pattern.test(content));
    },
  checkRoleEscalation(file: any, tool: any): RuleViolation[] {
        const violations: RuleViolation[] = [];

        if (!file.ast) return violations;

        const visitor = (node: ts.Node) => {
            // Check for role modification in tool
            if (ts.isCallExpression(node)) {
                const callText = node.getText(file.ast);

                if (this.isRoleModification(callText)) {
                    violations.push({
                        ruleId: 'role-validation',
                        severity: 'error',
                        message: `Tool '${tool.name}' contains role modification logic`,
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `Role modification: ${callText}`,
                        fix: 'Remove role modification from tool or require admin privileges'
                    });
                }

                // Check for role bypass attempts
                if (this.isRoleBypass(callText)) {
                    violations.push({
                        ruleId: 'role-validation',
                        severity: 'error',
                        message: `Tool '${tool.name}' attempts to bypass role validation`,
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `Role bypass: ${callText}`,
                        fix: 'Remove role bypass logic'
                    });
                }
            }

            // Check for conditional role bypasses
            if (ts.isIfStatement(node)) {
                const condition = node.expression.getText(file.ast);
                if (this.isRoleBypassCondition(condition)) {
                    violations.push({
                        ruleId: 'role-validation',
                        severity: 'error',
                        message: `Tool '${tool.name}' has conditional role bypass`,
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `Bypass condition: ${condition}`,
                        fix: 'Remove conditional role bypasses'
                    });
                }
            }

            ts.forEachChild(node, visitor);
        };

        visitor(file.ast);
        return violations;
    },
  isRoleModification(callText: string): boolean {
        const modificationPatterns = [
            /add.*role/i,
            /remove.*role/i,
            /set.*role/i,
            /assign.*role/i,
            /grant.*role/i,
            /revoke.*role/i,
            /promote/i,
            /demote/i
        ];

        return modificationPatterns.some(pattern => pattern.test(callText));
    },
  isRoleBypass(callText: string): boolean {
        const bypassPatterns = [
            /skip.*role/i,
            /bypass.*role/i,
            /ignore.*role/i,
            /override.*role/i,
            /force.*access/i
        ];

        return bypassPatterns.some(pattern => pattern.test(callText));
    },
  isRoleBypassCondition(condition: string): boolean {
        const bypassPatterns = [
            /!.*role/i,
            /role.*===.*null/i,
            /role.*===.*undefined/i,
            /skip.*role.*check/i,
            /debug.*mode/i,
            /dev.*mode/i
        ];

        return bypassPatterns.some(pattern => pattern.test(condition));
    },
  checkRoleBasedResourceAccess(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check if resources use role-based access
        for (const resource of context.mcpServer.resources || []) {
            if (!this.hasRoleBasedAccess(resource)) {
                violations.push({
                    ruleId: 'role-validation',
                    severity: 'warning',
                    message: `Resource '${resource.name}' lacks role-based access control`,
                    evidence: `Resource: ${resource.name}`,
                    fix: 'Add role-based access control to resource'
                });
            }
        }

        return violations;
    },
  hasRoleBasedAccess(resource: any): boolean {
        return resource.roles ||
            resource.accessControl?.roles ||
            resource.permissions?.some((perm: string) => perm.includes('role'));
    },
  checkFoxCorpRoles(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for Fox Corp specific role requirements
        const streamingTools = context.mcpServer.tools.filter(tool =>
            this.isStreamingTool(tool)
        );

        for (const tool of streamingTools) {
            if (!this.hasStreamingRoles(tool)) {
                violations.push({
                    ruleId: 'role-validation',
                    severity: 'error',
                    message: `Streaming tool '${tool.name}' requires Fox Corp streaming roles`,
                    evidence: `Tool: ${tool.name}, Category: streaming`,
                    fix: 'Add required streaming roles: stream_operator, content_manager, or analytics_viewer'
                });
            }
        }

        // Check for separation of duties
        const adminTools = context.mcpServer.tools.filter(tool =>
            this.isAdminTool(tool)
        );

        for (const tool of adminTools) {
            if (this.hasOperationalRoles(tool)) {
                violations.push({
                    ruleId: 'role-validation',
                    severity: 'warning',
                    message: `Admin tool '${tool.name}' allows operational roles - consider separation of duties`,
                    evidence: `Tool has both admin and operational role access`,
                    fix: 'Implement separation of duties between admin and operational roles'
                });
            }
        }

        return violations;
    },
  isStreamingTool(tool: any): boolean {
        const streamingPatterns = [
            /stream/i,
            /video/i,
            /media/i,
            /content/i,
            /conviva/i,
            /har/i
        ];

        return streamingPatterns.some(pattern =>
            pattern.test(tool.name) || pattern.test(tool.description || '')
        );
    },
  hasStreamingRoles(tool: any): boolean {
        const streamingRoles = [
            'stream_operator',
            'content_manager',
            'analytics_viewer',
            'media_admin'
        ];

        const toolRoles = Array.isArray(tool.roles) ? tool.roles : [tool.roles];
        return streamingRoles.some(role => toolRoles.includes(role));
    },
  isAdminTool(tool: any): boolean {
        const adminPatterns = [
            /admin/i,
            /manage/i,
            /config/i,
            /system/i,
            /user/i,
            /role/i
        ];

        return adminPatterns.some(pattern =>
            pattern.test(tool.name) || pattern.test(tool.description || '')
        );
    },
  hasOperationalRoles(tool: any): boolean {
        const operationalRoles = [
            'viewer',
            'editor',
            'stream_operator',
            'content_manager',
            'analytics_viewer'
        ];

        const toolRoles = Array.isArray(tool.roles) ? tool.roles : [tool.roles];
        return operationalRoles.some(role => toolRoles.includes(role));
    },
  getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
        return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    }
} as MCPSecurityRule;
