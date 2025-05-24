import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

export const rateLimitEnforcement: MCPSecurityRule = {
    id: 'rate-limit-enforcement',
    name: 'Rate Limit Enforcement',
    description: 'Ensures MCP tools have proper rate limiting to prevent abuse and resource exhaustion',
    severity: 'warning',
    category: 'rate-limiting',
    mandatory: false,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check each MCP tool for rate limiting
        for (const tool of context.mcpServer.tools) {
            const toolViolations = await this.checkToolRateLimit(tool, context);
            violations.push(...toolViolations);
        }

        // Check for global rate limiting middleware
        const globalViolations = this.checkGlobalRateLimit(context);
        violations.push(...globalViolations);

        // Check for high-risk tools that must have rate limiting
        const criticalViolations = this.checkCriticalToolsRateLimit(context);
        violations.push(...criticalViolations);

        return violations;
    }

  private async checkToolRateLimit(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check if tool has explicit rate limit configuration
        if (!tool.rateLimit) {
            const severity = this.isHighRiskTool(tool) ? 'error' : 'warning';
            violations.push({
                ruleId: 'rate-limit-enforcement',
                severity,
                message: `Tool '${tool.name}' lacks rate limiting configuration`,
                evidence: `Tool: ${tool.name}, Type: ${this.getToolRiskLevel(tool)}`,
                fix: 'Add rate limit configuration: { requests: 100, window: 60000, scope: "user" }'
            });
        } else {
            // Validate rate limit configuration
            const configViolations = this.validateRateLimitConfig(tool, context);
            violations.push(...configViolations);
        }

        // Check implementation for rate limiting logic
        const implViolations = await this.checkRateLimitImplementation(tool, context);
        violations.push(...implViolations);

        return violations;
    }

  private validateRateLimitConfig(tool: any, context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];
        const rateLimit = tool.rateLimit;

        // Check if rate limit values are reasonable
        if (rateLimit.requests > 1000) {
            violations.push({
                ruleId: 'rate-limit-enforcement',
                severity: 'warning',
                message: `Tool '${tool.name}' has very high rate limit (${rateLimit.requests} requests)`,
                evidence: `Rate limit: ${rateLimit.requests} requests per ${rateLimit.window}ms`,
                fix: 'Consider lowering rate limit for better protection'
            });
        }

        if (rateLimit.window < 1000) {
            violations.push({
                ruleId: 'rate-limit-enforcement',
                severity: 'warning',
                message: `Tool '${tool.name}' has very short rate limit window (${rateLimit.window}ms)`,
                evidence: `Window: ${rateLimit.window}ms`,
                fix: 'Consider using a longer time window (e.g., 60000ms for 1 minute)'
            });
        }

        // Check for missing required fields
        if (!rateLimit.scope) {
            violations.push({
                ruleId: 'rate-limit-enforcement',
                severity: 'error',
                message: `Tool '${tool.name}' rate limit missing scope definition`,
                evidence: 'Rate limit scope not specified',
                fix: 'Add scope: "user" | "global" | "tool" to rate limit configuration'
            });
        }

        // Fox Corp specific: streaming tools should have stricter limits
        if (context.config.foxCorp?.streamingAssets && this.isStreamingTool(tool)) {
            if (rateLimit.requests > 100) {
                violations.push({
                    ruleId: 'rate-limit-enforcement',
                    severity: 'error',
                    message: `Streaming tool '${tool.name}' rate limit too high for Fox Corp standards`,
                    evidence: `Current: ${rateLimit.requests} requests, Fox Corp max: 100`,
                    fix: 'Set rate limit to maximum 100 requests per window for streaming tools'
                });
            }
        }

        return violations;
    }

  private async checkRateLimitImplementation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Find tool implementation file
        const implFile = context.sourceFiles.find(file =>
            file.content.includes(tool.name) &&
            (file.content.includes('async') || file.content.includes('function'))
        );

        if (!implFile || !implFile.ast) {
            return violations;
        }

        // Check for rate limiting logic in implementation
        const hasRateLimitCode = this.checkForRateLimitingCode(implFile);
        if (!hasRateLimitCode && !tool.rateLimit) {
            violations.push({
                ruleId: 'rate-limit-enforcement',
                severity: 'error',
                message: `Tool '${tool.name}' implementation lacks rate limiting logic`,
                file: implFile.path,
                fix: 'Implement rate limiting middleware or add rate limit checks'
            });
        }

        // Check for proper rate limit error handling
        const hasRateLimitErrorHandling = this.checkForRateLimitErrorHandling(implFile);
        if (!hasRateLimitErrorHandling && tool.rateLimit) {
            violations.push({
                ruleId: 'rate-limit-enforcement',
                severity: 'warning',
                message: `Tool '${tool.name}' lacks proper rate limit error handling`,
                file: implFile.path,
                fix: 'Add proper error responses for rate limit exceeded scenarios'
            });
        }

        // Check for rate limit bypass vulnerabilities
        const bypassViolations = this.checkRateLimitBypass(implFile);
        violations.push(...bypassViolations);

        return violations;
    }

  private checkForRateLimitingCode(file: any): boolean {
        const content = file.content.toLowerCase();
        const rateLimitPatterns = [
            /rate.*limit/,
            /throttle/,
            /bucket/,
            /sliding.*window/,
            /request.*count/,
            /limit.*exceeded/,
            /too.*many.*requests/
        ];

        return rateLimitPatterns.some(pattern => pattern.test(content));
    }

  private checkForRateLimitErrorHandling(file: any): boolean {
        const content = file.content.toLowerCase();
        const errorPatterns = [
            /429/,  // Too Many Requests status code
            /rate.*limit.*exceeded/,
            /too.*many.*requests/,
            /quota.*exceeded/,
            /throttled/
        ];

        return errorPatterns.some(pattern => pattern.test(content));
    }

  private checkRateLimitBypass(file: any): RuleViolation[] {
        const violations: RuleViolation[] = [];

        if (!file.ast) return violations;

        const visitor = (node: ts.Node) => {
            // Check for potential rate limit bypasses
            if (ts.isIfStatement(node)) {
                const condition = node.expression.getText(file.ast);

                // Look for admin/privileged user bypasses
                if (this.isPrivilegedBypass(condition)) {
                    violations.push({
                        ruleId: 'rate-limit-enforcement',
                        severity: 'warning',
                        message: 'Potential rate limit bypass for privileged users detected',
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `Condition: ${condition}`,
                        fix: 'Ensure privileged users still have reasonable rate limits'
                    });
                }

                // Look for IP-based bypasses that might be exploitable
                if (this.isIPBasedBypass(condition)) {
                    violations.push({
                        ruleId: 'rate-limit-enforcement',
                        severity: 'error',
                        message: 'Potential IP-based rate limit bypass vulnerability',
                        file: file.path,
                        line: this.getLineNumber(file.ast, node),
                        evidence: `IP bypass condition: ${condition}`,
                        fix: 'Validate IP-based bypasses and ensure they cannot be spoofed'
                    });
                }
            }

            ts.forEachChild(node, visitor);
        };

        visitor(file.ast);
        return violations;
    }

  private isPrivilegedBypass(condition: string): boolean {
        const privilegedPatterns = [
            /admin/i,
            /root/i,
            /superuser/i,
            /privileged/i,
            /bypass/i
        ];

        return privilegedPatterns.some(pattern => pattern.test(condition));
    }

  private isIPBasedBypass(condition: string): boolean {
        const ipPatterns = [
            /ip.*===.*['"]/,
            /whitelist.*ip/i,
            /trusted.*ip/i,
            /internal.*ip/i
        ];

        return ipPatterns.some(pattern => pattern.test(condition));
    }

  private checkGlobalRateLimit(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for global rate limiting middleware
        const hasGlobalRateLimit = context.sourceFiles.some(file =>
            this.checkForRateLimitingCode(file) &&
            file.content.toLowerCase().includes('middleware')
        );

        if (!hasGlobalRateLimit) {
            violations.push({
                ruleId: 'rate-limit-enforcement',
                severity: 'warning',
                message: 'No global rate limiting middleware detected',
                fix: 'Consider implementing global rate limiting middleware for additional protection'
            });
        }

        // Check package.json for rate limiting dependencies
        const rateLimitDeps = [
            'express-rate-limit',
            'rate-limiter-flexible',
            'bottleneck',
            'p-limit',
            'limiter'
        ];

        const hasDep = rateLimitDeps.some(dep =>
            context.packageJson.dependencies?.[dep] ||
            context.packageJson.devDependencies?.[dep]
        );

        if (!hasDep) {
            violations.push({
                ruleId: 'rate-limit-enforcement',
                severity: 'info',
                message: 'No rate limiting library found in dependencies',
                fix: `Consider adding a rate limiting library: ${rateLimitDeps.slice(0, 3).join(', ')}`
            });
        }

        return violations;
    }

  private checkCriticalToolsRateLimit(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Tools that MUST have rate limiting
        const criticalTools = context.mcpServer.tools.filter(tool =>
            this.isHighRiskTool(tool) || this.isStreamingTool(tool)
        );

        for (const tool of criticalTools) {
            if (!tool.rateLimit) {
                violations.push({
                    ruleId: 'rate-limit-enforcement',
                    severity: 'error',
                    message: `Critical tool '${tool.name}' MUST have rate limiting`,
                    evidence: `Tool category: ${this.getToolCategory(tool)}`,
                    fix: 'Add mandatory rate limiting configuration for this critical tool'
                });
            }
        }

        return violations;
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
            /create/i
        ];

        return highRiskPatterns.some(pattern =>
            pattern.test(tool.name) || pattern.test(tool.description || '')
        );
    }

  private isStreamingTool(tool: any): boolean {
        const streamingPatterns = [
            /stream/i,
            /video/i,
            /media/i,
            /content/i,
            /asset/i,
            /conviva/i,
            /har/i
        ];

        return streamingPatterns.some(pattern =>
            pattern.test(tool.name) || pattern.test(tool.description || '')
        );
    }

  private getToolRiskLevel(tool: any): string {
        if (this.isHighRiskTool(tool)) return 'HIGH_RISK';
        if (this.isStreamingTool(tool)) return 'STREAMING';
        return 'STANDARD';
    }

  private getToolCategory(tool: any): string {
        if (this.isStreamingTool(tool)) return 'Streaming/Media';
        if (this.isHighRiskTool(tool)) return 'System/Admin';
        return 'General';
    }

  private getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
        return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    }
};