import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

// Helper functions defined outside the rule object
function isConvivaTool(tool: any): boolean {
    const convivaPatterns = [
        /conviva/i,
        /analytics/i,
        /qoe/i,
        /quality.*experience/i,
        /video.*analytics/i,
        /heartbeat/i,
        /session.*data/i
    ];

    return convivaPatterns.some(pattern =>
        pattern.test(tool.name) || pattern.test(tool.description || '')
    );
}

function hasSessionIdValidation(tool: any): boolean {
    if (!tool.inputSchema || !tool.inputSchema.properties) {
        return false;
    }

    const sessionIdField = tool.inputSchema.properties.sessionId ||
        tool.inputSchema.properties.session_id ||
        tool.inputSchema.properties.convivaSessionId;

    return sessionIdField &&
        (sessionIdField.pattern || sessionIdField.format) &&
        sessionIdField.maxLength;
}

function hasKeyValidation(content: string): boolean {
    const validationPatterns = [
        /validate.*key/i,
        /key.*validation/i,
        /verify.*key/i,
        /check.*key.*format/i
    ];

    return validationPatterns.some(pattern => pattern.test(content));
}

function checkCustomerKeyHandling(file: any, tool: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    const content = file.content;

    // Check for hardcoded customer keys
    const customerKeyPatterns = [
        /customer.*key.*=.*["'][^"']{20,}["']/i,
        /conviva.*key.*=.*["'][^"']{20,}["']/i,
        /api.*key.*=.*["'][^"']{20,}["']/i
    ];

    for (const pattern of customerKeyPatterns) {
        if (pattern.test(content)) {
            violations.push({
                ruleId: 'conviva-validation',
                severity: 'error',
                message: `Conviva tool '${tool.name}' contains hardcoded customer key`,
                file: file.path,
                evidence: 'Hardcoded Conviva customer key detected',
                fix: 'Move customer key to secure environment variables'
            });
        }
    }

    // Check for proper key validation
    if (content.toLowerCase().includes('customer') &&
        content.toLowerCase().includes('key') &&
        !hasKeyValidation(content)) {
        violations.push({
            ruleId: 'conviva-validation',
            severity: 'warning',
            message: `Conviva tool '${tool.name}' lacks customer key validation`,
            file: file.path,
            fix: 'Add customer key format validation'
        });
    }

    return violations;
}

function isAnalyticsCall(callText: string): boolean {
    const analyticsPatterns = [
        /conviva/i,
        /analytics/i,
        /track/i,
        /report/i,
        /send.*data/i,
        /heartbeat/i
    ];

    return analyticsPatterns.some(pattern => pattern.test(callText));
}

function mayContainPII(callText: string): boolean {
    const piiPatterns = [
        /email/i,
        /phone/i,
        /name/i,
        /address/i,
        /userId/i,
        /user.*id/i,
        /personal/i,
        /private/i
    ];

    return piiPatterns.some(pattern => pattern.test(callText));
}

function getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

function checkPIIInAnalytics(file: any, tool: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    if (!file.ast) return violations;

    const visitor = (node: ts.Node) => {
        if (ts.isCallExpression(node)) {
            const callText = node.getText(file.ast);

            // Check for analytics calls that might include PII
            if (isAnalyticsCall(callText) && mayContainPII(callText)) {
                violations.push({
                    ruleId: 'conviva-validation',
                    severity: 'error',
                    message: `Conviva tool '${tool.name}' may send PII in analytics data`,
                    file: file.path,
                    line: getLineNumber(file.ast, node),
                    evidence: 'Analytics call may contain personally identifiable information',
                    fix: 'Remove or hash PII before sending to Conviva'
                });
            }
        }

        ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return violations;
}

function hasFrequentAnalyticsCalls(content: string): boolean {
    const frequentCallPatterns = [
        /setinterval/i,
        /settimeout/i,
        /every.*second/i,
        /heartbeat/i,
        /periodic/i
    ];

    return frequentCallPatterns.some(pattern => pattern.test(content));
}

function checkAnalyticsRateLimit(file: any, tool: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check if analytics calls are rate limited
    const content = file.content.toLowerCase();
    const hasRateLimit = /rate.*limit|throttle|limit.*request/i.test(content);

    if (!hasRateLimit && hasFrequentAnalyticsCalls(content)) {
        violations.push({
            ruleId: 'conviva-validation',
            severity: 'warning',
            message: `Conviva tool '${tool.name}' should implement rate limiting for analytics`,
            file: file.path,
            fix: 'Add rate limiting to prevent overwhelming Conviva servers'
        });
    }

    return violations;
}

function hasInsecureConvivaConfig(file: any): boolean {
    const content = file.content.toLowerCase();
    const insecurePatterns = [
        /debug.*true/i,
        /log.*level.*debug/i,
        /verbose.*true/i,
        /test.*mode.*true/i
    ];

    return insecurePatterns.some(pattern => pattern.test(content)) &&
        content.includes('conviva');
}

function hasDebugModeEnabled(file: any): boolean {
    const content = file.content.toLowerCase();
    return /conviva.*debug.*true|debug.*conviva.*true/i.test(content);
}

function checkConvivaConfiguration(context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    const configFiles = context.sourceFiles.filter(file =>
        file.path.includes('config') ||
        file.content.toLowerCase().includes('conviva')
    );

    for (const file of configFiles) {
        // Check for insecure configuration
        if (hasInsecureConvivaConfig(file)) {
            violations.push({
                ruleId: 'conviva-validation',
                severity: 'error',
                message: 'Insecure Conviva configuration detected',
                file: file.path,
                evidence: 'Conviva configuration may expose sensitive data',
                fix: 'Secure Conviva configuration with proper access controls'
            });
        }

        // Check for debug mode in production
        if (hasDebugModeEnabled(file)) {
            violations.push({
                ruleId: 'conviva-validation',
                severity: 'warning',
                message: 'Conviva debug mode should be disabled in production',
                file: file.path,
                fix: 'Disable debug mode for production deployments'
            });
        }
    }

    return violations;
}

function hasUserConsentHandling(file: any): boolean {
    const content = file.content.toLowerCase();
    const consentPatterns = [
        /consent/i,
        /gdpr/i,
        /privacy.*agreement/i,
        /opt.*in/i,
        /analytics.*permission/i
    ];

    return consentPatterns.some(pattern => pattern.test(content));
}

function hasDataRetentionPolicy(file: any): boolean {
    const content = file.content.toLowerCase();
    const retentionPatterns = [
        /retention/i,
        /expire/i,
        /ttl/i,
        /delete.*after/i,
        /purge/i
    ];

    return retentionPatterns.some(pattern => pattern.test(content));
}

function checkConvivaPrivacy(context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for user consent handling
    const hasConsentHandling = context.sourceFiles.some(file =>
        hasUserConsentHandling(file)
    );

    if (!hasConsentHandling) {
        context.sourceFiles.forEach(file => {
            violations.push({
                ruleId: 'conviva-validation',
                severity: 'warning',
                message: 'No user consent handling found for Conviva analytics',
                fix: 'Implement user consent collection before sending analytics data',
                file: file.path,
                evidence: `File content: ${file.content.slice(0, 100)}...`
            });
        });
    }

    // Check for data retention policies
    const hasDataRetention = context.sourceFiles.some(file =>
        hasDataRetentionPolicy(file)
    );

    if (!hasDataRetention) {
        violations.push({
            ruleId: 'conviva-validation',
            severity: 'info',
            message: 'No data retention policy found for Conviva data',
            fix: 'Document and implement data retention policies for analytics'
        });
    }

    return violations;
}

async function checkConvivaToolSecurity(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    // Check for proper session ID validation
    if (!hasSessionIdValidation(tool)) {
        violations.push({
            ruleId: 'conviva-validation',
            severity: 'error',
            message: `Conviva tool '${tool.name}' lacks session ID validation`,
            evidence: 'Session ID validation required for Conviva integration',
            fix: 'Add session ID format validation and sanitization',
            file: implFile?.path
        });
    }

    // Check for customer key protection
    const implFile = context.sourceFiles.find(file =>
        file.content.includes(tool.name)
    );

    if (implFile) {
        const keyViolations = checkCustomerKeyHandling(implFile, tool);
        violations.push(...keyViolations);

        // Check for PII in analytics data
        const piiViolations = checkPIIInAnalytics(implFile, tool);
        violations.push(...piiViolations);

        // Check for rate limiting on analytics calls
        const rateLimitViolations = checkAnalyticsRateLimit(implFile, tool);
        violations.push(...rateLimitViolations);
    }

    return violations;
}

// The actual rule object - only contains the required interface properties
export const convivaValidation: MCPSecurityRule = {
    id: 'conviva-validation',
    name: 'Conviva Integration Security',
    description: 'Ensures secure Conviva analytics integration for Fox Corp streaming',
    severity: 'warning',
    category: 'fox-streaming',
    mandatory: false,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        if (!context.config.foxCorp?.convivaIntegration) {
            return violations;
        }

        // Check for Conviva-related tools
        const convivaTools = context.mcpServer.tools.filter(tool =>
            isConvivaTool(tool)
        );

        for (const tool of convivaTools) {
            const toolViolations = await checkConvivaToolSecurity(tool, context);
            violations.push(...toolViolations);
        }

        // Check for Conviva configuration security
        const configViolations = checkConvivaConfiguration(context);
        violations.push(...configViolations);

        // Check for data privacy compliance
        const privacyViolations = checkConvivaPrivacy(context);
        violations.push(...privacyViolations);

        return violations;
    }
};