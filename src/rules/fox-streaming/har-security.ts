import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

// Helper functions defined outside the rule object
function isHARTool(tool: any): boolean {
    const harPatterns = [
        /har/i,
        /http.*archive/i,
        /network.*capture/i,
        /traffic.*analysis/i,
        /performance.*analysis/i,
        /browser.*capture/i
    ];

    return harPatterns.some(pattern =>
        pattern.test(tool.name) || pattern.test(tool.description || '')
    );
}

function hasFileSizeValidation(tool: any): boolean {
    if (!tool.inputSchema || !tool.inputSchema.properties) {
        return false;
    }

    // Check for file size limits in schema
    const fileProperties = Object.values(tool.inputSchema.properties).filter((prop: any) =>
        prop.type === 'string' &&
        (prop.format === 'binary' || prop.maxLength)
    );

    return fileProperties.some((prop: any) =>
        prop.maxLength && prop.maxLength <= 52428800 // 50MB
    );
}

function hasContentValidation(tool: any): boolean {
    if (!tool.inputSchema || !tool.inputSchema.properties) {
        return false;
    }

    // Check for HAR schema validation
    const harProperties = Object.values(tool.inputSchema.properties).filter((prop: any) =>
        prop.type === 'object' &&
        (prop.properties || prop.$ref)
    );

    return harProperties.length > 0;
}

function hasSensitiveDataFiltering(tool: any): boolean {
    // This would typically be checked in implementation
    // For now, check if tool description mentions filtering
    const description = tool.description || '';
    const filteringKeywords = [
        'filter',
        'sanitize',
        'clean',
        'remove',
        'redact',
        'mask'
    ];

    return filteringKeywords.some(keyword =>
        description.toLowerCase().includes(keyword)
    );
}

function isUnsafeJSONParsing(callText: string): boolean {
    return /JSON\.parse\(/i.test(callText) &&
        !/validate|check|limit|safe/i.test(callText);
}

function isSensitiveDataAccess(callText: string): boolean {
    const sensitivePatterns = [
        /headers/i,
        /cookies/i,
        /authorization/i,
        /authentication/i,
        /token/i,
        /password/i,
        /session/i
    ];

    return sensitivePatterns.some(pattern => pattern.test(callText));
}

function isFileSystemOperation(callText: string): boolean {
    const fileOpPatterns = [
        /fs\./,
        /readFile/i,
        /writeFile/i,
        /createWriteStream/i,
        /createReadStream/i
    ];

    return fileOpPatterns.some(pattern => pattern.test(callText));
}

function isCredentialAccess(propAccess: string): boolean {
    const credentialPatterns = [
        /\.authorization/i,
        /\.cookie/i,
        /\.token/i,
        /\.password/i,
        /\.secret/i,
        /\.key/i,
        /\.auth/i
    ];

    return credentialPatterns.some(pattern => pattern.test(propAccess));
}

function getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

function hasMemoryIssues(file: any): boolean {
    const content = file.content.toLowerCase();
    return content.includes('json.parse') &&
        !content.includes('stream') &&
        !content.includes('chunk');
}

function hasSynchronousProcessing(file: any): boolean {
    const content = file.content.toLowerCase();
    const syncPatterns = [
        /readfilesync/i,
        /json\.parse.*\)/,
        /while.*\(/,
        /for.*\(/
    ];

    return syncPatterns.some(pattern => pattern.test(content)) &&
        content.includes('har');
}

function hasProperErrorHandling(file: any): boolean {
    const content = file.content.toLowerCase();
    const errorPatterns = [
        /try.*catch/,
        /catch.*error/,
        /error.*handling/,
        /\.catch\(/
    ];

    return errorPatterns.some(pattern => pattern.test(content));
}

function hasCredentialLogging(file: any): boolean {
    const content = file.content.toLowerCase();
    return (content.includes('log') || content.includes('console')) &&
        (content.includes('authorization') ||
            content.includes('cookie') ||
            content.includes('token'));
}

function hasPIIExposure(file: any): boolean {
    const content = file.content.toLowerCase();
    const piiPatterns = [
        /email/i,
        /phone/i,
        /address/i,
        /name/i,
        /userid/i,
        /ssn/i
    ];

    return piiPatterns.some(pattern => pattern.test(content)) &&
        content.includes('har');
}

function hasInsecureDataStorage(file: any): boolean {
    const content = file.content.toLowerCase();
    const storagePatterns = [
        /localstorage/i,
        /sessionstorage/i,
        /cookie/i,
        /filesystem/i,
        /temp/i
    ];

    return storagePatterns.some(pattern => pattern.test(content)) &&
        content.includes('har') &&
        !content.includes('encrypt');
}

async function checkHARImplementation(file: any, tool: any): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    if (!file.ast) return violations;

    const visitor = (node: ts.Node) => {
        // Check for HAR parsing
        if (ts.isCallExpression(node)) {
            const callText = node.getText(file.ast);

            // Check for unsafe JSON parsing
            if (isUnsafeJSONParsing(callText)) {
                violations.push({
                    ruleId: 'har-security',
                    severity: 'error',
                    message: `HAR tool '${tool.name}' uses unsafe JSON parsing`,
                    file: file.path,
                    line: getLineNumber(file.ast, node),
                    evidence: 'JSON.parse without validation can be dangerous',
                    fix: 'Use safe JSON parsing with size limits and validation'
                });
            }

            // Check for sensitive data handling
            if (isSensitiveDataAccess(callText)) {
                violations.push({
                    ruleId: 'har-security',
                    severity: 'warning',
                    message: `HAR tool '${tool.name}' accesses sensitive HAR data`,
                    file: file.path,
                    line: getLineNumber(file.ast, node),
                    evidence: 'Accessing headers or cookies without filtering',
                    fix: 'Filter sensitive data before processing'
                });
            }

            // Check for file system operations
            if (isFileSystemOperation(callText)) {
                violations.push({
                    ruleId: 'har-security',
                    severity: 'error',
                    message: `HAR tool '${tool.name}' performs file system operations`,
                    file: file.path,
                    line: getLineNumber(file.ast, node),
                    evidence: 'File operations should be restricted for HAR processing',
                    fix: 'Use memory-only HAR processing or secure file handling'
                });
            }
        }

        // Check for credential exposure
        if (ts.isPropertyAccessExpression(node)) {
            const propAccess = node.getText(file.ast);
            if (isCredentialAccess(propAccess)) {
                violations.push({
                    ruleId: 'har-security',
                    severity: 'error',
                    message: `HAR tool '${tool.name}' may expose credentials`,
                    file: file.path,
                    line: getLineNumber(file.ast, node),
                    evidence: `Accessing: ${propAccess}`,
                    fix: 'Filter credentials from HAR data before processing'
                });
            }
        }

        ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return violations;
}

async function checkHARToolSecurity(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    // Check for file size validation
    if (!hasFileSizeValidation(tool)) {
        violations.push({
            ruleId: 'har-security',
            severity: 'error',
            message: `HAR tool '${tool.name}' lacks file size validation`,
            evidence: 'HAR files can be very large and cause DoS',
            fix: 'Add file size limits (max 50MB) for HAR uploads'
        });
    }

    // Check for content validation
    if (!hasContentValidation(tool)) {
        violations.push({
            ruleId: 'har-security',
            severity: 'error',
            message: `HAR tool '${tool.name}' lacks content validation`,
            evidence: 'HAR files must be validated for malicious content',
            fix: 'Add JSON schema validation for HAR file structure'
        });
    }

    // Check for sensitive data filtering
    if (!hasSensitiveDataFiltering(tool)) {
        violations.push({
            ruleId: 'har-security',
            severity: 'error',
            message: `HAR tool '${tool.name}' lacks sensitive data filtering`,
            evidence: 'HAR files may contain cookies, tokens, and passwords',
            fix: 'Implement filtering to remove sensitive headers and data'
        });
    }

    // Check implementation
    const implFile = context.sourceFiles.find(file =>
        file.content.includes(tool.name)
    );

    if (implFile) {
        const implViolations = await checkHARImplementation(implFile, tool);
        violations.push(...implViolations);
    }

    return violations;
}

function checkHARFileHandling(context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for HAR file processing in source files
    const harFiles = context.sourceFiles.filter(file =>
        file.content.toLowerCase().includes('har') ||
        file.content.toLowerCase().includes('http archive')
    );

    for (const file of harFiles) {
        // Check for memory usage concerns
        if (hasMemoryIssues(file)) {
            violations.push({
                ruleId: 'har-security',
                severity: 'warning',
                message: 'HAR processing may have memory usage issues',
                file: file.path,
                evidence: 'Large HAR files can cause memory exhaustion',
                fix: 'Implement streaming HAR processing for large files'
            });
        }

        // Check for synchronous processing
        if (hasSynchronousProcessing(file)) {
            violations.push({
                ruleId: 'har-security',
                severity: 'warning',
                message: 'HAR processing should be asynchronous',
                file: file.path,
                evidence: 'Synchronous HAR processing can block the event loop',
                fix: 'Use asynchronous HAR processing methods'
            });
        }

        // Check for error handling
        if (!hasProperErrorHandling(file)) {
            violations.push({
                ruleId: 'har-security',
                severity: 'error',
                message: 'HAR processing lacks proper error handling',
                file: file.path,
                fix: 'Add comprehensive error handling for HAR parsing failures'
            });
        }
    }

    return violations;
}

function checkHARDataSecurity(context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for sensitive data patterns in HAR-related code
    const harFiles = context.sourceFiles.filter(file =>
        file.content.toLowerCase().includes('har')
    );

    for (const file of harFiles) {
        // Check for credential logging
        if (hasCredentialLogging(file)) {
            violations.push({
                ruleId: 'har-security',
                severity: 'error',
                message: 'HAR processing may log sensitive credentials',
                file: file.path,
                evidence: 'Credentials from HAR files should not be logged',
                fix: 'Filter credentials before logging HAR data'
            });
        }

        // Check for PII exposure
        if (hasPIIExposure(file)) {
            violations.push({
                ruleId: 'har-security',
                severity: 'error',
                message: 'HAR processing may expose personally identifiable information',
                file: file.path,
                evidence: 'PII in HAR files must be protected',
                fix: 'Implement PII filtering and anonymization'
            });
        }

        // Check for data storage security
        if (hasInsecureDataStorage(file)) {
            violations.push({
                ruleId: 'har-security',
                severity: 'error',
                message: 'HAR data stored insecurely',
                file: file.path,
                evidence: 'HAR files contain sensitive network data',
                fix: 'Encrypt HAR data at rest and implement access controls'
            });
        }
    }

    return violations;
}

// The actual rule object - only contains the required interface properties
export const harSecurity: MCPSecurityRule = {
    id: 'har-security',
    name: 'HAR File Security Validation',
    description: 'Ensures secure handling of HTTP Archive (HAR) files for Fox Corp network analysis',
    severity: 'error',
    category: 'fox-streaming',
    mandatory: true,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        if (!context.config.foxCorp?.harValidation) {
            return violations;
        }

        // Check for HAR-related tools
        const harTools = context.mcpServer.tools.filter(tool =>
            isHARTool(tool)
        );

        for (const tool of harTools) {
            const toolViolations = await checkHARToolSecurity(tool, context);
            violations.push(...toolViolations);
        }

        // Check for HAR file handling security
        const fileViolations = checkHARFileHandling(context);
        violations.push(...fileViolations);

        // Check for sensitive data exposure in HAR files
        const dataViolations = checkHARDataSecurity(context);
        violations.push(...dataViolations);

        return violations;
    }
};