import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

export const resourceAccess: MCPSecurityRule = {
    id: 'resource-access',
    name: 'Resource Access Control',
    description: 'Validates proper access controls for MCP resources and sensitive data',
    severity: 'warning',
    category: 'authorization',
    mandatory: false,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check MCP resources for proper access controls
        for (const resource of context.mcpServer.resources || []) {
            const resourceViolations = await this.checkResourceAccess(resource, context);
            violations.push(...resourceViolations);
        }

        // Check for file system access controls
        const fileViolations = this.checkFileSystemAccess(context);
        violations.push(...fileViolations);

        // Check for database access controls
        const dbViolations = this.checkDatabaseAccess(context);
        violations.push(...dbViolations);

        // Check for network resource access
        const networkViolations = this.checkNetworkAccess(context);
        violations.push(...networkViolations);

        // Fox Corp specific: streaming resource protection
        if (context.config.foxCorp?.streamingAssets) {
            const streamingViolations = this.checkStreamingResourceAccess(context);
            violations.push(...streamingViolations);
        }

        return violations;
    }

  private async checkResourceAccess(resource: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check if resource has access control metadata
        if (!resource.accessControl && !resource.permissions) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'warning',
                message: `Resource '${resource.name}' lacks access control configuration`,
                evidence: `Resource: ${resource.name}, URI: ${resource.uri}`,
                fix: 'Add accessControl or permissions configuration to resource'
            });
        }

        // Check for sensitive resource patterns
        if (this.isSensitiveResource(resource)) {
            if (!resource.accessControl || resource.accessControl.level !== 'restricted') {
                violations.push({
                    ruleId: 'resource-access',
                    severity: 'error',
                    message: `Sensitive resource '${resource.name}' requires restricted access`,
                    evidence: `Resource type: ${this.getResourceType(resource)}`,
                    fix: 'Set accessControl.level to "restricted" for sensitive resources'
                });
            }
        }

        // Check resource URI for security issues
        const uriViolations = this.validateResourceURI(resource);
        violations.push(...uriViolations);

        // Check for resource implementation security
        const implViolations = await this.checkResourceImplementation(resource, context);
        violations.push(...implViolations);

        return violations;
    }

 private isSensitiveResource(resource: any): boolean {
        const sensitivePatterns = [
            /config/i,
            /secret/i,
            /key/i,
            /credential/i,
            /password/i,
            /token/i,
            /user/i,
            /admin/i,
            /private/i,
            /internal/i,
            /stream/i,
            /media/i,
            /content/i
        ];

        return sensitivePatterns.some(pattern =>
            pattern.test(resource.name) ||
            pattern.test(resource.uri) ||
            pattern.test(resource.type || '')
        );
    }

 private getResourceType(resource: any): string {
        if (resource.uri.includes('file://')) return 'file';
        if (resource.uri.includes('http://') || resource.uri.includes('https://')) return 'web';
        if (resource.uri.includes('db://') || resource.uri.includes('database://')) return 'database';
        if (resource.uri.includes('stream://')) return 'streaming';
        return 'unknown';
    }

 private validateResourceURI(resource: any): RuleViolation[] {
        const violations: RuleViolation[] = [];
        const uri = resource.uri;

        // Check for insecure protocols
        if (uri.startsWith('http://')) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'warning',
                message: `Resource '${resource.name}' uses insecure HTTP protocol`,
                evidence: `URI: ${uri}`,
                fix: 'Use HTTPS instead of HTTP for secure communication'
            });
        }

        // Check for localhost/internal URIs that might be exposed
        if (this.isInternalURI(uri) && !this.hasProperInternalAccess(resource)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'error',
                message: `Resource '${resource.name}' exposes internal URI without proper access control`,
                evidence: `Internal URI: ${uri}`,
                fix: 'Add proper access controls for internal resources'
            });
        }

        // Check for path traversal vulnerabilities in file URIs
        if (uri.includes('file://') && this.hasPathTraversal(uri)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'error',
                message: `Resource '${resource.name}' URI contains path traversal patterns`,
                evidence: `URI: ${uri}`,
                fix: 'Remove path traversal patterns (../) from resource URI'
            });
        }

        // Check for hardcoded credentials in URI
        if (this.hasCredentialsInURI(uri)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'error',
                message: `Resource '${resource.name}' URI contains embedded credentials`,
                evidence: 'Credentials detected in URI',
                fix: 'Remove credentials from URI and use proper authentication'
            });
        }

        return violations;
    }

 private isInternalURI(uri: string): boolean {
        const internalPatterns = [
            /localhost/i,
            /127\.0\.0\.1/,
            /192\.168\./,
            /10\./,
            /172\.(1[6-9]|2[0-9]|3[01])\./,
            /internal/i,
            /private/i
        ];

        return internalPatterns.some(pattern => pattern.test(uri));
    }

 private hasProperInternalAccess(resource: any): boolean {
        return resource.accessControl &&
            (resource.accessControl.level === 'restricted' ||
                resource.accessControl.internal === true);
    }

 private hasPathTraversal(uri: string): boolean {
        const traversalPatterns = [
            /\.\.\//,
            /\.\.\\/,
            /%2e%2e%2f/i,
            /%2e%2e%5c/i
        ];

        return traversalPatterns.some(pattern => pattern.test(uri));
    }

 private hasCredentialsInURI(uri: string): boolean {
        const credentialPatterns = [
            /:\/\/[^:@]+:[^@]+@/,  // username:password@
            /api[_-]?key=/i,
            /token=/i,
            /secret=/i,
            /password=/i
        ];

        return credentialPatterns.some(pattern => pattern.test(uri));
    }

 private async checkResourceImplementation(resource: any, context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Find files that handle this resource
        const resourceFiles = context.sourceFiles.filter(file =>
            file.content.includes(resource.name) ||
            file.content.includes(resource.uri)
        );

        for (const file of resourceFiles) {
            if (!file.ast) continue;

            // Check for access control in implementation
            const hasAccessCheck = this.hasAccessControlCheck(file);
            if (!hasAccessCheck) {
                violations.push({
                    ruleId: 'resource-access',
                    severity: 'warning',
                    message: `Resource '${resource.name}' implementation lacks access control checks`,
                    file: file.path,
                    fix: 'Add access control validation in resource handler'
                });
            }

            // Check for proper error handling
            const hasSecureErrorHandling = this.hasSecureErrorHandling(file);
            if (!hasSecureErrorHandling) {
                violations.push({
                    ruleId: 'resource-access',
                    severity: 'warning',
                    message: `Resource '${resource.name}' may leak information through error messages`,
                    file: file.path,
                    fix: 'Implement secure error handling that does not expose sensitive information'
                });
            }
        }

        return violations;
    }

 private checkFileSystemAccess(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        for (const file of context.sourceFiles) {
            if (!file.ast) continue;

            const visitor = (node: ts.Node) => {
                if (ts.isCallExpression(node)) {
                    const callText = node.getText(file.ast);

                    // Check for file system operations
                    if (this.isFileSystemOperation(callText)) {
                        const fsViolations = this.analyzeFileSystemCall(node, file, callText);
                        violations.push(...fsViolations);
                    }
                }

                ts.forEachChild(node, visitor);
            };

            visitor(file.ast);
        }

        return violations;
    }

 private isFileSystemOperation(callText: string): boolean {
        const fsPatterns = [
            /fs\.(read|write|unlink|mkdir|rmdir)/,
            /readFile/,
            /writeFile/,
            /createReadStream/,
            /createWriteStream/,
            /path\.join/,
            /path\.resolve/
        ];

        return fsPatterns.some(pattern => pattern.test(callText));
    }

 private analyzeFileSystemCall(node: ts.CallExpression, file: any, callText: string): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for path validation
        if (!this.hasPathValidation(callText, file)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'error',
                message: 'File system operation lacks path validation',
                file: file.path,
                line: this.getLineNumber(file.ast, node),
                evidence: `Operation: ${callText.substring(0, 50)}...`,
                fix: 'Add path validation to prevent directory traversal'
            });
        }

        // Check for write operations to sensitive directories
        if (this.isWriteToSensitiveDirectory(callText)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'error',
                message: 'Write operation to sensitive directory detected',
                file: file.path,
                line: this.getLineNumber(file.ast, node),
                evidence: `Write operation: ${callText}`,
                fix: 'Restrict write access to safe directories only'
            });
        }

        return violations;
    }

 private hasPathValidation(callText: string, file: any): boolean {
        // Look for path validation in surrounding context
        const context = this.getCallContext(callText, file);
        const validationPatterns = [
            /validate.*path/i,
            /sanitize.*path/i,
            /path\.normalize/,
            /path\.resolve/,
            /allowlist/i,
            /whitelist/i
        ];

        return validationPatterns.some(pattern => pattern.test(context));
    }

 private getCallContext(callText: string, file: any): string {
        const callIndex = file.content.indexOf(callText);
        const start = Math.max(0, callIndex - 200);
        const end = Math.min(file.content.length, callIndex + 200);
        return file.content.substring(start, end);
    }

 private isWriteToSensitiveDirectory(callText: string): boolean {
        const sensitivePatterns = [
            /\/etc\//,
            /\/root\//,
            /\/var\/log\//,
            /\/usr\/bin\//,
            /C:\\Windows\\System32/i,
            /C:\\Program Files/i
        ];

        return sensitivePatterns.some(pattern => pattern.test(callText));
    }

 private checkDatabaseAccess(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        for (const file of context.sourceFiles) {
            if (!file.ast) continue;

            const visitor = (node: ts.Node) => {
                if (ts.isCallExpression(node)) {
                    const callText = node.getText(file.ast);

                    // Check for database operations
                    if (this.isDatabaseOperation(callText)) {
                        const dbViolations = this.analyzeDatabaseCall(node, file, callText);
                        violations.push(...dbViolations);
                    }
                }

                ts.forEachChild(node, visitor);
            };

            visitor(file.ast);
        }

        return violations;
    }

 private isDatabaseOperation(callText: string): boolean {
        const dbPatterns = [
            /\.query\(/,
            /\.execute\(/,
            /\.find\(/,
            /\.create\(/,
            /\.update\(/,
            /\.delete\(/,
            /\.remove\(/,
            /SELECT.*FROM/i,
            /INSERT.*INTO/i,
            /UPDATE.*SET/i,
            /DELETE.*FROM/i
        ];

        return dbPatterns.some(pattern => pattern.test(callText));
    }

 private analyzeDatabaseCall(node: ts.CallExpression, file: any, callText: string): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for parameterized queries
        if (this.isRawSQLQuery(callText) && !this.isParameterized(callText)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'error',
                message: 'Database query appears to use string concatenation instead of parameters',
                file: file.path,
                line: this.getLineNumber(file.ast, node),
                evidence: `Query: ${callText.substring(0, 50)}...`,
                fix: 'Use parameterized queries to prevent SQL injection'
            });
        }

        // Check for access control in database operations
        if (!this.hasDBAccessControl(callText, file)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'warning',
                message: 'Database operation lacks access control validation',
                file: file.path,
                line: this.getLineNumber(file.ast, node),
                evidence: `Operation: ${callText.substring(0, 50)}...`,
                fix: 'Add user/role validation before database operations'
            });
        }

        return violations;
    }

 private isRawSQLQuery(callText: string): boolean {
        const sqlPatterns = [
            /SELECT.*FROM/i,
            /INSERT.*INTO/i,
            /UPDATE.*SET/i,
            /DELETE.*FROM/i
        ];

        return sqlPatterns.some(pattern => pattern.test(callText));
    }

 private isParameterized(callText: string): boolean {
        const paramPatterns = [
            /\$\d+/,  // PostgreSQL style $1, $2
            /\?/,     // MySQL/SQLite style ?
            /:\w+/    // Named parameters :param
        ];

        return paramPatterns.some(pattern => pattern.test(callText));
    }

 private hasDBAccessControl(callText: string, file: any): boolean {
        const context = this.getCallContext(callText, file);
        const accessPatterns = [
            /check.*permission/i,
            /user.*id/i,
            /role/i,
            /authorize/i,
            /access.*control/i
        ];

        return accessPatterns.some(pattern => pattern.test(context));
    }

 private checkNetworkAccess(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        for (const file of context.sourceFiles) {
            if (!file.ast) continue;

            const visitor = (node: ts.Node) => {
                if (ts.isCallExpression(node)) {
                    const callText = node.getText(file.ast);

                    // Check for network operations
                    if (this.isNetworkOperation(callText)) {
                        const netViolations = this.analyzeNetworkCall(node, file, callText);
                        violations.push(...netViolations);
                    }
                }

                ts.forEachChild(node, visitor);
            };

            visitor(file.ast);
        }

        return violations;
    }

 private isNetworkOperation(callText: string): boolean {
        const networkPatterns = [
            /fetch\(/,
            /axios\./,
            /http\./,
            /https\./,
            /request\(/,
            /get\(/,
            /post\(/,
            /put\(/,
            /delete\(/
        ];

        return networkPatterns.some(pattern => pattern.test(callText));
    }

 private analyzeNetworkCall(node: ts.CallExpression, file: any, callText: string): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for URL validation
        if (!this.hasURLValidation(callText, file)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'warning',
                message: 'Network request lacks URL validation',
                file: file.path,
                line: this.getLineNumber(file.ast, node),
                evidence: `Request: ${callText.substring(0, 50)}...`,
                fix: 'Add URL validation and allowlist checking'
            });
        }

        // Check for SSRF protection
        if (this.maybeSSRFVulnerable(callText)) {
            violations.push({
                ruleId: 'resource-access',
                severity: 'error',
                message: 'Potential SSRF vulnerability in network request',
                file: file.path,
                line: this.getLineNumber(file.ast, node),
                evidence: `Potential SSRF: ${callText}`,
                fix: 'Implement SSRF protection with URL allowlists and internal IP blocking'
            });
        }

        return violations;
    }

 private hasURLValidation(callText: string, file: any): boolean {
        const context = this.getCallContext(callText, file);
        const validationPatterns = [
            /validate.*url/i,
            /allowlist/i,
            /whitelist/i,
            /url.*parse/i,
            /url.*validate/i
        ];

        return validationPatterns.some(pattern => pattern.test(context));
    }

 private maybeSSRFVulnerable(callText: string): boolean {
        // Check if URL comes from user input without validation
        const userInputPatterns = [
            /params\./,
            /request\./,
            /args\./,
            /input\./
        ];

        return userInputPatterns.some(pattern => pattern.test(callText));
    }

 private checkStreamingResourceAccess(context: AnalysisContext): RuleViolation[] {
        const violations: RuleViolation[] = [];

        // Check for streaming-specific resources
        const streamingResources = context.mcpServer.resources?.filter(resource =>
            this.isStreamingResource(resource)
        ) || [];

        for (const resource of streamingResources) {
            // Streaming resources must have DRM protection
            if (!this.hasDRMProtection(resource)) {
                violations.push({
                    ruleId: 'resource-access',
                    severity: 'error',
                    message: `Streaming resource '${resource.name}' lacks DRM protection`,
                    evidence: `Resource: ${resource.name}, Type: streaming`,
                    fix: 'Implement DRM protection for streaming content'
                });
            }

            // Streaming resources must have geo-blocking
            if (!this.hasGeoBlocking(resource)) {
                violations.push({
                    ruleId: 'resource-access',
                    severity: 'warning',
                    message: `Streaming resource '${resource.name}' lacks geo-blocking`,
                    evidence: `Resource: ${resource.name}`,
                    fix: 'Implement geo-blocking for content licensing compliance'
                });
            }

            // Check for content watermarking
            if (!this.hasWatermarking(resource)) {
                violations.push({
                    ruleId: 'resource-access',
                    severity: 'warning',
                    message: `Streaming resource '${resource.name}' lacks watermarking`,
                    evidence: `Resource: ${resource.name}`,
                    fix: 'Add content watermarking for piracy protection'
                });
            }
        }

        return violations;
    }

 private isStreamingResource(resource: any): boolean {
        const streamingPatterns = [
            /stream/i,
            /video/i,
            /media/i,
            /content/i,
            /\.m3u8$/,
            /\.mpd$/,
            /hls/i,
            /dash/i
        ];

        return streamingPatterns.some(pattern =>
            pattern.test(resource.name) ||
            pattern.test(resource.uri) ||
            pattern.test(resource.type || '')
        );
    }

 private hasDRMProtection(resource: any): boolean {
        const drmPatterns = [
            /drm/i,
            /fairplay/i,
            /widevine/i,
            /playready/i,
            /encrypted/i,
            /protection/i
        ];

        const resourceText = JSON.stringify(resource).toLowerCase();
        return drmPatterns.some(pattern => pattern.test(resourceText));
    }

 private hasGeoBlocking(resource: any): boolean {
        const geoPatterns = [
            /geo/i,
            /region/i,
            /country/i,
            /location/i,
            /territory/i,
            /block/i
        ];

        const resourceText = JSON.stringify(resource).toLowerCase();
        return geoPatterns.some(pattern => pattern.test(resourceText));
    }

 private hasWatermarking(resource: any): boolean {
        const watermarkPatterns = [
            /watermark/i,
            /forensic/i,
            /session.*id/i,
            /user.*id/i
        ];

        const resourceText = JSON.stringify(resource).toLowerCase();
        return watermarkPatterns.some(pattern => pattern.test(resourceText));
    }

 private hasAccessControlCheck(file: any): boolean {
        const content = file.content.toLowerCase();
        const accessPatterns = [
            /check.*access/i,
            /verify.*permission/i,
            /authorize/i,
            /permission.*check/i,
            /access.*control/i,
            /can.*access/i
        ];

        return accessPatterns.some(pattern => pattern.test(content));
    }

 private hasSecureErrorHandling(file: any): boolean {
        const content = file.content.toLowerCase();
        const secureErrorPatterns = [
            /generic.*error/i,
            /sanitize.*error/i,
            /safe.*error/i,
            /error.*message.*filter/i
        ];

        const insecureErrorPatterns = [
            /stack.*trace/i,
            /error\.stack/i,
            /throw.*error/i,
            /console\.error/i
        ];

        const hasSecure = secureErrorPatterns.some(pattern => pattern.test(content));
        const hasInsecure = insecureErrorPatterns.some(pattern => pattern.test(content));

        return hasSecure && !hasInsecure;
    }

 private getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
        return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    }
};