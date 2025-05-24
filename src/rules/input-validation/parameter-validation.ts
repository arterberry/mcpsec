import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

// Helper functions defined outside the rule object
function getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

function isDangerousEnumValue(value: string): boolean {
    const dangerousPatterns = [
        /\.\./,           // Path traversal
        /script/i,        // Script injection
        /javascript:/i,   // JavaScript protocol
        /data:/i,         // Data URLs
        /eval/i,          // Eval function
        /function/i,      // Function definitions
        /__proto__/,      // Prototype pollution
        /constructor/     // Constructor access
    ];

    return dangerousPatterns.some(pattern => pattern.test(value));
}

function isSensitiveField(fieldName: string): boolean {
    const sensitivePatterns = [
        /password/i,
        /secret/i,
        /token/i,
        /key/i,
        /credential/i,
        /auth/i,
        /email/i,
        /phone/i,
        /ssn/i,
        /credit/i
    ];

    return sensitivePatterns.some(pattern => pattern.test(fieldName));
}

function needsFormatValidation(fieldName: string): boolean {
    const formatFields = [
        { pattern: /email/i, format: 'email' },
        { pattern: /url|uri/i, format: 'uri' },
        { pattern: /date/i, format: 'date-time' },
        { pattern: /time/i, format: 'time' },
        { pattern: /uuid/i, format: 'uuid' },
        { pattern: /ip/i, format: 'ipv4' }
    ];

    return formatFields.some(field => field.pattern.test(fieldName));
}

function shouldBePositive(fieldName: string): boolean {
    const positivePatterns = [
        /count/i,
        /size/i,
        /length/i,
        /width/i,
        /height/i,
        /duration/i,
        /timeout/i,
        /limit/i,
        /max/i,
        /quantity/i
    ];

    return positivePatterns.some(pattern => pattern.test(fieldName));
}

function isStreamingTool(tool: any): boolean {
    const streamingPatterns = [
        /stream/i,
        /video/i,
        /media/i,
        /content/i,
        /asset/i
    ];

    return streamingPatterns.some(pattern =>
        pattern.test(tool.name) || pattern.test(tool.description || '')
    );
}

function isConvivaTool(tool: any): boolean {
    const convivaPatterns = [
        /conviva/i,
        /analytics/i,
        /metrics/i,
        /qoe/i
    ];

    return convivaPatterns.some(pattern =>
        pattern.test(tool.name) || pattern.test(tool.description || '')
    );
}

function isHARTool(tool: any): boolean {
    const harPatterns = [
        /har/i,
        /http.*archive/i,
        /network.*capture/i
    ];

    return harPatterns.some(pattern =>
        pattern.test(tool.name) || pattern.test(tool.description || '')
    );
}

function hasStreamIdValidation(streamIdSchema: any): boolean {
    return streamIdSchema.pattern &&
        (streamIdSchema.pattern.includes('fox') || streamIdSchema.pattern.includes('[a-zA-Z0-9-]+'));
}

function hasContentTypeValidation(contentTypeSchema: any): boolean {
    return contentTypeSchema.enum &&
        contentTypeSchema.enum.some((type: string) =>
            ['live', 'vod', 'sports', 'news'].includes(type.toLowerCase())
        );
}

function hasAssetUrlValidation(assetUrlSchema: any): boolean {
    return assetUrlSchema.pattern &&
        (assetUrlSchema.pattern.includes('fox') || assetUrlSchema.pattern.includes('\.fox\.'));
}

function hasSessionIdValidation(sessionIdSchema: any): boolean {
    return sessionIdSchema.pattern && sessionIdSchema.pattern.length > 10;
}

function hasMetricNameValidation(metricNameSchema: any): boolean {
    return metricNameSchema.enum && metricNameSchema.enum.length > 0;
}

function hasHARSizeValidation(harSchema: any): boolean {
    return harSchema.maxLength && harSchema.maxLength <= 10000000; // 10MB limit
}

function hasHARFormatValidation(harSchema: any): boolean {
    return harSchema.type === 'object' && harSchema.properties;
}

function hasValidationLibraryUsage(file: any): boolean {
    const content = file.content.toLowerCase();
    const validationLibraries = [
        /joi\./,
        /yup\./,
        /ajv/,
        /validator\./,
        /express-validator/,
        /class-validator/,
        /validate\(/
    ];

    return validationLibraries.some(lib => lib.test(content));
}

function hasSchemaValidation(file: any): boolean {
    const content = file.content.toLowerCase();
    const validationPatterns = [
        /validate.*schema/,
        /schema.*validate/,
        /validate.*input/,
        /input.*validate/,
        /validate.*param/,
        /param.*validate/,
        /check.*schema/,
        /schema.*check/
    ];

    return validationPatterns.some(pattern => pattern.test(content));
}

function hasValidationErrorHandling(file: any): boolean {
    const content = file.content.toLowerCase();
    const errorPatterns = [
        /validation.*error/,
        /invalid.*param/,
        /param.*error/,
        /400/,  // Bad Request status
        /bad.*request/,
        /invalid.*input/
    ];

    return errorPatterns.some(pattern => pattern.test(content));
}

function findDuplicateSchemas(schemas: any[]): any[] {
    const schemaStrings = schemas.map(schema => JSON.stringify(schema));
    const duplicates: any[] = [];
    const seen = new Set();

    for (const schemaString of schemaStrings) {
        if (seen.has(schemaString)) {
            duplicates.push(schemaString);
        } else {
            seen.add(schemaString);
        }
    }

    return duplicates;
}

function validatePropertySchema(toolName: string, propName: string, propSchema: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for missing type
    if (!propSchema.type) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Tool '${toolName}' parameter '${propName}' lacks type definition`,
            evidence: `Parameter: ${propName}`,
            fix: 'Add type definition to parameter schema'
        });
    }

    // Check for string validation rules
    if (propSchema.type === 'string') {
        const stringViolations = validateStringSchema(toolName, propName, propSchema);
        violations.push(...stringViolations);
    }

    // Check for number validation rules
    if (propSchema.type === 'number' || propSchema.type === 'integer') {
        const numberViolations = validateNumberSchema(toolName, propName, propSchema);
        violations.push(...numberViolations);
    }

    // Check for array validation rules
    if (propSchema.type === 'array') {
        const arrayViolations = validateArraySchema(toolName, propName, propSchema);
        violations.push(...arrayViolations);
    }

    // Check for object validation rules
    if (propSchema.type === 'object') {
        const objectViolations = validateObjectSchema(toolName, propName, propSchema);
        violations.push(...objectViolations);
    }

    return violations;
}

function validateStringSchema(toolName: string, propName: string, propSchema: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for length constraints
    if (!propSchema.maxLength) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' string parameter '${propName}' lacks maxLength constraint`,
            evidence: `Parameter: ${propName}, Type: string`,
            fix: 'Add maxLength constraint to prevent DoS attacks'
        });
    }

    // Check for dangerous patterns in enum values
    if (propSchema.enum) {
        for (const enumValue of propSchema.enum) {
            if (isDangerousEnumValue(enumValue)) {
                violations.push({
                    ruleId: 'parameter-validation',
                    severity: 'error',
                    message: `Tool '${toolName}' parameter '${propName}' has dangerous enum value`,
                    evidence: `Dangerous enum value: ${enumValue}`,
                    fix: 'Remove dangerous enum values that could be exploited'
                });
            }
        }
    }

    // Check for pattern validation for sensitive fields
    if (isSensitiveField(propName) && !propSchema.pattern) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Tool '${toolName}' sensitive parameter '${propName}' lacks pattern validation`,
            evidence: `Sensitive parameter: ${propName}`,
            fix: 'Add regex pattern validation for sensitive fields'
        });
    }

    // Check for format validation
    if (needsFormatValidation(propName) && !propSchema.format) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' parameter '${propName}' should have format validation`,
            evidence: `Parameter: ${propName}`,
            fix: 'Add format validation (email, uri, date-time, etc.)'
        });
    }

    return violations;
}

function validateNumberSchema(toolName: string, propName: string, propSchema: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for range constraints
    if (propSchema.minimum === undefined && propSchema.maximum === undefined) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' number parameter '${propName}' lacks range constraints`,
            evidence: `Parameter: ${propName}, Type: ${propSchema.type}`,
            fix: 'Add minimum/maximum constraints to prevent invalid values'
        });
    }

    // Check for unreasonably large maximum values
    if (propSchema.maximum && propSchema.maximum > Number.MAX_SAFE_INTEGER) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Tool '${toolName}' parameter '${propName}' has unsafe maximum value`,
            evidence: `Maximum: ${propSchema.maximum}`,
            fix: 'Set reasonable maximum value within safe integer range'
        });
    }

    // Check for negative minimums where inappropriate
    if (shouldBePositive(propName) && propSchema.minimum < 0) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' parameter '${propName}' allows negative values inappropriately`,
            evidence: `Minimum: ${propSchema.minimum}`,
            fix: 'Set minimum to 0 or positive value for count/size parameters'
        });
    }

    return violations;
}

function validateArraySchema(toolName: string, propName: string, propSchema: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for items schema
    if (!propSchema.items) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Tool '${toolName}' array parameter '${propName}' lacks items schema`,
            evidence: `Parameter: ${propName}, Type: array`,
            fix: 'Define schema for array items'
        });
    }

    // Check for maxItems constraint
    if (!propSchema.maxItems) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' array parameter '${propName}' lacks maxItems constraint`,
            evidence: `Parameter: ${propName}`,
            fix: 'Add maxItems constraint to prevent DoS attacks'
        });
    }

    // Check for reasonable maxItems value
    if (propSchema.maxItems && propSchema.maxItems > 10000) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' array parameter '${propName}' has very large maxItems`,
            evidence: `MaxItems: ${propSchema.maxItems}`,
            fix: 'Consider reducing maxItems to prevent resource exhaustion'
        });
    }

    return violations;
}

function validateObjectSchema(toolName: string, propName: string, propSchema: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for properties definition
    if (!propSchema.properties) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' object parameter '${propName}' lacks properties definition`,
            evidence: `Parameter: ${propName}, Type: object`,
            fix: 'Define properties schema for object parameters'
        });
    }

    // Check for additionalProperties setting
    if (propSchema.additionalProperties === undefined) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' object parameter '${propName}' should explicitly set additionalProperties`,
            evidence: `Parameter: ${propName}`,
            fix: 'Set additionalProperties: false to prevent unexpected properties'
        });
    }

    // Warn about allowing additional properties
    if (propSchema.additionalProperties === true) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${toolName}' object parameter '${propName}' allows additional properties`,
            evidence: `Parameter: ${propName}`,
            fix: 'Consider disabling additionalProperties for better validation'
        });
    }

    return violations;
}

function validateStreamingParameters(tool: any, schema: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for stream ID validation
    if (schema.properties?.streamId && !hasStreamIdValidation(schema.properties.streamId)) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Streaming tool '${tool.name}' lacks proper stream ID validation`,
            evidence: 'Stream ID parameter missing format validation',
            fix: 'Add regex pattern validation for Fox Corp stream ID format'
        });
    }

    // Check for content type validation
    if (schema.properties?.contentType && !hasContentTypeValidation(schema.properties.contentType)) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Streaming tool '${tool.name}' lacks content type validation`,
            evidence: 'Content type parameter missing enum validation',
            fix: 'Add enum validation for allowed Fox Corp content types'
        });
    }

    // Check for asset URL validation
    if (schema.properties?.assetUrl && !hasAssetUrlValidation(schema.properties.assetUrl)) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Streaming tool '${tool.name}' lacks asset URL validation`,
            evidence: 'Asset URL parameter missing domain validation',
            fix: 'Add pattern validation to ensure asset URLs are from Fox domains'
        });
    }

    return violations;
}

function validateConvivaParameters(tool: any, schema: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for session ID validation
    if (schema.properties?.sessionId && !hasSessionIdValidation(schema.properties.sessionId)) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Conviva tool '${tool.name}' lacks session ID validation`,
            evidence: 'Session ID parameter missing format validation',
            fix: 'Add proper Conviva session ID format validation'
        });
    }

    // Check for metric name validation
    if (schema.properties?.metricName && !hasMetricNameValidation(schema.properties.metricName)) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Conviva tool '${tool.name}' lacks metric name validation`,
            evidence: 'Metric name parameter missing enum validation',
            fix: 'Add enum validation for allowed Conviva metrics'
        });
    }

    return violations;
}

function validateHARParameters(tool: any, schema: any): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for HAR file size limits
    if (schema.properties?.harData && !hasHARSizeValidation(schema.properties.harData)) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `HAR tool '${tool.name}' lacks file size validation`,
            evidence: 'HAR data parameter missing size constraints',
            fix: 'Add maxLength constraint to prevent large HAR file uploads'
        });
    }

    // Check for HAR format validation
    if (schema.properties?.harContent && !hasHARFormatValidation(schema.properties.harContent)) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `HAR tool '${tool.name}' lacks format validation`,
            evidence: 'HAR content parameter missing format validation',
            fix: 'Add JSON schema validation for HAR file format'
        });
    }

    return violations;
}

function validateFoxCorpSchema(tool: any, context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];
    const schema = tool.inputSchema;

    // Streaming content parameters must have specific validation
    if (context.config.foxCorp?.streamingAssets && isStreamingTool(tool)) {
        const streamingViolations = validateStreamingParameters(tool, schema);
        violations.push(...streamingViolations);
    }

    // Conviva integration parameters
    if (context.config.foxCorp?.convivaIntegration && isConvivaTool(tool)) {
        const convivaViolations = validateConvivaParameters(tool, schema);
        violations.push(...convivaViolations);
    }

    // HAR validation parameters
    if (context.config.foxCorp?.harValidation && isHARTool(tool)) {
        const harViolations = validateHARParameters(tool, schema);
        violations.push(...harViolations);
    }

    return violations;
}

function validateSchemaStructure(tool: any, context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];
    const schema = tool.inputSchema;

    // Check for required properties
    if (!schema.properties) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Tool '${tool.name}' schema lacks properties definition`,
            evidence: 'Schema missing properties field',
            fix: 'Add properties definition to input schema'
        });
        return violations;
    }

    // Check each property for validation rules
    for (const [propName, propSchema] of Object.entries(schema.properties)) {
        const propViolations = validatePropertySchema(tool.name, propName, propSchema as any);
        violations.push(...propViolations);
    }

    // Check for missing required field
    if (!schema.required) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${tool.name}' schema should specify required fields`,
            evidence: 'Schema missing required field',
            fix: 'Add required array to specify mandatory parameters'
        });
    }

    // Fox Corp specific validations
    if (context.config.foxCorp) {
        const foxViolations = validateFoxCorpSchema(tool, context);
        violations.push(...foxViolations);
    }

    return violations;
}

async function checkValidationImplementation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    // Find tool implementation
    const implFile = context.sourceFiles.find(file =>
        file.content.includes(tool.name) &&
        (file.content.includes('function') || file.content.includes('=>'))
    );

    if (!implFile || !implFile.ast) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Cannot analyze validation implementation for tool '${tool.name}'`
        });
        return violations;
    }

    // Check for validation library usage
    const hasValidationLibrary = hasValidationLibraryUsage(implFile);
    if (!hasValidationLibrary) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${tool.name}' implementation doesn't use validation library`,
            file: implFile.path,
            fix: 'Use validation library (joi, yup, ajv) to validate parameters against schema'
        });
    }

    // Check for schema validation in implementation
    const hasSchemaValidationCheck = hasSchemaValidation(implFile);
    if (!hasSchemaValidationCheck) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Tool '${tool.name}' implementation lacks schema validation`,
            file: implFile.path,
            fix: 'Add parameter validation against the defined JSON schema'
        });
    }

    // Check for validation error handling
    const hasValidationErrorHandlingCheck = hasValidationErrorHandling(implFile);
    if (!hasValidationErrorHandlingCheck) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: `Tool '${tool.name}' lacks proper validation error handling`,
            file: implFile.path,
            fix: 'Add proper error handling for validation failures'
        });
    }

    return violations;
}

async function checkToolParameterValidation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];

    // Check if tool has input schema
    if (!tool.inputSchema) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: `Tool '${tool.name}' lacks input schema definition`,
            evidence: `Tool: ${tool.name}`,
            fix: 'Define JSON schema for tool input parameters'
        });
        return violations;
    }

    // Validate schema structure
    const schemaViolations = validateSchemaStructure(tool, context);
    violations.push(...schemaViolations);

    // Check implementation for validation logic
    const implViolations = await checkValidationImplementation(tool, context);
    violations.push(...implViolations);

    return violations;
}

function checkValidationSchemas(context: AnalysisContext): RuleViolation[] {
    const violations: RuleViolation[] = [];

    // Check for consistent schema usage across tools
    const schemas = context.mcpServer.tools
        .filter(tool => tool.inputSchema)
        .map(tool => tool.inputSchema);

    if (schemas.length === 0) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'error',
            message: 'No tools have input schemas defined',
            fix: 'Define JSON schemas for all tool input parameters'
        });
        return violations;
    }

    // Check for schema validation library in dependencies
    const validationDeps = [
        'joi',
        'yup',
        'ajv',
        'validator',
        'express-validator',
        'class-validator'
    ];

    const hasValidationDep = validationDeps.some(dep =>
        context.packageJson.dependencies?.[dep] ||
        context.packageJson.devDependencies?.[dep]
    );

    if (!hasValidationDep) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'warning',
            message: 'No validation library found in dependencies',
            fix: `Add a validation library: ${validationDeps.slice(0, 3).join(', ')}`
        });
    }

    // Check for common schema patterns that might indicate copy-paste errors
    const duplicateSchemas = findDuplicateSchemas(schemas);
    if (duplicateSchemas.length > 0) {
        violations.push({
            ruleId: 'parameter-validation',
            severity: 'info',
            message: 'Found duplicate schemas across tools',
            evidence: `${duplicateSchemas.length} tools have identical schemas`,
            fix: 'Consider extracting common schemas to reusable definitions'
        });
    }

    return violations;
}

// The actual rule object - only contains the required interface properties
export const parameterValidation: MCPSecurityRule = {
    id: 'parameter-validation',
    name: 'Parameter Validation',
    description: 'Ensures all tool parameters are properly validated according to their schemas',
    severity: 'error',
    category: 'input-validation',
    mandatory: true,

    async check(context: AnalysisContext): Promise<RuleViolation[]> {
        const violations: RuleViolation[] = [];

        // Check each tool for parameter validation
        for (const tool of context.mcpServer.tools) {
            const toolViolations = await checkToolParameterValidation(tool, context);
            violations.push(...toolViolations);
        }

        // Check for validation schema consistency
        const schemaViolations = checkValidationSchemas(context);
        violations.push(...schemaViolations);

        return violations;
    }
};
