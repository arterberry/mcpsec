import { SourceFile, MCPServerInfo, MCPTool } from '../core/types';
import * as ts from 'typescript';

export interface MCPProtocolAnalysis {
  protocolCompliance: ProtocolComplianceInfo;
  toolDefinitions: ToolDefinitionInfo[];
  resourceDefinitions: ResourceDefinitionInfo[];
  promptDefinitions: PromptDefinitionInfo[];
  securityConfiguration: SecurityConfigInfo;
}

export interface ProtocolComplianceInfo {
  hasValidStructure: boolean;
  missingComponents: string[];
  invalidComponents: string[];
  version: string | null;
}

export interface ToolDefinitionInfo {
  name: string;
  hasValidSchema: boolean;
  hasDescription: boolean;
  hasInputValidation: boolean;
  hasOutputValidation: boolean;
  hasErrorHandling: boolean;
  securityIssues: string[];
}

export interface ResourceDefinitionInfo {
  name: string;
  hasValidSchema: boolean;
  hasAccessControl: boolean;
  securityIssues: string[];
}

export interface PromptDefinitionInfo {
  name: string;
  hasValidSchema: boolean;
  hasInputSanitization: boolean;
  securityIssues: string[];
}

export interface SecurityConfigInfo {
  hasAuthentication: boolean;
  hasAuthorization: boolean;
  hasRateLimiting: boolean;
  hasInputValidation: boolean;
  hasAuditLogging: boolean;
  missingSecurityFeatures: string[];
}

export class MCPProtocolAnalyzer {
  private mcpKeywords = new Set([
    'tools', 'resources', 'prompts', 'notifications',
    'initialize', 'call_tool', 'get_resource', 'get_prompt',
    'list_tools', 'list_resources', 'list_prompts'
  ]);

  private securityPatterns = {
    authentication: [
      /auth/i, /token/i, /credential/i, /login/i, /verify/i
    ],
    authorization: [
      /permission/i, /role/i, /access/i, /allow/i, /deny/i
    ],
    validation: [
      /validate/i, /sanitize/i, /check/i, /verify/i
    ],
    logging: [
      /log/i, /audit/i, /record/i, /track/i
    ]
  };

  public async analyze(sourceFiles: SourceFile[]): Promise<MCPServerInfo> {
    const serverInfo: MCPServerInfo = {
      name: '',
      version: '',
      tools: [],
      resources: [],
      prompts: []
    };

    // Find main server file
    const serverFile = this.findServerFile(sourceFiles);
    if (serverFile) {
      serverInfo.name = this.extractServerName(serverFile);
      serverInfo.version = this.extractVersion(serverFile);
    }

    // Analyze each source file for MCP components
    for (const file of sourceFiles) {
      if (!file.ast) continue;

      const tools = this.extractTools(file);
      const resources = this.extractResources(file);
      const prompts = this.extractPrompts(file);

      serverInfo.tools.push(...tools);
      serverInfo.resources.push(...resources);
      serverInfo.prompts.push(...prompts);
    }

    return serverInfo;
  }

  public analyzeProtocolCompliance(sourceFiles: SourceFile[]): MCPProtocolAnalysis {
    const analysis: MCPProtocolAnalysis = {
      protocolCompliance: {
        hasValidStructure: false,
        missingComponents: [],
        invalidComponents: [],
        version: null
      },
      toolDefinitions: [],
      resourceDefinitions: [],
      promptDefinitions: [],
      securityConfiguration: {
        hasAuthentication: false,
        hasAuthorization: false,
        hasRateLimiting: false,
        hasInputValidation: false,
        hasAuditLogging: false,
        missingSecurityFeatures: []
      }
    };

    // Check protocol compliance
    analysis.protocolCompliance = this.checkProtocolCompliance(sourceFiles);
    
    // Analyze security configuration
    analysis.securityConfiguration = this.analyzeSecurityConfiguration(sourceFiles);

    // Analyze component definitions
    for (const file of sourceFiles) {
      if (!file.ast) continue;

      const tools = this.analyzeToolDefinitions(file);
      const resources = this.analyzeResourceDefinitions(file);
      const prompts = this.analyzePromptDefinitions(file);

      analysis.toolDefinitions.push(...tools);
      analysis.resourceDefinitions.push(...resources);
      analysis.promptDefinitions.push(...prompts);
    }

    return analysis;
  }

  private findServerFile(sourceFiles: SourceFile[]): SourceFile | null {
    // Look for main server file patterns
    const serverPatterns = [
      /server\.(ts|js)$/,
      /index\.(ts|js)$/,
      /main\.(ts|js)$/,
      /app\.(ts|js)$/
    ];

    for (const pattern of serverPatterns) {
      const file = sourceFiles.find(f => pattern.test(f.path));
      if (file && this.containsMCPCode(file)) {
        return file;
      }
    }

    // Fallback: find any file with MCP-related code
    return sourceFiles.find(f => this.containsMCPCode(f)) || null;
  }

  private containsMCPCode(file: SourceFile): boolean {
    const content = file.content.toLowerCase();
    return Array.from(this.mcpKeywords).some(keyword => content.includes(keyword));
  }

  private extractServerName(file: SourceFile): string {
    // Try to extract server name from package.json reference or config
    const namePatterns = [
      /name:\s*['"`]([^'"`]+)['"`]/,
      /serverName:\s*['"`]([^'"`]+)['"`]/,
      /"name":\s*"([^"]+)"/
    ];

    for (const pattern of namePatterns) {
      const match = file.content.match(pattern);
      if (match) {
        return match[1];
      }
    }

    return 'unknown-mcp-server';
  }

  private extractVersion(file: SourceFile): string {
    const versionPatterns = [
      /version:\s*['"`]([^'"`]+)['"`]/,
      /"version":\s*"([^"]+)"/
    ];

    for (const pattern of versionPatterns) {
      const match = file.content.match(pattern);
      if (match) {
        return match[1];
      }
    }

    return '1.0.0';
  }

  private extractTools(file: SourceFile): MCPTool[] {
    const tools: MCPTool[] = [];

    if (!file.ast) return tools;

    const visitor = (node: ts.Node) => {
      // Look for tool definitions
      if (this.isToolDefinition(node, file)) {
        const tool = this.parseToolDefinition(node, file);
        if (tool) {
          tools.push(tool);
        }
      }

      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return tools;
  }

  private extractResources(file: SourceFile): MCPResource[] {
    const resources: MCPResource[] = [];

    if (!file.ast) return resources;

    const visitor = (node: ts.Node) => {
      if (this.isResourceDefinition(node, file)) {
        const resource = this.parseResourceDefinition(node, file);
        if (resource) {
          resources.push(resource);
        }
      }

      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return resources;
  }

  private extractPrompts(file: SourceFile): MCPPrompt[] {
    const prompts: MCPPrompt[] = [];

    if (!file.ast) return prompts;

    const visitor = (node: ts.Node) => {
      if (this.isPromptDefinition(node, file)) {
        const prompt = this.parsePromptDefinition(node, file);
        if (prompt) {
          prompts.push(prompt);
        }
      }

      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
    return prompts;
  }

  private isToolDefinition(node: ts.Node, file: SourceFile): boolean {
    if (ts.isObjectLiteralExpression(node) || ts.isFunctionDeclaration(node)) {
      const nodeText = node.getText(file.ast!).toLowerCase();
      return nodeText.includes('tool') && 
             (nodeText.includes('name') || nodeText.includes('description'));
    }
    return false;
  }

  private isResourceDefinition(node: ts.Node, file: SourceFile): boolean {
    if (ts.isObjectLiteralExpression(node) || ts.isFunctionDeclaration(node)) {
      const nodeText = node.getText(file.ast!).toLowerCase();
      return nodeText.includes('resource') && 
             (nodeText.includes('uri') || nodeText.includes('name'));
    }
    return false;
  }

  private isPromptDefinition(node: ts.Node, file: SourceFile): boolean {
    if (ts.isObjectLiteralExpression(node) || ts.isFunctionDeclaration(node)) {
      const nodeText = node.getText(file.ast!).toLowerCase();
      return nodeText.includes('prompt') && 
             (nodeText.includes('name') || nodeText.includes('template'));
    }
    return false;
  }

  private parseToolDefinition(node: ts.Node, file: SourceFile): MCPTool | null {
    const tool: Partial<MCPTool> = {
      permissions: [],
      rateLimit: undefined
    };

    if (ts.isObjectLiteralExpression(node)) {
      for (const property of node.properties) {
        if (ts.isPropertyAssignment(property) && ts.isIdentifier(property.name)) {
          const propertyName = property.name.text;
          const value = property.initializer;

          switch (propertyName) {
            case 'name':
              if (ts.isStringLiteral(value)) {
                tool.name = value.text;
              }
              break;
            case 'description':
              if (ts.isStringLiteral(value)) {
                tool.description = value.text;
              }
              break;
            case 'inputSchema':
              tool.inputSchema = this.parseSchema(value, file);
              break;
          }
        }
      }
    } else if (ts.isFunctionDeclaration(node) && node.name) {
      tool.name = node.name.text;
      tool.description = this.extractFunctionDescription(node, file);
      tool.inputSchema = this.inferInputSchema(node, file);
    }

    tool.implementation = file.path;

    return tool.name ? tool as MCPTool : null;
  }

  private parseResourceDefinition(node: ts.Node, file: SourceFile): MCPResource | null {
    // Implementation similar to parseToolDefinition but for resources
    return {
      name: 'extracted_resource',
      uri: 'resource://example',
      type: 'text'
    };
  }

  private parsePromptDefinition(node: ts.Node, file: SourceFile): MCPPrompt | null {
    // Implementation similar to parseToolDefinition but for prompts
    return {
      name: 'extracted_prompt',
      template: 'Example prompt template'
    };
  }

  private parseSchema(node: ts.Node, file: SourceFile): any {
    try {
      // Try to evaluate the schema object
      const schemaText = node.getText(file.ast!);
      // This is a simplified implementation
      // In practice, you'd need more robust schema parsing
      return JSON.parse(schemaText.replace(/'/g, '"'));
    } catch {
      return {};
    }
  }

  private extractFunctionDescription(node: ts.FunctionDeclaration, file: SourceFile): string {
    // Look for JSDoc comments
    const comments = ts.getLeadingCommentRanges(file.content, node.getFullStart());
    if (comments && comments.length > 0) {
      const comment = file.content.substring(comments[0].pos, comments[0].end);
      const descMatch = comment.match(/\*\s*(.+)/);
      if (descMatch) {
        return descMatch[1].trim();
      }
    }
    return `Function ${node.name?.text || 'unknown'}`;
  }

  private inferInputSchema(node: ts.FunctionDeclaration, file: SourceFile): any {
    const schema: any = {
      type: 'object',
      properties: {}
    };

    if (node.parameters) {
      for (const param of node.parameters) {
        if (ts.isIdentifier(param.name)) {
          const paramName = param.name.text;
          schema.properties[paramName] = {
            type: this.inferTypeFromParameter(param, file)
          };
        }
      }
    }

    return schema;
  }

  private inferTypeFromParameter(param: ts.ParameterDeclaration, file: SourceFile): string {
    if (param.type) {
      const typeText = param.type.getText(file.ast!);
      if (typeText.includes('string')) return 'string';
      if (typeText.includes('number')) return 'number';
      if (typeText.includes('boolean')) return 'boolean';
      if (typeText.includes('[]')) return 'array';
    }
    return 'string'; // Default fallback
  }

  private checkProtocolCompliance(sourceFiles: SourceFile[]): ProtocolComplianceInfo {
    const compliance: ProtocolComplianceInfo = {
      hasValidStructure: false,
      missingComponents: [],
      invalidComponents: [],
      version: null
    };

    const requiredComponents = ['tools', 'initialize', 'call_tool'];
    const foundComponents = new Set<string>();

    for (const file of sourceFiles) {
      const content = file.content.toLowerCase();
      
      for (const component of requiredComponents) {
        if (content.includes(component)) {
          foundComponents.add(component);
        }
      }

      // Extract MCP version if present
      const versionMatch = content.match(/mcp.*version.*['"`]([0-9.]+)['"`]/i);
      if (versionMatch) {
        compliance.version = versionMatch[1];
      }
    }

    compliance.missingComponents = requiredComponents.filter(
      comp => !foundComponents.has(comp)
    );

    compliance.hasValidStructure = compliance.missingComponents.length === 0;

    return compliance;
  }

  private analyzeSecurityConfiguration(sourceFiles: SourceFile[]): SecurityConfigInfo {
    const config: SecurityConfigInfo = {
      hasAuthentication: false,
      hasAuthorization: false,
      hasRateLimiting: false,
      hasInputValidation: false,
      hasAuditLogging: false,
      missingSecurityFeatures: []
    };

    for (const file of sourceFiles) {
      const content = file.content.toLowerCase();

      // Check for authentication
      if (this.securityPatterns.authentication.some(pattern => pattern.test(content))) {
        config.hasAuthentication = true;
      }

      // Check for authorization
      if (this.securityPatterns.authorization.some(pattern => pattern.test(content))) {
        config.hasAuthorization = true;
      }

      // Check for rate limiting
      if (content.includes('rate') && content.includes('limit')) {
        config.hasRateLimiting = true;
      }

      // Check for input validation
      if (this.securityPatterns.validation.some(pattern => pattern.test(content))) {
        config.hasInputValidation = true;
      }

      // Check for audit logging
      if (this.securityPatterns.logging.some(pattern => pattern.test(content))) {
        config.hasAuditLogging = true;
      }
    }

    // Identify missing security features
    const securityFeatures = [
      { key: 'hasAuthentication', name: 'Authentication' },
      { key: 'hasAuthorization', name: 'Authorization' },
      { key: 'hasRateLimiting', name: 'Rate Limiting' },
      { key: 'hasInputValidation', name: 'Input Validation' },
      { key: 'hasAuditLogging', name: 'Audit Logging' }
    ];

    config.missingSecurityFeatures = securityFeatures
      .filter(feature => !config[feature.key as keyof SecurityConfigInfo])
      .map(feature => feature.name);

    return config;
  }

  private analyzeToolDefinitions(file: SourceFile): ToolDefinitionInfo[] {
    const definitions: ToolDefinitionInfo[] = [];
    
    // This would analyze individual tool definitions for security issues
    // Implementation would be similar to extractTools but focused on security
    
    return definitions;
  }

  private analyzeResourceDefinitions(file: SourceFile): ResourceDefinitionInfo[] {
    const definitions: ResourceDefinitionInfo[] = [];
    
    // Analyze resource definitions for security issues
    
    return definitions;
  }

  private analyzePromptDefinitions(file: SourceFile): PromptDefinitionInfo[] {
    const definitions: PromptDefinitionInfo[] = [];
    
    // Analyze prompt definitions for security issues
    
    return definitions;
  }
}