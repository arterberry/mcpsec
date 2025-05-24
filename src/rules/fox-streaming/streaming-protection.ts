import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';
import * as ts from 'typescript';

export const foxStreamingProtection: MCPSecurityRule = {
  id: 'fox-streaming-protection',
  name: 'Fox Streaming Asset Protection',
  description: 'Ensures streaming assets and IP are protected with appropriate access controls',
  severity: 'error',
  category: 'fox-streaming',
  mandatory: true,
  
  async check(context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];
    
    if (!context.config.foxCorp?.streamingAssets) {
      return violations;
    }

    // Check for streaming-related tools
    const streamingTools = context.mcpServer.tools.filter(tool => 
      tool.name.toLowerCase().includes('stream') ||
      tool.description.toLowerCase().includes('stream') ||
      tool.description.toLowerCase().includes('video') ||
      tool.description.toLowerCase().includes('media')
    );

    for (const tool of streamingTools) {
      // Ensure streaming tools have proper authentication
      if (!tool.permissions.includes('streaming:read') && !tool.permissions.includes('streaming:admin')) {
        violations.push({
          ruleId: 'fox-streaming-protection',
          severity: 'error',
          message: `Streaming tool '${tool.name}' must have explicit streaming permissions`,
          evidence: `Tool: ${tool.name}, Current permissions: ${tool.permissions.join(', ')}`
        });
      }

      // Check for rate limiting on streaming tools
      if (!tool.rateLimit) {
        violations.push({
          ruleId: 'fox-streaming-protection',
          severity: 'warning',
          message: `Streaming tool '${tool.name}' should have rate limiting to protect infrastructure`,
          fix: 'Add rateLimit configuration to prevent abuse'
        });
      }

      // Analyze tool implementation for security patterns
      const implViolations = await this.analyzeStreamingImplementation(tool, context);
      violations.push(...implViolations);
    }

    return violations;
  }

  private async analyzeStreamingImplementation(tool: any, context: AnalysisContext): Promise<RuleViolation[]> {
    const violations: RuleViolation[] = [];
    
    // Find the implementation file
    const implFile = context.sourceFiles.find(file => 
      file.content.includes(tool.name) || 
      file.path.includes(tool.implementation)
    );

    if (!implFile || !implFile.ast) {
      return violations;
    }

    // Check for hardcoded streaming URLs or credentials
    const visitor = (node: ts.Node) => {
      if (ts.isStringLiteral(node)) {
        const value = node.text;
        
        // Check for streaming URLs without proper validation
        if (this.isStreamingUrl(value) && !this.hasProperValidation(implFile.content, value)) {
          violations.push({
            ruleId: 'fox-streaming-protection',
            severity: 'error',
            message: 'Streaming URLs must be validated and sanitized',
            file: implFile.path,
            line: this.getLineNumber(implFile.ast!, node),
            evidence: `Found URL: ${value}`,
            fix: 'Use URL validation and allowlist checking'
          });
        }

        // Check for hardcoded credentials
        if (this.containsCredentials(value)) {
          violations.push({
            ruleId: 'fox-streaming-protection',
            severity: 'error',
            message: 'Hardcoded credentials detected in streaming tool',
            file: implFile.path,
            line: this.getLineNumber(implFile.ast!, node),
            evidence: 'Hardcoded credential pattern found',
            fix: 'Use environment variables or secure credential storage'
          });
        }
      }
      
      ts.forEachChild(node, visitor);
    };

    visitor(implFile.ast);
    return violations;
  }

  private isStreamingUrl(url: string): boolean {
    const streamingPatterns = [
      /rtmp:\/\//i,
      /hls:\/\//i,
      /dash:\/\//i,
      /\.m3u8/i,
      /\.mpd/i,
      /streaming/i,
      /media\.fox/i
    ];
    
    return streamingPatterns.some(pattern => pattern.test(url));
  }

  private hasProperValidation(content: string, url: string): boolean {
    const context = content.substring(
      Math.max(0, content.indexOf(url) - 200),
      content.indexOf(url) + 200
    );
    
    return /validate|sanitize|allowlist|whitelist/i.test(context);
  }

  private containsCredentials(value: string): boolean {
    const credentialPatterns = [
      /api[_-]?key/i,
      /secret/i,
      /token/i,
      /password/i,
      /auth/i
    ];
    
    return credentialPatterns.some(pattern => pattern.test(value)) && 
           value.length > 10 && 
           /[a-zA-Z0-9]{8,}/.test(value);
  }

  private getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  }
};