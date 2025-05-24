import { AnalysisContext, MCPSecurityRule, RuleViolation, MCPSecConfig, SourceFile, MCPServerInfo } from './types';
import { getAllRules } from '../rules';
import { StaticAnalyzer } from '../analyzers/static-analyzer';
import { RuntimeAnalyzer } from '../analyzers/runtime-analyzer';
import { MCPProtocolAnalyzer } from '../analyzers/mcp-protocol-analyzer';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import * as ts from 'typescript';

export class MCPSecurityAnalyzer {
  private rules: MCPSecurityRule[];
  private staticAnalyzer: StaticAnalyzer;
  private runtimeAnalyzer: RuntimeAnalyzer;
  private protocolAnalyzer: MCPProtocolAnalyzer;

  constructor(private config: MCPSecConfig) {
    this.rules = getAllRules().filter(rule => 
      this.config.rules[rule.id]?.enabled !== false
    );
    this.staticAnalyzer = new StaticAnalyzer();
    this.runtimeAnalyzer = new RuntimeAnalyzer();
    this.protocolAnalyzer = new MCPProtocolAnalyzer();
  }

  public async analyze(projectPath: string): Promise<RuleViolation[]> {
    const context = await this.buildAnalysisContext(projectPath);
    const violations: RuleViolation[] = [];

    // Run all security rules
    for (const rule of this.rules) {
      try {
        const ruleViolations = await rule.check(context);
        violations.push(...ruleViolations);
      } catch (error: any) {
        console.error(`Error running rule ${rule.id}:`, error);
        violations.push({
          ruleId: rule.id,
          severity: 'error',
          message: `Rule execution failed: ${error.message}`
        });
      }
    }

    // Apply severity overrides from config
    return violations.map(violation => ({
      ...violation,
      severity: this.config.rules[violation.ruleId]?.severity || violation.severity
    }));
  }

  private async buildAnalysisContext(projectPath: string): Promise<AnalysisContext> {
    const sourceFiles = this.loadSourceFiles(projectPath);
    const packageJson = this.loadPackageJson(projectPath);
    const mcpServer = await this.analyzeMCPServer(projectPath, sourceFiles);

    return {
      projectPath,
      mcpServer,
      sourceFiles,
      packageJson,
      config: this.config
    };
  }

  private loadSourceFiles(projectPath: string): SourceFile[] {
    const files: SourceFile[] = [];
    
    const walkDir = (dir: string) => {
      const items = readdirSync(dir);
      
      for (const item of items) {
        const fullPath = join(dir, item);
        const stat = statSync(fullPath);
        
        if (stat.isDirectory()) {
          // Skip ignored directories
          const relativePath = fullPath.replace(projectPath, '').substring(1);
          if (!this.shouldIgnore(relativePath)) {
            walkDir(fullPath);
          }
        } else if (this.isAnalyzableFile(fullPath)) {
          const content = readFileSync(fullPath, 'utf-8');
          files.push({
            path: fullPath,
            content,
            ast: this.parseTypeScript(content, fullPath)
          });
        }
      }
    };

    walkDir(projectPath);
    return files;
  }

  private parseTypeScript(content: string, filePath: string): ts.SourceFile | undefined {
    try {
      return ts.createSourceFile(
        filePath,
        content,
        ts.ScriptTarget.Latest,
        true
      );
    } catch (error: any) {
      console.warn(`Failed to parse TypeScript file ${filePath}:`, error);
      return undefined;
    }
  }

  private loadPackageJson(projectPath: string): any {
    try {
      const packagePath = join(projectPath, 'package.json');
      return JSON.parse(readFileSync(packagePath, 'utf-8'));
    } catch (error: any) {
      return {};
    }
  }

  private async analyzeMCPServer(projectPath: string, sourceFiles: SourceFile[]): Promise<MCPServerInfo> {
    return this.protocolAnalyzer.analyze(sourceFiles);
  }

  private isAnalyzableFile(filePath: string): boolean {
    const ext = extname(filePath);
    return ['.ts', '.js', '.json'].includes(ext);
  }

  private shouldIgnore(relativePath: string): boolean {
    return this.config.ignorePatterns.some(pattern => {
      const regex = new RegExp(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'));
      return regex.test(relativePath);
    });
  }
}
