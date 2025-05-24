import { SourceFile, MCPTool } from '../core/types';
import * as ts from 'typescript';

export interface StaticAnalysisResult {
  functions: FunctionInfo[];
  imports: ImportInfo[];
  exports: ExportInfo[];
  securityPatterns: SecurityPattern[];
  dependencies: DependencyInfo[];
}

export interface FunctionInfo {
  name: string;
  parameters: ParameterInfo[];
  returnType: string;
  isAsync: boolean;
  file: string;
  line: number;
  visibility: 'public' | 'private' | 'protected';
}

export interface ParameterInfo {
  name: string;
  type: string;
  optional: boolean;
  hasValidation: boolean;
}

export interface ImportInfo {
  module: string;
  imports: string[];
  file: string;
  line: number;
  isDynamic: boolean;
}

export interface ExportInfo {
  name: string;
  type: 'function' | 'class' | 'variable' | 'default';
  file: string;
  line: number;
}

export interface SecurityPattern {
  type: 'dangerous-function' | 'hardcoded-secret' | 'unsafe-regex' | 'eval-usage' | 'sql-injection' | 'command-injection';
  severity: 'high' | 'medium' | 'low';
  description: string;
  file: string;
  line: number;
  code: string;
}

export interface DependencyInfo {
  name: string;
  version: string;
  vulnerabilities: VulnerabilityInfo[];
  license: string;
}

export interface VulnerabilityInfo {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fixedIn?: string;
}

export class StaticAnalyzer {
  private dangerousFunctions = new Set([
    'eval', 'Function', 'setTimeout', 'setInterval',
    'exec', 'execSync', 'spawn', 'spawnSync',
    'system', 'shell_exec', 'passthru'
  ]);

  private secretPatterns = [
    /api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})/gi,
    /secret["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})/gi,
    /password["\s]*[:=]["\s]*([a-zA-Z0-9]{8,})/gi,
    /token["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})/gi,
    /aws[_-]?access[_-]?key["\s]*[:=]["\s]*([A-Z0-9]{20})/gi,
    /aws[_-]?secret[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9/+=]{40})/gi
  ];

  public analyze(sourceFiles: SourceFile[]): StaticAnalysisResult {
    const result: StaticAnalysisResult = {
      functions: [],
      imports: [],
      exports: [],
      securityPatterns: [],
      dependencies: []
    };

    for (const file of sourceFiles) {
      if (!file.ast) continue;

      // Analyze AST
      this.analyzeAST(file, result);
      
      // Analyze raw content for patterns
      this.analyzeContent(file, result);
    }

    return result;
  }

  private analyzeAST(file: SourceFile, result: StaticAnalysisResult): void {
    const visitor = (node: ts.Node) => {
      // Analyze function declarations
      if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isArrowFunction(node)) {
        const functionInfo = this.extractFunctionInfo(node, file);
        if (functionInfo) {
          result.functions.push(functionInfo);
        }
      }

      // Analyze import statements
      if (ts.isImportDeclaration(node)) {
        const importInfo = this.extractImportInfo(node, file);
        if (importInfo) {
          result.imports.push(importInfo);
        }
      }

      // Analyze export statements
      if (ts.isExportDeclaration(node) || ts.isExportAssignment(node)) {
        const exportInfo = this.extractExportInfo(node, file);
        if (exportInfo) {
          result.exports.push(exportInfo);
        }
      }

      // Analyze function calls for dangerous patterns
      if (ts.isCallExpression(node)) {
        const securityPattern = this.analyzeCallExpression(node, file);
        if (securityPattern) {
          result.securityPatterns.push(securityPattern);
        }
      }

      // Analyze template literals for injection vulnerabilities
      if (ts.isTemplateExpression(node)) {
        const patterns = this.analyzeTemplateExpression(node, file);
        result.securityPatterns.push(...patterns);
      }

      ts.forEachChild(node, visitor);
    };

    visitor(file.ast);
  }

  private analyzeContent(file: SourceFile, result: StaticAnalysisResult): void {
    // Check for hardcoded secrets
    for (const pattern of this.secretPatterns) {
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const line = this.getLineFromIndex(file.content, match.index);
        result.securityPatterns.push({
          type: 'hardcoded-secret',
          severity: 'high',
          description: 'Hardcoded secret or credential detected',
          file: file.path,
          line,
          code: match[0]
        });
      }
    }

    // Check for unsafe regular expressions (ReDoS)
    const regexPattern = /\/(.+?)\/[gimuy]*/g;
    let regexMatch;
    while ((regexMatch = regexPattern.exec(file.content)) !== null) {
      if (this.isUnsafeRegex(regexMatch[1])) {
        const line = this.getLineFromIndex(file.content, regexMatch.index);
        result.securityPatterns.push({
          type: 'unsafe-regex',
          severity: 'medium',
          description: 'Regular expression vulnerable to ReDoS attacks',
          file: file.path,
          line,
          code: regexMatch[0]
        });
      }
    }
  }

  private extractFunctionInfo(node: ts.Node, file: SourceFile): FunctionInfo | null {
    let name = '';
    let parameters: ParameterInfo[] = [];
    let returnType = 'any';
    let isAsync = false;

    if (ts.isFunctionDeclaration(node)) {
      name = node.name?.text || 'anonymous';
      parameters = this.extractParameters(node.parameters, file);
      returnType = node.type?.getText(file.ast!) || 'any';
      isAsync = node.modifiers?.some(mod => mod.kind === ts.SyntaxKind.AsyncKeyword) || false;
    } else if (ts.isMethodDeclaration(node)) {
      name = node.name.getText(file.ast!);
      parameters = this.extractParameters(node.parameters, file);
      returnType = node.type?.getText(file.ast!) || 'any';
      isAsync = node.modifiers?.some(mod => mod.kind === ts.SyntaxKind.AsyncKeyword) || false;
    } else if (ts.isArrowFunction(node)) {
      name = 'arrow_function';
      parameters = this.extractParameters(node.parameters, file);
      returnType = node.type?.getText(file.ast!) || 'any';
      isAsync = node.modifiers?.some(mod => mod.kind === ts.SyntaxKind.AsyncKeyword) || false;
    }

    return {
      name,
      parameters,
      returnType,
      isAsync,
      file: file.path,
      line: this.getLineNumber(file.ast!, node),
      visibility: this.getVisibility(node)
    };
  }

  private extractParameters(parameters: ts.NodeArray<ts.ParameterDeclaration>, file: SourceFile): ParameterInfo[] {
    return parameters.map(param => ({
      name: param.name.getText(file.ast!),
      type: param.type?.getText(file.ast!) || 'any',
      optional: !!param.questionToken,
      hasValidation: this.hasParameterValidation(param, file)
    }));
  }

  private hasParameterValidation(param: ts.ParameterDeclaration, file: SourceFile): boolean {
    // Simple heuristic: check if parameter has type guards or validation decorators
    const paramText = param.getText(file.ast!);
    const validationPatterns = [
      /@IsString/, /@IsNumber/, /@IsEmail/, /@IsOptional/,
      /@Min\(/, /@Max\(/, /@Length\(/, /@Matches\(/,
      /validate/, /sanitize/, /check/
    ];

    return validationPatterns.some(pattern => pattern.test(paramText));
  }

  private extractImportInfo(node: ts.ImportDeclaration, file: SourceFile): ImportInfo | null {
    const moduleSpecifier = node.moduleSpecifier;
    if (!ts.isStringLiteral(moduleSpecifier)) return null;

    const imports: string[] = [];
    
    if (node.importClause) {
      if (node.importClause.name) {
        imports.push(node.importClause.name.text);
      }
      
      if (node.importClause.namedBindings) {
        if (ts.isNamespaceImport(node.importClause.namedBindings)) {
          imports.push(`* as ${node.importClause.namedBindings.name.text}`);
        } else if (ts.isNamedImports(node.importClause.namedBindings)) {
          for (const element of node.importClause.namedBindings.elements) {
            imports.push(element.name.text);
          }
        }
      }
    }

    return {
      module: moduleSpecifier.text,
      imports,
      file: file.path,
      line: this.getLineNumber(file.ast!, node),
      isDynamic: false
    };
  }

  private extractExportInfo(node: ts.ExportDeclaration | ts.ExportAssignment, file: SourceFile): ExportInfo | null {
    if (ts.isExportDeclaration(node)) {
      if (node.exportClause && ts.isNamedExports(node.exportClause)) {
        // Return first export for simplicity
        const firstExport = node.exportClause.elements[0];
        if (firstExport) {
          return {
            name: firstExport.name.text,
            type: 'variable',
            file: file.path,
            line: this.getLineNumber(file.ast!, node)
          };
        }
      }
    } else if (ts.isExportAssignment(node)) {
      return {
        name: 'default',
        type: 'default',
        file: file.path,
        line: this.getLineNumber(file.ast!, node)
      };
    }

    return null;
  }

  private analyzeCallExpression(node: ts.CallExpression, file: SourceFile): SecurityPattern | null {
    const expression = node.expression;
    
    // Check for dangerous function calls
    if (ts.isIdentifier(expression) && this.dangerousFunctions.has(expression.text)) {
      return {
        type: 'dangerous-function',
        severity: 'high',
        description: `Use of dangerous function: ${expression.text}`,
        file: file.path,
        line: this.getLineNumber(file.ast!, node),
        code: node.getText(file.ast!)
      };
    }

    // Check for eval usage
    if (ts.isIdentifier(expression) && expression.text === 'eval') {
      return {
        type: 'eval-usage',
        severity: 'high',
        description: 'Use of eval() function creates code injection vulnerability',
        file: file.path,
        line: this.getLineNumber(file.ast!, node),
        code: node.getText(file.ast!)
      };
    }

    // Check for potential SQL injection
    if (ts.isPropertyAccessExpression(expression) && 
        (expression.name.text === 'query' || expression.name.text === 'exec')) {
      const args = node.arguments;
      if (args.length > 0 && this.containsStringConcatenation(args[0], file)) {
        return {
          type: 'sql-injection',
          severity: 'high',
          description: 'Potential SQL injection vulnerability',
          file: file.path,
          line: this.getLineNumber(file.ast!, node),
          code: node.getText(file.ast!)
        };
      }
    }

    // Check for command injection
    if (ts.isIdentifier(expression) && 
        ['exec', 'spawn', 'execSync', 'spawnSync'].includes(expression.text)) {
      const args = node.arguments;
      if (args.length > 0 && this.containsUnsafeInput(args[0], file)) {
        return {
          type: 'command-injection',
          severity: 'high',
          description: 'Potential command injection vulnerability',
          file: file.path,
          line: this.getLineNumber(file.ast!, node),
          code: node.getText(file.ast!)
        };
      }
    }

    return null;
  }

  private analyzeTemplateExpression(node: ts.TemplateExpression, file: SourceFile): SecurityPattern[] {
    const patterns: SecurityPattern[] = [];
    const templateText = node.getText(file.ast!);

    // Check for potential SQL injection in template literals
    if (this.looksLikeSQL(templateText)) {
      patterns.push({
        type: 'sql-injection',
        severity: 'medium',
        description: 'Template literal may contain SQL injection vulnerability',
        file: file.path,
        line: this.getLineNumber(file.ast!, node),
        code: templateText
      });
    }

    // Check for potential command injection in template literals
    if (this.looksLikeCommand(templateText)) {
      patterns.push({
        type: 'command-injection',
        severity: 'medium',
        description: 'Template literal may contain command injection vulnerability',
        file: file.path,
        line: this.getLineNumber(file.ast!, node),
        code: templateText
      });
    }

    return patterns;
  }

  private containsStringConcatenation(node: ts.Node, file: SourceFile): boolean {
    return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken;
  }

  private containsUnsafeInput(node: ts.Node, file: SourceFile): boolean {
    const nodeText = node.getText(file.ast!);
    const unsafePatterns = [
      /params\./,
      /request\./,
      /args\./,
      /process\.argv/,
      /user.*input/i
    ];

    return unsafePatterns.some(pattern => pattern.test(nodeText));
  }

  private looksLikeSQL(text: string): boolean {
    const sqlPatterns = [
      /SELECT\s+.*\s+FROM/i,
      /INSERT\s+INTO/i,
      /UPDATE\s+.*\s+SET/i,
      /DELETE\s+FROM/i,
      /CREATE\s+TABLE/i,
      /DROP\s+TABLE/i
    ];

    return sqlPatterns.some(pattern => pattern.test(text));
  }

  private looksLikeCommand(text: string): boolean {
    const commandPatterns = [
      /rm\s+/i,
      /del\s+/i,
      /cat\s+/i,
      /ls\s+/i,
      /dir\s+/i,
      /cp\s+/i,
      /mv\s+/i,
      /mkdir\s+/i
    ];

    return commandPatterns.some(pattern => pattern.test(text));
  }

  private isUnsafeRegex(regex: string): boolean {
    // Simple ReDoS detection patterns
    const redosPatterns = [
      /\(.*\+.*\).*\+/,  // (a+)+
      /\(.*\*.*\).*\*/,  // (a*)*
      /\(.*\+.*\).*\{/,  // (a+){n,m}
      /\(.*\|.*\).*\+/   // (a|b)+
    ];

    return redosPatterns.some(pattern => pattern.test(regex));
  }

  private getVisibility(node: ts.Node): 'public' | 'private' | 'protected' {
    if (ts.canHaveModifiers(node) && node.modifiers) {
      for (const modifier of node.modifiers) {
        if (modifier.kind === ts.SyntaxKind.PrivateKeyword) return 'private';
        if (modifier.kind === ts.SyntaxKind.ProtectedKeyword) return 'protected';
      }
    }
    return 'public';
  }

  private getLineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  }

  private getLineFromIndex(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }
}
