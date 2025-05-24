export interface MCPSecurityRule {
  id: string;
  name: string;
  description: string;
  severity: 'error' | 'warning' | 'info';
  category: SecurityCategory;
  mandatory: boolean;
  check: (context: AnalysisContext) => Promise<RuleViolation[]>;
}

export interface RuleViolation {
  ruleId: string;
  severity: 'error' | 'warning' | 'info';
  message: string;
  file?: string;
  line?: number;
  column?: number;
  fix?: string;
  evidence?: string;
}

export interface AnalysisContext {
  projectPath: string;
  mcpServer: MCPServerInfo;
  sourceFiles: SourceFile[];
  packageJson: any;
  config: MCPSecConfig;
}

export interface MCPServerInfo {
  name: string;
  version: string;
  tools: MCPTool[];
  resources: MCPResource[];
  prompts: MCPPrompt[];
}

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: any;
  implementation: string;
  permissions: string[];
  rateLimit?: RateLimit;
}

export interface MCPSecConfig {
  rules: Record<string, RuleConfig>;
  extends?: string[];
  foxCorp?: FoxCorpConfig;
  ignorePatterns: string[];
  severity: {
    error: number;
    warning: number;
  };
}

export interface FoxCorpConfig {
  streamingAssets: boolean;
  convivaIntegration: boolean;
  harValidation: boolean;
  auditLevel: 'basic' | 'comprehensive' | 'forensic';
}

export interface RuleConfig {
  enabled: boolean;
  severity?: 'error' | 'warning' | 'info';
  options?: Record<string, any>;
}

export type SecurityCategory = 
  | 'authentication'
  | 'authorization' 
  | 'input-validation'
  | 'rate-limiting'
  | 'audit-logging'
  | 'data-protection'
  | 'fox-streaming';

export interface SourceFile {
  path: string;
  content: string;
  ast?: any;
}

export interface RateLimit {
  requests: number;
  window: number; // milliseconds
  scope: 'user' | 'global' | 'tool';
}