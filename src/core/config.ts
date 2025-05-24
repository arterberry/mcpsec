import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { MCPSecConfig } from './types';

export class ConfigManager {
  private static instance: ConfigManager;
  private config: MCPSecConfig;

  private constructor() {}

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  public loadConfig(projectPath: string, configPath?: string): MCPSecConfig {
    const defaultConfig = this.loadDefaultConfig();
    let userConfig = {};

    // Load user config
    if (configPath && existsSync(configPath)) {
      userConfig = JSON.parse(readFileSync(configPath, 'utf-8'));
    } else {
      // Look for standard config files
      const configFiles = [
        '.mcpsec.json',
        '.mcpsec.js',
        'mcpsec.config.json'
      ];

      for (const file of configFiles) {
        const filePath = join(projectPath, file);
        if (existsSync(filePath)) {
          userConfig = JSON.parse(readFileSync(filePath, 'utf-8'));
          break;
        }
      }
    }

    // Merge configurations
    this.config = this.mergeConfigs(defaultConfig, userConfig);
    return this.config;
  }

  private loadDefaultConfig(): MCPSecConfig {
    return {
      rules: {
        'auth-required': { enabled: true, severity: 'error' },
        'role-validation': { enabled: true, severity: 'error' },
        'input-sanitization': { enabled: true, severity: 'error' },
        'parameter-validation': { enabled: true, severity: 'error' },
        'injection-detection': { enabled: true, severity: 'error' },
        'permission-checks': { enabled: true, severity: 'error' },
        'resource-access': { enabled: true, severity: 'warning' },
        'rate-limit-enforcement': { enabled: true, severity: 'warning' },
        'audit-logging': { enabled: true, severity: 'error' },
        'fox-streaming-protection': { enabled: true, severity: 'error' },
        'conviva-validation': { enabled: true, severity: 'warning' },
        'har-security': { enabled: true, severity: 'error' }
      },
      foxCorp: {
        streamingAssets: true,
        convivaIntegration: true,
        harValidation: true,
        auditLevel: 'comprehensive'
      },
      ignorePatterns: [
        'node_modules/**',
        'dist/**',
        '*.test.ts',
        '*.spec.ts'
      ],
      severity: {
        error: 2,
        warning: 1
      }
    };
  }

  private mergeConfigs(defaultConfig: MCPSecConfig, userConfig: any): MCPSecConfig {
    return {
      ...defaultConfig,
      ...userConfig,
      rules: {
        ...defaultConfig.rules,
        ...userConfig.rules
      },
      foxCorp: {
        ...defaultConfig.foxCorp,
        ...userConfig.foxCorp
      }
    };
  }

  public getConfig(): MCPSecConfig {
    return this.config;
  }
}