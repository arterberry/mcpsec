#!/usr/bin/env node

import { Command } from 'commander';
import { MCPSecurityAnalyzer } from '../core/analyzer';
import { ConfigManager } from '../core/config';
import { SecurityReporter } from '../core/reporter';
import { RuleViolation } from '../core/types';
import chalk from 'chalk';
import { readFileSync } from 'fs';
import { join } from 'path';

const program = new Command();
const packageJson = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf-8'));

program
  .name('mcpsec')
  .description('MCP Security Analysis Tool')
  .version(packageJson.version);

program
  .command('analyze')
  .description('Analyze MCP server for security vulnerabilities')
  .argument('<path>', 'Path to MCP server project')
  .option('-c, --config <path>', 'Path to configuration file')
  .option('-f, --format <format>', 'Output format (text|json|junit|sarif)', 'text')
  .option('-o, --output <path>', 'Output file path')
  .option('--fail-on <level>', 'Fail on violation level (error|warning)', 'error')
  .option('--fox-corp', 'Enable Fox Corporation specific rules')
  .option('--streaming', 'Enable streaming asset protection rules')
  .option('--conviva', 'Enable Conviva integration checks')
  .option('--har-validation', 'Enable HAR file validation checks')
  .action(async (projectPath: string, options: any) => {
    try {
      console.log(chalk.blue('🔍 MCPSec - Analyzing MCP Server Security...'));
      console.log(chalk.gray(`Project: ${projectPath}`));

      // Load configuration
      const configManager = ConfigManager.getInstance();
      const config = configManager.loadConfig(projectPath, options.config);

      // Apply CLI overrides
      if (options.foxCorp) {
        config.foxCorp = { ...config.foxCorp!, streamingAssets: true };
      }
      if (options.streaming) {
        config.foxCorp = { ...config.foxCorp!, streamingAssets: true };
      }
      if (options.conviva) {
        config.foxCorp = { ...config.foxCorp!, convivaIntegration: true };
      }
      if (options.harValidation) {
        config.foxCorp = { ...config.foxCorp!, harValidation: true };
      }

      // Create analyzer and run analysis
      const analyzer = new MCPSecurityAnalyzer(config);
      const violations = await analyzer.analyze(projectPath);

      // Generate report
      const reporter = new SecurityReporter(config);
      const report = await reporter.generateReport(violations, options.format);

      // Output results
      if (options.output) {
        await reporter.writeReport(report, options.output, options.format);
        console.log(chalk.green(`✅ Report written to ${options.output}`));
      } else {
        console.log(report);
      }

      // Summary
      const errorCount = violations.filter(v => v.severity === 'error').length;
      const warningCount = violations.filter(v => v.severity === 'warning').length;
      const infoCount = violations.filter(v => v.severity === 'info').length;

      console.log('\n' + chalk.bold('Summary:'));
      console.log(`${chalk.red('Errors:')} ${errorCount}`);
      console.log(`${chalk.yellow('Warnings:')} ${warningCount}`);
      console.log(`${chalk.blue('Info:')} ${infoCount}`);

      // Exit with appropriate code
      const shouldFail = (options.failOn === 'error' && errorCount > 0) ||
                        (options.failOn === 'warning' && (errorCount > 0 || warningCount > 0));

      if (shouldFail) {
        process.exit(1);
      } else {
        console.log(chalk.green('\n✅ Security analysis completed successfully'));
        process.exit(0);
      }

    } catch (error: any) {
      console.error(chalk.red('❌ Analysis failed:'), error.message);
      process.exit(1);
    }
  });

program
  .command('init')
  .description('Initialize MCPSec configuration for Fox Corp project')
  .argument('[path]', 'Project path', '.')
  .option('--template <template>', 'Configuration template (basic|fox-corp|strict)', 'fox-corp')
  .action(async (projectPath: string, options: any) => {
    try {
      const configManager = ConfigManager.getInstance();
      await configManager.initializeConfig(projectPath, options.template);
      console.log(chalk.green('✅ MCPSec configuration initialized'));
    } catch (error: any) {
      console.error(chalk.red('❌ Configuration initialization failed:'), error.message);
      process.exit(1);
    }
  });

program
  .command('rules')
  .description('List available security rules')
  .option('--category <category>', 'Filter by category')
  .option('--mandatory-only', 'Show only mandatory rules')
  .action(async (options: any) => {
    try {
      const { getAllRules } = await import('../rules');
      let rules = getAllRules();

      if (options.category) {
        rules = rules.filter(rule => rule.category === options.category);
      }

      if (options.mandatoryOnly) {
        rules = rules.filter(rule => rule.mandatory);
      }

      console.log(chalk.bold('\nAvailable Security Rules:\n'));

      for (const rule of rules) {
        const mandatoryBadge = rule.mandatory ? chalk.red('[MANDATORY]') : chalk.gray('[OPTIONAL]');
        const severityColor = rule.severity === 'error' ? chalk.red : 
                             rule.severity === 'warning' ? chalk.yellow : chalk.blue;
        
        console.log(`${chalk.bold(rule.name)} ${mandatoryBadge}`);
        console.log(`  ID: ${rule.id}`);
        console.log(`  Category: ${chalk.cyan(rule.category)}`);
        console.log(`  Severity: ${severityColor(rule.severity)}`);
        console.log(`  Description: ${rule.description}`);
        console.log('');
      }

    } catch (error: any) {
      console.error(chalk.red('❌ Failed to list rules:'), error.message);
      process.exit(1);
    }
  });

program
  .command('validate-config')
  .description('Validate MCPSec configuration file')
  .argument('<config>', 'Path to configuration file')
  .action(async (configPath: string) => {
    try {
      const configManager = ConfigManager.getInstance();
      const isValid = await configManager.validateConfig(configPath);
      
      if (isValid) {
        console.log(chalk.green('✅ Configuration is valid'));
      } else {
        console.log(chalk.red('❌ Configuration is invalid'));
        process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red('❌ Configuration validation failed:'), error.message);
      process.exit(1);
    }
  });

if ((require as any).main === module) {
  program.parse();
}

export { program };