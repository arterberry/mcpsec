import { RuleViolation, MCPSecConfig } from './types';
import { writeFileSync } from 'fs';
import chalk from 'chalk';

export class SecurityReporter {
  constructor(private config: MCPSecConfig) {}

  async generateReport(violations: RuleViolation[], format: string): Promise<string> {
    switch (format.toLowerCase()) {
      case 'json':
        return this.generateJSONReport(violations);
      case 'junit':
        return this.generateJUnitReport(violations);
      case 'sarif':
        return this.generateSARIFReport(violations);
      case 'text':
      default:
        return this.generateTextReport(violations);
    }
  }

  async writeReport(report: string, outputPath: string, format: string): Promise<void> {
    writeFileSync(outputPath, report, 'utf-8');
  }

  private generateTextReport(violations: RuleViolation[]): string {
    if (violations.length === 0) {
      return chalk.green('✅ No security violations found!\n');
    }

    let report = chalk.bold.red('\n🚨 Security Violations Found:\n\n');

    // Group violations by severity
    const errorViolations = violations.filter(v => v.severity === 'error');
    const warningViolations = violations.filter(v => v.severity === 'warning');
    const infoViolations = violations.filter(v => v.severity === 'info');

    // Errors
    if (errorViolations.length > 0) {
      report += chalk.red.bold(`\n🔴 ERRORS (${errorViolations.length}):\n`);
      for (const violation of errorViolations) {
        report += this.formatViolation(violation, 'error');
      }
    }

    // Warnings
    if (warningViolations.length > 0) {
      report += chalk.yellow.bold(`\n🟡 WARNINGS (${warningViolations.length}):\n`);
      for (const violation of warningViolations) {
        report += this.formatViolation(violation, 'warning');
      }
    }

    // Info
    if (infoViolations.length > 0) {
      report += chalk.blue.bold(`\n🔵 INFO (${infoViolations.length}):\n`);
      for (const violation of infoViolations) {
        report += this.formatViolation(violation, 'info');
      }
    }

    return report;
  }

  private formatViolation(violation: RuleViolation, severity: string): string {
    const severityColor = severity === 'error' ? chalk.red : 
                         severity === 'warning' ? chalk.yellow : chalk.blue;
    
    let formatted = `\n${severityColor('●')} ${chalk.bold(violation.message)}\n`;
    formatted += `  Rule: ${chalk.cyan(violation.ruleId)}\n`;
    
    if (violation.file) {
      const location = violation.line ? `${violation.file}:${violation.line}` : violation.file;
      formatted += `  Location: ${chalk.gray(location)}\n`;
    }
    
    if (violation.evidence) {
      formatted += `  Evidence: ${chalk.gray(violation.evidence)}\n`;
    }
    
    if (violation.fix) {
      formatted += `  Fix: ${chalk.green(violation.fix)}\n`;
    }
    
    return formatted + '\n';
  }

  private generateJSONReport(violations: RuleViolation[]): string {
    const report = {
      timestamp: new Date().toISOString(),
      tool: 'MCPSec',
      version: '1.0.0',
      summary: {
        total: violations.length,
        errors: violations.filter(v => v.severity === 'error').length,
        warnings: violations.filter(v => v.severity === 'warning').length,
        info: violations.filter(v => v.severity === 'info').length
      },
      violations: violations
    };

    return JSON.stringify(report, null, 2);
  }

  private generateJUnitReport(violations: RuleViolation[]): string {
    const errorCount = violations.filter(v => v.severity === 'error').length;
    const warningCount = violations.filter(v => v.severity === 'warning').length;
    
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += `<testsuite name="MCPSec Security Analysis" tests="${violations.length}" failures="${errorCount}" errors="0" skipped="${warningCount}">\n`;
    
    for (const violation of violations) {
      xml += `  <testcase name="${violation.ruleId}" classname="MCPSec">\n`;
      
      if (violation.severity === 'error') {
        xml += `    <failure message="${this.escapeXml(violation.message)}">\n`;
        xml += `      ${this.escapeXml(violation.evidence || '')}\n`;
        xml += `    </failure>\n`;
      } else if (violation.severity === 'warning') {
        xml += `    <skipped message="${this.escapeXml(violation.message)}"/>\n`;
      }
      
      xml += `  </testcase>\n`;
    }
    
    xml += '</testsuite>\n';
    return xml;
  }

  private generateSARIFReport(violations: RuleViolation[]): string {
    const sarif = {
      version: '2.1.0',
      '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'MCPSec',
            version: '1.0.0',
            informationUri: 'https://github.com/foxcorp/mcpsec'
          }
        },
        results: violations.map(violation => ({
          ruleId: violation.ruleId,
          message: { text: violation.message },
          level: violation.severity === 'error' ? 'error' : 
                 violation.severity === 'warning' ? 'warning' : 'note',
          locations: violation.file ? [{
            physicalLocation: {
              artifactLocation: { uri: violation.file },
              region: violation.line ? { startLine: violation.line } : undefined
            }
          }] : []
        }))
      }]
    };

    return JSON.stringify(sarif, null, 2);
  }

  private escapeXml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
}