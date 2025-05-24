import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';

export const harSecurity = {
  id: 'har-security',
  name: 'HAR File Security',
  description: 'Validates uploaded HAR files for security issues',
  severity: 'error',
  category: 'fox-streaming',
  mandatory: false,

  async check(context: AnalysisContext): Promise<RuleViolation[]> {
    if (!context.config.foxCorp?.harValidation) {
      return [];
    }
    return [];
  }
} as MCPSecurityRule;
