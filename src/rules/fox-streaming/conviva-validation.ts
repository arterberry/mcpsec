import { MCPSecurityRule, AnalysisContext, RuleViolation } from '../../core/types';

export const convivaValidation = {
  id: 'conviva-validation',
  name: 'Conviva Integration Validation',
  description: 'Validates Conviva integration for streaming tools',
  severity: 'warning',
  category: 'fox-streaming',
  mandatory: false,

  async check(context: AnalysisContext): Promise<RuleViolation[]> {
    if (!context.config.foxCorp?.convivaIntegration) {
      return [];
    }
    return [];
  }
} as MCPSecurityRule;
