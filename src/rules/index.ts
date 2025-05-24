// Import all rules for the analyzer
import { MCPSecurityRule } from '../core/types';

// Fox streaming rules
import { foxStreamingProtection } from './fox-streaming/streaming-protection';
import { convivaValidation } from './fox-streaming/conviva-validation';
import { harSecurity } from './fox-streaming/har-security';

// Input validation rules
import { injectionDetection } from './input-validation/injection-detection';
import { sanitizationRequired } from './input-validation/sanitization';
import { parameterValidation } from './input-validation/parameter-validation';

// Authentication rules
import { authRequired } from './authentication/auth-required';
import { roleValidation } from './authentication/role-validation';

// Authorization rules
import { permissionChecks } from './authorization/permission-checks';
import { resourceAccess } from './authorization/resource-access';

// Rate limiting rules
import { rateLimitEnforcement } from './rate-limiting/rate-limit-enforcement';

// Audit rules
import { auditLoggingRequirements } from './audit/logging-requirements';

// Export all rules
export {
  foxStreamingProtection,
  convivaValidation,
  harSecurity,
  injectionDetection,
  sanitizationRequired,
  parameterValidation,
  authRequired,
  roleValidation,
  permissionChecks,
  resourceAccess,
  rateLimitEnforcement,
  auditLoggingRequirements
};

// Function to get all rules for the analyzer
export function getAllRules(): MCPSecurityRule[] {
  return [
    foxStreamingProtection,
    convivaValidation,
    harSecurity,
    injectionDetection,
    sanitizationRequired,
    parameterValidation,
    authRequired,
    roleValidation,
    permissionChecks,
    resourceAccess,
    rateLimitEnforcement,
    auditLoggingRequirements
  ];
}
