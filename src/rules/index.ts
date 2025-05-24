// Import all rules for the analyzer to use
import { foxStreamingProtection } from './fox-streaming/streaming-protection';
import { injectionDetection } from './input-validation/injection-detection';
import { auditLoggingRequirements } from './audit/logging-requirements';

// Import and export other rules as they're created
import { MCPSecurityRule } from '../core/types';

// Authentication rules
import { authRequired } from './authentication/auth-required';
import { roleValidation } from './authentication/role-validation';

// Input validation rules
import { sanitizationRequired } from './input-validation/sanitization';
import { parameterValidation } from './input-validation/parameter-validation';

// Authorization rules
import { permissionChecks } from './authorization/permission-checks';
import { resourceAccess } from './authorization/resource-access';

// Rate limiting rules
import { rateLimitEnforcement } from './rate-limiting/rate-limit-enforcement';

// Conviva and HAR specific rules (for Fox Corp)
import { convivaValidation } from './fox-streaming/conviva-validation';
import { harSecurity } from './fox-streaming/har-security';

export {
  foxStreamingProtection,
  injectionDetection,
  auditLoggingRequirements,
  authRequired,
  roleValidation,
  sanitizationRequired,
  parameterValidation,
  permissionChecks,
  resourceAccess,
  rateLimitEnforcement,
  convivaValidation,
  harSecurity
};

export function getAllRules(): MCPSecurityRule[] {
  return [
    foxStreamingProtection,
    injectionDetection,
    auditLoggingRequirements,
    authRequired,
    roleValidation,
    sanitizationRequired,
    parameterValidation,
    permissionChecks,
    resourceAccess,
    rateLimitEnforcement,
    convivaValidation,
    harSecurity
  ];
}
