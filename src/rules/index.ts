// Export all rules for the analyzer to use
export { foxStreamingProtection } from './fox-streaming/streaming-protection';
export { injectionDetection } from './input-validation/injection-detection';
export { auditLoggingRequirements } from './audit/logging-requirements';

// Import and export other rules as they're created
import { MCPSecurityRule } from '../core/types';
import { foxStreamingProtection } from './fox-streaming/streaming-protection';
import { injectionDetection } from './input-validation/injection-detection';
import { auditLoggingRequirements } from './audit/logging-requirements';

// Authentication rules
export { authRequired } from './authentication/auth-required';
export { roleValidation } from './authentication/role-validation';
// Removed redundant imports
// Removed redundant imports

// Input validation rules
export { sanitizationRequired } from './input-validation/sanitization';
export { parameterValidation } from './input-validation/parameter-validation';
// Removed redundant imports
// Removed redundant imports

// Authorization rules
export { permissionChecks } from './authorization/permission-checks';
export { resourceAccess } from './authorization/resource-access';
// Removed redundant imports
// Removed redundant imports

// Rate limiting rules
export { rateLimitEnforcement } from './rate-limiting/rate-limit-enforcement';
// Removed redundant imports

// Conviva and HAR specific rules (for Fox Corp)
export { convivaValidation } from './fox-streaming/conviva-validation';
export { harSecurity } from './fox-streaming/har-security';
// Removed redundant imports
// Removed redundant imports

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