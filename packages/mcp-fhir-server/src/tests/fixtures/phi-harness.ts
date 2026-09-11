import { PHIAuthorizationEngine } from '../../security/phi-authorization-engine.js';
import { AuditLogger } from '../../security/audit-logger.js';
import { PHIProtectionConfig, User } from '../../types/phi-types.js';

/**
 * A user that clears both `hasPatientLevelAccess` and `hasRestrictedAccess`.
 *
 * Without one, `handleIdentifiableResource` blocks the request and the result
 * carries no masked resource at all -- which is how a `not.toContain` canary
 * assertion passes vacuously. See `authorizeAndMask` below.
 */
export const AUTHORIZED_USER: User = {
  id: 'test-clinician',
  roles: ['clinician', 'admin'],
  permissions: ['patient:read', 'restricted:read']
};

/**
 * `'permissive'` is the only engine mode that returns a MASKED identifiable
 * resource. `'strict'` blocks it and `'trusted'`/disabled short-circuits before
 * masking, so a masking regression test must run in permissive mode or it
 * tests nothing.
 */
export function createAuthEngine(
  mode: PHIProtectionConfig['mode'] = 'permissive'
): PHIAuthorizationEngine {
  const config: PHIProtectionConfig = {
    enabled: true,
    mode,
    allowEmergencyAccess: false,
    emergencyAccessDurationMinutes: 30,
    auditAllAccess: true,
    defaultMaskingRules: [],
    resourceOverrides: {}
  };
  return new PHIAuthorizationEngine(config, new AuditLogger(false));
}

export interface MaskOutcome {
  authorized: boolean;
  maskedResource: unknown | undefined;
  reason?: string;
}

/**
 * Authorize, then mask. `maskedResource` is left `undefined` when the engine
 * did not actually produce masked output, so a test can prove masking ran
 * before asserting anything about its contents.
 */
export async function authorizeAndMask(
  engine: PHIAuthorizationEngine,
  resource: unknown,
  user: User | undefined = AUTHORIZED_USER
): Promise<MaskOutcome> {
  const result = await engine.authorizeResourceAccess(user, resource, 'read', 'test-session');
  const maskedResource =
    result.allowed && result.requiresMasking ? engine.applyMasking(resource, result) : undefined;
  return { authorized: result.allowed, maskedResource, reason: result.reason };
}

/** Serialize the way the MCP tool path does, so `remove` -> undefined drops out. */
export function serialize(value: unknown): string {
  return JSON.stringify(value);
}
