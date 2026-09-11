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
 * RESOLVED AT INTEGRATION (conflict 2: permissive vs strict).
 *
 * Lane C wrote this harness against the pre-fix engine, where 'permissive' was
 * the only mode that returned a MASKED identifiable resource: 'strict' blocked
 * it and 'trusted'/disabled short-circuited before masking ever ran.
 *
 * Lane E settled the post-fix behaviour and its verdict governs here.
 * handleIdentifiableResource no longer has any unmasked-allow path, so 'strict'
 * now returns a properly MASKED identifiable resource for a privileged user.
 * Lane B independently made 'permissive' unreachable from any valid
 * PhiGuardConfig (ENGINE_MODE_BY_GUARD_MODE has no entry for it).
 *
 * The default is therefore 'strict' -- the mode production can actually reach.
 * A caller may still pass 'permissive' explicitly to exercise that engine
 * branch, but no regression test should depend on it by default.
 */
export function createAuthEngine(
  mode: PHIProtectionConfig['mode'] = 'strict'
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
