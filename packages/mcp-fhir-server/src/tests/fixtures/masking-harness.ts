import { expect } from '@jest/globals';
import { PhiGuard } from '../../security/phi-guard.js';
import { PHIAuthorizationEngine } from '../../security/phi-authorization-engine.js';
import { AuditLogger } from '../../security/audit-logger.js';
import { PHILevel, type User, type PHIProtectionConfig } from '../../types/phi-types.js';
import { serialise } from './canary.js';

/**
 * Shared masking harness for the canary suite and the golden corpus.
 *
 * Its whole job is to make a canary assertion impossible to pass vacuously.
 */

export interface MaskingOutcome {
  authorized: boolean;
  maskedResource?: unknown;
  reason?: string;
  /** True only if the pipeline reported that it actually applied masking. */
  maskingApplied: boolean;
}

/**
 * THE ANTI-VACUITY GUARD. Call this before every `not.toContain(CANARY)`.
 *
 * Why this exists
 * ---------------
 * In safe mode `Patient` is IDENTIFIABLE and
 * phi-authorization-engine.ts:208-218 BLOCKS it outright when no user is
 * supplied -- which is exactly what fhir-tools.ts:234 and :310 do. The call
 * then returns `{ authorized: false }` with NO `maskedResource`, and
 *
 *     expect(JSON.stringify(result.maskedResource)).not.toContain(CANARY)
 *
 * passes. Not because anything was masked, but because it is asserting over
 * `JSON.stringify(undefined)` -- an object that never held the value. The test
 * is green, the reviewer is satisfied, and the masking path was never
 * executed.
 *
 * A bare not.toContain on a possibly-absent object is a FALSE GATE. Treat one
 * as a defect in review.
 */
export function expectMaskingActuallyRan(outcome: MaskingOutcome): void {
  expect(outcome.authorized).toBe(true);
  expect(outcome.maskedResource).toBeDefined();
}

/**
 * Stricter variant: also require that the pipeline said it applied masking.
 *
 * `authorized === true` is not sufficient on its own. In strict mode a user
 * WITH patient-level access falls through handleIdentifiableResource to the
 * default branch at phi-authorization-engine.ts:240-255, which returns
 * `allowed: true` and NO `requiresMasking`. PhiGuard then sets
 * `maskedResource = resource` -- the raw, unmasked original. Both of the
 * assertions above hold, and the resource is untouched.
 *
 * So `expectMaskingActuallyRan` proves the object exists; this proves the
 * masking engine ran on it.
 */
export function expectMaskingEngineRan(outcome: MaskingOutcome): void {
  expectMaskingActuallyRan(outcome);
  expect(outcome.maskingApplied).toBe(true);
}

/** Assert a value appears nowhere in the serialised output. */
export function expectNotLeaked(
  outcome: MaskingOutcome,
  forms: ReadonlyArray<{ label: string; value: string }>
): void {
  const blob = serialise(outcome.maskedResource);
  for (const form of forms) {
    expect(blob.includes(form.value)).toBe(false);
  }
}

/** A clinician with patient-level access. */
export function clinician(): User {
  return {
    id: 'clinician-canary',
    roles: ['clinician'],
    permissions: ['patient:read'],
    phiAccessLevel: PHILevel.IDENTIFIABLE
  } as User;
}

/** A user cleared for RESTRICTED resources as well. */
export function restrictedAccessUser(): User {
  return {
    id: 'admin-canary',
    roles: ['admin'],
    permissions: ['patient:*', 'restricted:read'],
    phiAccessLevel: PHILevel.RESTRICTED
  } as User;
}

/**
 * Mask through the PUBLIC path -- the same `PhiGuard.authorizeAndMaskResource`
 * that fhir-tools.ts calls. This is the end-to-end contract.
 */
export async function maskViaGuard(
  resource: unknown,
  options: { user?: User; mode?: 'safe' | 'trusted' } = {}
): Promise<MaskingOutcome> {
  // Passing false disables audit output -- the canary must not be judged by what a
  // logger did or did not print, and the engine logs every decision to stdout.
  const auditLogger = new AuditLogger(false);
  const guard = new PhiGuard(
    { mode: options.mode ?? 'safe', maskFields: [], removeFields: [] },
    auditLogger
  );

  const result = await guard.authorizeAndMaskResource(
    resource as never,
    options.user,
    'read',
    'canary-session'
  );

  return {
    authorized: result.authorized,
    maskedResource: result.maskedResource,
    reason: result.reason,
    // PhiGuard does not report whether masking ran, so infer it: if the
    // returned object is IDENTICAL by reference to the input, nothing was
    // applied -- applyMasking deep-clones (phi-masking-engine.ts:20).
    maskingApplied:
      result.maskedResource !== undefined && result.maskedResource !== resource
  };
}

/**
 * Mask through the ENGINE directly, in a configuration where masking is
 * guaranteed to run.
 *
 * This is not a convenience shortcut -- it is load-bearing. Today there is no
 * PhiGuard configuration that masks an IDENTIFIABLE resource at all:
 *
 *   * no user            -> strict mode BLOCKS (authorized: false)
 *   * clinician user     -> allowed, but requiresMasking is never set, so the
 *                           RAW resource comes back
 *   * mode 'trusted'     -> `enabled: false`, short-circuits entirely
 *
 * Engine mode 'permissive' -- the one mode that returns a MASKED identifiable
 * resource -- is unreachable from any valid PhiGuardConfig, because
 * phi-guard.ts:18 maps 'safe' to 'strict' and everything else to 'permissive'
 * while `enabled: config.mode !== 'trusted'` kills the 'trusted' case first.
 *
 * Driving the engine directly lets the canary test the MASKING RULES on their
 * own, separately from the authorization hole above. Without it, every canary
 * case would fail for the same single upstream reason and the suite would tell
 * the later lanes nothing about their own surfaces.
 */
export async function maskViaEngine(
  resource: unknown,
  options: { user?: User; mode?: PHIProtectionConfig['mode'] } = {}
): Promise<MaskingOutcome> {
  // Passing false disables audit output -- the canary must not be judged by what a
  // logger did or did not print, and the engine logs every decision to stdout.
  const auditLogger = new AuditLogger(false);
  const config: PHIProtectionConfig = {
    enabled: true,
    mode: options.mode ?? 'permissive',
    allowEmergencyAccess: false,
    emergencyAccessDurationMinutes: 30,
    auditAllAccess: false,
    defaultMaskingRules: [],
    resourceOverrides: {}
  };

  const engine = new PHIAuthorizationEngine(config, auditLogger);
  const authResult = await engine.authorizeResourceAccess(
    options.user,
    resource,
    'read',
    'canary-session'
  );

  if (!authResult.allowed) {
    return {
      authorized: false,
      reason: authResult.message ?? authResult.reason,
      maskingApplied: false
    };
  }

  const masked = engine.applyMasking(resource, authResult);

  return {
    authorized: true,
    maskedResource: masked,
    maskingApplied: Boolean(authResult.requiresMasking) && masked !== resource
  };
}