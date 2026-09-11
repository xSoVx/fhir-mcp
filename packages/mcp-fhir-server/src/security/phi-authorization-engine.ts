import {
  PHILevel,
  PHIClassificationResult,
  AuthorizationResult,
  MaskingRule,
  User,
  PHIProtectionConfig,
  PHIProtectionError,
  EmergencyAccessGrant,
  AuditMetadata
} from '../types/phi-types.js';
import { PHIClassifier } from './phi-classifier.js';
import { PHIMaskingEngine } from './phi-masking-engine.js';
import { AuditLogger } from './audit-logger.js';

/* ==========================================================================
 * Structural masking invariant
 * --------------------------------------------------------------------------
 * INVARIANT: an authorization result that says `allowed: true` for a resource
 * classified IDENTIFIABLE or more sensitive MUST carry `requiresMasking: true`
 * and a NON-EMPTY `maskingRules` array.
 *
 * This is enforced in three layers, strongest first:
 *
 *   1. TYPE       - `PHIAccessDecision` has no variant that can express
 *                   "allow, no masking" for a PHI-bearing level. The only
 *                   unmasked-allow variants are `allow-unmasked-non-phi`
 *                   (whose `phiLevel` field has the literal type
 *                   `PHILevel.NONE`, so it cannot be constructed for any other
 *                   level) and `allow-bypass` (two enumerated, audited
 *                   break-glass routes). `allow-masked` carries a non-empty
 *                   TUPLE type, so `[]` is a compile error.
 *   2. REFINEMENT - rule arrays arriving from the classifier have a length the
 *                   compiler cannot know. `allowMaskedOrDeny()` is the only
 *                   way to narrow one into the tuple type, and it returns a
 *                   DENY decision when the array is empty. Fail closed.
 *   3. RUNTIME    - `assertMaskingInvariant()` re-checks the finished
 *                   `AuthorizationResult` on every exit from
 *                   `authorizeResourceAccess`, so a future hand-written object
 *                   literal that sidesteps the constructors still throws
 *                   rather than leaking.
 *
 * There is no layer 4 ("a comment asking the next author to be careful").
 * ========================================================================== */

/** Sensitivity ordering. Higher rank = more sensitive. */
export const PHI_SENSITIVITY_RANK: Readonly<Record<PHILevel, number>> = {
  [PHILevel.NONE]: 0,
  [PHILevel.MINIMAL]: 1,
  [PHILevel.IDENTIFIABLE]: 2,
  [PHILevel.RESTRICTED]: 3
};

/**
 * True when a PHI level may never be returned unmasked.
 * An unrecognised level is treated as maximally sensitive (fail closed).
 */
export function requiresMandatoryMasking(phiLevel: PHILevel): boolean {
  const rank = PHI_SENSITIVITY_RANK[phiLevel];
  if (typeof rank !== 'number') {
    return true;
  }
  return rank >= PHI_SENSITIVITY_RANK[PHILevel.IDENTIFIABLE];
}

/** A masking rule list the type system knows is non-empty. */
export type NonEmptyMaskingRules = readonly [MaskingRule, ...MaskingRule[]];

export function isNonEmptyMaskingRules(
  rules: readonly MaskingRule[] | undefined | null
): rules is NonEmptyMaskingRules {
  return Array.isArray(rules) && rules.length > 0;
}

/** The engine's own mode vocabulary (distinct from PhiGuardConfig.mode). */
export type EngineMode = 'strict' | 'permissive' | 'audit-only';

export const ENGINE_MODES: readonly EngineMode[] = ['strict', 'permissive', 'audit-only'];

/**
 * Parse a configured mode string. Returns null for anything unrecognised so
 * that callers must handle it - there is no "default to permissive".
 */
export function resolveEngineMode(raw: unknown): EngineMode | null {
  switch (raw) {
    case 'strict':
      return 'strict';
    case 'permissive':
      return 'permissive';
    case 'audit-only':
      return 'audit-only';
    default:
      return null;
  }
}

/** The two enumerated routes that may return PHI unmasked. Both are audited. */
export type AccessBypass = 'protection-disabled' | 'emergency-grant';

export type PHIAccessDecision =
  | {
      readonly kind: 'deny';
      readonly reason: string;
      readonly message: string;
    }
  | {
      readonly kind: 'allow-unmasked-non-phi';
      /** Literal type: this variant is unconstructible for any other level. */
      readonly phiLevel: PHILevel.NONE;
    }
  | {
      readonly kind: 'allow-masked';
      readonly maskingRules: NonEmptyMaskingRules;
    }
  | {
      readonly kind: 'allow-bypass';
      readonly bypass: AccessBypass;
      readonly reason: string;
    };

export function denyAccess(reason: string, message: string): PHIAccessDecision {
  return { kind: 'deny', reason, message };
}

/**
 * The ONLY unmasked allow for a classified resource. The parameter type is the
 * enum member `PHILevel.NONE`, so `allowNonPhi(PHILevel.IDENTIFIABLE)` does not
 * compile.
 */
export function allowNonPhi(phiLevel: PHILevel.NONE): PHIAccessDecision {
  return { kind: 'allow-unmasked-non-phi', phiLevel };
}

/**
 * Refinement boundary. Rules of unknown length go in; either a provably
 * non-empty allow-decision or a deny comes out. Never an unmasked allow.
 */
export function allowMaskedOrDeny(
  rules: readonly MaskingRule[] | undefined | null,
  phiLevel: PHILevel
): PHIAccessDecision {
  if (!isNonEmptyMaskingRules(rules)) {
    return denyAccess(
      'MASKING_RULES_UNAVAILABLE',
      `Access to a ${phiLevel} resource requires masking, but no masking rules were produced for it`
    );
  }
  return { kind: 'allow-masked', maskingRules: rules };
}

export function allowBypass(bypass: AccessBypass, reason: string): PHIAccessDecision {
  return { kind: 'allow-bypass', bypass, reason };
}

/** Project a decision onto the wire type consumed by PhiGuard. */
export function decisionToAuthorizationResult(
  decision: PHIAccessDecision,
  auditMetadata: AuditMetadata
): AuthorizationResult {
  switch (decision.kind) {
    case 'deny':
      auditMetadata.accessGranted = false;
      return {
        allowed: false,
        reason: decision.reason,
        message: decision.message,
        auditMetadata
      };

    case 'allow-unmasked-non-phi':
      auditMetadata.accessGranted = true;
      return { allowed: true, auditMetadata };

    case 'allow-masked':
      auditMetadata.accessGranted = true;
      return {
        allowed: true,
        requiresMasking: true,
        maskingRules: [...decision.maskingRules],
        auditMetadata
      };

    case 'allow-bypass':
      auditMetadata.accessGranted = true;
      auditMetadata.phiMaskingBypass = decision.bypass;
      return { allowed: true, reason: decision.reason, auditMetadata };

    default: {
      // Exhaustiveness: a new variant added without a case is a compile error.
      const unreachable: never = decision;
      return {
        allowed: false,
        reason: 'UNKNOWN_DECISION_KIND',
        message: `Unrecognised authorization decision: ${JSON.stringify(unreachable)}`,
        auditMetadata
      };
    }
  }
}

/**
 * Runtime backstop for layer 3. Throws rather than returning, so a violation
 * surfaces as a denied request (PhiGuard catches and reports unauthorized)
 * instead of a silently unmasked resource.
 */
export function assertMaskingInvariant(
  result: AuthorizationResult,
  phiLevel: PHILevel,
  decision?: PHIAccessDecision
): void {
  if (!result.allowed) {
    return;
  }
  if (!requiresMandatoryMasking(phiLevel)) {
    return;
  }
  if (decision?.kind === 'allow-bypass') {
    return;
  }
  if (result.requiresMasking === true && isNonEmptyMaskingRules(result.maskingRules)) {
    return;
  }
  throw new PHIProtectionError(
    'PHI masking invariant violated: an allow-decision for a ' +
      `${phiLevel} resource carried no masking rules. Refusing to return it.`,
    phiLevel,
    result.auditMetadata?.resourceType ?? 'unknown',
    result.auditMetadata?.operation ?? 'unknown'
  );
}

/**
 * PHI Authorization Engine
 * Core component that enforces PHI protection policies and access controls
 */
export class PHIAuthorizationEngine {
  private phiClassifier: PHIClassifier;
  private maskingEngine: PHIMaskingEngine;
  private auditLogger: AuditLogger;
  private emergencyGrants = new Map<string, EmergencyAccessGrant>();
  private config: PHIProtectionConfig;
  private grantCleanupTimer: ReturnType<typeof setInterval>;

  constructor(
    config: PHIProtectionConfig,
    auditLogger: AuditLogger
  ) {
    this.config = config;
    this.phiClassifier = new PHIClassifier();
    this.maskingEngine = new PHIMaskingEngine();
    this.auditLogger = auditLogger;

    // Clean up expired emergency grants every 5 minutes
    this.grantCleanupTimer = setInterval(() => this.cleanupExpiredGrants(), 5 * 60 * 1000);
    // Do not hold the process (or a test runner) open for a housekeeping timer.
    (this.grantCleanupTimer as unknown as { unref?: () => void }).unref?.();
  }

  /**
   * Main authorization check for resource access
   */
  public async authorizeResourceAccess(
    user: User | undefined,
    resource: any,
    operation: string,
    sessionId: string = 'unknown'
  ): Promise<AuthorizationResult> {
    const startTime = Date.now();

    try {
      // Classify the resource
      const classification = this.phiClassifier.classifyResource(resource);

      // Create audit metadata
      const auditMetadata: AuditMetadata = {
        timestamp: new Date(),
        userId: user?.id,
        sessionId,
        resourceType: resource.resourceType,
        resourceId: resource.id,
        operation,
        phiLevel: classification.phiLevel,
        accessGranted: false // Will be updated based on decision
      };

      const decision = this.decide(user, resource, classification, auditMetadata);
      const authResult = decisionToAuthorizationResult(decision, auditMetadata);

      // Layer 3: nothing leaves this method without satisfying the invariant.
      assertMaskingInvariant(authResult, classification.phiLevel, decision);

      await this.auditLogger.log({
        operation: decision.kind === 'allow-bypass' && decision.bypass === 'emergency-grant'
          ? `phi_emergency_access_${operation}`
          : `phi_authorization_${operation}`,
        success: authResult.allowed,
        duration: Date.now() - startTime,
        metadata: auditMetadata,
        error: authResult.allowed ? undefined : authResult.reason
      });

      return authResult;

    } catch (error) {
      // Log authorization errors
      await this.auditLogger.log({
        operation: `phi_authorization_${operation}`,
        success: false,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      throw error;
    }
  }

  /**
   * Single decision funnel. Every route to an allow passes through here, and
   * every route produces a PHIAccessDecision - never a bare object literal.
   */
  private decide(
    user: User | undefined,
    resource: any,
    classification: PHIClassificationResult,
    auditMetadata: AuditMetadata
  ): PHIAccessDecision {
    // Bypass 1: PHI protection globally disabled by configuration.
    if (!this.config.enabled) {
      return allowBypass('protection-disabled', 'PHI_PROTECTION_DISABLED');
    }

    // Bypass 2: an active, audited break-glass grant.
    const emergencyGrant = this.checkEmergencyAccess(user, resource);
    if (emergencyGrant) {
      auditMetadata.emergencyAccess = true;
      auditMetadata.justification = emergencyGrant.justification;
      return allowBypass('emergency-grant', 'EMERGENCY_ACCESS_GRANTED');
    }

    return this.applyPHIProtectionRules(user, classification);
  }

  /**
   * Apply PHI protection rules based on classification
   */
  private applyPHIProtectionRules(
    user: User | undefined,
    classification: PHIClassificationResult
  ): PHIAccessDecision {

    // A configuration whose mode cannot be interpreted has no defined security
    // posture. Deny everything except genuinely non-PHI resources, rather than
    // falling through to whichever branch happens to come next.
    if (classification.phiLevel !== PHILevel.NONE && resolveEngineMode(this.config.mode) === null) {
      return denyAccess(
        'UNRECOGNISED_PHI_MODE',
        `Unrecognised PHI protection mode "${String(this.config.mode)}"; ` +
          `expected one of: ${ENGINE_MODES.join(' | ')}`
      );
    }

    switch (classification.phiLevel) {
      case PHILevel.NONE:
        // Always allow access to non-PHI resources
        return allowNonPhi(PHILevel.NONE);

      case PHILevel.MINIMAL:
        // Allow with masking for minimal PHI
        return allowMaskedOrDeny(classification.requiredMasking, PHILevel.MINIMAL);

      case PHILevel.IDENTIFIABLE:
        return this.handleIdentifiableResource(user, classification);

      case PHILevel.RESTRICTED:
        return this.handleRestrictedResource(user, classification);

      default: {
        // Exhaustiveness check plus fail-closed runtime behaviour for a value
        // that is not a member of the enum at all.
        const unreachable: never = classification.phiLevel;
        return denyAccess(
          'UNKNOWN_PHI_LEVEL',
          `Unknown PHI level: ${String(unreachable)}`
        );
      }
    }
  }

  /**
   * Handle access to patient-identifiable resources.
   *
   * Every allow returned here is an `allow-masked` decision. There is no
   * branch that can return an unmasked allow for an IDENTIFIABLE resource -
   * the return type makes it unrepresentable.
   */
  private handleIdentifiableResource(
    user: User | undefined,
    classification: PHIClassificationResult
  ): PHIAccessDecision {

    const mode = resolveEngineMode(this.config.mode);

    // Unrecognised mode => deny. Never "fall through to allow".
    if (mode === null) {
      return denyAccess(
        'UNRECOGNISED_PHI_MODE',
        `Unrecognised PHI protection mode "${String(this.config.mode)}"; ` +
          `expected one of: ${ENGINE_MODES.join(' | ')}`
      );
    }

    switch (mode) {
      case 'strict':
        // Strict blocks anyone without patient-level access, and masks
        // everyone else. It no longer returns raw PHI to privileged users.
        if (!this.hasPatientLevelAccess(user)) {
          return denyAccess(
            'PHI_PROTECTION_ENABLED',
            'Access to patient-identifiable resources blocked in PHI protection mode'
          );
        }
        return allowMaskedOrDeny(classification.requiredMasking, PHILevel.IDENTIFIABLE);

      case 'permissive':
        // Permissive does not gate on permissions, but still masks.
        return allowMaskedOrDeny(classification.requiredMasking, PHILevel.IDENTIFIABLE);

      case 'audit-only':
        // "Audit only" means "do not block", not "return PHI in the clear".
        return allowMaskedOrDeny(classification.requiredMasking, PHILevel.IDENTIFIABLE);

      default: {
        const unreachable: never = mode;
        return denyAccess(
          'UNRECOGNISED_PHI_MODE',
          `Unrecognised PHI protection mode: ${String(unreachable)}`
        );
      }
    }
  }

  /**
   * Handle access to restricted resources
   */
  private handleRestrictedResource(
    user: User | undefined,
    classification: PHIClassificationResult
  ): PHIAccessDecision {

    // Always require special permissions for restricted resources
    if (!this.hasRestrictedAccess(user)) {
      return denyAccess(
        'RESTRICTED_RESOURCE',
        'Special permissions required for restricted resources'
      );
    }

    return allowMaskedOrDeny(classification.requiredMasking, PHILevel.RESTRICTED);
  }

  /**
   * Check if user has patient-level access permissions
   */
  private hasPatientLevelAccess(user: User | undefined): boolean {
    if (!user) return false;

    return user.permissions.includes('patient:read') ||
           user.permissions.includes('patient:*') ||
           user.roles.includes('clinician') ||
           user.roles.includes('admin') ||
           user.phiAccessLevel === PHILevel.IDENTIFIABLE;
  }

  /**
   * Check if user has restricted resource access
   */
  private hasRestrictedAccess(user: User | undefined): boolean {
    if (!user) return false;

    return user.permissions.includes('restricted:read') ||
           user.permissions.includes('admin:*') ||
           user.roles.includes('admin') ||
           user.phiAccessLevel === PHILevel.RESTRICTED;
  }
  /**
   * Request emergency access to PHI resources
   */
  public async requestEmergencyAccess(
    user: User,
    resourceType: string,
    resourceId: string,
    justification: string
  ): Promise<EmergencyAccessGrant> {

    if (!this.config.allowEmergencyAccess) {
      throw new PHIProtectionError(
        'Emergency access is not enabled',
        PHILevel.IDENTIFIABLE,
        resourceType,
        'emergency_access'
      );
    }

    if (!user.emergencyAccessEnabled) {
      throw new PHIProtectionError(
        'User does not have emergency access permissions',
        PHILevel.IDENTIFIABLE,
        resourceType,
        'emergency_access'
      );
    }

    // Validate emergency justification
    if (!this.validateEmergencyJustification(justification)) {
      throw new PHIProtectionError(
        'Invalid emergency access justification',
        PHILevel.IDENTIFIABLE,
        resourceType,
        'emergency_access'
      );
    }

    // Create emergency access grant
    const grant: EmergencyAccessGrant = {
      grantId: this.generateGrantId(),
      userId: user.id,
      resourceId,
      resourceType,
      grantedAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.emergencyAccessDurationMinutes * 60 * 1000),
      justification,
      auditTrail: true
    };

    // Store the grant
    this.emergencyGrants.set(grant.grantId, grant);

    // Log emergency access request
    await this.auditLogger.log({
      operation: 'phi_emergency_access_granted',
      success: true,
      metadata: {
        userId: user.id,
        resourceType,
        resourceId,
        grantId: grant.grantId,
        justification,
        expiresAt: grant.expiresAt
      }
    });

    return grant;
  }

  /**
   * Check for emergency access override
   */
  private checkEmergencyAccess(
    user: User | undefined,
    resource: any
  ): EmergencyAccessGrant | null {

    if (!user || !this.config.allowEmergencyAccess) {
      return null;
    }

    // Find active emergency grants for this user and resource
    for (const grant of this.emergencyGrants.values()) {
      if (grant.userId === user.id &&
          grant.resourceType === resource.resourceType &&
          (grant.resourceId === resource.id || grant.resourceId === '*') &&
          grant.expiresAt > new Date()) {
        return grant;
      }
    }

    return null;
  }

  /**
   * Validate emergency access justification
   */
  private validateEmergencyJustification(justification: string): boolean {
    if (!justification || justification.length < 10) {
      return false;
    }

    // Check for valid emergency keywords
    const emergencyKeywords = [
      'emergency',
      'urgent',
      'critical',
      'life-threatening',
      'immediate care',
      'patient safety'
    ];

    const lowerJustification = justification.toLowerCase();
    return emergencyKeywords.some(keyword =>
      lowerJustification.includes(keyword)
    );
  }

  /**
   * Generate unique grant ID
   */
  private generateGrantId(): string {
    return `phi_grant_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clean up expired emergency grants
   */
  private cleanupExpiredGrants(): void {
    const now = new Date();
    for (const [grantId, grant] of this.emergencyGrants.entries()) {
      if (grant.expiresAt <= now) {
        this.emergencyGrants.delete(grantId);
      }
    }
  }

  /**
   * Apply masking to resource based on authorization result.
   *
   * Previously this silently returned the raw resource whenever
   * `maskingRules` was missing. It now fails closed: if masking was demanded
   * the rules must exist, or nothing is returned at all.
   */
  public applyMasking(resource: any, authResult: AuthorizationResult): any {
    if (!authResult.requiresMasking) {
      return resource;
    }

    const rules = authResult.maskingRules;
    if (!isNonEmptyMaskingRules(rules)) {
      throw new PHIProtectionError(
        'Masking was required but no masking rules were supplied; ' +
          'refusing to return the resource unmasked',
        authResult.auditMetadata?.phiLevel ?? PHILevel.RESTRICTED,
        authResult.auditMetadata?.resourceType ?? 'unknown',
        authResult.auditMetadata?.operation ?? 'unknown'
      );
    }

    return this.maskingEngine.applyMasking(resource, [...rules]);
  }

  /**
   * Update PHI protection configuration
   */
  public updateConfig(newConfig: Partial<PHIProtectionConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get current PHI protection status
   */
  public getStatus(): {
    enabled: boolean;
    mode: string;
    modeRecognised: boolean;
    activeEmergencyGrants: number;
    classificationCacheSize: number;
  } {
    return {
      enabled: this.config.enabled,
      mode: this.config.mode,
      modeRecognised: resolveEngineMode(this.config.mode) !== null,
      activeEmergencyGrants: this.emergencyGrants.size,
      classificationCacheSize: this.phiClassifier.getCacheStats().size
    };
  }

  /**
   * Clear all caches and reset state
   */
  public reset(): void {
    this.phiClassifier.clearCache();
    this.maskingEngine.clearCache();
    this.emergencyGrants.clear();
  }

  /**
   * Release the housekeeping timer. Safe to call more than once.
   */
  public dispose(): void {
    clearInterval(this.grantCleanupTimer);
    this.reset();
  }
}