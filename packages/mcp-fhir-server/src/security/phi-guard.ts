import { FhirResource } from '../types/fhir.js';
import { PhiGuardConfig } from '../types/config.js';
import { PHIAuthorizationEngine } from './phi-authorization-engine.js';
import { User, PHIProtectionConfig } from '../types/phi-types.js';
import { AuditLogger } from './audit-logger.js';

/**
 * The complete set of PHI guard modes accepted as *input* configuration.
 *
 * This is deliberately exhaustive and closed. A DLP control must fail at
 * startup on an unrecognised mode rather than silently degrade at runtime,
 * so there is no "default" branch anywhere in this module.
 */
export const PHI_GUARD_MODES = ['safe', 'trusted'] as const;
export type PhiGuardMode = (typeof PHI_GUARD_MODES)[number];

/**
 * Engine mode resolution.
 *
 * Note that neither entry maps to 'permissive'. 'permissive' is the only
 * engine mode that returns *masked but still identifiable* resources, and it
 * is intentionally unreachable from any valid PhiGuardConfig. 'trusted'
 * disables the engine outright (enabled: false), but its engine mode is still
 * pinned to the strictest value so that flipping `enabled` can never widen
 * access as a side effect.
 */
const ENGINE_MODE_BY_GUARD_MODE: Readonly<Record<PhiGuardMode, PHIProtectionConfig['mode']>> = {
  safe: 'strict',
  trusted: 'strict'
};

/**
 * Parse and validate a PHI guard mode, throwing on anything unrecognised.
 *
 * Accepts `unknown` on purpose: the common real-world failure is an unchecked
 * cast of an env var (`process.env.PHI_MODE as 'safe' | 'trusted'`), where the
 * value may be `undefined`, `''`, or a case variant such as `'Safe'`. Every
 * one of those must be a startup error, never a quiet fallback.
 */
export function parsePhiGuardMode(value: unknown, source = 'config.mode'): PhiGuardMode {
  if (typeof value === 'string' && (PHI_GUARD_MODES as readonly string[]).includes(value)) {
    return value as PhiGuardMode;
  }

  throw new Error(
    `phi-guard: unrecognised mode ${JSON.stringify(value)} (from ${source}). ` +
    `Use one of: ${PHI_GUARD_MODES.join(' | ')}. ` +
    `PHI protection refuses to start rather than fall back to a weaker mode.`
  );
}

export class PhiGuard {
  private config: PhiGuardConfig;
  private readonly auditLogger: AuditLogger;
  private readonly phiAuthEngine: PHIAuthorizationEngine;

  /** The engine mode this guard actually resolved to. Exposed for assertions. */
  public readonly engineMode: PHIProtectionConfig['mode'];
  /** Whether the PHI authorization engine is enabled. Exposed for assertions. */
  public readonly engineEnabled: boolean;

  constructor(config: PhiGuardConfig, auditLogger: AuditLogger) {
    // Fail closed: without an audit logger there is no accountable record of
    // PHI access, so the guard must not exist at all. Previously the logger
    // was optional and omitting it silently skipped the authorization engine.
    if (!auditLogger) {
      throw new Error(
        'phi-guard: an AuditLogger is required. PHI masking will not run without ' +
        'an accountable audit sink.'
      );
    }

    const mode = parsePhiGuardMode(config?.mode);

    this.auditLogger = auditLogger;
    this.config = { ...config, mode };
    this.engineEnabled = mode !== 'trusted';
    this.engineMode = ENGINE_MODE_BY_GUARD_MODE[mode];

    const phiConfig: PHIProtectionConfig = {
      enabled: this.engineEnabled,
      mode: this.engineMode,
      allowEmergencyAccess: true,
      emergencyAccessDurationMinutes: 30,
      auditAllAccess: true,
      defaultMaskingRules: [],
      resourceOverrides: {}
    };

    // Unconditional: the engine is always constructed, so there is no
    // legacy fall-through path.
    this.phiAuthEngine = new PHIAuthorizationEngine(phiConfig, auditLogger);
  }

  /**
   * Enhanced authorization check using PHI engine.
   *
   * Always routes through the authorization engine. The previous legacy
   * `maskResource()` fall-through has been removed: it was only reachable when
   * the engine was absent, which can no longer happen.
   */
  async authorizeAndMaskResource(
    resource: FhirResource,
    user?: User,
    operation: string = 'read',
    sessionId: string = 'unknown'
  ): Promise<{ authorized: boolean; maskedResource?: FhirResource; reason?: string }> {

    try {
      const authResult = await this.phiAuthEngine.authorizeResourceAccess(
        user,
        resource,
        operation,
        sessionId
      );

      if (!authResult.allowed) {
        return {
          authorized: false,
          reason: authResult.message || authResult.reason
        };
      }

      // Apply masking if required
      let maskedResource = resource;
      if (authResult.requiresMasking) {
        maskedResource = this.phiAuthEngine.applyMasking(resource, authResult);
      }

      return {
        authorized: true,
        maskedResource
      };

    } catch (error) {
      // Fail closed, and scrub. The thrown object routinely carries the
      // offending resource, directly or in a stack frame, and `reason` is
      // surfaced to the caller verbatim. Record only the failure class.
      this.auditLogger.logMaskingFailure({
        resourceType: resource?.resourceType,
        resourceId: resource?.id,
        errorName: error instanceof Error ? error.name : 'unknown',
        stage: 'authorize'
      });

      return {
        authorized: false,
        reason: 'PHI_AUTHORIZATION_FAILED'
      };
    }
  }

  maskResource(resource: FhirResource): FhirResource {
    if (this.config.mode === 'trusted') {
      return resource;
    }

    const masked = JSON.parse(JSON.stringify(resource));
    
    // Apply field removal
    this.config.removeFields.forEach(field => {
      this.removeField(masked, field);
    });

    // Apply field masking
    this.config.maskFields.forEach(field => {
      this.maskField(masked, field);
    });

    // Apply standard PHI safeguards for 'safe' mode
    if (this.config.mode === 'safe') {
      this.applySafeguards(masked);
    }

    return masked;
  }

  private removeField(obj: any, fieldPath: string) {
    const parts = fieldPath.split('.');
    let current = obj;
    
    for (let i = 0; i < parts.length - 1; i++) {
      if (!current[parts[i]]) return;
      current = current[parts[i]];
    }
    
    delete current[parts[parts.length - 1]];
  }

  private maskField(obj: any, fieldPath: string) {
    const parts = fieldPath.split('.');
    let current = obj;
    
    for (let i = 0; i < parts.length - 1; i++) {
      if (!current[parts[i]]) return;
      current = current[parts[i]];
    }
    
    const lastPart = parts[parts.length - 1];
    if (current[lastPart]) {
      current[lastPart] = '***MASKED***';
    }
  }

  private applySafeguards(resource: any) {
    // Mask names
    if (resource.name) {
      if (Array.isArray(resource.name)) {
        resource.name.forEach((name: any) => this.maskName(name));
      } else {
        this.maskName(resource.name);
      }
    }

    // Convert birthDate to age
    if (resource.birthDate) {
      const birthYear = new Date(resource.birthDate).getFullYear();
      const currentYear = new Date().getFullYear();
      resource.age = currentYear - birthYear;
      delete resource.birthDate;
    }

    // Mask addresses
    if (resource.address) {
      if (Array.isArray(resource.address)) {
        resource.address.forEach((addr: any) => this.maskAddress(addr));
      } else {
        this.maskAddress(resource.address);
      }
    }

    // Remove government identifiers
    if (resource.identifier) {
      resource.identifier = resource.identifier.filter((id: any) => {
        const system = id.system?.toLowerCase() || '';
        return !system.includes('ssn') && 
               !system.includes('social') && 
               !system.includes('government') &&
               !system.includes('national');
      });
    }

    // Mask telecom
    if (resource.telecom) {
      if (Array.isArray(resource.telecom)) {
        resource.telecom.forEach((tel: any) => {
          if (tel.value) tel.value = '***MASKED***';
        });
      }
    }

    // Recursively apply to nested resources
    Object.keys(resource).forEach(key => {
      if (typeof resource[key] === 'object' && resource[key] !== null) {
        if (Array.isArray(resource[key])) {
          resource[key].forEach((item: any) => {
            if (typeof item === 'object') {
              this.applySafeguards(item);
            }
          });
        } else {
          this.applySafeguards(resource[key]);
        }
      }
    });
  }

  private maskName(name: any) {
    if (name.given) {
      name.given = name.given.map(() => '***');
    }
    if (name.family) {
      name.family = '***';
    }
  }

  private maskAddress(address: any) {
    if (address.line) {
      address.line = ['***MASKED***'];
    }
    if (address.city) address.city = '***';
    if (address.postalCode) address.postalCode = '***';
  }
}

export const DEFAULT_PHI_CONFIG: PhiGuardConfig = {
  mode: 'safe',
  maskFields: [],
  removeFields: []
};
