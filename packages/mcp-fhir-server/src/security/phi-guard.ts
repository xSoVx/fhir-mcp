import { FhirResource } from '../types/fhir.js';
import { PhiGuardConfig } from '../types/config.js';
import { PHIAuthorizationEngine } from './phi-authorization-engine.js';
import { User, PHIProtectionConfig } from '../types/phi-types.js';
import { AuditLogger } from './audit-logger.js';

export class PhiGuard {
  private config: PhiGuardConfig;
  private phiAuthEngine?: PHIAuthorizationEngine;

  constructor(config: PhiGuardConfig, auditLogger?: AuditLogger) {
    this.config = config;
    
    // Initialize PHI authorization engine if audit logger provided
    if (auditLogger) {
      const phiConfig: PHIProtectionConfig = {
        enabled: config.mode !== 'trusted',
        mode: config.mode === 'safe' ? 'strict' : 'permissive',
        allowEmergencyAccess: true,
        emergencyAccessDurationMinutes: 30,
        auditAllAccess: true,
        defaultMaskingRules: [],
        resourceOverrides: {}
      };
      
      this.phiAuthEngine = new PHIAuthorizationEngine(phiConfig, auditLogger);
    }
  }

  /**
   * Enhanced authorization check using PHI engine
   */
  async authorizeAndMaskResource(
    resource: FhirResource, 
    user?: User,
    operation: string = 'read',
    sessionId: string = 'unknown'
  ): Promise<{ authorized: boolean; maskedResource?: FhirResource; reason?: string }> {
    
    // Use new PHI authorization engine if available
    if (this.phiAuthEngine) {
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
        return {
          authorized: false,
          reason: error instanceof Error ? error.message : 'PHI authorization failed'
        };
      }
    }

    // Fallback to legacy masking
    return {
      authorized: true,
      maskedResource: this.maskResource(resource)
    };
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