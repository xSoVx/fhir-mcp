import { FhirResource } from '../types/fhir.js';
import { PhiGuardConfig } from '../types/config.js';

export class PhiGuard {
  private config: PhiGuardConfig;

  constructor(config: PhiGuardConfig) {
    this.config = config;
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