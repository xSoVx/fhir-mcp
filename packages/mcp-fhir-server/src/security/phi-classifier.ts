import {
  PHILevel,
  PHIClassificationResult,
  MaskingRule,
  RESOURCE_PHI_MATRIX,
  DEFAULT_MASKING_RULES,
  SENSITIVE_FIELD_PATTERNS,
  GLOBAL_IDENTIFIER_MASKING_RULES
} from '../types/phi-types.js';

/**
 * PHI Classification Engine
 * Automatically classifies FHIR resources based on their PHI sensitivity level
 */
export class PHIClassifier {
  private classificationCache = new Map<string, PHIClassificationResult>();
  /**
   * Classify a FHIR resource for PHI sensitivity
   */
  public classifyResource(resource: any): PHIClassificationResult {
    const resourceType = resource.resourceType;
    if (!resourceType) {
      throw new Error('Resource must have a resourceType');
    }

    // Check cache first
    const cacheKey = this.generateCacheKey(resource);
    const cached = this.classificationCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    // Get base PHI level from matrix
    const basePHILevel = RESOURCE_PHI_MATRIX[resourceType] || PHILevel.RESTRICTED;
    
    // Analyze resource content for dynamic classification
    const analysis = this.analyzeResourceContent(resource);
    
    // Determine final PHI level
    const finalPHILevel = this.determineFinalPHILevel(basePHILevel, analysis);
    
    // Generate classification result
    const result: PHIClassificationResult = {
      resourceType,
      phiLevel: finalPHILevel,
      identifiableFields: analysis.identifiableFields,
      sensitiveFields: analysis.sensitiveFields,
      allowedOperations: this.getAllowedOperations(finalPHILevel),
      requiredMasking: this.getMaskingRules(resource, finalPHILevel),
      riskScore: this.calculateRiskScore(resource, analysis)
    };

    // Cache the result
    this.classificationCache.set(cacheKey, result);
    
    return result;
  }

  /**
   * Analyze resource content for sensitive information
   */
  private analyzeResourceContent(resource: any): {
    identifiableFields: string[];
    sensitiveFields: string[];
    hasPatientReferences: boolean;
    hasDirectIdentifiers: boolean;
  } {
    const identifiableFields: string[] = [];
    const sensitiveFields: string[] = [];
    let hasPatientReferences = false;
    let hasDirectIdentifiers = false;

    // Recursive field analysis
    const analyzeFields = (obj: any, path: string = '') => {
      if (!obj || typeof obj !== 'object') return;

      for (const [key, value] of Object.entries(obj)) {
        const fieldPath = path ? `${path}.${key}` : key;

        // Check for patient references
        if (key === 'reference' && typeof value === 'string') {
          if ((value as string).startsWith('Patient/')) {
            hasPatientReferences = true;
            identifiableFields.push(fieldPath);
          }
        }

        // Check for direct identifiers
        if (key === 'identifier' || key === 'id') {
          hasDirectIdentifiers = true;
          identifiableFields.push(fieldPath);
        }

        // Check against sensitive patterns
        if (SENSITIVE_FIELD_PATTERNS.some(pattern => pattern.test(key))) {
          sensitiveFields.push(fieldPath);
          
          // Names, addresses, etc. are identifiable
          if (/name|address|birth|phone|email|ssn|social/i.test(key)) {
            identifiableFields.push(fieldPath);
          }
        }

        // Recurse into nested objects and arrays
        if (typeof value === 'object') {
          if (Array.isArray(value)) {
            value.forEach((item, index) => {
              if (typeof item === 'object') {
                analyzeFields(item, `${fieldPath}[${index}]`);
              }
            });
          } else {
            analyzeFields(value, fieldPath);
          }
        }
      }
    };

    analyzeFields(resource);

    return {
      identifiableFields,
      sensitiveFields,
      hasPatientReferences,
      hasDirectIdentifiers
    };
  }

  /**
   * Determine final PHI level based on base level and content analysis
   */
  private determineFinalPHILevel(basePHILevel: PHILevel, analysis: any): PHILevel {
    // If resource has patient references, it's at least IDENTIFIABLE
    if (analysis.hasPatientReferences && basePHILevel === PHILevel.NONE) {
      return PHILevel.IDENTIFIABLE;
    }

    // If resource has direct identifiers, upgrade level
    if (analysis.hasDirectIdentifiers && basePHILevel === PHILevel.MINIMAL) {
      return PHILevel.IDENTIFIABLE;
    }

    return basePHILevel;
  }

  /**
   * Get allowed operations for PHI level
   */
  private getAllowedOperations(phiLevel: PHILevel): string[] {
    switch (phiLevel) {
      case PHILevel.NONE:
        return ['read', 'search', 'create', 'update', 'delete'];
      case PHILevel.MINIMAL:
        return ['read', 'search']; // Limited operations
      case PHILevel.IDENTIFIABLE:
        return []; // No operations when PHI protection enabled
      case PHILevel.RESTRICTED:
        return []; // No operations without special permissions
      default:
        return [];
    }
  }

  /**
   * Get masking rules for resource and PHI level
   */
  private getMaskingRules(resource: any, phiLevel: PHILevel): MaskingRule[] {
    const baseMaskingRules = [...DEFAULT_MASKING_RULES[phiLevel]];
    
    // Add resource-specific masking rules
    const resourceSpecificRules = this.getResourceSpecificMaskingRules(resource);
    
    return [...baseMaskingRules, ...resourceSpecificRules];
  }

  /**
   * Get resource-specific masking rules
   */
  private getResourceSpecificMaskingRules(resource: any): MaskingRule[] {
    const rules: MaskingRule[] = [];
    const resourceType = resource.resourceType;

    switch (resourceType) {
      case 'Patient':
        rules.push(
          // Belt and braces. DEFAULT_MASKING_RULES[IDENTIFIABLE] and
          // GLOBAL_IDENTIFIER_MASKING_RULES both hash `identifier` already;
          // stating it here documents the intent at the site a reader looks.
          { field: 'identifier', maskingType: 'hash' },
          { field: 'name', maskingType: 'replace', replacement: '***' },
          { field: 'birthDate', maskingType: 'partial' }, // Show year only
          { field: 'address', maskingType: 'remove' },
          { field: 'telecom', maskingType: 'remove' },
          { field: 'photo', maskingType: 'remove' }
        );
        break;

      case 'RelatedPerson':
        // IL-Core gives RelatedPerson the SAME national-ID slice as Patient.
        rules.push(
          { field: 'identifier', maskingType: 'hash' },
          { field: 'name', maskingType: 'replace', replacement: '***' },
          { field: 'birthDate', maskingType: 'partial' },
          { field: 'address', maskingType: 'remove' },
          { field: 'telecom', maskingType: 'remove' },
          { field: 'photo', maskingType: 'remove' },
          { field: 'patient', maskingType: 'hash' }
        );
        break;

      case 'Observation':
        rules.push(
          { field: 'subject', maskingType: 'hash' }, // Hash patient reference
          { field: 'performer', maskingType: 'hash' },
          { field: 'note', maskingType: 'remove' } // Remove free text
        );
        break;

      case 'Encounter':
        rules.push(
          { field: 'identifier', maskingType: 'hash' },
          { field: 'subject', maskingType: 'hash' },
          { field: 'participant', maskingType: 'remove' },
          { field: 'account', maskingType: 'hash' }
        );
        break;

      case 'Coverage':
        // `subscriberId` is a plain string, not an Identifier, so neither the
        // PHI-level defaults nor GLOBAL_IDENTIFIER_MASKING_RULES reach it. In
        // Israeli payer data it very often *is* the national ID.
        rules.push(
          { field: 'identifier', maskingType: 'hash' },
          { field: 'subscriberId', maskingType: 'hash' },
          { field: 'dependent', maskingType: 'hash' },
          { field: 'subscriber', maskingType: 'hash' },
          { field: 'beneficiary', maskingType: 'hash' },
          { field: 'policyHolder', maskingType: 'hash' }
        );
        break;

      case 'Organization':
        rules.push(
          { field: 'contact', maskingType: 'remove' },
          { field: 'endpoint', maskingType: 'remove' }
        );
        break;

      case 'Practitioner':
        rules.push(
          { field: 'identifier', maskingType: 'hash' },
          { field: 'name', maskingType: 'partial' }, // Show role/specialty only
          { field: 'telecom', maskingType: 'remove' },
          { field: 'address', maskingType: 'remove' },
          { field: 'photo', maskingType: 'remove' }
        );
        break;

      case 'DocumentReference':
        rules.push(
          { field: 'identifier', maskingType: 'hash' },
          { field: 'subject', maskingType: 'hash' },
          { field: 'description', maskingType: 'remove' }
        );
        break;

      case 'DiagnosticReport':
        rules.push(
          { field: 'identifier', maskingType: 'hash' },
          { field: 'subject', maskingType: 'hash' },
          { field: 'conclusion', maskingType: 'remove' }
        );
        break;
    }

    // Global rules are PREPENDED, so a resource type with no `case` above --
    // and any type added to the matrix later -- still receives them.
    return [...this.getGlobalMaskingRules(), ...rules];
  }

  /**
   * Masking rules applied to every resource regardless of type.
   *
   * These are the defence-in-depth layer. They are intentionally independent
   * of both `RESOURCE_PHI_MATRIX` and the `switch` above, so that adding a new
   * resource type cannot silently omit them.
   */
  private getGlobalMaskingRules(): MaskingRule[] {
    return [...GLOBAL_IDENTIFIER_MASKING_RULES];
  }

  /**
   * Calculate risk score for resource access
   */
  private calculateRiskScore(resource: any, analysis: any): number {
    let riskScore = 0;

    // Base score by resource type
    const resourceType = resource.resourceType;
    const phiLevel = RESOURCE_PHI_MATRIX[resourceType] || PHILevel.RESTRICTED;
    
    switch (phiLevel) {
      case PHILevel.NONE: riskScore += 0; break;
      case PHILevel.MINIMAL: riskScore += 25; break;
      case PHILevel.IDENTIFIABLE: riskScore += 75; break;
      case PHILevel.RESTRICTED: riskScore += 100; break;
    }

    // Increase risk for patient references
    if (analysis.hasPatientReferences) {
      riskScore += 25;
    }

    // Increase risk for direct identifiers
    if (analysis.hasDirectIdentifiers) {
      riskScore += 15;
    }

    // Increase risk for number of sensitive fields
    riskScore += Math.min(analysis.sensitiveFields.length * 2, 20);

    return Math.min(riskScore, 100); // Cap at 100
  }

  /**
   * Generate cache key for resource
   */
  private generateCacheKey(resource: any): string {
    const resourceType = resource.resourceType;
    const resourceId = resource.id || 'unknown';
    const resourceHash = this.hashObject(resource);
    return `${resourceType}:${resourceId}:${resourceHash}`;
  }

  /**
   * Simple hash function for cache keys
   */
  private hashObject(obj: any): string {
    const str = JSON.stringify(obj);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }

  /**
   * Clear classification cache
   */
  public clearCache(): void {
    this.classificationCache.clear();
  }

  /**
   * Get cache statistics
   */
  public getCacheStats(): { size: number; hitRate: number } {
    return {
      size: this.classificationCache.size,
      hitRate: 0 // TODO: Implement hit rate tracking
    };
  }
}
