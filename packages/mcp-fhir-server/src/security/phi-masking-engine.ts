import crypto from 'crypto';
import { MaskingRule } from '../types/phi-types.js';

/**
 * PHI Masking Engine
 * Applies various masking strategies to protect sensitive health information
 */
export class PHIMaskingEngine {
  private hashCache = new Map<string, string>();

  /**
   * Apply masking rules to a resource
   */
  public applyMasking(resource: any, rules: MaskingRule[]): any {
    if (!resource || rules.length === 0) {
      return resource;
    }

    // Deep clone the resource to avoid modifying the original
    const maskedResource = this.deepClone(resource);

    // Apply each masking rule
    rules.forEach(rule => {
      this.applyMaskingRule(maskedResource, rule);
    });

    return maskedResource;
  }

  /**
   * Apply a single masking rule
   */
  private applyMaskingRule(resource: any, rule: MaskingRule): void {
    const { field, maskingType, preserveFormat, replacement, condition } = rule;

    // Handle wildcard masking (remove all fields except resourceType)
    if (field === '*') {
      Object.keys(resource).forEach(key => {
        if (key !== 'resourceType' && key !== 'id') {
          delete resource[key];
        }
      });
      return;
    }

    // Apply field-specific masking
    this.applyFieldMasking(resource, field, maskingType, {
      preserveFormat,
      replacement,
      condition
    });
  }

  /**
   * Apply masking to specific fields
   */
  private applyFieldMasking(
    obj: any, 
    fieldPath: string, 
    maskingType: MaskingRule['maskingType'],
    options: {
      preserveFormat?: boolean;
      replacement?: string;
      condition?: string;
    } = {}
  ): void {
    if (!obj || typeof obj !== 'object') return;

    // Handle array indices in field path
    const pathParts = fieldPath.split('.');
    const currentField = pathParts[0];
    const remainingPath = pathParts.slice(1).join('.');

    // If this is the target field, apply masking
    if (pathParts.length === 1) {
      if (Object.prototype.hasOwnProperty.call(obj, currentField)) {
        obj[currentField] = this.maskValue(obj[currentField], maskingType, options);
      }
      return;
    }

    // Navigate deeper into the object structure
    if (obj[currentField]) {
      if (Array.isArray(obj[currentField])) {
        // Handle array fields
        obj[currentField].forEach((item: any) => {
          if (typeof item === 'object') {
            this.applyFieldMasking(item, remainingPath, maskingType, options);
          }
        });
      } else if (typeof obj[currentField] === 'object') {
        // Handle nested objects
        this.applyFieldMasking(obj[currentField], remainingPath, maskingType, options);
      }
    }
  }

  /**
   * Mask a specific value based on masking type
   */
  private maskValue(
    value: any, 
    maskingType: MaskingRule['maskingType'],
    options: {
      preserveFormat?: boolean;
      replacement?: string;
      condition?: string;
    } = {}
  ): any {
    if (value === null || value === undefined) {
      return value;
    }

    switch (maskingType) {
      case 'remove':
        return undefined; // Will be deleted by JSON.stringify

      case 'replace':
        return options.replacement || '***';

      case 'hash':
        return this.hashValue(value);

      case 'partial':
        return this.partialMask(value, options.preserveFormat);

      case 'aggregate':
        return this.aggregateValue(value);

      default:
        return value;
    }
  }

  /**
   * Hash a value for consistent anonymization
   */
  private hashValue(value: any): string {
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
    
    // Check cache first
    if (this.hashCache.has(stringValue)) {
      return this.hashCache.get(stringValue)!;
    }

    // Create hash
    const hash = crypto
      .createHash('sha256')
      .update(stringValue)
      .digest('hex')
      .substring(0, 16); // Use first 16 characters

    // Cache the result
    this.hashCache.set(stringValue, hash);
    
    return hash;
  }

  /**
   * Apply partial masking to preserve some information
   */
  private partialMask(value: any, preserveFormat: boolean = false): string {
    const stringValue = String(value);

    if (stringValue.length <= 2) {
      return '*'.repeat(stringValue.length);
    }

    // Handle different value types
    if (preserveFormat) {
      // Preserve format for structured data
      if (stringValue.includes('@')) {
        // Email: show first letter and domain
        const [local, domain] = stringValue.split('@');
        return `${local[0]}***@${domain}`;
      }
      
      if (stringValue.includes('-')) {
        // Phone/ID numbers: mask middle parts
        const parts = stringValue.split('-');
        return parts.map((part, index) => 
          index === 0 || index === parts.length - 1 
            ? part 
            : '*'.repeat(part.length)
        ).join('-');
      }
    }

    // Default partial masking: show first and last character
    if (stringValue.length <= 4) {
      return stringValue[0] + '*'.repeat(stringValue.length - 2) + stringValue.slice(-1);
    }

    return stringValue.substring(0, 2) + 
           '*'.repeat(stringValue.length - 4) + 
           stringValue.slice(-2);
  }

  /**
   * Aggregate value for statistical use
   */
  private aggregateValue(value: any): string {
    if (typeof value === 'number') {
      // Round numbers to ranges
      if (value < 10) return '<10';
      if (value < 100) return `${Math.floor(value / 10) * 10}-${Math.floor(value / 10) * 10 + 9}`;
      return `${Math.floor(value / 100) * 100}+`;
    }

    if (typeof value === 'string') {
      // Categorize strings
      if (/\d{4}-\d{2}-\d{2}/.test(value)) {
        // Date: show year only
        return value.substring(0, 4);
      }
      
      if (value.length < 5) return 'short';
      if (value.length < 20) return 'medium';
      return 'long';
    }

    return 'aggregated';
  }

  /**
   * Deep clone an object
   */
  private deepClone(obj: any): any {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    if (obj instanceof Date) {
      return new Date(obj.getTime());
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.deepClone(item));
    }

    const cloned: any = {};
    Object.keys(obj).forEach(key => {
      cloned[key] = this.deepClone(obj[key]);
    });

    return cloned;
  }

  /**
   * Validate that masking was applied correctly
   */
  public validateMasking(original: any, masked: any, rules: MaskingRule[]): {
    valid: boolean;
    violations: string[];
  } {
    const violations: string[] = [];

    rules.forEach(rule => {
      const originalValue = this.getFieldValue(original, rule.field);
      const maskedValue = this.getFieldValue(masked, rule.field);

      // Check that sensitive data was properly masked
      if (rule.maskingType === 'remove' && maskedValue !== undefined) {
        violations.push(`Field ${rule.field} should have been removed`);
      }

      if (rule.maskingType === 'replace' && maskedValue === originalValue) {
        violations.push(`Field ${rule.field} should have been replaced`);
      }

      if (rule.maskingType === 'hash' && maskedValue === originalValue) {
        violations.push(`Field ${rule.field} should have been hashed`);
      }
    });

    return {
      valid: violations.length === 0,
      violations
    };
  }

  /**
   * Get field value using dot notation path
   */
  private getFieldValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : undefined;
    }, obj);
  }

  /**
   * Clear hash cache
   */
  public clearCache(): void {
    this.hashCache.clear();
  }

  /**
   * Get masking engine statistics
   */
  public getStats(): {
    cacheSize: number;
    totalMaskingOperations: number;
  } {
    return {
      cacheSize: this.hashCache.size,
      totalMaskingOperations: 0 // TODO: Implement operation counting
    };
  }
}