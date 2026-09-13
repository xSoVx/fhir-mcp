import Joi from 'joi';
import DOMPurify from 'isomorphic-dompurify';

export interface ValidationRule {
  field: string;
  schema: Joi.Schema;
  sanitize?: boolean;
  maxLength?: number;
}

/**
 * A validation failure, structured.
 *
 * The point of this type is that it has nowhere to put the offending value.
 * `errors` is prose meant for the caller; `failures` is what the audit log
 * records, and it carries only the field that failed and the rule it failed.
 * Deriving one from the other by parsing strings -- which an earlier cut of this
 * change did -- guesses wrong as soon as two producers disagree about whether
 * `a: b` means "field: rule" or "rule: field".
 */
export interface ValidationFailure {
  /** Field path the failure occurred on. Bounded to an identifier. */
  field?: string;
  /** The rule that failed. Never a value. */
  code: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  /** Value-free failure descriptors. This is what may be logged. */
  failures?: ValidationFailure[];
  sanitizedData?: any;
}

/**
 * Input Validation and Sanitization Engine
 * Provides comprehensive validation for FHIR inputs and API parameters
 */
export class InputValidator {
  private validationCache = new Map<string, ValidationResult>();

  /**
   * Validate FHIR resource input
   */
  public validateFhirResource(resource: any): ValidationResult {
    const errors: string[] = [];
    const failures: ValidationFailure[] = [];

    // Basic structure validation
    if (!resource || typeof resource !== 'object') {
      return {
        valid: false,
        errors: ['Resource must be a valid object'],
        failures: [{ code: 'not_an_object' }]
      };
    }

    // Required fields validation
    if (!resource.resourceType) {
      errors.push('resourceType is required');
      failures.push({ field: 'resourceType', code: 'required' });
    }

    // Resource type validation.
    //
    // The rejected value is NOT interpolated into the message. These strings are
    // returned to the caller AND handed to the audit logger, so anything
    // interpolated here becomes a log entry. Name the field, not the value.
    if (resource.resourceType && !this.isValidResourceType(resource.resourceType)) {
      errors.push('Invalid resourceType');
      failures.push({ field: 'resourceType', code: 'unknown_resource_type' });
    }

    // ID validation if present
    if (resource.id && !this.isValidId(resource.id)) {
      errors.push('Invalid resource ID format');
      failures.push({ field: 'id', code: 'malformed' });
    }

    // Sanitize and validate text fields
    const sanitizedResource = this.sanitizeResource(resource);

    // Additional resource-specific validation
    const resourceValidation = this.validateResourceSpecific(sanitizedResource);
    errors.push(...resourceValidation.errors);
    failures.push(...(resourceValidation.failures ?? []));

    return {
      valid: errors.length === 0,
      errors,
      failures,
      sanitizedData: sanitizedResource
    };
  }

  /**
   * Validate search parameters
   */
  public validateSearchParams(resourceType: string, params: any): ValidationResult {
    const errors: string[] = [];
    const failures: ValidationFailure[] = [];
    const sanitizedParams: any = {};

    if (!resourceType || !this.isValidResourceType(resourceType)) {
      errors.push('Invalid or missing resourceType');
      failures.push({ field: 'resourceType', code: 'invalid_or_missing' });
    }

    if (params && typeof params === 'object') {
      for (const [key, value] of Object.entries(params)) {
        // Validate parameter name
        // `key` has just FAILED the parameter-name check, i.e. it is arbitrary
        // caller-controlled text of unknown shape. It is not echoed, and the
        // failure descriptor carries no field for the same reason.
        if (!this.isValidSearchParam(key)) {
          errors.push('Unrecognized search parameter');
          failures.push({ code: 'unrecognized_search_parameter' });
          continue;
        }

        // Sanitize parameter value
        const sanitizedValue = this.sanitizeSearchParam(key, value);
        if (sanitizedValue !== null) {
          sanitizedParams[key] = sanitizedValue;
        } else {
          // `key` passed isValidSearchParam, so it is a bounded identifier
          // (leading letter, <= 100 chars) and naming it cannot reproduce a
          // numeric identifier. The VALUE is not recorded.
          errors.push(`Invalid value for parameter: ${key}`);
          failures.push({ field: InputValidator.boundPathSegment(key), code: 'invalid_value' });
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      failures,
      sanitizedData: { resourceType, params: sanitizedParams }
    };
  }

  /**
   * Validate API input arguments
   */
  public validateApiInput(operation: string, args: any): ValidationResult {
    const cacheKey = `${operation}:${JSON.stringify(args)}`;
    const cached = this.validationCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const result = this.performApiValidation(operation, args);
    
    // Cache the result for performance
    this.validationCache.set(cacheKey, result);
    
    return result;
  }

  /**
   * Sanitize resource content
   */
  private sanitizeResource(resource: any): any {
    if (!resource || typeof resource !== 'object') {
      return resource;
    }

    const sanitized = { ...resource };

    // Recursively sanitize object properties
    Object.keys(sanitized).forEach(key => {
      const value = sanitized[key];
      
      if (typeof value === 'string') {
        // Sanitize HTML/script content
        sanitized[key] = DOMPurify.sanitize(value, { 
          ALLOWED_TAGS: [], // Remove all HTML tags
          ALLOWED_ATTR: []
        });
        
        // Additional text sanitization
        sanitized[key] = this.sanitizeText(sanitized[key]);
        
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map(item => 
          typeof item === 'object' ? this.sanitizeResource(item) : this.sanitizeText(String(item))
        );
      } else if (value && typeof value === 'object') {
        sanitized[key] = this.sanitizeResource(value);
      }
    });

    return sanitized;
  }

  /**
   * Sanitize text content
   */
  private sanitizeText(text: string): string {
    if (typeof text !== 'string') return text;

    return text
      // Remove potential SQL injection patterns
      .replace(/('|(\\')|(;)|(\\)|(\/\*)|(\\*\/)|(\\x))/gi, '')
      // Remove script-like patterns
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      // Limit length to prevent buffer overflow
      .substring(0, 10000)
      .trim();
  }

  /**
   * Validate search parameter value
   */
  private sanitizeSearchParam(key: string, value: any): any {
    if (value === null || value === undefined) {
      return null;
    }

    // Convert to string for validation
    const stringValue = String(value);

    // Check for injection patterns
    if (this.containsSqlInjection(stringValue) || this.containsXssPatterns(stringValue)) {
      return null;
    }

    // Parameter-specific validation
    switch (key) {
      case '_count': {
        const count = parseInt(stringValue, 10);
        return (count >= 1 && count <= 1000) ? count : null;
      }
        
      case '_sort':
        return this.isValidSortParam(stringValue) ? stringValue : null;
        
      case '_elements':
        if (Array.isArray(value)) {
          return value.filter(elem => this.isValidElementParam(String(elem)));
        }
        return this.isValidElementParam(stringValue) ? stringValue : null;
        
      default:
        // Generic parameter validation
        return stringValue.length <= 500 ? this.sanitizeText(stringValue) : null;
    }
  }

  /**
   * Perform API-specific validation
   */
  private performApiValidation(operation: string, args: any): ValidationResult {
    const errors: string[] = [];
    const failures: ValidationFailure[] = [];
    const sanitizedArgs = args;

    switch (operation) {
      case 'fhir.search':
        return this.validateSearchArgs(args);
      case 'fhir.read':
        return this.validateReadArgs(args);
      case 'fhir.create':
        return this.validateCreateArgs(args);
      case 'fhir.update':
        return this.validateUpdateArgs(args);
      default:
        errors.push(`Unknown operation: ${operation}`);
        failures.push({ code: 'unknown_operation' });
    }

    return {
      valid: errors.length === 0,
      errors,
      failures,
      sanitizedData: sanitizedArgs
    };
  }

  /**
   * Validate search operation arguments
   */
  private validateSearchArgs(args: any): ValidationResult {
    const schema = Joi.object({
      resourceType: Joi.string().required().custom(this.validateResourceType),
      params: Joi.object().optional(),
      count: Joi.number().integer().min(1).max(1000).optional(),
      sort: Joi.string().custom(this.validateSortParam).optional(),
      elements: Joi.array().items(Joi.string()).optional()
    });

    const { error, value } = schema.validate(args);
    
    return {
      valid: !error,
      errors: error ? error.details.map(detail => InputValidator.joiFailureClass(detail)) : [],
      failures: error ? error.details.map(detail => InputValidator.joiFailure(detail)) : [],
      sanitizedData: value
    };
  }

  /**
   * Validate read operation arguments
   */
  private validateReadArgs(args: any): ValidationResult {
    const schema = Joi.object({
      resourceType: Joi.string().required().custom(this.validateResourceType),
      id: Joi.string().required().custom(this.validateId),
      elements: Joi.array().items(Joi.string()).optional()
    });

    const { error, value } = schema.validate(args);
    
    return {
      valid: !error,
      errors: error ? error.details.map(detail => InputValidator.joiFailureClass(detail)) : [],
      failures: error ? error.details.map(detail => InputValidator.joiFailure(detail)) : [],
      sanitizedData: value
    };
  }

  /**
   * Validate create operation arguments
   */
  private validateCreateArgs(args: any): ValidationResult {
    const errors: string[] = [];
    const failures: ValidationFailure[] = [];

    if (!args.resource) {
      errors.push('resource is required for create operation');
      failures.push({ field: 'resource', code: 'required' });
    } else {
      const resourceValidation = this.validateFhirResource(args.resource);
      errors.push(...resourceValidation.errors);
      failures.push(...(resourceValidation.failures ?? []));
    }

    return {
      valid: errors.length === 0,
      errors,
      failures,
      sanitizedData: args
    };
  }

  /**
   * Validate update operation arguments
   */
  private validateUpdateArgs(args: any): ValidationResult {
    const errors: string[] = [];
    const failures: ValidationFailure[] = [];

    if (!args.resource) {
      errors.push('resource is required for update operation');
      failures.push({ field: 'resource', code: 'required' });
    } else {
      const resourceValidation = this.validateFhirResource(args.resource);
      errors.push(...resourceValidation.errors);
      failures.push(...(resourceValidation.failures ?? []));
    }

    if (!args.id) {
      errors.push('id is required for update operation');
      failures.push({ field: 'id', code: 'required' });
    } else if (!this.isValidId(args.id)) {
      errors.push('Invalid resource ID format for update');
      failures.push({ field: 'id', code: 'malformed' });
    }

    return {
      valid: errors.length === 0,
      errors,
      failures,
      sanitizedData: args
    };
  }

  /**
   * Validate resource-specific rules
   */
  private validateResourceSpecific(resource: any): ValidationResult {
    const errors: string[] = [];
    const failures: ValidationFailure[] = [];
    const resourceType = resource.resourceType;

    switch (resourceType) {
      case 'Patient':
        if (resource.name && !Array.isArray(resource.name)) {
          errors.push('Patient.name must be an array');
          failures.push({ field: 'Patient.name', code: 'not_an_array' });
        }
        break;
        
      case 'Observation':
        if (!resource.status) {
          errors.push('Observation.status is required');
          failures.push({ field: 'Observation.status', code: 'required' });
        }
        if (!resource.code) {
          errors.push('Observation.code is required');
          failures.push({ field: 'Observation.code', code: 'required' });
        }
        break;
        
      // Add more resource-specific validations as needed
    }

    return {
      valid: errors.length === 0,
      errors,
      failures
    };
  }

  /**
   * Check if resource type is valid
   */
  private isValidResourceType(resourceType: string): boolean {
    const validResourceTypes = [
      'Patient', 'Observation', 'Condition', 'MedicationRequest', 'Encounter',
      'Procedure', 'DiagnosticReport', 'AllergyIntolerance', 'CarePlan',
      'Organization', 'Practitioner', 'Location', 'Device',
      'ValueSet', 'CodeSystem', 'StructureDefinition', 'CapabilityStatement',
      'Coverage', 'ExplanationOfBenefit', 'Claim'
      // Add more as needed
    ];
    
    return validResourceTypes.includes(resourceType);
  }

  /**
   * Validate resource ID format
   */
  private isValidId(id: string): boolean {
    // FHIR ID rules: 1-64 characters, alphanumeric, dash, underscore, period
    return /^[A-Za-z0-9\-_.]+$/.test(id) && id.length >= 1 && id.length <= 64;
  }

  /**
   * Check if search parameter name is valid
   */
  private isValidSearchParam(param: string): boolean {
    // Common FHIR search parameters
    const validParams = /^[a-zA-Z][a-zA-Z0-9-_]*(\.[a-zA-Z][a-zA-Z0-9-_]*)*$|^_[a-zA-Z]+$/;
    return validParams.test(param) && param.length <= 100;
  }

  /**
   * Validate sort parameter
   */
  private isValidSortParam(sort: string): boolean {
    // Format: field1,-field2 (dash for descending)
    return /^-?[a-zA-Z][a-zA-Z0-9_.-]*(,-?[a-zA-Z][a-zA-Z0-9_.-]*)*$/.test(sort);
  }

  /**
   * Validate element parameter
   */
  private isValidElementParam(element: string): boolean {
    // FHIR element paths
    return /^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)*$/.test(element);
  }

  /**
   * Check for SQL injection patterns
   */
  private containsSqlInjection(input: string): boolean {
    const sqlPatterns = [
      /('|(\\'))/i,
      /(;|(\\);)/i,
      /(--|(\\)--)/i,
      /(union\s+(select|all))/i,
      /(select\s+.*\s+from)/i,
      /(insert\s+into)/i,
      /(update\s+.*\s+set)/i,
      /(delete\s+from)/i,
      /(drop\s+(table|database))/i,
      /(exec(\s|\+)+(sp_|xp_))/i
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Check for XSS patterns
   */
  private containsXssPatterns(input: string): boolean {
    const xssPatterns = [
      /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
      /<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<object[\s\S]*?>[\s\S]*?<\/object>/gi,
      /<embed[\s\S]*?>/gi,
      /<link[\s\S]*?>/gi
    ];

    return xssPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Custom Joi validators
   */
  private validateResourceType = (value: string, helpers: Joi.CustomHelpers) => {
    if (!this.isValidResourceType(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  };

  private validateId = (value: string, helpers: Joi.CustomHelpers) => {
    if (!this.isValidId(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  };

  private validateSortParam = (value: string, helpers: Joi.CustomHelpers) => {
    if (!this.isValidSortParam(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  };

  /**
   * Render a Joi validation failure as a CLASS, not as prose.
   *
   * Joi's `detail.message` quotes the offending value for several rule types --
   * `string.pattern.base` renders as `"id" with value "<value>" fails to match
   * the required pattern`. Those messages were handed straight to the audit
   * logger, so a rejected FHIR id or search value was written to the log
   * verbatim. `detail.path` and `detail.type` carry the same diagnostic
   * information -- which field, which rule -- and carry no value at all.
   *
   * Path segments are bounded rather than trusted: Joi reports an unknown
   * top-level key using the caller's own key name in the path.
   */
  private static joiFailureClass(detail: Joi.ValidationErrorItem): string {
    const path = detail.path
      .map((segment) => InputValidator.boundPathSegment(segment))
      .join('.');
    const code = detail.type || 'invalid';
    return path ? `${path}: ${code}` : code;
  }

  /** The same failure as a structured descriptor: field and rule, no value. */
  private static joiFailure(detail: Joi.ValidationErrorItem): ValidationFailure {
    const field = detail.path
      .map((segment) => InputValidator.boundPathSegment(segment))
      .join('.');
    const code = detail.type || 'invalid';
    return field ? { field, code } : { code };
  }

  /** A path segment is a bounded identifier or it is nothing. */
  private static boundPathSegment(segment: string | number): string {
    if (typeof segment === 'number') return String(segment);
    return /^[A-Za-z_][A-Za-z0-9_.-]{0,40}$/.test(segment) ? segment : '(unrecognized)';
  }

  /**
   * Clear validation cache
   */
  public clearCache(): void {
    this.validationCache.clear();
  }

  /**
   * Get validation statistics
   */
  public getStats(): {
    cacheSize: number;
    validationCount: number;
  } {
    return {
      cacheSize: this.validationCache.size,
      validationCount: 0 // TODO: Implement counter
    };
  }
}