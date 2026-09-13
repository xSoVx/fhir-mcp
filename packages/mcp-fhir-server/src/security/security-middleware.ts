import { InputValidator } from './input-validator.js';
import { RateLimiter, RateLimitRequest, RateLimitResult } from './rate-limiter.js';
import { SecurityHeadersManager, SecurityHeaders } from './security-headers.js';
import { AuditLogger } from './audit-logger.js';
import { PHILevel } from '../types/phi-types.js';

export interface SecurityMiddlewareConfig {
  enableInputValidation: boolean;
  enableRateLimiting: boolean;
  enableSecurityHeaders: boolean;
  enableAuditLogging: boolean;
  healthcareCompliant: boolean;
  customValidationRules?: any[];
  rateLimitOverrides?: Record<string, any>;
  securityHeaderOverrides?: Record<string, string>;
}

export interface SecurityContext {
  userId?: string;
  sessionId: string;
  ipAddress?: string;
  userAgent?: string;
  operation: string;
  resourceType?: string;
  phiLevel?: PHILevel;
  isEmergencyAccess?: boolean;
}

export interface SecurityResult {
  allowed: boolean;
  reason?: string;
  headers?: SecurityHeaders;
  validatedInput?: any;
  rateLimitInfo?: RateLimitResult;
  securityViolations?: string[];
  riskLevel?: 'low' | 'medium' | 'high';
}

/**
 * Comprehensive Security Middleware
 * Integrates all security components for FHIR-MCP protection
 */
export class SecurityMiddleware {
  private inputValidator: InputValidator;
  private rateLimiter: RateLimiter;
  private securityHeaders: SecurityHeadersManager;
  private auditLogger: AuditLogger;
  private config: SecurityMiddlewareConfig;

  constructor(
    config: Partial<SecurityMiddlewareConfig> = {},
    auditLogger?: AuditLogger
  ) {
    this.config = {
      enableInputValidation: true,
      enableRateLimiting: true,
      enableSecurityHeaders: true,
      enableAuditLogging: true,
      healthcareCompliant: true,
      ...config
    };

    // Initialize security components
    this.inputValidator = new InputValidator();
    this.rateLimiter = new RateLimiter();
    this.securityHeaders = new SecurityHeadersManager({
      healthcareCompliant: this.config.healthcareCompliant,
      ...this.config.securityHeaderOverrides
    });
    this.auditLogger = auditLogger || new AuditLogger(this.config.enableAuditLogging);

    // Apply configuration overrides
    if (this.config.rateLimitOverrides) {
      Object.entries(this.config.rateLimitOverrides).forEach(([name, config]) => {
        this.rateLimiter.addConfig(name, config);
      });
    }
  }

  /**
   * Process security checks for incoming requests
   */
  public async processRequest(
    context: SecurityContext,
    requestData?: any
  ): Promise<SecurityResult> {
    const startTime = Date.now();
    const violations: string[] = [];
    let riskLevel: 'low' | 'medium' | 'high' = 'low';

    try {
      // 1. Rate Limiting Check
      let rateLimitInfo: RateLimitResult | undefined;
      if (this.config.enableRateLimiting) {
        const rateLimitRequest: RateLimitRequest = {
          userId: context.userId,
          sessionId: context.sessionId,
          operation: context.operation,
          resourceType: context.resourceType,
          phiLevel: context.phiLevel,
          ipAddress: context.ipAddress,
          userAgent: context.userAgent
        };

        rateLimitInfo = this.rateLimiter.checkRateLimit(rateLimitRequest);
        
        if (!rateLimitInfo.allowed) {
          await this.auditSecurityDenial('rate_limit_exceeded', context, requestData, {
            denialReason: rateLimitInfo.reason,
            remainingRequests: rateLimitInfo.remainingRequests
          });

          return {
            allowed: false,
            reason: rateLimitInfo.reason,
            rateLimitInfo,
            riskLevel: 'high'
          };
        }
      }

      // 2. Input Validation
      let validatedInput = requestData;
      if (this.config.enableInputValidation && requestData) {
        const validationResult = this.inputValidator.validateApiInput(
          context.operation,
          requestData
        );

        if (!validationResult.valid) {
          violations.push(...validationResult.errors);
          riskLevel = 'high';

          // LEAK 1 (unauthenticated, reachable through the real tool surface).
          //
          // This used to log `originalInput: this.sanitizeForLogging(requestData)`
          // -- the caller's entire request, passed through a keyword denylist
          // (password|token|authorization|ssn|birthdate). A live fhir.search on
          // Patient therefore wrote given and family names and a nine-digit
          // national ID into the audit stream in clear text. `birthdate` WAS
          // redacted, which is exactly what made the control look effective.
          //
          // The request is no longer logged at all. A validation failure is
          // fully described by its CLASS and the FIELD it occurred on, and
          // neither of those needs the value that failed. Anything short of
          // dropping the payload is a denylist by another name.
          await this.auditSecurityDenial('input_validation_failed', context, requestData, {
            failureCount: validationResult.errors.length,
            // Structured, value-free descriptors built by the validator itself
            // (ValidationFailure: a field and a rule, with nowhere to put a
            // value). NOT parsed out of the human-readable messages -- an
            // earlier cut of this change did that and mislabelled Joi's
            // `field: rule` as `rule: field`, which is the mistake
            // string-scraping a security control always eventually makes.
            validationFailures: validationResult.failures ?? []
          });

          return {
            allowed: false,
            reason: 'INPUT_VALIDATION_FAILED',
            securityViolations: validationResult.errors,
            riskLevel: 'high'
          };
        }

        validatedInput = validationResult.sanitizedData;
      }

      // 3. Security Headers Generation
      let headers: SecurityHeaders | undefined;
      if (this.config.enableSecurityHeaders) {
        headers = this.securityHeaders.generateHeaders();

        // Add CORS headers if needed
        if (context.operation.includes('cors')) {
          const corsHeaders = this.securityHeaders.generateCORSHeaders([]);
          headers = { ...headers, ...corsHeaders };
        }
      }

      // 4. Additional Healthcare Compliance Checks
      if (this.config.healthcareCompliant) {
        const complianceResult = await this.performComplianceChecks(context);
        if (!complianceResult.compliant) {
          violations.push(...complianceResult.violations);
          riskLevel = complianceResult.riskLevel;

          if (complianceResult.blockRequest) {
            // AUDIT COMPLETENESS. This return had no audit record before it, so
            // a denied Patient read -- the single most reviewable event this
            // control produces -- left no trace at all: fhir-tools returns as
            // soon as `allowed` is false and never reaches logFhirOperation. A
            // refusal that is not recorded cannot be reviewed, and a DLP control
            // whose refusals are invisible cannot be told apart from one that
            // was never consulted.
            await this.auditSecurityDenial(
              'healthcare_compliance_violation',
              context,
              requestData,
              { violationsDetected: complianceResult.violations.length, riskLevel }
            );

            return {
              allowed: false,
              reason: 'HEALTHCARE_COMPLIANCE_VIOLATION',
              securityViolations: complianceResult.violations,
              riskLevel
            };
          }
        }
      }

      // 5. PHI-Specific Security Checks
      if (context.phiLevel && context.phiLevel !== PHILevel.NONE) {
        const phiResult = await this.performPHISecurityChecks(context);
        if (!phiResult.allowed) {
          // Same audit-completeness gap as the compliance branch above.
          await this.auditSecurityDenial('phi_access_denied', context, requestData, {
            denialReason: phiResult.reason,
            riskLevel: 'high'
          });

          return {
            allowed: false,
            reason: phiResult.reason,
            riskLevel: 'high'
          };
        }
      }

      // Log successful security processing
      if (this.config.enableAuditLogging) {
        await this.auditSecurityEvent('security_check_passed', context, {
          processingTime: Date.now() - startTime,
          riskLevel,
          violationsDetected: violations.length
        });
      }

      return {
        allowed: true,
        headers,
        validatedInput,
        rateLimitInfo,
        securityViolations: violations,
        riskLevel
      };

    } catch (error) {
      // The CLASS of the failure, never its message. A message thrown anywhere
      // below this line routinely quotes the resource that caused it.
      await this.auditSecurityDenial('security_processing_error', context, requestData, {
        errorClass: AuditLogger.errorClass(error),
        processingTime: Date.now() - startTime
      });

      return {
        allowed: false,
        reason: 'SECURITY_PROCESSING_ERROR',
        riskLevel: 'high'
      };
    }
  }

  /**
   * Perform healthcare compliance checks
   */
  private async performComplianceChecks(
    context: SecurityContext
  ): Promise<{
    compliant: boolean;
    violations: string[];
    riskLevel: 'low' | 'medium' | 'high';
    blockRequest: boolean;
  }> {
    const violations: string[] = [];
    let riskLevel: 'low' | 'medium' | 'high' = 'low';
    let blockRequest = false;

    // Check for HIPAA compliance requirements
    if (context.phiLevel === PHILevel.IDENTIFIABLE || context.phiLevel === PHILevel.RESTRICTED) {
      if (!context.userId) {
        violations.push('PHI access requires authenticated user');
        riskLevel = 'high';
        blockRequest = true;
      }

      if (!context.sessionId || context.sessionId === 'anonymous') {
        violations.push('PHI access requires valid session');
        riskLevel = 'high';
        blockRequest = true;
      }
    }

    // Check for emergency access compliance
    if (context.isEmergencyAccess) {
      if (!context.userId) {
        violations.push('Emergency access requires user identification');
        riskLevel = 'high';
        blockRequest = true;
      }

      // Log emergency access for compliance
      await this.auditSecurityEvent('emergency_access_attempt', context, {
        operation: context.operation,
        resourceType: context.resourceType
      });
    }

    // Check for proper audit trail requirements
    if (context.phiLevel !== PHILevel.NONE && !this.config.enableAuditLogging) {
      violations.push('PHI access requires audit logging to be enabled');
      riskLevel = 'high';
      blockRequest = true;
    }

    return {
      compliant: violations.length === 0,
      violations,
      riskLevel,
      blockRequest
    };
  }

  /**
   * Perform PHI-specific security checks
   */
  private async performPHISecurityChecks(context: SecurityContext): Promise<{
    allowed: boolean;
    reason?: string;
  }> {
    // Additional PHI security checks beyond basic authorization
    
    // Check for bulk access patterns that might indicate data mining
    if (context.operation === 'fhir.search' && context.phiLevel === PHILevel.IDENTIFIABLE) {
      const recentRequests = await this.checkRecentPHIRequests();
      if (recentRequests > 50) { // Configurable threshold
        return {
          allowed: false,
          reason: 'EXCESSIVE_PHI_ACCESS_DETECTED'
        };
      }
    }

    // Check for off-hours access patterns
    const now = new Date();
    const hour = now.getHours();
    if (hour < 6 || hour > 22) { // Outside normal business hours
      if (context.phiLevel === PHILevel.IDENTIFIABLE && !context.isEmergencyAccess) {
        await this.auditSecurityEvent('off_hours_phi_access', context, {
          accessTime: now.toISOString(),
          hour
        });
        // Don't block but flag for review
      }
    }

    return { allowed: true };
  }

  /**
   * Check recent PHI requests for patterns
   */
  private async checkRecentPHIRequests(): Promise<number> {
    // This would typically query a database or cache
    // For now, return a mock value
    return 0;
  }

  /**
   * Audit security events
   */
  private async auditSecurityEvent(
    event: string,
    context: SecurityContext,
    additionalData?: any
  ): Promise<void> {
    if (!this.config.enableAuditLogging) return;

    await this.auditLogger.log({
      operation: `security.${event}`,
      success: event.includes('passed') || event.includes('granted'),
      userId: context.userId,
      metadata: {
        sessionId: context.sessionId,
        operation: context.operation,
        resourceType: context.resourceType,
        phiLevel: context.phiLevel,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: new Date().toISOString(),
        ...additionalData
      }
    });
  }

  /**
   * Record a REFUSAL.
   *
   * Every `allowed: false` return from processRequest goes through here, for two
   * reasons. Completeness: the callers of this middleware return the moment
   * `allowed` is false, so a refusal not recorded here is not recorded anywhere
   * -- denied Patient reads previously produced no audit record at all.
   * Uniformity: one function decides what a refusal record contains, so a new
   * deny branch cannot invent its own shape and quietly include the request it
   * refused.
   *
   * `requestData` is passed in but is NEVER logged as a payload. The only thing
   * taken from it is the resource id, handed to AuditLogger as a top-level
   * `resourceId`, which hashes it. That is deliberate: a refusal the reviewer
   * cannot tie to a record is close to useless, and a refusal that quotes the
   * record is the leak this lane exists to close. The hash gives correlation
   * without content.
   */
  private async auditSecurityDenial(
    event: string,
    context: SecurityContext,
    requestData: any,
    additionalData?: Record<string, unknown>
  ): Promise<void> {
    if (!this.config.enableAuditLogging) return;

    const resourceId =
      requestData && typeof requestData === 'object' && typeof requestData.id === 'string'
        ? requestData.id
        : undefined;

    await this.auditLogger.log({
      operation: `security.${event}`,
      success: false,
      userId: context.userId,
      resourceType: context.resourceType,
      resourceId,
      metadata: {
        sessionId: context.sessionId,
        operation: context.operation,
        resourceType: context.resourceType,
        phiLevel: context.phiLevel,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        accessDenied: true,
        timestamp: new Date().toISOString(),
        ...additionalData
      }
    });
  }

  /**
   * Handle emergency bypass request
   */
  public async handleEmergencyBypass(
    context: SecurityContext,
    justification: string
  ): Promise<SecurityResult> {
    // Log emergency bypass for audit
    await this.auditSecurityEvent('emergency_bypass_requested', context, {
      justification,
      timestamp: new Date().toISOString()
    });

    // Generate emergency headers
    const headers = this.securityHeaders.generateHeaders();
    headers['X-Emergency-Access'] = 'true';

    // Use emergency bypass for rate limiting
    const rateLimitInfo = this.rateLimiter.emergencyBypass({
      userId: context.userId,
      sessionId: context.sessionId,
      operation: context.operation,
      resourceType: context.resourceType,
      phiLevel: context.phiLevel
    });

    return {
      allowed: true,
      reason: 'EMERGENCY_BYPASS_GRANTED',
      headers,
      rateLimitInfo,
      riskLevel: 'high' // High risk but allowed for emergency
    };
  }

  /**
   * Get security middleware statistics
   */
  public getStats(): {
    inputValidation: any;
    rateLimiting: any;
    securityHeaders: any;
    totalRequestsProcessed: number;
    securityViolationsDetected: number;
  } {
    return {
      inputValidation: this.inputValidator.getStats(),
      rateLimiting: this.rateLimiter.getStats(),
      securityHeaders: this.securityHeaders.generateSecurityReport(),
      totalRequestsProcessed: 0, // TODO: Implement counter
      securityViolationsDetected: 0 // TODO: Implement counter
    };
  }

  /**
   * Update security configuration
   */
  public updateConfig(updates: Partial<SecurityMiddlewareConfig>): void {
    this.config = { ...this.config, ...updates };
    
    // Update component configurations
    if (updates.securityHeaderOverrides) {
      this.securityHeaders.updateConfig(updates.securityHeaderOverrides as any);
    }
  }

  /**
   * Reset security state (for testing or maintenance)
   */
  public reset(): void {
    this.inputValidator.clearCache();
    this.rateLimiter.resetLimits('*');
  }
}