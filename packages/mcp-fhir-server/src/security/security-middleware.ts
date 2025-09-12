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
          await this.auditSecurityEvent('rate_limit_exceeded', context, {
            reason: rateLimitInfo.reason,
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

          await this.auditSecurityEvent('input_validation_failed', context, {
            errors: validationResult.errors,
            originalInput: this.sanitizeForLogging(requestData)
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
      const errorMessage = error instanceof Error ? error.message : 'Unknown security error';
      
      await this.auditSecurityEvent('security_processing_error', context, {
        error: errorMessage,
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
   * Sanitize data for logging (remove sensitive information)
   */
  private sanitizeForLogging(data: any): any {
    if (!data) return data;

    const sanitized = JSON.parse(JSON.stringify(data));
    const sensitiveFields = ['password', 'token', 'authorization', 'ssn', 'birthdate'];

    const sanitizeObject = (obj: any): any => {
      if (typeof obj !== 'object' || obj === null) return obj;

      Object.keys(obj).forEach(key => {
        const lowerKey = key.toLowerCase();
        if (sensitiveFields.some(field => lowerKey.includes(field))) {
          obj[key] = '***REDACTED***';
        } else if (typeof obj[key] === 'object') {
          obj[key] = sanitizeObject(obj[key]);
        }
      });

      return obj;
    };

    return sanitizeObject(sanitized);
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