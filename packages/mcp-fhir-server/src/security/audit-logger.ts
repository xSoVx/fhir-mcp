import { createHash } from 'node:crypto';

export interface AuditEvent {
  timestamp: string;
  traceId: string;
  operation: string;
  resourceType?: string;
  resourceId?: string;
  resourceIdHash?: string;
  userId?: string;
  success: boolean;
  error?: string;
  duration?: number;
  metadata?: Record<string, unknown>;
}

export class AuditLogger {
  private enableAudit: boolean;

  constructor(enableAudit: boolean = true) {
    this.enableAudit = enableAudit;
  }

  log(event: Omit<AuditEvent, 'timestamp' | 'traceId'>) {
    if (!this.enableAudit) return;

    const auditEvent: AuditEvent = {
      ...event,
      timestamp: new Date().toISOString(),
      traceId: this.generateTraceId()
    };

    // Redact any potential PHI from metadata
    if (auditEvent.metadata) {
      auditEvent.metadata = this.redactSensitiveData(auditEvent.metadata);
    }

    // A FHIR resource id is a direct identifier on the PHI path (fhir.read is
    // called with the caller's raw id). It was previously emitted verbatim as
    // a sibling of the redacted metadata. Replace it with a stable hash so the
    // audit trail stays correlatable without becoming a PHI store.
    if (auditEvent.resourceId !== undefined) {
      auditEvent.resourceIdHash = AuditLogger.hashIdentifier(auditEvent.resourceId);
      delete auditEvent.resourceId;
    }

    // Log to console in structured format (in production, this would go to proper logging infrastructure)
    console.log(JSON.stringify(auditEvent));
  }

  logFhirOperation(
    operation: string,
    resourceType: string,
    resourceId?: string,
    success: boolean = true,
    error?: string,
    metadata?: Record<string, unknown>
  ) {
    this.log({
      operation: `fhir.${operation}`,
      resourceType,
      resourceId,
      success,
      error,
      metadata
    });
  }

  logTerminologyOperation(
    operation: string,
    success: boolean = true,
    error?: string,
    metadata?: Record<string, unknown>
  ) {
    this.log({
      operation: `terminology.${operation}`,
      success,
      error,
      metadata
    });
  }

  /**
   * Record a PHI masking/authorization failure.
   *
   * Records the *class* of failure only: resource type, a hashed resource id
   * and the error name. The error object itself is never accepted here, and
   * never logged, because a thrown error routinely carries the offending
   * resource directly or in a stack frame.
   */
  logMaskingFailure(failure: {
    resourceType?: string;
    resourceId?: string;
    errorName?: string;
    stage?: string;
  }) {
    this.log({
      operation: 'phi.masking_failure',
      resourceType: failure.resourceType ?? 'unknown',
      resourceId: failure.resourceId,
      success: false,
      error: failure.errorName ?? 'unknown',
      metadata: {
        stage: failure.stage ?? 'unknown'
      }
    });
  }

  /**
   * One-way hash of a direct identifier, for correlation without exposure.
   * Truncated to 16 hex chars: enough to correlate within a log stream,
   * not a reversible identifier on its own.
   */
  static hashIdentifier(value: string): string {
    if (value === '') return 'empty';
    return createHash('sha256').update(value).digest('hex').substring(0, 16);
  }
  private generateTraceId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  private redactSensitiveData(data: Record<string, unknown>): Record<string, unknown> {
    const redacted = { ...data };
    const sensitiveFields = ['token', 'authorization', 'password', 'secret', 'ssn', 'birthdate'];
    
    Object.keys(redacted).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (sensitiveFields.some(field => lowerKey.includes(field))) {
        redacted[key] = '***REDACTED***';
      }
    });

    return redacted;
  }
}