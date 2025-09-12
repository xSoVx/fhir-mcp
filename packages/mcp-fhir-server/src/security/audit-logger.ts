export interface AuditEvent {
  timestamp: string;
  traceId: string;
  operation: string;
  resourceType?: string;
  resourceId?: string;
  userId?: string;
  success: boolean;
  error?: string;
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