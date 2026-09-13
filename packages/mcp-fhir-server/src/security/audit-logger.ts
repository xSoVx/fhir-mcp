import { createHash } from 'node:crypto';


/**
 * Cap on the nesting audit metadata is walked to. Audit metadata is flat by
 * construction; an unbounded walk over caller-supplied structures is a
 * denial-of-service surface, and a cycle is a hang.
 */
const AUDIT_MAX_DEPTH = 4;

/** Cap on the length of any single string written to an audit record. */
const AUDIT_MAX_STRING = 200;

/**
 * THE ALLOWLIST: metadata keys that may be written to the audit log verbatim.
 *
 * Every entry here is an operational fact about the request -- who asked, what
 * they asked for by type, what the control decided, how long it took. None of
 * them is a field of a FHIR resource.
 *
 * Adding a key to this list is a privacy decision. The question to answer is
 * not "is this key useful" but "can a caller put a patient's data in it". If
 * the answer is yes or maybe, it belongs in AUDIT_HASHED_KEYS or nowhere.
 */
const AUDIT_SAFE_KEYS: ReadonlySet<string> = new Set([
  // Who and which request.
  'userId',
  'sessionId',
  'traceId',
  'requestId',
  'ipAddress',
  'userAgent',

  // What was attempted, by class only.
  'operation',
  'resourceType',
  'phiLevel',
  'accessGranted',
  'accessDenied',
  'stage',
  'reason',
  'denialReason',
  'errorName',
  'errorClass',
  'decision',
  'bypass',
  'phiMaskingBypass',
  'emergencyAccess',

  // Validation outcome, as classes rather than the offending input.
  'validationFailures',
  'failureCount',
  'failureClasses',
  'path',
  'field',
  'code',

  // Timing, counts and risk scoring.
  'timestamp',
  'accessTime',
  'hour',
  'duration',
  'processingTime',
  'riskLevel',
  'violationsDetected',
  'remainingRequests',
  'retryAfter',
  'resultCount',
  'suppressedCount',
  'resourceCount',
  'maskedFieldCount',
  'returned',
  'total',

  // Server lifecycle. Found by RUNNING the built server rather than by reading
  // it: startup emits an audit record describing its own configuration, and an
  // allowlist that had not been shown this record would have silently gutted
  // it. That is the allowlist's cost, and this is what paying it looks like --
  // once, visibly, by whoever adds the field.
  'phiMode',
  'auditEnabled',
  'securityFeaturesEnabled',
  'inputValidation',
  'rateLimiting',
  'securityHeaders',
  'healthcareCompliant',
  'phiAuthorization',
  'version',

  // Terminology operations: concept codes and canonical URLs, not PHI.
  'fhirVersion',
  'system',
  'url',
  'filter',
  'found'
]);

/**
 * Keys that name a DIRECT IDENTIFIER: hashed, not dropped.
 *
 * An audit trail that cannot say which record was touched is not much of an
 * audit trail (HIPAA 164.312(b) expects exactly that), so these keep their
 * correlating power and lose their content. A hashed id is emitted under
 * `<key>Hash` so no reader can mistake it for the raw value.
 */
const AUDIT_HASHED_KEYS: ReadonlySet<string> = new Set([
  'resourceId',
  'id',
  'identifier',
  'patientId',
  'subjectId',
  'mrn',
  'reference'
]);
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

    // Structural allowlist over metadata -- see sanitizeMetadata. What used to
    // be here was a keyword denylist, and it leaked.
    if (auditEvent.metadata) {
      auditEvent.metadata = this.sanitizeMetadata(auditEvent.metadata);
    }

    // A FHIR resource id is a direct identifier on the PHI path (fhir.read is
    // called with the caller's raw id). It was previously emitted verbatim as
    // a sibling of the redacted metadata. Replace it with a stable hash so the
    // audit trail stays correlatable without becoming a PHI store.
    if (auditEvent.resourceId !== undefined) {
      auditEvent.resourceIdHash = AuditLogger.hashIdentifier(auditEvent.resourceId);
      delete auditEvent.resourceId;
    }

    // `error` is a failure CLASS, never a message: a thrown error routinely
    // quotes the resource that broke it. Producers pass
    // AuditLogger.errorClass(e). The bound below is only a blast-radius limit
    // for a producer not yet converted -- it cannot make a short PHI-bearing
    // message safe, which is why the contract lives at the producers.
    if (typeof auditEvent.error === 'string') {
      auditEvent.error = AuditLogger.boundString(auditEvent.error);
    }

    AuditLogger.emit(JSON.stringify(auditEvent));
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

  /**
   * Structural allowlist over audit metadata.
   *
   * What was here before was a keyword DENYLIST --
   * `token|authorization|password|secret|ssn|birthdate` -- applied to the top
   * level of `metadata` only. Both halves of that were wrong, and both were
   * observed leaking in a live run against a real FHIR server:
   *
   *   - It is a denylist. A `fhir.search` on Patient wrote given and family
   *     names and a nine-digit national ID into the log in clear text, because
   *     `name`, `identifier` and `id` were not on the list. `birthdate` WAS
   *     redacted, which is precisely what made the control look like it was
   *     working. Adding the three missing keys moves the next miss rather than
   *     removing it: the set of PHI-bearing key names in FHIR is not
   *     enumerable, and callers nest arbitrary resource fragments here.
   *   - It was shallow. Anything one level down was never inspected at all.
   *
   * An allowlist inverts the failure mode. A key nobody anticipated is dropped
   * instead of published, which is the only direction a data-loss-prevention
   * control is allowed to fail in. The cost is that a genuinely useful new
   * field is silently missing until someone adds it to AUDIT_SAFE_KEYS -- paid
   * once, visibly, by whoever adds the field, instead of continuously and
   * invisibly by patients.
   */
  private sanitizeMetadata(
    data: Record<string, unknown>,
    depth: number = 0
  ): Record<string, unknown> {
    const clean: Record<string, unknown> = {};
    const dropped: string[] = [];

    for (const [key, value] of Object.entries(data)) {
      if (AUDIT_HASHED_KEYS.has(key)) {
        if (typeof value === 'string') {
          clean[`${key}Hash`] = AuditLogger.hashIdentifier(value);
        } else if (value !== undefined && value !== null) {
          // An identifier that is not a string is not something this function
          // can hash without guessing. Drop it.
          dropped.push(key);
        }
        continue;
      }

      if (!AUDIT_SAFE_KEYS.has(key)) {
        dropped.push(key);
        continue;
      }

      clean[key] = this.sanitizeValue(value, depth);
    }

    // Record THAT something was withheld. An audit record that silently
    // shrinks is indistinguishable from one that was never populated, and a
    // reviewer needs to be able to tell those apart.
    if (depth === 0 && dropped.length > 0) {
      clean.redactedFields = dropped.map((name) => AuditLogger.safeKeyName(name));
    }

    return clean;
  }

  /**
   * Sanitize a value belonging to an allowlisted key.
   *
   * Structures are re-entered under the same allowlist, so an allowlisted
   * container cannot smuggle a denied key through its children.
   */
  private sanitizeValue(value: unknown, depth: number): unknown {
    if (value === null || value === undefined) return value;

    if (value instanceof Date) return value.toISOString();

    if (Array.isArray(value)) {
      if (depth >= AUDIT_MAX_DEPTH) return '[depth-capped]';
      return value.map((item) => this.sanitizeValue(item, depth + 1));
    }

    if (typeof value === 'object') {
      if (depth >= AUDIT_MAX_DEPTH) return '[depth-capped]';
      return this.sanitizeMetadata(value as Record<string, unknown>, depth + 1);
    }

    if (typeof value === 'string') return AuditLogger.boundString(value);

    return value;
  }

  /**
   * Allowlisted keys hold codes, classes and enum values, not prose. A long
   * string in one means a caller put something unexpected into an expected
   * key; truncate rather than publish it whole.
   */
  private static boundString(value: string): string {
    return value.length > AUDIT_MAX_STRING
      ? `${value.substring(0, AUDIT_MAX_STRING)}...[truncated]`
      : value;
  }

  /**
   * Audit metadata key names come from this codebase, not from callers. This
   * is belt and braces for the day that stops being true: a key name is not
   * allowed to become a smuggling channel for a value.
   */
  private static safeKeyName(name: string): string {
    return /^[A-Za-z0-9_]{1,40}$/.test(name) ? name : '(unnamed)';
  }

  /**
   * The CLASS of an error, for the `error` field of an audit record.
   *
   * Never `error.message`. A message is written by whoever threw, and in this
   * codebase that routinely means it quotes the resource: a forced throw during
   * a PHI authorization produced `error: "boom for patient <name> MRN <id>"` in
   * the audit stream. The class says what went wrong without saying who it
   * went wrong to.
   */
  static errorClass(error: unknown): string {
    if (error instanceof Error) {
      return error.name || error.constructor?.name || 'Error';
    }
    if (error === null || error === undefined) return 'UnknownError';
    if (typeof error === 'object') {
      return (error as { constructor?: { name?: string } }).constructor?.name ?? 'UnknownError';
    }
    return typeof error;
  }

  /**
   * Where audit records go: stderr, NOT stdout.
   *
   * This server speaks JSON-RPC over stdio (index.ts, StdioServerTransport),
   * so stdout is the protocol channel. Every record written with console.log
   * was interleaved with protocol frames on the same stream -- a correctness
   * bug for any client that parses the stream strictly, as much as a privacy
   * one, since the audit trail then lands wherever the client happens to pipe
   * the protocol rather than in a log the covered entity controls. The rest of
   * the server already writes diagnostics to stderr (index.ts uses
   * console.error for its whole startup banner), so stderr is both correct and
   * consistent.
   *
   * AUDIT_SINK=stdout restores the previous behaviour for a deployment that is
   * scraping audit records off stdout today.
   */
  private static emit(line: string): void {
    if (process.env.AUDIT_SINK === 'stdout') {
      console.log(line);
      return;
    }
    console.error(line);
  }
}