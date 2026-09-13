import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import {
  AuditLogger,
  RESOURCE_TYPE_UNRECOGNISED,
  RESOURCE_TYPE_UNKNOWN
} from '../security/audit-logger.js';
import { SecurityMiddleware } from '../security/security-middleware.js';
import { PHILevel } from '../types/phi-types.js';
import { CANARY, CANARY_RESOURCE_TYPE } from './fixtures/canary.js';

/**
 * FINDING C: `resourceType` was echoed verbatim into audit records.
 *
 * A `resourceType` of `Patient000000018` appeared in plaintext at TWO places in
 * one audit record -- the top level, and again inside `metadata`, because
 * `security-middleware.ts auditSecurityDenial()` populates both. It is narrower
 * than the `originalInput` leak that preceded it (one field, and only on the
 * rejection path) but it is still attacker-controlled free text written verbatim
 * into the audit stream with NO credentials: a log-injection and PHI-smuggling
 * channel that happens to be spelled as a type name. `id` and `params` were
 * already handled; `resourceType` was missed.
 *
 * ANTI-VACUITY. Asserting "the canary is absent from the audit stream" is
 * trivially true of an audit stream that is EMPTY, and the reachable path here is
 * a request that FAILS VALIDATION -- exactly the shape of run that can quietly
 * produce no record at all. So every test below proves a record was emitted, and
 * proves it is the record under test, before asserting what it does not contain.
 */

/** Capture what the logger writes, without swallowing the rest of the run. */
class StreamRecorder {
  readonly lines: string[] = [];
  private originalError?: typeof console.error;
  private originalLog?: typeof console.log;

  install(): void {
    this.originalError = console.error;
    this.originalLog = console.log;
    console.error = (...args: unknown[]) => {
      this.lines.push(args.map(String).join(' '));
    };
    console.log = (...args: unknown[]) => {
      this.lines.push(args.map(String).join(' '));
    };
  }

  restore(): void {
    if (this.originalError) console.error = this.originalError;
    if (this.originalLog) console.log = this.originalLog;
  }

  get combined(): string {
    return this.lines.join('\n');
  }
}

describe('finding C - resourceType is constrained, not echoed', () => {
  let recorder: StreamRecorder;

  beforeEach(() => {
    recorder = new StreamRecorder();
  });

  afterEach(() => {
    recorder.restore();
  });

  test('safeResourceType keeps a real type and rejects a smuggled one', () => {
    // Kept: a type this server actually knows.
    expect(AuditLogger.safeResourceType('Patient')).toBe('Patient');
    expect(AuditLogger.safeResourceType('DiagnosticReport')).toBe('DiagnosticReport');
    // The producers' own placeholder is reserved, so an internal "no type here"
    // is not reported as a rejected caller value.
    expect(AuditLogger.safeResourceType(RESOURCE_TYPE_UNKNOWN)).toBe(RESOURCE_TYPE_UNKNOWN);

    // Rejected: the observed attack, and the canary in any position.
    expect(AuditLogger.safeResourceType(CANARY_RESOURCE_TYPE)).toBe(RESOURCE_TYPE_UNRECOGNISED);
    expect(AuditLogger.safeResourceType(CANARY)).toBe(RESOURCE_TYPE_UNRECOGNISED);
    expect(AuditLogger.safeResourceType(`${CANARY}Patient`)).toBe(RESOURCE_TYPE_UNRECOGNISED);

    // Rejected: log-injection shapes. A newline in an audit stream lets an
    // attacker forge an entire additional record.
    expect(AuditLogger.safeResourceType('Patient\nsuccess=true')).toBe(RESOURCE_TYPE_UNRECOGNISED);
    expect(AuditLogger.safeResourceType('{"injected":true}')).toBe(RESOURCE_TYPE_UNRECOGNISED);

    // Rejected: prototype keys. The matrix is consulted with hasOwnProperty
    // precisely so `constructor` and `toString` are not inherited into the
    // vocabulary -- a truthy lookup or `in` would pass all three of these.
    expect(AuditLogger.safeResourceType('constructor')).toBe(RESOURCE_TYPE_UNRECOGNISED);
    expect(AuditLogger.safeResourceType('toString')).toBe(RESOURCE_TYPE_UNRECOGNISED);
    expect(AuditLogger.safeResourceType('__proto__')).toBe(RESOURCE_TYPE_UNRECOGNISED);

    // Non-strings cannot be trusted to stringify safely either.
    expect(AuditLogger.safeResourceType(undefined)).toBe(RESOURCE_TYPE_UNKNOWN);
    expect(AuditLogger.safeResourceType({ toString: () => CANARY })).toBe(RESOURCE_TYPE_UNKNOWN);
  });

  test('a hostile resourceType reaches neither place in an emitted record', () => {
    recorder.install();
    // Liveness: prove the recorder is capturing at all, so a later "absent"
    // assertion cannot pass because capture silently failed.
    console.error('recorder-liveness-sentinel');
    expect(recorder.combined).toContain('recorder-liveness-sentinel');

    const logger = new AuditLogger(true);
    logger.log({
      operation: 'security.input_validation_failed',
      success: false,
      resourceType: CANARY_RESOURCE_TYPE,
      metadata: {
        // The second site: auditSecurityDenial() writes resourceType into
        // metadata as well as at the top level.
        resourceType: CANARY_RESOURCE_TYPE,
        accessDenied: true
      }
    });
    recorder.restore();

    // Prove the record exists and is the one under test BEFORE asserting absence.
    const emitted = recorder.lines.filter((l) => l.includes('security.input_validation_failed'));
    expect(emitted.length).toBeGreaterThan(0);

    const record = JSON.parse(emitted[0]) as {
      resourceType?: string;
      metadata?: Record<string, unknown>;
    };

    // Both places are now the constrained value -- and both are ASSERTED, because
    // fixing one and missing the other is how this finding came about.
    expect(record.resourceType).toBe(RESOURCE_TYPE_UNRECOGNISED);
    expect(record.metadata?.resourceType).toBe(RESOURCE_TYPE_UNRECOGNISED);

    // And the canary appears nowhere in the serialised record at all.
    expect(emitted.join('\n')).not.toContain(CANARY);
  });

  test('a legitimate resourceType still reaches the record, in both places', () => {
    // The constraint is only worth having if it does not gut the audit trail.
    // Dropping the field would pass every absence assertion above and destroy
    // the operational fact -- which resource CLASS was touched -- on every
    // legitimate record.
    recorder.install();
    const logger = new AuditLogger(true);
    logger.logFhirOperation('read', 'Patient', 'p1', true);
    recorder.restore();

    const emitted = recorder.lines.filter((l) => l.includes('fhir.read'));
    expect(emitted.length).toBeGreaterThan(0);

    const record = JSON.parse(emitted[0]) as { resourceType?: string };
    expect(record.resourceType).toBe('Patient');
  });

  test('through the real middleware: a probe that fails validation logs no canary', async () => {
    // The reachable, UNAUTHENTICATED path. fhir-tools.ts builds its
    // SecurityContext from the RAW args before validation runs, so the record
    // describing the rejection is populated from the value that was rejected.
    recorder.install();
    console.error('recorder-liveness-sentinel');
    expect(recorder.combined).toContain('recorder-liveness-sentinel');

    const middleware = new SecurityMiddleware(
      {
        healthcareCompliant: true,
        enableInputValidation: true,
        enableRateLimiting: false,
        enableSecurityHeaders: true,
        enableAuditLogging: true
      },
      new AuditLogger(true)
    );

    const result = await middleware.processRequest(
      {
        userId: undefined,
        sessionId: 'probe-session',
        operation: 'fhir.search',
        resourceType: CANARY_RESOURCE_TYPE,
        phiLevel: PHILevel.RESTRICTED
      },
      { resourceType: CANARY_RESOURCE_TYPE }
    );
    recorder.restore();

    // Prove the path went where this test says it went: the request was refused,
    // and refused for the validation reason, not some earlier unrelated gate.
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('INPUT_VALIDATION_FAILED');

    // Prove a denial record was actually written.
    const emitted = recorder.lines.filter((l) => l.includes('security.'));
    expect(emitted.length).toBeGreaterThan(0);

    // Only now is absence meaningful.
    expect(recorder.combined).not.toContain(CANARY);
    expect(recorder.combined).not.toContain(CANARY_RESOURCE_TYPE);
  });
});
