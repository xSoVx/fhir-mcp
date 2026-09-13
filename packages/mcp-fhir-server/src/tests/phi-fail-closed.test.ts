import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { PhiGuard, parsePhiGuardMode, PHI_GUARD_MODES } from '../security/phi-guard.js';
import { AuditLogger, AUDIT_HASH_PATTERN } from '../security/audit-logger.js';
import { FhirTools } from '../tools/fhir-tools.js';
import { PhiGuardConfig } from '../types/config.js';

/**
 * Regression tests for PHI remediation findings 2 and 7.
 *
 * Finding 2 - masking silently disabled itself when no audit logger was
 *             injected, and any mode string that was not exactly 'safe'
 *             resolved to the permissive engine mode.
 * Finding 7 - console.warn('PHI authorization error:', error) could write the
 *             offending resource to stdout.
 *
 * NOTE ON VACUOUS ASSERTIONS. In safe mode a Patient is IDENTIFIABLE and is
 * blocked outright by phi-authorization-engine.ts:208-218 when no user is
 * supplied, so authorizeAndMaskResource() returns { authorized: false } with
 * NO maskedResource. A bare `expect(JSON.stringify(x)).not.toContain(CANARY)`
 * would then pass on an object that never held the value. Every assertion
 * below that claims "the canary is absent" is preceded by an assertion that
 * the path which could have leaked it actually executed.
 */

// Repointed at integration: lane B declared a fourth copy of the literal.
// It lives in exactly one module now (conflict 1).
import { CANARY, LEGACY_UNSALTED_SHA256 } from './fixtures/canary.js';

const SAFE_CONFIG: PhiGuardConfig = { mode: 'safe', maskFields: [], removeFields: [] };

function patientWithCanary(): any {
  return {
    resourceType: 'Patient',
    id: 'patient-canary-1',
    // No `system` on purpose: the legacy applySafeguards() path filtered
    // identifiers by system substring only, so this one passed through.
    identifier: [{ value: CANARY }],
    name: [{ family: 'Cohen', given: ['Tamar'] }]
  };
}

/**
 * Records every console sink. Deliberately NOT jest.spyOn: jest.setup.js
 * replaces global.console with an object whose warn/error are already
 * jest.fn(), and jest.clearAllMocks() runs in its afterEach. Installing our
 * own recorder and proving it live (see the sentinel assertion in each test
 * that uses it) removes any doubt about a silently swallowed spy.
 */
class ConsoleRecorder {
  public calls: string[] = [];
  private saved: Record<string, any> = {};
  private readonly sinks = ['log', 'warn', 'error', 'info', 'debug'] as const;

  install(): void {
    this.calls = [];
    for (const sink of this.sinks) {
      this.saved[sink] = (console as any)[sink];
      (console as any)[sink] = (...args: unknown[]) => {
        this.calls.push(args.map(a => {
          if (a instanceof Error) return a.stack ?? a.message;
          return typeof a === 'string' ? a : JSON.stringify(a);
        }).join(' '));
      };
    }
  }

  restore(): void {
    for (const sink of this.sinks) {
      (console as any)[sink] = this.saved[sink];
    }
  }

  get combined(): string {
    return this.calls.join('\n');
  }
}

/** Captures structured audit events without going through console. */
class CapturingAuditLogger extends AuditLogger {
  public events: any[] = [];

  constructor() {
    super(true);
  }

  log(event: any): void {
    this.events.push(event);
    super.log(event);
  }
}

describe('Finding 2 - PhiGuard fails closed at construction', () => {
  let auditLogger: AuditLogger;

  beforeEach(() => {
    auditLogger = new AuditLogger(false);
  });

  test('refuses to construct without an audit logger', () => {
    // @ts-expect-error - omitting auditLogger must be a TYPE error as well as
    // a runtime error. If this @ts-expect-error ever reports "unused", the
    // parameter has silently become optional again and finding 2 has regressed.
    expect(() => new PhiGuard(SAFE_CONFIG)).toThrow(/AuditLogger is required/);
  });

  test('refuses to construct with a falsy audit logger', () => {
    expect(() => new PhiGuard(SAFE_CONFIG, undefined as any)).toThrow(/AuditLogger is required/);
    expect(() => new PhiGuard(SAFE_CONFIG, null as any)).toThrow(/AuditLogger is required/);
  });

  test('throws on an unrecognised mode', () => {
    expect(() => new PhiGuard({ ...SAFE_CONFIG, mode: 'saef' as any }, auditLogger))
      .toThrow(/unrecognised mode/);
  });

  test('rejects PHI_MODE=Safe - the real-world casing typo', () => {
    // Previously `process.env.PHI_MODE as 'safe' | 'trusted'` accepted this
    // and the mode mapping resolved it to the permissive engine mode.
    expect(() => parsePhiGuardMode('Safe', 'process.env.PHI_MODE'))
      .toThrow(/unrecognised mode/);
    expect(() => new PhiGuard({ ...SAFE_CONFIG, mode: 'Safe' as any }, auditLogger))
      .toThrow(/unrecognised mode/);
  });

  test('rejects the empty string and undefined - the unset env var cases', () => {
    const bad: unknown[] = ['', undefined, null, 0, {}, [], 'permissive', 'strict', 'TRUSTED'];
    for (const value of bad) {
      expect(() => parsePhiGuardMode(value)).toThrow(/unrecognised mode/);
    }
  });

  test('never maps any valid mode to the permissive engine mode', () => {
    // Asserted over the FULL input domain, not a sample: PHI_GUARD_MODES is
    // the closed union, so this is exhaustive by construction.
    expect(PHI_GUARD_MODES.length).toBeGreaterThan(0);
    for (const mode of PHI_GUARD_MODES) {
      const guard = new PhiGuard({ ...SAFE_CONFIG, mode }, auditLogger);
      expect(guard.engineMode).not.toBe('permissive');
    }
  });

  test('resolves safe to strict-and-enabled, trusted to disabled', () => {
    const safe = new PhiGuard({ ...SAFE_CONFIG, mode: 'safe' }, auditLogger);
    expect(safe.engineMode).toBe('strict');
    expect(safe.engineEnabled).toBe(true);

    const trusted = new PhiGuard({ ...SAFE_CONFIG, mode: 'trusted' }, auditLogger);
    expect(trusted.engineEnabled).toBe(false);
    // Pinned strict even though disabled, so flipping `enabled` cannot widen
    // access as a side effect.
    expect(trusted.engineMode).toBe('strict');
  });

  test('the legacy maskResource() fall-through is unreachable', async () => {
    // Before the fix, a guard built without a logger answered
    // { authorized: true, maskedResource: <legacy-masked> } for this resource.
    // After the fix the engine always runs, and in safe mode with no user an
    // IDENTIFIABLE resource is blocked - nothing is returned at all.
    const guard = new PhiGuard(SAFE_CONFIG, auditLogger);
    const result = await guard.authorizeAndMaskResource(patientWithCanary(), undefined, 'read', 's1');

    expect(result.authorized).toBe(false);
    expect(result.maskedResource).toBeUndefined();
    expect(result.reason).toBeDefined();
  });

  test('the legacy path it replaced really did leak - documents why it was removed', () => {
    // This asserts the OLD behaviour is bad, on the still-public maskResource().
    // It is the reason the fall-through was deleted rather than left in place:
    // applySafeguards() filters identifiers by `system` substring, so an
    // identifier with no system survives verbatim.
    const guard = new PhiGuard(SAFE_CONFIG, auditLogger);
    const legacy = guard.maskResource(patientWithCanary() as any);

    expect(JSON.stringify(legacy)).toContain(CANARY);
  });
});

describe('Finding 7 - failures are logged as a class, never as a payload', () => {
  const recorder = new ConsoleRecorder();

  afterEach(() => {
    recorder.restore();
  });

  function fakeSecurityMiddleware() {
    return {
      processRequest: async (_ctx: any, args: any) => ({ allowed: true, validatedInput: args }),
      getStats: () => ({})
    };
  }

  function toolsWithThrowingGuard(auditLogger: AuditLogger) {
    const throwingGuard = {
      authorizeAndMaskResource: async () => {
        // Mimics the real hazard: the thrown object carries the offending
        // input, which is exactly what console.warn(error) used to print.
        throw new Error('masking blew up on ' + JSON.stringify(patientWithCanary()));
      }
    };

    const fhirProvider = {
      search: async () => ({
        total: 1,
        entry: [{ resource: patientWithCanary() }],
        link: []
      })
    };

    return new FhirTools(
      fhirProvider as any,
      throwingGuard as any,
      auditLogger,
      fakeSecurityMiddleware() as any
    );
  }

  test('does not write the resource to any console sink on masking failure', async () => {
    const auditLogger = new CapturingAuditLogger();
    const tools = toolsWithThrowingGuard(auditLogger);

    recorder.install();
    // Sentinel: prove the recorder is live before trusting a negative result.
    console.warn('recorder-liveness-sentinel');
    expect(recorder.combined).toContain('recorder-liveness-sentinel');

    const response = await tools.handleSearch({ resourceType: 'Patient' });
    recorder.restore();

    // Prove the failure path actually executed. Without this the negative
    // assertion below would pass on a run where nothing happened at all.
    const failures = auditLogger.events.filter(e => e.operation === 'phi.masking_failure');
    expect(failures).toHaveLength(1);
    expect(failures[0].error).toBe('Error');
    expect(failures[0].resourceType).toBe('Patient');

    // The actual guarantee.
    expect(recorder.combined).not.toContain(CANARY);
    expect(recorder.combined).not.toContain('masking blew up');
    // And the structured sink carries no payload either.
    expect(JSON.stringify(failures[0])).not.toContain(CANARY);
    expect(JSON.stringify(failures[0])).not.toContain('Cohen');

    // Fail-closed preserved: the entry is absent from the response.
    expect(response.content[0].text).not.toContain(CANARY);
  });

  test('reports suppressedCount when an entry is dropped', async () => {
    const auditLogger = new CapturingAuditLogger();
    const tools = toolsWithThrowingGuard(auditLogger);

    const response = await tools.handleSearch({ resourceType: 'Patient' });
    const result = JSON.parse(response.content[0].text);

    expect(result.suppressedCount).toBe(1);
    expect(result.returned).toBe(0);
    expect(result.entries).toHaveLength(0);
    // total still reflects what the server said, so the omission is visible
    // as the gap between total and returned.
    expect(result.total).toBe(1);
  });

  test('counts policy denials in suppressedCount too', async () => {
    const auditLogger = new CapturingAuditLogger();
    const denyingGuard = {
      authorizeAndMaskResource: async () => ({
        authorized: false,
        reason: 'PHI_PROTECTION_ENABLED'
      })
    };
    const fhirProvider = {
      search: async () => ({
        total: 2,
        entry: [{ resource: patientWithCanary() }, { resource: patientWithCanary() }],
        link: []
      })
    };
    const tools = new FhirTools(
      fhirProvider as any,
      denyingGuard as any,
      auditLogger,
      fakeSecurityMiddleware() as any
    );

    const response = await tools.handleSearch({ resourceType: 'Patient' });
    const result = JSON.parse(response.content[0].text);

    expect(result.suppressedCount).toBe(2);
    expect(result.entries).toHaveLength(0);
  });
});

describe('Finding 7 - the audit sink itself does not become a PHI store', () => {
  test('does not log a raw resourceId', () => {
    const recorder = new ConsoleRecorder();
    recorder.install();
    console.log('recorder-liveness-sentinel');
    expect(recorder.combined).toContain('recorder-liveness-sentinel');

    const auditLogger = new AuditLogger(true);
    auditLogger.logFhirOperation('read', 'Patient', CANARY, true);
    recorder.restore();

    // Prove something was emitted before asserting what it does not contain.
    const emitted = recorder.calls.filter(c => c.includes('fhir.read'));
    expect(emitted.length).toBeGreaterThan(0);

    const blob = emitted.join('\n');
    expect(blob).toContain('resourceIdHash');
    expect(blob).not.toContain(CANARY);
    expect(blob).not.toContain('"resourceId"');
  });

  test('logMaskingFailure records a class, and cannot be handed an Error', () => {
    const auditLogger = new CapturingAuditLogger();
    auditLogger.logMaskingFailure({
      resourceType: 'Patient',
      resourceId: CANARY,
      errorName: 'TypeError',
      stage: 'search'
    });

    expect(auditLogger.events).toHaveLength(1);
    const blob = JSON.stringify(auditLogger.events[0]);
    // The name-only contract means no message and no stack can reach the sink.
    expect(blob).not.toContain('stack');
    expect(auditLogger.events[0].error).toBe('TypeError');
    expect(auditLogger.events[0].operation).toBe('phi.masking_failure');
  });

  test('hashIdentifier is stable within a process, and is not the input', () => {
    const h1 = AuditLogger.hashIdentifier(CANARY);
    const h2 = AuditLogger.hashIdentifier(CANARY);

    expect(h1).toBe(h2);
    expect(h1).not.toContain(CANARY);
    // Shape is asserted against the PRODUCER's exported pattern rather than a
    // regex copied to the call site. The previous version of this test pinned
    // /^[0-9a-f]{16}$/ -- the literal shape of the vulnerable construction --
    // under the name "non-reversible in shape", so the test was certifying the
    // bug. A shape assertion cannot speak to reversibility at all; the test
    // below is the one that can.
    expect(h1).toMatch(AUDIT_HASH_PATTERN);
    expect(AuditLogger.hashIdentifier('')).toBe('empty');
  });

  test('THE FINDING A REGRESSION: a logged hash is not sha256(id) truncated', () => {
    // This is the regression that must never return, so it is asserted
    // DIRECTLY against the attack rather than against a shape.
    //
    // The original: AuditLogger.hashIdentifier computed
    // sha256(value).substring(0, 16) beneath a docstring calling itself "not a
    // reversible identifier on its own". A live patient id was recovered from a
    // real audit line by direct comparison -- the logged 05ed50b66d21a25a is
    // sha256('137230016')[0..15], exactly. LEGACY_UNSALTED_SHA256 computes that
    // same construction over the canary (fixtures/canary.ts, where it is
    // documented as "equivalent to publishing the ID"), so comparing against it
    // reproduces the attack rather than a description of it.
    const legacy = LEGACY_UNSALTED_SHA256;

    // Anti-vacuity: prove the comparison value is the real attack before
    // asserting anything does not equal it. If the fixture ever stopped
    // computing the legacy digest, an inequality assertion against it would
    // pass for the wrong reason.
    expect(legacy).toMatch(/^[0-9a-f]{16}$/);
    expect(legacy).toHaveLength(16);

    const logged = AuditLogger.hashIdentifier(CANARY);

    // Prove the function actually produced something first.
    expect(typeof logged).toBe('string');
    expect(logged.length).toBeGreaterThan(0);

    expect(logged).not.toBe(legacy);
    expect(logged).not.toContain(legacy);
    // Not merely a different truncation of the same unkeyed digest, either.
    expect(logged).not.toContain(legacy.slice(0, 8));
  });

  test('the audit hash is KEYED: rotating the key changes it', () => {
    // The property that distinguishes a keyed hash from a digest, asserted
    // behaviourally. A bare sha256 is a pure function of its input and is
    // therefore INVARIANT under key rotation -- so this test fails closed if
    // anyone reintroduces one, independently of the shape and the inequality
    // above.
    const keyA = Buffer.alloc(32, 0xa1);
    const keyB = Buffer.alloc(32, 0xb2);

    AuditLogger.rotateHashKey(keyA);
    const underA = AuditLogger.hashIdentifier(CANARY);
    // Deterministic under a fixed key, or "changes on rotation" would be
    // indistinguishable from "changes every call".
    expect(AuditLogger.hashIdentifier(CANARY)).toBe(underA);

    AuditLogger.rotateHashKey(keyB);
    const underB = AuditLogger.hashIdentifier(CANARY);

    expect(underB).not.toBe(underA);
    // Restoring the key restores the hash: the key is the ONLY thing that
    // changed, so this rules out a nonce or a timestamp being responsible.
    AuditLogger.rotateHashKey(keyA);
    expect(AuditLogger.hashIdentifier(CANARY)).toBe(underA);

    // And neither is the legacy digest.
    expect(underA).not.toBe(LEGACY_UNSALTED_SHA256);
    expect(underB).not.toBe(LEGACY_UNSALTED_SHA256);

    // A key too weak to key anything is refused rather than stretched.
    expect(() => AuditLogger.rotateHashKey(Buffer.alloc(8))).toThrow();
  });

  test('no console.* in src/tools or src/security receives a resource or bare error', async () => {
    // Structural guard rather than behavioural: stops a future console.warn on
    // a resource path from reintroducing finding 7 unnoticed.
    const { readFileSync, readdirSync, existsSync } = await import('node:fs');
    const { join } = await import('node:path');

    const candidates = [
      join(process.cwd(), 'src'),
      join(process.cwd(), 'packages', 'mcp-fhir-server', 'src')
    ];
    const srcRoot = candidates.find(c => existsSync(join(c, 'security')));
    expect(srcRoot).toBeDefined();

    const offenders: string[] = [];

    for (const dir of ['tools', 'security']) {
      const base = join(srcRoot as string, dir);
      for (const file of readdirSync(base).filter(f => f.endsWith('.ts'))) {
        const src = readFileSync(join(base, file), 'utf8');
        src.split('\n').forEach((line, i) => {
          if (!/console\.(log|warn|error|info|debug)\s*\(/.test(line)) return;
          // audit-logger.ts is the one structured sink; it receives
          // already-redacted, already-hashed input. That call now lives in a
          // single private emit(line: string) -- the sink moved off stdout,
          // because stdout is this server's JSON-RPC channel -- so the
          // exemption follows it rather than being pinned to one expression.
          if (file === 'audit-logger.ts' && /console\.\w+\(line\)/.test(line)) return;
          if (file === 'audit-logger.ts' && line.includes('JSON.stringify(auditEvent)')) return;
          // Strip the `console.<method>` token before looking for payload
          // words. Otherwise `console.error(anything)` matches /\berror\b/ on
          // its own method name, so every console.error in these directories is
          // an offender by construction regardless of what it is handed -- the
          // guard would be reporting the sink's name, not its argument.
          const args = line.replace(/console\.(log|warn|error|info|debug)/g, 'console');
          if (/\b(resource|entry|error|payload|bundle)\b/.test(args)) {
            offenders.push(dir + '/' + file + ':' + (i + 1) + ': ' + line.trim());
          }
        });
      }
    }

    expect(offenders).toEqual([]);
  });
});
