import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  PHIAuthorizationEngine,
  PHI_SENSITIVITY_RANK,
  requiresMandatoryMasking,
  resolveEngineMode,
  allowMaskedOrDeny,
  allowNonPhi,
  isNonEmptyMaskingRules,
  assertMaskingInvariant,
  ENGINE_MODES
} from '../security/phi-authorization-engine.js';
import { AuditLogger } from '../security/audit-logger.js';
import {
  PHILevel,
  PHIProtectionConfig,
  AuthorizationResult,
  PHIProtectionError
} from '../types/phi-types.js';
import { PHIClassifier } from '../security/phi-classifier.js';
import {
  CANARY,
  canaryPatient,
  USER_PROFILES,
  VALID_MODES,
  INVALID_MODES,
  RESOURCE_CASES
} from './lane-e-phi-canary-fixture.js';

function makeConfig(mode: unknown, enabled = true): PHIProtectionConfig {
  return {
    enabled,
    mode: mode as PHIProtectionConfig['mode'],
    allowEmergencyAccess: false,
    emergencyAccessDurationMinutes: 30,
    auditAllAccess: true,
    defaultMaskingRules: [],
    resourceOverrides: {}
  };
}

let engines: PHIAuthorizationEngine[] = [];

function newEngine(mode: unknown, enabled = true): PHIAuthorizationEngine {
  const e = new PHIAuthorizationEngine(makeConfig(mode, enabled), new AuditLogger(false));
  engines.push(e);
  return e;
}

beforeEach(() => { engines = []; });
afterEach(() => { engines.forEach(e => e.dispose()); engines = []; });

describe('PHI sensitivity ordering', () => {
  it('ranks the four levels NONE < MINIMAL < IDENTIFIABLE < RESTRICTED', () => {
    expect(PHI_SENSITIVITY_RANK[PHILevel.NONE]).toBeLessThan(PHI_SENSITIVITY_RANK[PHILevel.MINIMAL]);
    expect(PHI_SENSITIVITY_RANK[PHILevel.MINIMAL]).toBeLessThan(PHI_SENSITIVITY_RANK[PHILevel.IDENTIFIABLE]);
    expect(PHI_SENSITIVITY_RANK[PHILevel.IDENTIFIABLE]).toBeLessThan(PHI_SENSITIVITY_RANK[PHILevel.RESTRICTED]);
  });

  it.each(Object.values(PHILevel))('classifies mandatory-masking for %s', (level) => {
    const expected = level === PHILevel.IDENTIFIABLE || level === PHILevel.RESTRICTED;
    expect(requiresMandatoryMasking(level)).toBe(expected);
  });

  it('treats an unrecognised PHI level as maximally sensitive', () => {
    expect(requiresMandatoryMasking('sideways' as PHILevel)).toBe(true);
    expect(requiresMandatoryMasking(undefined as unknown as PHILevel)).toBe(true);
  });
});

describe('engine mode resolution is total and fails closed', () => {
  it.each(VALID_MODES)('resolves %s to itself', (m) => {
    expect(resolveEngineMode(m)).toBe(m);
  });

  it('enumerates exactly the three recognised modes', () => {
    expect([...ENGINE_MODES].sort()).toEqual(['audit-only', 'permissive', 'strict']);
  });

  it.each(INVALID_MODES.map((m, i) => [i, m] as const))(
    'resolves invalid mode #%i (%p) to null, never to permissive',
    (_i, m) => {
      const resolved = resolveEngineMode(m);
      expect(resolved).toBeNull();
      expect(resolved).not.toBe('permissive');
    }
  );
});

describe('allow-decision constructors cannot express an unmasked PHI allow', () => {
  it('allowMaskedOrDeny returns a DENY for an empty rule set', () => {
    const d = allowMaskedOrDeny([], PHILevel.IDENTIFIABLE);
    expect(d.kind).toBe('deny');
    expect(d).toMatchObject({ reason: 'MASKING_RULES_UNAVAILABLE' });
  });

  it.each([undefined, null, []])('allowMaskedOrDeny denies for %p', (rules) => {
    expect(allowMaskedOrDeny(rules as never, PHILevel.RESTRICTED).kind).toBe('deny');
  });

  it('allowMaskedOrDeny returns allow-masked for a non-empty rule set', () => {
    const d = allowMaskedOrDeny([{ field: 'identifier', maskingType: 'hash' }], PHILevel.IDENTIFIABLE);
    expect(d.kind).toBe('allow-masked');
  });

  it('allowNonPhi only accepts PHILevel.NONE', () => {
    expect(allowNonPhi(PHILevel.NONE).kind).toBe('allow-unmasked-non-phi');
    // @ts-expect-error - the type makes an unmasked allow for PHI unrepresentable
    allowNonPhi(PHILevel.IDENTIFIABLE);
  });

  it('isNonEmptyMaskingRules rejects every empty-ish shape', () => {
    expect(isNonEmptyMaskingRules([])).toBe(false);
    expect(isNonEmptyMaskingRules(undefined)).toBe(false);
    expect(isNonEmptyMaskingRules(null)).toBe(false);
    expect(isNonEmptyMaskingRules([{ field: 'x', maskingType: 'remove' }])).toBe(true);
  });
});

describe('assertMaskingInvariant (layer 3 runtime backstop)', () => {
  const meta = {
    timestamp: new Date(), sessionId: 's', resourceType: 'Patient',
    operation: 'read', phiLevel: PHILevel.IDENTIFIABLE, accessGranted: true
  };

  it('throws on a hand-written unmasked allow for IDENTIFIABLE', () => {
    const bad: AuthorizationResult = { allowed: true, auditMetadata: meta };
    expect(() => assertMaskingInvariant(bad, PHILevel.IDENTIFIABLE)).toThrow(PHIProtectionError);
  });

  it('throws when requiresMasking is set but the rule set is empty', () => {
    const bad: AuthorizationResult = { allowed: true, requiresMasking: true, maskingRules: [], auditMetadata: meta };
    expect(() => assertMaskingInvariant(bad, PHILevel.IDENTIFIABLE)).toThrow(/masking invariant violated/i);
  });

  it('permits a denial, a NONE allow, and a properly masked allow', () => {
    expect(() => assertMaskingInvariant({ allowed: false }, PHILevel.RESTRICTED)).not.toThrow();
    expect(() => assertMaskingInvariant({ allowed: true }, PHILevel.NONE)).not.toThrow();
    expect(() => assertMaskingInvariant(
      { allowed: true, requiresMasking: true, maskingRules: [{ field: 'identifier', maskingType: 'hash' }], auditMetadata: meta },
      PHILevel.IDENTIFIABLE
    )).not.toThrow();
  });

  it('exempts only a declared bypass decision', () => {
    const bypassed: AuthorizationResult = { allowed: true, auditMetadata: meta };
    expect(() => assertMaskingInvariant(bypassed, PHILevel.IDENTIFIABLE,
      { kind: 'allow-bypass', bypass: 'emergency-grant', reason: 'EMERGENCY_ACCESS_GRANTED' })).not.toThrow();
    expect(() => assertMaskingInvariant(bypassed, PHILevel.IDENTIFIABLE,
      { kind: 'allow-unmasked-non-phi', phiLevel: PHILevel.NONE })).toThrow();
  });
});

/* ==========================================================================
 * THE EXHAUSTIVE SWEEP
 * Every (mode x user-profile x resource/PHI-level) combination the engine
 * accepts - valid modes and invalid ones - is executed, not sampled.
 * ======================================================================== */
describe('exhaustive domain sweep: no allow-decision escapes unmasked', () => {
  const ALL_MODES: readonly unknown[] = [...VALID_MODES, ...INVALID_MODES];

  interface Row {
    mode: unknown; user: string; resource: string; level: PHILevel;
    result?: AuthorizationResult; threw?: string;
  }

  async function sweep(): Promise<Row[]> {
    const classifier = new PHIClassifier();
    const rows: Row[] = [];
    for (const mode of ALL_MODES) {
      const engine = newEngine(mode);
      for (const profile of USER_PROFILES) {
        for (const rc of RESOURCE_CASES) {
          const resource = rc.make(`c${rows.length}`);
          const level = classifier.classifyResource(resource).phiLevel;
          try {
            const result = await engine.authorizeResourceAccess(profile.user, resource, 'read', 'sweep');
            rows.push({ mode, user: profile.label, resource: rc.label, level, result });
          } catch (e) {
            rows.push({ mode, user: profile.label, resource: rc.label, level, threw: e instanceof Error ? e.message : String(e) });
          }
        }
      }
    }
    return rows;
  }

  let rows: Row[];
  beforeEach(async () => { rows = await sweep(); });

  it('enumerates the full cross product (guards the sweep itself against vacuity)', () => {
    const expected = ALL_MODES.length * USER_PROFILES.length * RESOURCE_CASES.length;
    expect(rows.length).toBe(expected);
    expect(expected).toBeGreaterThan(1000);
    expect(USER_PROFILES.length).toBe(12);
    expect(RESOURCE_CASES.length).toBe(7);
    expect(rows.filter(r => r.result?.allowed === true).length).toBeGreaterThan(0);
    expect(rows.filter(r => r.result?.allowed === false).length).toBeGreaterThan(0);
    expect(rows.filter(r => r.threw !== undefined)).toEqual([]);
  });

  it('covers every PHI level', () => {
    const levels = [...new Set(rows.map(r => r.level))].sort();
    expect(levels).toEqual(
      [PHILevel.IDENTIFIABLE, PHILevel.MINIMAL, PHILevel.NONE, PHILevel.RESTRICTED].sort()
    );
  });

  it('never returns allowed:true without masking for IDENTIFIABLE or RESTRICTED', () => {
    const violations = rows.filter(r => {
      const res = r.result;
      if (!res?.allowed) return false;
      if (!requiresMandatoryMasking(r.level)) return false;
      return res.requiresMasking !== true || !isNonEmptyMaskingRules(res.maskingRules);
    }).map(r => `mode=${JSON.stringify(r.mode)} user=${r.user} resource=${r.resource} level=${r.level}`);

    expect(violations).toEqual([]);
  });

  it('denies every PHI-bearing combination whose mode is unrecognised', () => {
    const unrecognised = rows.filter(r => resolveEngineMode(r.mode) === null);
    expect(unrecognised.length).toBeGreaterThan(0);
    const bad = unrecognised
      .filter(r => r.level !== PHILevel.NONE && r.result?.allowed === true)
      .map(r => `mode=${JSON.stringify(r.mode)} user=${r.user} resource=${r.resource} level=${r.level}`);
    expect(bad).toEqual([]);
    // ...and the deny carries the right reason, not an incidental one.
    const reasons = new Set(unrecognised.filter(r => r.level !== PHILevel.NONE).map(r => r.result?.reason));
    expect(reasons).toEqual(new Set(['UNRECOGNISED_PHI_MODE']));
  });

  it('the declared PHI level of every fixture matches what the classifier produces', () => {
    const classifier = new PHIClassifier();
    const mismatches = RESOURCE_CASES
      .map(rc => ({ label: rc.label, declared: rc.expectedLevel, actual: classifier.classifyResource(rc.make('fx')).phiLevel }))
      .filter(x => x.declared !== x.actual);
    expect(mismatches).toEqual([]);
  });

  it('strict mode allows IDENTIFIABLE to exactly the patient-level profiles', () => {
    const strict = rows.filter(r => r.mode === 'strict' && r.level === PHILevel.IDENTIFIABLE);
    expect(strict.length).toBeGreaterThan(0);
    for (const r of strict) {
      const profile = USER_PROFILES.find(p => p.label === r.user)!;
      expect({ user: r.user, allowed: r.result?.allowed })
        .toEqual({ user: r.user, allowed: profile.patientLevel });
    }
  });

  it('RESTRICTED is allowed to exactly the restricted-access profiles, in every recognised mode', () => {
    const restricted = rows.filter(r => r.level === PHILevel.RESTRICTED);
    expect(restricted.length).toBeGreaterThan(0);
    for (const r of restricted) {
      const profile = USER_PROFILES.find(p => p.label === r.user)!;
      const expectedAllowed = profile.restricted && resolveEngineMode(r.mode) !== null;
      expect({ k: `${String(r.mode)}|${r.user}`, allowed: r.result?.allowed })
        .toEqual({ k: `${String(r.mode)}|${r.user}`, allowed: expectedAllowed });
    }
  });

  it('NONE-level resources are allowed everywhere and never claim masking', () => {
    const none = rows.filter(r => r.level === PHILevel.NONE);
    expect(none.length).toBeGreaterThan(0);
    for (const r of none) {
      expect(r.result?.allowed).toBe(true);
      expect(r.result?.requiresMasking).toBeUndefined();
    }
  });
});

describe('protection-disabled bypass is an enumerated global route', () => {
  it('returns unmasked but records the bypass in audit metadata', async () => {
    const engine = newEngine('strict', false);
    const res = await engine.authorizeResourceAccess(undefined, canaryPatient('x'), 'read', 's');
    expect(res.allowed).toBe(true);
    expect(res.requiresMasking).toBeUndefined();
    expect(res.auditMetadata?.phiMaskingBypass).toBe('protection-disabled');
    expect(res.reason).toBe('PHI_PROTECTION_DISABLED');
  });
});

describe('emergency break-glass is an enumerated, audited exception', () => {
  it('is labelled as a bypass rather than silently unmasked', async () => {
    const cfg = makeConfig('strict');
    cfg.allowEmergencyAccess = true;
    const engine = new PHIAuthorizationEngine(cfg, new AuditLogger(false));
    engines.push(engine);
    const user = { id: 'u-er', roles: ['clinician'], permissions: [], emergencyAccessEnabled: true };
    await engine.requestEmergencyAccess(user, 'Patient', '*', 'emergency - life-threatening presentation');
    const res = await engine.authorizeResourceAccess(user, canaryPatient('er'), 'read', 's');
    expect(res.allowed).toBe(true);
    expect(res.auditMetadata?.phiMaskingBypass).toBe('emergency-grant');
    expect(res.auditMetadata?.emergencyAccess).toBe(true);
    expect(res.reason).toBe('EMERGENCY_ACCESS_GRANTED');
  });
});

describe('applyMasking fails closed', () => {
  it('throws rather than returning the raw resource when rules are missing', () => {
    const engine = newEngine('strict');
    const patient = canaryPatient('am');
    expect(() => engine.applyMasking(patient, { allowed: true, requiresMasking: true }))
      .toThrow(PHIProtectionError);
    expect(() => engine.applyMasking(patient, { allowed: true, requiresMasking: true, maskingRules: [] }))
      .toThrow(/refusing to return the resource unmasked/i);
  });

  it('does not leak the canary through the empty-rules path', () => {
    const engine = newEngine('strict');
    const patient = canaryPatient('am2');
    expect(JSON.stringify(patient)).toContain(CANARY);
    let leaked: string | undefined;
    try {
      leaked = JSON.stringify(engine.applyMasking(patient, { allowed: true, requiresMasking: true, maskingRules: [] }));
    } catch {
      leaked = undefined;
    }
    expect(leaked).toBeUndefined();
  });
});
