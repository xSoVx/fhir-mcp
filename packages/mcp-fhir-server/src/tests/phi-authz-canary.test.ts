import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { PHIAuthorizationEngine, requiresMandatoryMasking } from '../security/phi-authorization-engine.js';
import { AuditLogger } from '../security/audit-logger.js';
import { PHILevel, PHIProtectionConfig, User } from '../types/phi-types.js';
import { PHIClassifier } from '../security/phi-classifier.js';
import { CANARY, canaryPatient, USER_PROFILES, VALID_MODES, RESOURCE_CASES } from './lane-e-phi-canary-fixture.js';

/* ==========================================================================
 * Lane E canary suite.
 *
 * The vacuity trap is the subject of this lane, so every canary assertion
 * here first PROVES the path it is guarding actually ran and produced data:
 *
 *     1. authorized === true              (not blocked)
 *     2. maskedResource !== undefined     (masking produced output)
 *     3. masking was GENUINELY applied    (output differs from input, and the
 *                                          specific identifying field changed)
 *     4. ...only then: the canary is absent.
 *
 * A bare `not.toContain(CANARY)` on a possibly-absent object passes because
 * the canary was never in the object. That is a false gate, and this suite
 * treats one as a defect.
 * ======================================================================== */

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

const CLINICIAN: User = { id: 'u-clin', roles: ['clinician'], permissions: [] };
const ADMIN: User = { id: 'u-adm', roles: ['admin'], permissions: [] };

/** The full authorize -> mask pipeline, exactly as PhiGuard drives it. */
async function authorizeAndMask(
  engine: PHIAuthorizationEngine,
  resource: Record<string, any>,
  user: User | undefined
): Promise<{ authorized: boolean; maskedResource?: any; reason?: string }> {
  const r = await engine.authorizeResourceAccess(user, resource, 'read', 'canary');
  if (!r.allowed) return { authorized: false, reason: r.message ?? r.reason };
  const maskedResource = r.requiresMasking ? engine.applyMasking(resource, r) : resource;
  return { authorized: true, maskedResource };
}

describe('the canary itself is load-bearing', () => {
  it('is a valid Israeli ID with leading zeros and is genuinely present in the fixture', () => {
    expect(CANARY).toBe('000000018');
    expect(CANARY.startsWith('0')).toBe(true);
    expect(JSON.stringify(canaryPatient())).toContain(CANARY);
  });

  it('appears in every fixture resource, so no case can pass by omission', () => {
    const missing = RESOURCE_CASES
      .filter(rc => !JSON.stringify(rc.make('x')).includes(CANARY))
      .map(rc => rc.label);
    expect(missing).toEqual([]);
  });
});

describe('strict mode + privileged user returns a MASKED identifiable resource', () => {
  it.each([
    ['clinician', CLINICIAN],
    ['admin', ADMIN]
  ])('%s: authorized, output present, masking applied, canary gone', async (_label, user) => {
    const engine = newEngine('strict');
    const input = canaryPatient('strict-priv');
    const inputJson = JSON.stringify(input);

    // Precondition: the canary really is in the input.
    expect(inputJson).toContain(CANARY);

    const out = await authorizeAndMask(engine, input, user);

    // 1. the path ran and was not blocked
    expect(out.authorized).toBe(true);
    // 2. it produced data
    expect(out.maskedResource).toBeDefined();
    const outJson = JSON.stringify(out.maskedResource);
    expect(outJson.length).toBeGreaterThan(0);
    // 3. masking was genuinely applied, not a passthrough
    expect(out.maskedResource).not.toBe(input);
    expect(outJson).not.toEqual(inputJson);
    expect(out.maskedResource.resourceType).toBe('Patient');
    // The whole identifier array is replaced by a hash token (a string), so
    // assert the replacement happened rather than assuming array shape.
    expect(typeof out.maskedResource.identifier).toBe('string');
    expect(out.maskedResource.identifier).not.toBe(CANARY);
    expect(out.maskedResource.identifier).toMatch(/^[0-9a-f]{16}$/);
    expect(out.maskedResource.birthDate).toBeUndefined();
    expect(out.maskedResource.name).toEqual('***');
    expect(out.maskedResource.address).toBeUndefined();
    expect(out.maskedResource.telecom).toBeUndefined();
    // 4. and only now: the canary is nowhere
    expect(outJson).not.toContain(CANARY);
    // the original object was not mutated in place
    expect(JSON.stringify(input)).toEqual(inputJson);
  });

  it('blocks the same resource for an unprivileged caller (the gate still exists)', async () => {
    const engine = newEngine('strict');
    const out = await authorizeAndMask(engine, canaryPatient('strict-anon'), undefined);
    expect(out.authorized).toBe(false);
    expect(out.maskedResource).toBeUndefined();
    expect(out.reason).toMatch(/blocked in PHI protection mode/i);
  });
});

describe('THE REGRESSION: every mode now masks an identifiable resource', () => {
  it.each(VALID_MODES)(
    'mode=%s returns a masked, canary-free Patient to a privileged user',
    async (mode) => {
      const engine = newEngine(mode);
      const input = canaryPatient(`m-${mode}`);
      expect(JSON.stringify(input)).toContain(CANARY);

      const out = await authorizeAndMask(engine, input, CLINICIAN);

      expect(out.authorized).toBe(true);
      expect(out.maskedResource).toBeDefined();
      expect(JSON.stringify(out.maskedResource)).not.toEqual(JSON.stringify(input));
      expect(out.maskedResource.identifier).not.toBe(CANARY);
      expect(typeof out.maskedResource.identifier).toBe('string');
      expect(JSON.stringify(out.maskedResource)).not.toContain(CANARY);
    }
  );
});

describe('exhaustive canary sweep: no allowed response carries the canary', () => {
  it('over every recognised mode x user profile x resource, an allow is always masked and clean', async () => {
    const classifier = new PHIClassifier();
    const leaks: string[] = [];
    let provenMaskedAllows = 0;
    let denials = 0;
    let cases = 0;

    for (const mode of VALID_MODES) {
      const engine = newEngine(mode);
      for (const profile of USER_PROFILES) {
        for (const rc of RESOURCE_CASES) {
          cases++;
          const input = rc.make(`s${cases}`);
          const inputJson = JSON.stringify(input);
          const level = classifier.classifyResource(input).phiLevel;
          const key = `mode=${mode} user=${profile.label} res=${rc.label} level=${level}`;

          // Non-vacuity precondition, per case.
          if (!inputJson.includes(CANARY)) { leaks.push(`${key} :: FIXTURE HAS NO CANARY`); continue; }

          const out = await authorizeAndMask(engine, input, profile.user);

          if (!out.authorized) { denials++; continue; }
          if (out.maskedResource === undefined) { leaks.push(`${key} :: allowed but produced no output`); continue; }

          const outJson = JSON.stringify(out.maskedResource);

          if (requiresMandatoryMasking(level)) {
            // The allow must have been a masked allow, and masking must have
            // actually changed the document.
            if (outJson === inputJson) { leaks.push(`${key} :: allowed but output identical to input`); continue; }
            provenMaskedAllows++;
          }
          if (level !== PHILevel.NONE && outJson.includes(CANARY)) {
            leaks.push(`${key} :: CANARY PRESENT IN OUTPUT`);
          }
        }
      }
    }

    // Guard the sweep against vacuity before trusting its verdict.
    expect(cases).toBe(VALID_MODES.length * USER_PROFILES.length * RESOURCE_CASES.length);
    expect(cases).toBeGreaterThan(200);
    expect(denials).toBeGreaterThan(0);
    expect(provenMaskedAllows).toBeGreaterThan(0);

    expect(leaks).toEqual([]);
  });
});

describe('the two enumerated bypasses are the only unmasked routes, and they are labelled', () => {
  it('protection-disabled returns the raw resource - and says so', async () => {
    const engine = newEngine('strict', false);
    const input = canaryPatient('disabled');
    const r = await engine.authorizeResourceAccess(CLINICIAN, input, 'read', 'c');
    expect(r.allowed).toBe(true);
    expect(r.requiresMasking).toBeUndefined();
    // This IS a leak of the canary - deliberately, because PHI protection is
    // switched off. It must be attributable, never silent.
    expect(r.auditMetadata?.phiMaskingBypass).toBe('protection-disabled');
    expect(r.auditMetadata?.accessGranted).toBe(true);
  });

  it('no OTHER route produces an unlabelled unmasked allow for PHI', async () => {
    const classifier = new PHIClassifier();
    const unlabelled: string[] = [];
    let checked = 0;
    for (const mode of VALID_MODES) {
      const engine = newEngine(mode);
      for (const profile of USER_PROFILES) {
        for (const rc of RESOURCE_CASES) {
          const input = rc.make(`u${checked++}`);
          const level = classifier.classifyResource(input).phiLevel;
          if (level === PHILevel.NONE) continue;
          const r = await engine.authorizeResourceAccess(profile.user, input, 'read', 'c');
          if (!r.allowed) continue;
          if (r.requiresMasking === true) continue;
          if (r.auditMetadata?.phiMaskingBypass) continue;
          unlabelled.push(`mode=${mode} user=${profile.label} res=${rc.label} level=${level}`);
        }
      }
    }
    expect(checked).toBeGreaterThan(200);
    expect(unlabelled).toEqual([]);
  });
});
