import { describe, test, expect } from '@jest/globals';
import crypto from 'crypto';
import util from 'util';
import {
  PHIMaskingEngine,
  PSEUDONYM_TOKEN_PATTERN
} from '../security/phi-masking-engine.js';
import { PHIClassifier } from '../security/phi-classifier.js';
import { MaskingRule } from '../types/phi-types.js';
import { CANARY, LEGACY_UNSALTED_SHA256 } from './fixtures/canary.js';

/**
 * Finding 4 - pseudonym hashes were unsalted and globally stable.
 *
 * GUARD AGAINST VACUOUS ASSERTIONS
 * The plan's §0.3 trap is that `expect(x).not.toContain(CANARY)` passes
 * trivially when `x` is undefined or was never masked at all. These are direct
 * engine tests rather than PhiGuard tests, so the `authorized === true` /
 * `maskedResource !== undefined` pair does not apply literally; the equivalent
 * here is `expectMaskingRan`, which proves a non-empty rule set produced a
 * distinct, defined output BEFORE any negative assertion is made.
 */
function expectMaskingRan(original: any, masked: any, rules: MaskingRule[]): void {
  expect(rules.length).toBeGreaterThan(0);
  expect(masked).toBeDefined();
  expect(masked).not.toBeNull();
  expect(masked).not.toBe(original);
}

const HASH_IDENTIFIER: MaskingRule[] = [{ field: 'identifier', maskingType: 'hash' }];

function patientWithCanary(): any {
  return {
    resourceType: 'Patient',
    id: 'p1',
    identifier: [{ system: 'http://example.org/il-id', value: CANARY }]
  };
}

describe('PHIMaskingEngine - pseudonym tokens (finding 4)', () => {
  test('emits a prefixed token, not a raw digest', () => {
    const engine = new PHIMaskingEngine();
    const original = patientWithCanary();

    const masked = engine.applyMasking(original, HASH_IDENTIFIER);
    expectMaskingRan(original, masked, HASH_IDENTIFIER);

    expect(typeof masked.identifier).toBe('string');
    expect(masked.identifier).toMatch(PSEUDONYM_TOKEN_PATTERN);
  });

  test('never emits the unsalted sha256 of the canary', () => {
    const engine = new PHIMaskingEngine();
    const original = patientWithCanary();

    const masked = engine.applyMasking(original, HASH_IDENTIFIER);
    expectMaskingRan(original, masked, HASH_IDENTIFIER);

    const blob = JSON.stringify(masked);
    expect(blob).not.toContain(CANARY);
    expect(blob).not.toContain(LEGACY_UNSALTED_SHA256);
  });

  test('the legacy digest is what a rainbow table inverts - it must be gone', () => {
    // Sanity-check the fixture itself, so this suite fails loudly if the
    // constant ever stops representing the pre-fix output.
    const recomputed = crypto.createHash('sha256').update(CANARY).digest('hex').substring(0, 16);
    expect(LEGACY_UNSALTED_SHA256).toBe(recomputed);
    expect(LEGACY_UNSALTED_SHA256).toHaveLength(16);
  });
});

describe('PHIMaskingEngine - session scoping (finding 4)', () => {
  /**
   * This pair IS the property. Either half alone is misleading:
   * stability alone is the bug; instability alone breaks the model's ability
   * to join a subject across resources.
   */
  test('the SAME engine produces the SAME token twice (in-session join preserved)', () => {
    const engine = new PHIMaskingEngine();

    const first = engine.applyMasking(patientWithCanary(), HASH_IDENTIFIER);
    const second = engine.applyMasking(patientWithCanary(), HASH_IDENTIFIER);

    expect(first.identifier).toMatch(PSEUDONYM_TOKEN_PATTERN);
    expect(first.identifier).toBe(second.identifier);
  });

  test('TWO engines produce DIFFERENT tokens for the same input (cross-session linkability destroyed)', () => {
    const engineA = new PHIMaskingEngine();
    const engineB = new PHIMaskingEngine();

    const a = engineA.applyMasking(patientWithCanary(), HASH_IDENTIFIER);
    const b = engineB.applyMasking(patientWithCanary(), HASH_IDENTIFIER);

    expect(a.identifier).toMatch(PSEUDONYM_TOKEN_PATTERN);
    expect(b.identifier).toMatch(PSEUDONYM_TOKEN_PATTERN);
    expect(a.identifier).not.toBe(b.identifier);
  });

  test('a pinned key gives reproducible tokens - the variation is the key, not per-call randomness', () => {
    const key = Buffer.alloc(32, 7);
    const a = new PHIMaskingEngine({ sessionKey: key });
    const b = new PHIMaskingEngine({ sessionKey: key });

    const tokenA = a.applyMasking(patientWithCanary(), HASH_IDENTIFIER).identifier;
    const tokenB = b.applyMasking(patientWithCanary(), HASH_IDENTIFIER).identifier;

    expect(tokenA).toBe(tokenB);

    // ...and a different key gives a different token for the same input.
    const c = new PHIMaskingEngine({ sessionKey: Buffer.alloc(32, 8) });
    expect(c.applyMasking(patientWithCanary(), HASH_IDENTIFIER).identifier).not.toBe(tokenA);
  });

  test('rotating the session key changes the token', () => {
    const engine = new PHIMaskingEngine();
    const before = engine.applyMasking(patientWithCanary(), HASH_IDENTIFIER).identifier;

    engine.rotateSessionKey();

    const after = engine.applyMasking(patientWithCanary(), HASH_IDENTIFIER).identifier;
    expect(after).toMatch(PSEUDONYM_TOKEN_PATTERN);
    expect(after).not.toBe(before);
  });

  test('distinct inputs get distinct tokens within a session', () => {
    const engine = new PHIMaskingEngine();
    const one = engine.applyMasking({ resourceType: 'Patient', identifier: CANARY }, HASH_IDENTIFIER);
    const two = engine.applyMasking({ resourceType: 'Patient', identifier: '000000026' }, HASH_IDENTIFIER);

    expect(one.identifier).not.toBe(two.identifier);
  });
});

describe('PHIMaskingEngine - the session key never escapes (finding 4)', () => {
  test('is absent from JSON.stringify, Object.keys, spread and util.inspect', () => {
    const key = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');
    const engine = new PHIMaskingEngine({ sessionKey: key });

    engine.applyMasking(patientWithCanary(), HASH_IDENTIFIER);

    const keyHex = key.toString('hex');
    const keyUtf8 = key.toString('utf8');
    const keyB64 = key.toString('base64');

    const surfaces = [
      JSON.stringify(engine),
      JSON.stringify({ engine }),
      util.inspect(engine, { depth: 10 }),
      String(engine),
      Object.keys(engine).join(','),
      JSON.stringify({ ...engine }),
      JSON.stringify(engine.getStats())
    ];

    for (const surface of surfaces) {
      expect(surface).not.toContain(keyHex);
      expect(surface).not.toContain(keyUtf8);
      expect(surface).not.toContain(keyB64);
      expect(surface).not.toContain(CANARY);
    }
  });

  test('getStats() reports counts only - never keys or values', () => {
    const engine = new PHIMaskingEngine();
    engine.applyMasking(patientWithCanary(), HASH_IDENTIFIER);

    const stats = engine.getStats();
    // TWO entries, not one, since lane I: the `identifier` hash this test's
    // HASH_IDENTIFIER rule asks for, plus the logical-id token that
    // pseudonymiseLogicalIds() now derives for `Patient.id`. Pinned exactly
    // rather than loosened to >= 1 -- the number is the non-vacuity proof that
    // the cache was populated at all, and a `toBeGreaterThan(0)` here would
    // keep passing if one of the two derivations silently stopped running.
    expect(stats.cacheSize).toBe(2);
    expect(Object.values(stats).every(v => typeof v === 'number')).toBe(true);
    expect(JSON.stringify(stats)).not.toContain(CANARY);
  });
});

describe('PHIMaskingEngine - end to end against the real classifier (finding 4)', () => {
  test('classifier-selected rules pseudonymise Patient.identifier', () => {
    const classifier = new PHIClassifier();
    const engine = new PHIMaskingEngine();
    const original = patientWithCanary();

    const classification = classifier.classifyResource(original);
    const rules = classification.requiredMasking;

    const masked = engine.applyMasking(original, rules);
    expectMaskingRan(original, masked, rules);

    const blob = JSON.stringify(masked);
    expect(blob).not.toContain(CANARY);
    expect(blob).not.toContain(LEGACY_UNSALTED_SHA256);
  });
});
