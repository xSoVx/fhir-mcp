import { describe, test, expect } from '@jest/globals';
import {
  CANARY,
  CANARY_BASE64,
  CANARY_FORMS,
  CANARY_NUMERIC_ENTITIES,
  HEBREW_NAME_ENTITIES,
  kitchenSinkBundle,
  kitchenSinkDocumentReference,
  kitchenSinkObservation,
  kitchenSinkPatient,
  serialise,
  asArray,
  asObject
} from './fixtures/canary.js';
import {
  clinician,
  expectMaskingActuallyRan,
  expectMaskingEngineRan,
  maskViaEngine,
  maskViaGuard,
  restrictedAccessUser
} from './fixtures/masking-harness.js';

/**
 * ============================================================================
 *  PHI CANARY -- the standing red-team assertion
 * ============================================================================
 *
 * One identifier, planted in every location a FHIR resource can hide one.
 * Mask, serialise, assert the string appears NOWHERE. This is not a unit test;
 * it is the thing that catches the leak nobody enumerated.
 *
 * HOW TO READ THIS FILE
 * ---------------------
 * Cases that currently leak are written with `test.failing()`. jest 29 inverts
 * the outcome: while the leak exists the case is reported as PASSED, and the
 * moment the leak is closed jest reports "Failing test passed unexpectedly"
 * and the suite goes RED.
 *
 * That is deliberate, and it is what makes "the canary stays green" an
 * enforceable contract from day one rather than an aspiration:
 *
 *   * the suite is green today, so CI can gate on it immediately
 *   * no leak is suppressed -- every one is named, visible and owned
 *   * a lane cannot quietly fix a leak: CI breaks until that lane also flips
 *     its `test.failing()` to a plain `test()` in the same commit
 *
 * Each block below names the task that owns it. Flip exactly the cases your
 * task closes; do not flip a case you did not fix, and do not delete one.
 *
 * THE TWO TRAPS
 * -------------
 * 1. VACUOUS PASS. `expect(serialise(masked)).not.toContain(CANARY)` passes
 *    trivially when `masked` is undefined -- which is what safe mode returns
 *    for a Patient with no user (phi-authorization-engine.ts:208-218). Every
 *    case here therefore calls expectMaskingActuallyRan() or
 *    expectMaskingEngineRan() FIRST. See fixtures/masking-harness.ts.
 *
 * 2. THE CANARY VALUE. CANARY is a valid Israeli ID with LEADING ZEROS,
 *    from IL-Core's own example. Any regex assuming a non-zero first digit
 *    misses it. And XHTML `&#x30;` is a legal way to write `0`, so the
 *    entity-encoded form is asserted alongside the plaintext -- a narrative
 *    scrubber must DECODE BEFORE it scans.
 */

describe('PHI canary', () => {
  // --------------------------------------------------------------------------
  // Harness self-tests. If these fail, nothing below this point means anything.
  // --------------------------------------------------------------------------
  describe('harness integrity', () => {
    test('the canary is a leading-zero Israeli ID, unchanged', () => {
      // Asserted structurally, never against an inlined copy of the literal:
      // a second copy is a second thing to keep in sync, and the whole point
      // of exporting CANARY from one module is that there is no second copy.
      expect(CANARY).toHaveLength(9);
      expect(CANARY).toMatch(/^0+/);
      expect(CANARY).toMatch(/^\d+$/);
      // The trap, made executable: a plausible-looking IL-ID regex that
      // requires a non-zero first digit does NOT match a valid ID.
      expect(/^[1-9]\d{8}$/.test(CANARY)).toBe(false);
      // Nor does anything that round-trips through a number.
      expect(String(Number(CANARY))).not.toBe(CANARY);
    });

    test('the encoded forms really do encode the canary', () => {
      expect(CANARY_NUMERIC_ENTITIES).toBe(
        '&#x30;&#x30;&#x30;&#x30;&#x30;&#x30;&#x30;&#x31;&#x38;'
      );
      expect(Buffer.from(CANARY_BASE64, 'base64').toString('utf8')).toBe(CANARY);
      // The encoded forms do NOT contain the plaintext, which is precisely why
      // asserting on the plaintext alone is insufficient.
      expect(CANARY_NUMERIC_ENTITIES.includes(CANARY)).toBe(false);
      expect(CANARY_BASE64.includes(CANARY)).toBe(false);
    });

    test('the fixture actually plants the canary in every surface', () => {
      const patient = serialise(kitchenSinkPatient());
      expect(patient).toContain(CANARY); // structured identifier
      expect(patient).toContain(CANARY_NUMERIC_ENTITIES); // narrative, encoded
      expect(patient).toContain(HEBREW_NAME_ENTITIES);
      expect(serialise(kitchenSinkPatient().contained)).toContain(CANARY);
      expect(serialise(kitchenSinkPatient().extension)).toContain(CANARY);
      expect(serialise(kitchenSinkPatient().link)).toContain(CANARY);
      expect(serialise(kitchenSinkDocumentReference())).toContain(CANARY_BASE64);
      expect(serialise(kitchenSinkBundle())).toContain(CANARY);
    });

    test('THE VACUITY TRAP: an unguarded not.toContain passes on a blocked call', async () => {
      // No user supplied -- exactly what fhir-tools.ts:234 and :310 do.
      const outcome = await maskViaGuard(kitchenSinkPatient());

      // Safe mode blocks Patient outright, so nothing was masked...
      expect(outcome.authorized).toBe(false);
      expect(outcome.maskedResource).toBeUndefined();

      // ...yet this is green. It is asserting over `null`. This is the false
      // gate every canary case in this file is written to avoid, reproduced
      // here so the guard can never be quietly dropped as boilerplate.
      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });

    test('authorized === true is still not enough on its own', async () => {
      // A clinician is NOT blocked in strict mode, so authorized is true and
      // maskedResource is defined -- both anti-vacuity assertions pass.
      const outcome = await maskViaGuard(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingActuallyRan(outcome);

      // But handleIdentifiableResource falls through to the default branch
      // (phi-authorization-engine.ts:240-255), which returns allowed WITHOUT
      // requiresMasking, so PhiGuard hands back the RAW resource.
      expect(outcome.maskingApplied).toBe(false);
      expect(serialise(outcome.maskedResource)).toContain(CANARY);
    });
  });
  // --------------------------------------------------------------------------
  // END-TO-END, through the same PhiGuard call fhir-tools.ts makes.
  //
  // OWNER: T1.1 (fail-closed mode + required audit logger) and whoever
  // reconciles handleIdentifiableResource. Today NO PhiGuard configuration
  // masks an IDENTIFIABLE resource at all:
  //     no user        -> blocked
  //     clinician      -> allowed, UNMASKED
  //     mode 'trusted' -> protection disabled entirely
  // Every case in this block therefore leaks for the SAME upstream reason.
  // Fixing the masking rules alone will not flip them.
  // --------------------------------------------------------------------------
  describe('end-to-end via PhiGuard [owner: T1.1]', () => {
    test.failing('does not leak the canary from a Patient read by a clinician', async () => {
      const outcome = await maskViaGuard(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });

    test.failing('does not leak the canary from an Observation read by a clinician', async () => {
      const outcome = await maskViaGuard(kitchenSinkObservation(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });

    test('a RESTRICTED resource IS masked end-to-end (the one path that works)', async () => {
      // Coverage is RESTRICTED; handleRestrictedResource DOES set
      // requiresMasking, and the RESTRICTED rule set is { field: '*',
      // maskingType: 'remove' }. This case is a plain test() and must stay
      // green -- it is the proof that the end-to-end wiring is sound and that
      // the failures above are an authorization-path problem, not a broken
      // harness.
      const outcome = await maskViaGuard(
        {
          resourceType: 'Coverage',
          id: 'cov-1',
          subscriberId: CANARY,
          identifier: [{ value: CANARY }]
        },
        { user: restrictedAccessUser() }
      );
      expectMaskingEngineRan(outcome);
      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });
  });

  // --------------------------------------------------------------------------
  // PER-SURFACE, driven through the engine in a configuration where masking is
  // guaranteed to run. This is what isolates each leak to the lane that owns
  // it, instead of having every case fail for one upstream reason.
  // --------------------------------------------------------------------------
  describe('surface: structured identifier [owner: T1.2]', () => {
    test('a top-level Patient.identifier IS hashed today', async () => {
      // Verifies the source review's CORRECTION (plan section 0.2): the review
      // claimed the identifier passes through verbatim because phi-guard.ts
      // sets `defaultMaskingRules: []`. That config field is DEAD -- nothing
      // reads it. The rules that reach the engine come from the imported
      // DEFAULT_MASKING_RULES constant, which hashes `identifier` for
      // IDENTIFIABLE. So whenever masking actually RUNS, this is covered.
      //
      // Plain test(); must STAY green. T1.2 adds the ALWAYS rule for defence
      // in depth. If that work makes this go red, the belt-and-braces rule has
      // broken the thing it was meant to protect.
      const outcome = await maskViaEngine(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      const masked = asObject(outcome.maskedResource);
      // The identifier array as a whole is hashed to an opaque string, taking
      // the nested assigner.display with it.
      expect(typeof masked.identifier).toBe('string');
      expect(serialise(masked.identifier)).not.toContain(CANARY);
    });

    test.failing('a resource type absent from the classifier switch masks its identifier', async () => {
      // RelatedPerson has no `case` in getResourceSpecificMaskingRules and is
      // absent from RESOURCE_PHI_MATRIX, so it defaults to RESTRICTED
      // (phi-classifier.ts:34). Flips when T1.2 makes `identifier` a global
      // ALWAYS rule rather than per-type enumeration -- and the assertion is
      // written so that merely stripping every field does not satisfy it.
      const outcome = await maskViaEngine(
        {
          resourceType: 'RelatedPerson',
          id: 'rp-1',
          identifier: [{ value: CANARY }],
          extension: [{ url: 'http://example.org/x', valueString: CANARY }]
        },
        { user: restrictedAccessUser() }
      );
      expectMaskingEngineRan(outcome);
      const masked = asObject(outcome.maskedResource);
      expect(masked.identifier).toBeDefined();
      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });
  });

  describe('surface: text.div narrative [owner: T2.1]', () => {
    test.failing('does not leak the canary through text.div, literal', async () => {
      const outcome = await maskViaEngine(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      expect(serialise(asObject(outcome.maskedResource).text)).not.toContain(CANARY);
    });

    test.failing('does not leak the canary through text.div as numeric character references', async () => {
      // The trap in executable form. A scrubber that regexes the RAW narrative
      // for the plaintext CANARY makes the case above pass while leaving this
      // one red.
      // Decode entities BEFORE scanning.
      const outcome = await maskViaEngine(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      const blob = serialise(outcome.maskedResource);
      expect(blob).not.toContain(CANARY_NUMERIC_ENTITIES);
      expect(blob).not.toContain(HEBREW_NAME_ENTITIES);
    });
  });
  describe('surface: contained[] [owner: T2.3]', () => {
    test.failing('masks a contained RelatedPerson inside a Patient by its own type', async () => {
      const outcome = await maskViaEngine(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      const contained = asObject(outcome.maskedResource).contained;
      // Assert the contained resource SURVIVES and is masked -- not that it
      // was deleted. A rule that drops `contained` wholesale would hide the
      // canary without masking anything, and would still be wrong.
      expect(Array.isArray(contained)).toBe(true);
      expect(asObject(asArray(contained)[0]).resourceType).toBe('RelatedPerson');
      expect(serialise(contained)).not.toContain(CANARY);
    });

    test.failing('masks a contained Patient inside an Observation by its own type', async () => {
      const outcome = await maskViaEngine(kitchenSinkObservation(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      const contained = asObject(outcome.maskedResource).contained;
      expect(Array.isArray(contained)).toBe(true);
      expect(asObject(asArray(contained)[0]).resourceType).toBe('Patient');
      expect(serialise(contained)).not.toContain(CANARY);
    });
  });

  describe('surface: Bundle.entry[].resource [owner: T2.3]', () => {
    test.failing('masks each Bundle entry by its own resource type', async () => {
      // Bundle is absent from RESOURCE_PHI_MATRIX -> defaults to RESTRICTED ->
      // the { field: '*' } rule strips `entry` wholesale, which happens to
      // hide the canary today. This case asserts the entries are MASKED, not
      // that the Bundle was emptied, so it stays honest once T2.3 recurses
      // properly and entries survive.
      const outcome = await maskViaEngine(kitchenSinkBundle(), {
        user: restrictedAccessUser()
      });
      expectMaskingEngineRan(outcome);
      const masked = asObject(outcome.maskedResource);
      expect(Array.isArray(masked.entry)).toBe(true);
      expect(masked.entry).toHaveLength(2);
      expect(serialise(masked.entry)).not.toContain(CANARY);
    });
  });

  describe('surface: Attachment.data [owner: T3.1]', () => {
    test.failing('does not leak a base64-encoded canary, and keeps contentType and size', async () => {
      const outcome = await maskViaEngine(kitchenSinkDocumentReference(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      const blob = serialise(outcome.maskedResource);
      // Assert the ENCODED form. The plaintext never appears inside the
      // attachment, so asserting only on it would pass vacuously.
      expect(blob).not.toContain(CANARY_BASE64);
      // The model may still be told a document exists.
      expect(blob).toContain('text/plain');
    });
  });

  describe('surface: extension[] [owner: UNASSIGNED]', () => {
    test.failing('does not leak the canary through a custom extension, at any nesting depth', async () => {
      // No finding in the source review named this surface, and no task in the
      // plan claims it. It is here because an unclaimed surface is exactly
      // what a canary exists to find. Whoever picks it up owns this flip.
      const outcome = await maskViaEngine(
        {
          resourceType: 'Patient',
          id: 'ext-only',
          extension: kitchenSinkPatient().extension
        },
        { user: clinician() }
      );
      expectMaskingEngineRan(outcome);
      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });
  });

  describe('surface: Reference.reference [owner: T4.x]', () => {
    test.failing('does not leak a raw id embedded in a reference string', async () => {
      // `subject.reference` is hashed for Observation, but `Patient/<id>`
      // strings elsewhere are not rewritten. Closing this properly is
      // bidirectional pseudonymization (finding 9 / Phase 4).
      const outcome = await maskViaEngine(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      expect(serialise(asObject(outcome.maskedResource).link)).not.toContain(CANARY);
    });
  });

  describe('surface: meta.security [owner: UNASSIGNED]', () => {
    test.failing('does not leak the canary through a meta.security tag display', async () => {
      // Another surface no finding named.
      const outcome = await maskViaEngine(
        {
          resourceType: 'Patient',
          id: 'meta-only',
          meta: kitchenSinkPatient().meta
        },
        { user: clinician() }
      );
      expectMaskingEngineRan(outcome);
      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });
  });

  // --------------------------------------------------------------------------
  // The whole-output assertion the source review actually asked for. Every
  // form, every surface, one resource. Flip these LAST -- when they go green,
  // the remediation is done.
  // --------------------------------------------------------------------------
  describe('the full red-team assertion [owner: all lanes; flip LAST]', () => {
    test.failing('leaks the canary nowhere, in any encoding, from the kitchen-sink Patient', async () => {
      const outcome = await maskViaEngine(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      const blob = serialise(outcome.maskedResource);
      // Compared as objects so a failure names WHICH encoding leaked, rather
      // than just reporting `true !== false`.
      for (const form of CANARY_FORMS) {
        expect({ form: form.label, leaked: blob.includes(form.value) }).toEqual({
          form: form.label,
          leaked: false
        });
      }
    });

    test.failing('leaks the canary nowhere from a Bundle of every fixture', async () => {
      const outcome = await maskViaEngine(
        {
          resourceType: 'Bundle',
          id: 'everything',
          type: 'collection',
          entry: [
            { resource: kitchenSinkPatient() },
            { resource: kitchenSinkObservation() },
            { resource: kitchenSinkDocumentReference() }
          ]
        },
        { user: restrictedAccessUser() }
      );
      expectMaskingEngineRan(outcome);
      const masked = asObject(outcome.maskedResource);
      expect(masked.entry).toHaveLength(3);
      const blob = serialise(masked);
      for (const form of CANARY_FORMS) {
        expect({ form: form.label, leaked: blob.includes(form.value) }).toEqual({
          form: form.label,
          leaked: false
        });
      }
    });
  });
});