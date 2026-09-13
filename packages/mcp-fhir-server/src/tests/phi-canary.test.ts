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
      // REWRITTEN AT INTEGRATION. Lane A wrote this against master, where a
      // clinician in strict mode was ALLOWED and handed back the RAW resource:
      // handleIdentifiableResource fell through to a branch that returned
      // allowed without requiresMasking. The test pinned that leak as proof
      // that uthorized && maskedResource is a weaker guard than masking
      // actually ran.
      //
      // Lane E closed that hole, so the original body now fails -- the engine
      // masks. The DISTINCTION it exists to defend is not obsolete, though: a
      // caller can still get authorized===true with maskedResource defined and
      // no masking applied, because 'trusted' mode disables protection and
      // returns the resource untouched. That is the surviving instance of the
      // same shape, so the test is repointed at it rather than deleted.
      const trusted = await maskViaGuard(kitchenSinkPatient(), {
        user: clinician(),
        mode: 'trusted'
      });

      // The WEAK guard is satisfied...
      expectMaskingActuallyRan(trusted);

      // ...and yet nothing was masked, and the canary is right there.
      expect(trusted.maskingApplied).toBe(false);
      expect(serialise(trusted.maskedResource)).toContain(CANARY);

      // The STRONG guard is what catches it. Proven by construction: it throws
      // on the same outcome the weak guard accepted.
      expect(() => expectMaskingEngineRan(trusted)).toThrow();

      // And the strong guard is not vacuously strict -- the same call in the
      // mode production actually uses does satisfy it.
      const safe = await maskViaGuard(kitchenSinkPatient(), { user: clinician() });
      expectMaskingEngineRan(safe);
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
    test('does not leak the canary from a Patient read by a clinician', async () => {
      // FLIPPED AT LANE I. The authorization hole this case was blocked on was
      // closed earlier (lane E), which is why the sibling Observation case is
      // already a plain test(). What kept THIS one red afterwards was the last
      // unmasked surface on the kitchen-sink Patient: `link[0].other.reference`
      // = 'Patient/000000018', a raw logical id embedded in a reference string.
      // Lane I rewrites every Reference in the graph, so the end-to-end path is
      // now clean for the Patient too.
      const outcome = await maskViaGuard(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });

    test('does not leak the canary from an Observation read by a clinician', async () => {
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

    test('a resource type absent from the classifier switch REMOVES its identifier', async () => {
      // CORRECTED AT LANE F -- this was a wrong expectation, not a leak.
      //
      // The case was written expecting a pseudonym TOKEN, on the theory that an
      // unenumerated type falls through to the global `identifier` hash rule. It
      // does not, and what it actually gets is STRONGER: an absent type defaults
      // to RESTRICTED, whose only rule is { field: '*', maskingType: 'remove' },
      // and that wildcard DELETES every field instead of hashing any of them. A
      // token is a handle that survives into the output; deletion leaves nothing
      // to hold. Asserting the token would have pinned the WEAKER of the two
      // outcomes, and a later regression from `remove` to `hash` would have read
      // as a pass.
      //
      // RelatedPerson is now listed explicitly in RESOURCE_PHI_MATRIX, so its
      // level no longer depends on the `|| RESTRICTED` fallthrough -- but the
      // assertion below is about what the WILDCARD does, and holds for any type
      // that reaches RESTRICTED by either route.
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

      // Non-vacuity: proven by what SURVIVES the wildcard, not by what is
      // missing. An empty or absent result would fail these two lines.
      expect(masked.resourceType).toBe('RelatedPerson');
      expect(Object.keys(masked).sort()).toEqual(['id', 'resourceType']);

      // The correction itself: removed, not tokenised.
      expect(masked.identifier).toBeUndefined();

      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });
  });

  describe('surface: text.div narrative [owner: T2.1]', () => {
    test('does not leak the canary through text.div, literal', async () => {
      const outcome = await maskViaEngine(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);
      expect(serialise(asObject(outcome.maskedResource).text)).not.toContain(CANARY);
    });

    test('does not leak the canary through text.div as numeric character references', async () => {
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
    test('masks a contained RelatedPerson inside a Patient by its own type', async () => {
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

    test('masks a contained Patient inside an Observation by its own type', async () => {
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
    test('strips Bundle.entry wholesale instead of masking entries in place', async () => {
      // DECIDED AT LANE F. Read the RESOURCE_PHI_MATRIX entry for 'Bundle'
      // before changing this.
      //
      // The original expectation -- entries survive, each masked by its own
      // resourceType -- describes what PHIMaskingEngine.maskNested() does, and
      // maskNested() genuinely does run here. Its output is then discarded by
      // the RESTRICTED wildcard, which deletes `entry` outright.
      //
      // That is kept deliberately. fhir-tools.ts de-structures the search Bundle
      // and submits one entry.resource at a time, so no production caller passes
      // a Bundle to PhiGuard; making the recursion reachable would restore no
      // functionality while downgrading Bundle from RESTRICTED to IDENTIFIABLE.
      // The assertion is therefore rewritten to pin the behaviour that exists
      // rather than the one the fixture author expected. If Bundle is ever
      // reclassified, this test must go back to the per-entry form -- that is
      // the trade, stated where someone will read it.
      const outcome = await maskViaEngine(kitchenSinkBundle(), {
        user: restrictedAccessUser()
      });
      expectMaskingEngineRan(outcome);
      const masked = asObject(outcome.maskedResource);

      // Non-vacuity, from both ends. The wildcard ran on a BUNDLE...
      expect(masked.resourceType).toBe('Bundle');
      expect(Object.keys(masked).sort()).toEqual(['id', 'resourceType']);
      expect(masked.entry).toBeUndefined();
      // ...and the fixture really did carry entries in, so the emptiness above
      // is the masking pass rather than a hollow fixture.
      expect(asArray(kitchenSinkBundle().entry)).toHaveLength(2);

      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });
  });

  describe('surface: Attachment.data [owner: T3.1]', () => {
    test('does not leak a base64-encoded canary, and keeps contentType and size', async () => {
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
    test('does not leak the canary through a custom extension, at any nesting depth', async () => {
      // CLOSED AT LANE F. No finding in the source review named this surface; it
      // is here because an unclaimed surface is exactly what a canary exists to
      // find. PHIMaskingEngine.scrubExtensions() now rebuilds every extension
      // from a { url, extension } whitelist at any depth, so every value[x] goes
      // -- not merely the valueString this fixture happens to use.
      const outcome = await maskViaEngine(
        {
          resourceType: 'Patient',
          id: 'ext-only',
          extension: kitchenSinkPatient().extension
        },
        { user: clinician() }
      );
      expectMaskingEngineRan(outcome);
      const masked = asObject(outcome.maskedResource);

      // Non-vacuity: the extensions were not simply deleted. Both url markers
      // survive, at the top level and one level down, so the assertion below is
      // about the VALUES being gone rather than the element being absent.
      const extensions = asArray(masked.extension);
      expect(extensions).toHaveLength(2);
      expect(asObject(extensions[0]).url).toBe(
        'http://example.org/StructureDefinition/legacy-mrn'
      );
      expect(asObject(extensions[0]).valueString).toBeUndefined();
      const nested = asArray(asObject(extensions[1]).extension);
      expect(nested).toHaveLength(1);
      expect(asObject(nested[0]).url).toBe('inner');
      expect(asObject(nested[0]).valueString).toBeUndefined();

      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });

    test('redacts every value[x] type, modifierExtension, and primitive extensions', async () => {
      // The fixture above uses valueString because a fixture has to pick one.
      // The RULE is not about valueString: it is that nothing but `url` and a
      // nested `extension` survives. These are the shapes the fixture does not
      // cover -- complex choice types, a modifierExtension, a non-conformant
      // extension that a value[x] blacklist would walk straight past, and an
      // extension hanging off a PRIMITIVE via its `_field` sibling, which has no
      // dot-path a MaskingRule could ever name.
      const outcome = await maskViaEngine(
        {
          resourceType: 'Patient',
          id: 'ext-general',
          extension: [
            { url: 'http://example.org/x1', valueIdentifier: { value: CANARY } },
            { url: 'http://example.org/x2', valueHumanName: { family: CANARY } },
            { url: 'http://example.org/x3', valueAddress: { line: [CANARY] } },
            { url: 'http://example.org/x4', valueAttachment: { data: CANARY_BASE64 } },
            {
              url: 'http://example.org/x5',
              valueReference: { reference: `Patient/${CANARY}` }
            },
            { url: 'http://example.org/x6', somethingElseEntirely: CANARY }
          ],
          modifierExtension: [
            { url: 'http://example.org/m1', valueString: CANARY }
          ],
          _birthDate: {
            extension: [{ url: 'http://example.org/b1', valueString: CANARY }]
          }
        },
        { user: clinician() }
      );
      expectMaskingEngineRan(outcome);
      const masked = asObject(outcome.maskedResource);

      // Non-vacuity: all three carriers survive as structure, so the absence
      // asserted below is redaction and not deletion.
      expect(asArray(masked.extension)).toHaveLength(6);
      expect(asArray(masked.modifierExtension)).toHaveLength(1);
      expect(asArray(asObject(masked._birthDate).extension)).toHaveLength(1);
      for (const extension of asArray(masked.extension)) {
        expect(Object.keys(asObject(extension))).toEqual(['url']);
      }

      const blob = serialise(outcome.maskedResource);
      for (const form of CANARY_FORMS) {
        expect({ form: form.label, leaked: blob.includes(form.value) }).toEqual({
          form: form.label,
          leaked: false
        });
      }
    });
  });

  describe('surface: Reference.reference [owner: T4.x]', () => {
    test('does not leak a raw id embedded in a reference string', async () => {
      // CLOSED AT LANE I. The original note read: "`subject.reference` is hashed
      // for Observation, but `Patient/<id>` strings elsewhere are not
      // rewritten." That was right, and a live audit against HAPI showed the
      // gap was TYPE-DEPENDENT rather than uniform: Observation, Encounter,
      // DiagnosticReport and DocumentReference carried a `subject` rule;
      // Condition, Procedure and MedicationRequest did not, and emitted
      // `Patient/<id>` raw.
      //
      // The note also said closing it properly needs bidirectional
      // pseudonymisation. The OUTBOUND half is what re-identification depends
      // on and is what landed: every Reference in the graph is rewritten
      // structurally, and the token comes from the same
      // PHIMaskingEngine.tokenForSubject() that `Resource.id` uses, so one
      // patient yields ONE token everywhere in a session instead of a
      // reference token and a separate `subject`-rule token for the same
      // person. The INBOUND half (resolving a token in a model's request back
      // to a real read) is still unbuilt and belongs to whoever owns the
      // entrypoints; nothing here depends on it.
      const outcome = await maskViaEngine(kitchenSinkPatient(), {
        user: clinician()
      });
      expectMaskingEngineRan(outcome);

      // Non-vacuity: the link element SURVIVES and still says what it pointed
      // at, so this is not passing because `link` was deleted. A rule that
      // dropped the element wholesale would satisfy the canary assertion below
      // while telling the consumer less.
      const link = asArray(asObject(outcome.maskedResource).link);
      expect(link).toHaveLength(1);
      const other = asObject(asObject(link[0]).other);
      expect(other.reference).toMatch(/^Patient\/PT_[A-Za-z0-9_-]{12}$/);

      expect(serialise(asObject(outcome.maskedResource).link)).not.toContain(CANARY);
    });
  });

  describe('surface: meta.security [owner: UNASSIGNED]', () => {
    test('does not leak the canary through a meta.security tag display', async () => {
      // CLOSED AT LANE F. Another surface no finding named. Covered as an
      // ELEMENT rather than as one field: GLOBAL_META_MASKING_RULES drops
      // meta.security[].display, meta.tag[].display and meta.source.
      const outcome = await maskViaEngine(
        {
          resourceType: 'Patient',
          id: 'meta-only',
          meta: kitchenSinkPatient().meta
        },
        { user: clinician() }
      );
      expectMaskingEngineRan(outcome);
      const masked = asObject(outcome.maskedResource);

      // Non-vacuity: `meta` survives and so does the CODED security label --
      // only the free text is gone. A rule that deleted `meta` wholesale would
      // hide the canary while telling the consumer LESS about how to handle the
      // resource, which is the wrong direction for a confidentiality label.
      const meta = asObject(masked.meta);
      expect(meta.versionId).toBe('1');
      const security = asArray(meta.security);
      expect(security).toHaveLength(1);
      expect(asObject(security[0]).code).toBe('restricted');
      expect(asObject(security[0]).display).toBeUndefined();

      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });

    test('covers the whole meta element: tag display and source, not just security', async () => {
      const outcome = await maskViaEngine(
        {
          resourceType: 'Patient',
          id: 'meta-general',
          meta: {
            versionId: '4',
            lastUpdated: '2024-01-01T00:00:00Z',
            source: `http://example.org/export/Patient/${CANARY}`,
            profile: [
              'http://fhir.health.gov.il/StructureDefinition/il-core-patient'
            ],
            security: [
              { system: 'http://example.org/labels', code: 'R', display: CANARY }
            ],
            tag: [
              {
                system: 'http://example.org/tags',
                code: 'batch-7',
                display: `MRN ${CANARY}`
              }
            ]
          }
        },
        { user: clinician() }
      );
      expectMaskingEngineRan(outcome);
      const meta = asObject(asObject(outcome.maskedResource).meta);

      // Kept: server bookkeeping, the canonical profile URL, and the
      // machine-readable half of both Codings.
      expect(meta.versionId).toBe('4');
      expect(asArray(meta.profile)).toHaveLength(1);
      expect(asObject(asArray(meta.security)[0]).code).toBe('R');
      expect(asObject(asArray(meta.tag)[0]).code).toBe('batch-7');

      // Gone: every free-text surface on the element.
      expect(asObject(asArray(meta.security)[0]).display).toBeUndefined();
      expect(asObject(asArray(meta.tag)[0]).display).toBeUndefined();
      expect(meta.source).toBeUndefined();

      expect(serialise(outcome.maskedResource)).not.toContain(CANARY);
    });
  });

  // --------------------------------------------------------------------------
  // The whole-output assertion the source review actually asked for. Every
  // form, every surface, one resource. Flip these LAST -- when they go green,
  // the remediation is done.
  // --------------------------------------------------------------------------
  describe('the full red-team assertion [owner: all lanes; flip LAST]', () => {
    test('leaks the canary nowhere, in any encoding, from the kitchen-sink Patient', async () => {
      // FLIPPED AT LANE I -- the "flip LAST" case for the Patient fixture.
      //
      // This is the whole-output assertion, so it only goes green when every
      // surface on the fixture is closed: identifier, narrative (literal AND
      // entity-encoded), contained[], extension[], meta, and -- last of the
      // nine -- the `Patient/<canary>` inside `link[0].other.reference`. The
      // Bundle sibling below is still `test.failing`: Bundle is RESTRICTED, so
      // `{ field: '*' }` strips `entry` and its `toHaveLength(3)` cannot hold.
      // That is a classification decision recorded on RESOURCE_PHI_MATRIX, not
      // a leak, and it is not this lane's to flip.
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
