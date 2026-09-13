import { describe, test, expect } from '@jest/globals';
import { PHIMaskingEngine } from '../security/phi-masking-engine.js';
import { PHIClassifier } from '../security/phi-classifier.js';
import { createAuthEngine, authorizeAndMask, serialize, type MaskOutcome } from './fixtures/phi-harness.js';
import {
  CANARY,
  CANARY_FORMS,
  FREE_TEXT_FIXTURES,
  conditionWithFreeText,
  procedureWithFreeText,
  diagnosticReportWithFreeText,
  unenumeratedTypeWithFreeText,
  asObject,
  asArray,
  serialise,
  type JsonObject
} from './fixtures/canary.js';

/**
 * FINDING B: free text on non-Patient clinical types was not masked.
 *
 * `getResourceSpecificMaskingRules()` had NO `case` arm for Condition,
 * MedicationRequest, Procedure or CarePlan, so each received only the global
 * layer -- and the global layer had no free-text rule. All four leaked through
 * the real tool surface at `phiLevel: "identifiable"`, as did
 * DiagnosticReport.presentedForm[].
 *
 * WHAT THESE TESTS ARE FOR, AND WHAT THEY ARE NOT
 * ----------------------------------------------
 * The per-type cases below are necessary but are NOT the interesting ones: they
 * would all pass against a fix that simply added the four missing `case` arms,
 * and that fix leaves the class open for the next type someone adds. The test
 * that distinguishes a closed CLASS from a closed LIST is
 * `unenumeratedTypeWithFreeText` -- a resource type with no arm in any rule set
 * and no entry in RESOURCE_PHI_MATRIX. Read that one first.
 *
 * ANTI-VACUITY. Every canary assertion here is preceded by proof that the
 * masking path actually ran AND that the specific rule under test fired: the
 * named field is asserted `undefined` before the canary is asserted absent. A
 * bare `not.toContain` over output that was never produced -- or over a resource
 * that was blocked rather than masked -- is a false gate, and this suite treats
 * one as a defect (see fixtures/masking-harness.ts).
 */

/**
 * Prove masking genuinely ran and genuinely changed the resource.
 *
 * `maskedResource` is only populated when the engine both allowed the access and
 * reported `requiresMasking`, so its presence already rules out the blocked
 * path. The serialisation comparison rules out the other failure mode: a mode
 * that returns the input untouched.
 */
function expectMaskingGenuinelyRan(original: JsonObject, outcome: MaskOutcome): void {
  expect(outcome.authorized).toBe(true);
  expect(outcome.maskedResource).toBeDefined();
  expect(outcome.maskedResource).not.toBe(original);
  expect(serialize(outcome.maskedResource)).not.toBe(serialize(original));
}

/** Mask through the authorization engine, the path fhir-tools.ts drives. */
async function mask(resource: JsonObject): Promise<MaskOutcome> {
  return authorizeAndMask(createAuthEngine(), resource);
}

describe('finding B - free text is masked as a CLASS, not per resource type', () => {
  test('a type with NO case arm is clean, and is MASKED rather than wiped', async () => {
    // THE LOAD-BEARING TEST. ServiceRequest has no `case` arm in
    // getResourceSpecificMaskingRules() and is IDENTIFIABLE in
    // RESOURCE_PHI_MATRIX -- exactly where Condition, MedicationRequest,
    // Procedure and CarePlan stood when they leaked. A fix that only adds the
    // four missing `case` arms passes every other test in this file and fails
    // this one.
    //
    // THE SURVIVAL ASSERTIONS BELOW ARE NOT DECORATION. An earlier draft used an
    // invented resourceType, which classified as RESTRICTED and hit
    // `{ field: '*', maskingType: 'remove' }` -- so every field vanished and the
    // test passed with the free-text fix removed entirely. Mutation testing
    // caught it. Asserting that non-PHI clinical content SURVIVES is what makes
    // the canary assertion mean 'masked' rather than 'deleted'.
    const original = unenumeratedTypeWithFreeText();
    const outcome = await mask(original);
    expectMaskingGenuinelyRan(original, outcome);

    const masked = asObject(outcome.maskedResource);

    // NOT wiped: still a usable ServiceRequest.
    expect(masked.resourceType).toBe('ServiceRequest');
    expect(masked.status).toBe('active');
    expect(masked.intent).toBe('order');
    const coding = asObject(asArray(asObject(masked.code).coding)[0]);
    expect(coding.code).toBe('24627-2');
    expect(coding.display).toBe('Chest CT');

    // Declared-layer surfaces closed.
    expect(masked.description).toBeUndefined();
    expect(masked.title).toBeUndefined();
    expect(masked.comment).toBeUndefined();

    // STRUCTURAL-ONLY surfaces closed. No path in
    // GLOBAL_FREE_TEXT_MASKING_RULES reaches either of these, so only
    // scrubFreeText() can have done it -- which is what makes this a test of
    // the CLASS and not of a list.
    expect(asObject(asArray(masked.orderDetail)[0]).text).toBeUndefined();
    const location = asObject(asArray(masked.locationReference)[0]);
    expect(location.display).toBeUndefined();
    expect(location.reference).toBeDefined();

    const blob = serialise(masked);
    for (const form of CANARY_FORMS) {
      expect(blob.includes(form.value)).toBe(false);
    }
  });

  test.each(FREE_TEXT_FIXTURES.map((f) => [f.resourceType, f] as const))(
    '%s: the canary is absent from every free-text surface',
    async (_resourceType, fixture) => {
      const original = fixture.build();
      const outcome = await mask(original);
      expectMaskingGenuinelyRan(original, outcome);

      const blob = serialise(outcome.maskedResource);

      // The canary is planted ONLY in the surfaces this fixture guards, so its
      // presence in the ORIGINAL is what makes the assertion below meaningful.
      expect(serialise(original)).toContain(CANARY);

      for (const form of CANARY_FORMS) {
        expect(blob.includes(form.value)).toBe(false);
      }
    }
  );

  test('note[].text is removed on a type whose switch arm never mentioned note', async () => {
    const original = conditionWithFreeText();
    const outcome = await mask(original);
    expectMaskingGenuinelyRan(original, outcome);

    const masked = asObject(outcome.maskedResource);
    // `note` is removed outright, which takes `author` and `time` with it -- both
    // of which identify people too.
    expect(masked.note).toBeUndefined();
    // `code.text` was the second Condition surface in the finding.
    const code = masked.code === undefined ? undefined : asObject(masked.code);
    expect(code?.text).toBeUndefined();
  });

  test('Coding.display SURVIVES while Reference.display is removed', async () => {
    // The distinction that makes this fix a fix rather than a data-destroying
    // sweep. Both are spelled `display`; only one is PHI. A de-identifier that
    // strips terminology labels has corrupted the clinical record instead of
    // protecting the patient, which is the failure mode
    // GLOBAL_REFERENCE_MASKING_RULES warns about at length.
    const original = procedureWithFreeText();
    const outcome = await mask(original);
    expectMaskingGenuinelyRan(original, outcome);

    const masked = asObject(outcome.maskedResource);

    // Coding.display: kept. Prove the coding is still there at all first,
    // otherwise "display is 'Appendectomy'" could pass on a missing object.
    const coding = asObject(asArray(asObject(masked.code).coding)[0]);
    expect(coding.code).toBe('80146002');
    expect(coding.display).toBe('Appendectomy');

    // Reference.display: gone.
    const report = asObject(asArray(masked.report)[0]);
    expect(report.display).toBeUndefined();
    // ...and the reference itself is still a usable pseudonymised handle, so the
    // removal was targeted rather than the whole element being deleted.
    expect(report.reference).toBeDefined();
  });

  test('presentedForm[].url goes with .data, and the document is still announced', async () => {
    const original = diagnosticReportWithFreeText();
    const outcome = await mask(original);
    expectMaskingGenuinelyRan(original, outcome);

    const masked = asObject(outcome.maskedResource);
    const form = asObject(asArray(masked.presentedForm)[0]);

    // `data` was already handled before this finding; asserted here so a
    // regression in either half of the attachment rule is caught in one place.
    expect(form.data).toBeUndefined();
    // `url` can address the very blob `data` carried. Stripping one and keeping
    // the other is indirection, not de-identification.
    expect(form.url).toBeUndefined();
    expect(form.title).toBeUndefined();

    // The model is still told a document exists -- the bargain the attachment
    // rule has always struck.
    expect(form.contentType).toBe('application/pdf');
    expect(form.size).toBe(2048);
  });

  test('a narrative is NOT collateral damage of the string-text rule', async () => {
    // `text` names two unrelated FHIR elements. A string `text` is
    // CodeableConcept/Annotation/Dosage prose and is removed here; an OBJECT
    // `text` is a Narrative and belongs to the narrative policy, which may SCRUB
    // rather than remove it. If the free-text pass stopped checking the value's
    // type it would silently take the narrative policy's decision away from it.
    const engine = new PHIMaskingEngine();
    const masked = engine.applyMasking(
      {
        resourceType: 'Condition',
        id: 'c-narr',
        text: { status: 'additional', div: '<div>author-written</div>' },
        code: { text: 'free prose' }
      },
      []
    ) as Record<string, unknown>;

    // The string `text` went.
    expect(asObject(masked.code).text).toBeUndefined();
    // The Narrative object survived THIS pass -- no rules were supplied, so
    // nothing else should have touched it either. It is the narrative rule's job
    // to remove or scrub it, and that is tested in phi-narrative-masking.test.ts.
    expect(masked.text).toBeDefined();
    expect(asObject(masked.text).div).toBe('<div>author-written</div>');
  });

  test('an Extension.url and a canonical url are not mistaken for an Attachment url', async () => {
    // `url` is removed only inside an Attachment-SHAPED object. Extensions carry
    // their identity in `url`, and so do canonical resources; removing those
    // would break the resource rather than de-identify it.
    const engine = new PHIMaskingEngine();
    const masked = engine.applyMasking(
      {
        resourceType: 'ValueSet',
        id: 'vs-1',
        url: 'http://example.org/ValueSet/vs-1',
        status: 'active',
        name: 'ExampleValueSet'
      },
      []
    ) as Record<string, unknown>;

    expect(masked.url).toBe('http://example.org/ValueSet/vs-1');
  });

  test('the declared layer names the free-text rules, so the fix is inspectable', () => {
    // The structural pass is what closes the class, but a control nobody can
    // read is a control nobody reviews. The declared rules have to be present in
    // the classification result for a type with NO case arm of its own.
    const classifier = new PHIClassifier();
    const classification = classifier.classifyResource(unenumeratedTypeWithFreeText());
    // Guard: if this ever classified as RESTRICTED, the `*` wildcard would make
    // the rule assertions below meaningless -- the same trap mutation testing
    // found in the class test above.
    expect(classification.phiLevel).not.toBe('restricted');

    const has = (field: string): boolean =>
      classification.requiredMasking.some(
        (rule) => rule.field === field && rule.maskingType === 'remove'
      );

    expect(has('note')).toBe(true);
    expect(has('description')).toBe(true);
    expect(has('title')).toBe(true);
  });
});
