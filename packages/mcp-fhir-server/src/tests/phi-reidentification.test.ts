import { describe, test, expect } from '@jest/globals';
import { PHIMaskingEngine, PSEUDONYM_TOKEN_PATTERN } from '../security/phi-masking-engine.js';
import { PHIClassifier } from '../security/phi-classifier.js';
import { CANARY, asArray, asObject, serialise } from './fixtures/canary.js';
import {
  clinician,
  expectMaskingEngineRan,
  maskViaEngine,
  restrictedAccessUser
} from './fixtures/masking-harness.js';

/**
 * ============================================================================
 *  RE-IDENTIFICATION -- the two paths that survived masking
 * ============================================================================
 *
 * A live runtime audit against HAPI found masked output still supported a
 * complete pivot back to the patient, by two independent routes:
 *
 *   1. `Resource.id` was NEVER masked. A Patient pseudonymised to `PT_<12ch>`
 *      still shipped `id: "137227909"`. The pseudonym closed nothing: anyone
 *      holding the "de-identified" output could re-read the original resource.
 *
 *   2. Reference exposure was TYPE-DEPENDENT, which nobody had documented:
 *
 *        Condition.subject / MedicationRequest.subject / Procedure.subject
 *          -> `Patient/<id>` survived RAW
 *        Observation.subject / Encounter.subject / DiagnosticReport
 *          -> reference masked (the type carried a `subject` rule)
 *        DocumentReference
 *          -> Patient ref masked, but `Encounter/<id>` survived
 *
 *      So it was never "references are never rewritten". Some resource types
 *      had the rule and some did not, and the ones that did not emitted a
 *      directly dereferenceable patient id.
 *
 * WHAT THIS FILE ASSERTS THAT NOTHING ELSE CAN
 * --------------------------------------------
 * The canary suite proves a VALUE is absent. The golden corpus proves the
 * SHAPE of the output is stable. Neither can prove the property this lane
 * actually turns on, which is token IDENTITY: that one patient yields ONE
 * token everywhere.
 *
 * The golden corpus is structurally incapable of it -- `placeholderiseHashes`
 * renders every token as "<<HASH>>", so `Patient/PT_aaa` and `Patient/PT_bbb`
 * are the same string in an expected.json. That is not a hypothetical: during
 * this lane's own implementation the reference rewrite was non-idempotent and
 * handed Observation a SECOND, different token for a patient whose `id` already
 * had one, and the golden diff for that run looked clean. It was caught by
 * comparing tokens directly, which is what `expectSameSubject` below does.
 *
 * ANTI-VACUITY
 * ------------
 * Every negative assertion here is preceded by positive proof that the path
 * ran: `expectMaskingEngineRan` (authorized === true, maskedResource defined,
 * maskingApplied === true) for the pipeline cases, and an explicit assertion
 * that the rewritten value is a real token -- never merely "not the raw id",
 * which `undefined` also satisfies.
 */

/** A real patient id, shaped like the one the audit actually found. */
const REAL_ID = '137227909';

/**
 * Assert a value is one of our pseudonym tokens, and return it.
 *
 * This is the anti-vacuity primitive for this file. `expect(id).not.toBe(REAL_ID)`
 * passes when `id` is undefined, when the field was deleted, and when masking
 * never ran at all. Requiring the TOKEN shape means the assertion can only pass
 * if a derivation actually happened.
 */
function expectToken(value: unknown): string {
  expect(typeof value).toBe('string');
  expect(value).toMatch(PSEUDONYM_TOKEN_PATTERN);
  return value as string;
}

/** Assert a reference is `Type/<token>` for the expected type, and return the token. */
function expectQualifiedToken(value: unknown, resourceType: string): string {
  expect(typeof value).toBe('string');
  const reference = value as string;
  const [prefix, token] = reference.split('/');
  // The TYPE must survive: a reader has to be able to tell an Observation about
  // a Patient from one about a Device, and the type is not identifying.
  expect(prefix).toBe(resourceType);
  return expectToken(token);
}

function maskWith(
  engine: PHIMaskingEngine,
  classifier: PHIClassifier,
  resource: Record<string, unknown>
): Record<string, unknown> {
  const rules = classifier.classifyResource(resource).requiredMasking;
  // Non-vacuity at the rule layer: an empty rule set would make every assertion
  // below meaningless, and a classifier regression is exactly how that happens.
  expect(rules.length).toBeGreaterThan(0);
  return engine.applyMasking(resource, rules) as Record<string, unknown>;
}

/** One patient referenced from a resource of the given type. */
function resourceReferencingPatient(resourceType: string, id: string): Record<string, unknown> {
  return {
    resourceType,
    id: `${resourceType.toLowerCase()}-1`,
    status: 'final',
    subject: { reference: `Patient/${id}`, display: 'Tamar Cohen' }
  };
}

describe('re-identification: finding 1 -- Resource.id', () => {
  test('a masked Patient does not ship its own logical id', async () => {
    const outcome = await maskViaEngine(
      { resourceType: 'Patient', id: REAL_ID, identifier: [{ value: CANARY }] },
      { user: clinician() }
    );
    expectMaskingEngineRan(outcome);
    const masked = asObject(outcome.maskedResource);

    // Non-vacuity first: `id` is still THERE, and it is a token. An assertion
    // that only checked `id !== REAL_ID` would pass on a deleted field.
    expectToken(masked.id);
    expect(serialise(masked)).not.toContain(REAL_ID);
  });

  test('the RESTRICTED wildcard no longer hands back the primary key', async () => {
    // This was the worst instance. `{ field: '*' }` deletes every field except
    // resourceType and `id` -- so a Coverage was reduced to a type plus the
    // real, dereferenceable server id. Masking at its most aggressive leaked
    // the one value that mattered.
    const outcome = await maskViaEngine(
      { resourceType: 'Coverage', id: REAL_ID, subscriberId: CANARY },
      { user: restrictedAccessUser() }
    );
    expectMaskingEngineRan(outcome);
    const masked = asObject(outcome.maskedResource);

    // The wildcard still ran, and `id` still survives it -- deliberately, so a
    // stripped resource stays distinguishable from redactedStub()'s bare
    // `{ resourceType }` fail-closed marker.
    expect(Object.keys(masked).sort()).toEqual(['id', 'resourceType']);
    expect(masked.resourceType).toBe('Coverage');
    // ...but what survives is a token, not the key.
    expectToken(masked.id);
    expect(serialise(masked)).not.toContain(REAL_ID);
  });

  test('a contained resource gets a FRAGMENT-scoped token, and #refs still resolve to it', () => {
    // A contained resource's `id` is a document-local fragment id, not a server
    // id -- FHIR says so, and it is only ever cited as `#id`. Both sides live in
    // one scope so the pair still resolves after masking. Breaking intra-document
    // resolution would be a correctness loss for no privacy gain.
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();

    const masked = maskWith(engine, classifier, {
      resourceType: 'Observation',
      id: REAL_ID,
      subject: { reference: '#p1' },
      contained: [{ resourceType: 'Patient', id: 'p1', identifier: [{ value: CANARY }] }]
    });

    const containedId = expectToken(asObject(asArray(masked.contained)[0]).id);
    const subject = asObject(masked.subject).reference as string;
    expect(subject.startsWith('#')).toBe(true);
    // THE POINT: the fragment reference still names the contained resource.
    expect(subject).toBe(`#${containedId}`);

    // And a contained fragment id is NOT conflated with a server id of the same
    // spelling -- they are different things and must not share a token.
    expect(containedId).not.toBe(engine.tokenForSubject('Patient', 'p1'));
  });

  test("a contained resource's fragment id is not the outer resource's token", () => {
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();
    const masked = maskWith(engine, classifier, {
      resourceType: 'Observation',
      id: 'shared',
      contained: [{ resourceType: 'Patient', id: 'shared' }]
    });
    const outer = expectToken(masked.id);
    const inner = expectToken(asObject(asArray(masked.contained)[0]).id);
    expect(outer).not.toBe(inner);
  });
});

describe('re-identification: finding 2 -- reference exposure is now uniform', () => {
  // The exact split the audit measured, plus types with no classifier `case` at
  // all. Parameterised on purpose: this is the regression guard for "a rule that
  // fires on some resource types and not others".
  const HAD_A_SUBJECT_RULE = ['Observation', 'Encounter', 'DiagnosticReport', 'DocumentReference'];
  const HAD_NO_SUBJECT_RULE = ['Condition', 'MedicationRequest', 'Procedure'];
  // Types with no `case` in the classifier switch but an IDENTIFIABLE entry in
  // RESOURCE_PHI_MATRIX. `List` is deliberately NOT here: it is absent from the
  // matrix, so it defaults to RESTRICTED and `{ field: '*' }` deletes `subject`
  // outright. Asserting a surviving tokenised reference for it would pin the
  // WEAKER of two safe outcomes. Its reference handling is covered structurally
  // by the List.entry case in phi-masking-nested.test.ts.
  const NEVER_ENUMERATED = ['CarePlan', 'ServiceRequest', 'Goal', 'AllergyIntolerance'];

  const ALL = [...HAD_A_SUBJECT_RULE, ...HAD_NO_SUBJECT_RULE, ...NEVER_ENUMERATED];

  test.each(ALL)('%s.subject is pseudonymised, not emitted raw', (resourceType) => {
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();
    const masked = maskWith(engine, classifier, resourceReferencingPatient(resourceType, REAL_ID));

    const subject = masked.subject;
    // Non-vacuity: the reference SURVIVES and still says it points at a Patient.
    // A rule that deleted `subject` would satisfy the leak assertion below while
    // telling the consumer strictly less.
    expect(subject).toBeDefined();
    expectQualifiedToken(asObject(subject).reference, 'Patient');

    // `Reference.display` is free text and in practice holds the patient's name.
    // No `subject` dot-path rule ever reached it.
    expect(asObject(subject).display).toBeUndefined();

    expect(serialise(masked)).not.toContain(REAL_ID);
    expect(serialise(masked)).not.toContain('Tamar');
  });

  test('the three types the audit found leaking are no longer distinguishable from the four that did not', () => {
    // Stated as an equivalence rather than as seven separate passes: the defect
    // was never "this type leaks", it was "treatment depends on the type". So
    // the assertion is that treatment is now IDENTICAL across the split.
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();

    const shapes = ALL.map((resourceType) => {
      const masked = maskWith(engine, classifier, resourceReferencingPatient(resourceType, REAL_ID));
      return {
        resourceType,
        subject: asObject(masked.subject).reference,
        idIsToken: PSEUDONYM_TOKEN_PATTERN.test(String(masked.id))
      };
    });

    // Every type resolves the SAME patient to the SAME reference string.
    const distinct = new Set(shapes.map((s) => s.subject));
    expect([...distinct]).toHaveLength(1);
    expect(shapes.every((s) => s.idIsToken)).toBe(true);
  });

  test('a DocumentReference Encounter reference is closed too, not just the Patient one', () => {
    // The audit found DocumentReference dropping the Patient ref while
    // `Encounter/<id>` survived -- the per-type rule named `subject` and nothing
    // else, so every OTHER reference on the resource walked straight past it.
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();
    const masked = maskWith(engine, classifier, {
      resourceType: 'DocumentReference',
      id: 'dr1',
      status: 'current',
      subject: { reference: `Patient/${REAL_ID}` },
      context: { encounter: [{ reference: 'Encounter/enc-4242' }] }
    });

    const encounter = asArray(asObject(masked.context).encounter)[0];
    expectQualifiedToken(asObject(encounter).reference, 'Encounter');
    expect(serialise(masked)).not.toContain('enc-4242');
  });

  test('references at paths no rule enumerates are rewritten (the structural guarantee)', () => {
    // `MaskingRule.field` is a fixed dot-path; a Reference has no fixed path.
    // These four are reachable by NO entry in GLOBAL_REFERENCE_MASKING_RULES,
    // which is the whole argument for the pass being structural.
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();
    const masked = maskWith(engine, classifier, {
      resourceType: 'Condition',
      id: 'c1',
      basedOn: [{ reference: `CarePlan/${REAL_ID}` }],
      partOf: [{ reference: 'Procedure/deep-1' }],
      evidence: [{ detail: [{ reference: 'Observation/deep-2' }] }],
      extraNesting: { a: { b: { c: { reference: 'Patient/deep-3' } } } }
    });

    expectQualifiedToken(asObject(asArray(masked.basedOn)[0]).reference, 'CarePlan');
    expectQualifiedToken(asObject(asArray(masked.partOf)[0]).reference, 'Procedure');
    const blob = serialise(masked);
    for (const raw of [REAL_ID, 'deep-1', 'deep-2', 'deep-3']) {
      expect({ raw, leaked: blob.includes(raw) }).toEqual({ raw, leaked: false });
    }
  });

  test('an absolute reference loses its origin server as well as its id', () => {
    // `https://hapi.example.org/fhir/Patient/137227909` is a complete
    // re-identification recipe on its own, so the base URL goes the way
    // meta.source went: removed, not hashed.
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();
    const masked = maskWith(engine, classifier, {
      resourceType: 'Condition',
      id: 'c1',
      subject: { reference: `https://hapi.example.org/fhir/Patient/${REAL_ID}/_history/3` }
    });

    expectQualifiedToken(asObject(masked.subject).reference, 'Patient');
    const blob = serialise(masked);
    expect(blob).not.toContain('hapi.example.org');
    expect(blob).not.toContain(REAL_ID);
    // `_history` is dropped: a version id narrows the resource further and is of
    // no use to a consumer that can no longer dereference anything.
    expect(blob).not.toContain('_history');
  });

  test('a reference shape we cannot decompose fails closed', () => {
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();
    const masked = maskWith(engine, classifier, {
      resourceType: 'Condition',
      id: 'c1',
      subject: { reference: `some-opaque-handle-${REAL_ID}` }
    });

    // Removed rather than guessed at. Non-vacuity: the element is still present
    // (so this is not passing because `subject` vanished), and it is the
    // `reference` value specifically that is gone.
    expect(masked.subject).toBeDefined();
    expect(asObject(masked.subject).reference).toBeUndefined();
    expect(serialise(masked)).not.toContain(REAL_ID);
  });

  test('Reference.identifier is dropped -- it is a national ID no subject path reaches', () => {
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();
    const masked = maskWith(engine, classifier, {
      resourceType: 'Condition',
      id: 'c1',
      subject: {
        reference: `Patient/${REAL_ID}`,
        identifier: {
          system: 'http://fhir.health.gov.il/identifier/il-national-id',
          value: CANARY
        }
      }
    });

    expectQualifiedToken(asObject(masked.subject).reference, 'Patient');
    expect(asObject(masked.subject).identifier).toBeUndefined();
    expect(serialise(masked)).not.toContain(CANARY);
  });
});

describe('re-identification: unified token derivation', () => {
  /**
   * THE CENTRAL ASSERTION OF THIS LANE.
   *
   * Lane F recommended against a reference rewriter for a real reason: the
   * pre-existing `{ field: 'subject', maskingType: 'hash' }` rule HMACs the
   * STRINGIFIED Reference OBJECT, while a rewriter HMACs the BARE id. Same
   * patient, two different `PT_` tokens in one document -- which destroys the
   * within-session join the engine deliberately preserves and would make a
   * reader conclude these are different people. Silently wrong linkage is worse
   * than a visibly raw id.
   *
   * The coherent fix lane F named was to unify derivation behind one
   * `tokenForSubject(type, id)`. This is the test that it actually happened.
   */
  test('one patient yields ONE token across id, subject, and every resource type', () => {
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();

    // The canonical value, straight from the single derivation point.
    const canonical = engine.tokenForSubject('Patient', REAL_ID);
    expectToken(canonical);

    // Appearance 1: the Patient's own logical id.
    const patient = maskWith(engine, classifier, { resourceType: 'Patient', id: REAL_ID });
    expect(patient.id).toBe(canonical);

    // Appearances 2..n: `subject` on types that DID carry a hash rule and types
    // that did not. These took different code paths before this lane and are
    // required to agree now.
    for (const resourceType of [
      'Observation', // had the rule -> used to HMAC the stringified object
      'Encounter', // had the rule
      'Condition', // had NO rule -> used to emit Patient/<id> raw
      'Procedure', // had NO rule
      'MedicationRequest' // had NO rule
    ]) {
      const masked = maskWith(engine, classifier, resourceReferencingPatient(resourceType, REAL_ID));
      expect({ resourceType, reference: asObject(masked.subject).reference }).toEqual({
        resourceType,
        reference: `Patient/${canonical}`
      });
    }
  });

  test('the join is not broken by a Reference that merely LOOKS different', () => {
    // The old derivation keyed on JSON.stringify(reference), so the SAME patient
    // cited once with a display name and once without already hashed to two
    // different tokens. The within-session join it was protecting worked only by
    // coincidence. Routed through tokenForSubject(type, id), the incidental
    // fields cannot matter.
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();

    const variants: Array<Record<string, unknown>> = [
      { reference: `Patient/${REAL_ID}` },
      { reference: `Patient/${REAL_ID}`, display: 'Tamar Cohen' },
      { reference: `Patient/${REAL_ID}`, type: 'Patient' },
      { reference: `Patient/${REAL_ID}/_history/2` },
      { reference: `https://hapi.example.org/fhir/Patient/${REAL_ID}` }
    ];

    const tokens = variants.map((subject) => {
      const masked = maskWith(engine, classifier, {
        resourceType: 'Observation',
        id: 'o1',
        status: 'final',
        subject
      });
      return asObject(masked.subject).reference;
    });

    expect(new Set(tokens).size).toBe(1);
    expect(tokens[0]).toBe(`Patient/${engine.tokenForSubject('Patient', REAL_ID)}`);
  });

  test('masking is idempotent -- re-masking output does not mint a second identity', () => {
    // Load-bearing, and not theoretical: Observation, Encounter,
    // DiagnosticReport and DocumentReference now carry the `subject` rule TWICE
    // (the global one plus their per-type one), so a non-idempotent rewrite
    // splits the patient in two WITHIN A SINGLE applyMasking() call. That is
    // exactly the bug this lane shipped and then caught.
    const engine = new PHIMaskingEngine();
    const classifier = new PHIClassifier();
    const original = resourceReferencingPatient('Observation', REAL_ID);

    const once = maskWith(engine, classifier, original);
    const twice = engine.applyMasking(once, classifier.classifyResource(once).requiredMasking);

    expect(asObject((twice as Record<string, unknown>).subject).reference).toBe(
      asObject(once.subject).reference
    );
    expect((twice as Record<string, unknown>).id).toBe(once.id);
  });

  test('different patients get different tokens (the derivation is not a constant)', () => {
    // The mirror of the assertion above, and the reason it is not vacuous: a
    // `tokenForSubject` that returned a fixed string would pass every equality
    // test in this file.
    const engine = new PHIMaskingEngine();
    expect(engine.tokenForSubject('Patient', REAL_ID)).not.toBe(
      engine.tokenForSubject('Patient', '137227910')
    );
    // And the scope is part of the key, so a Device with the same row id is not
    // asserted to be the same entity as the Patient.
    expect(engine.tokenForSubject('Patient', REAL_ID)).not.toBe(
      engine.tokenForSubject('Device', REAL_ID)
    );
  });

  test('a logical-id token is NOT the same token as an identifier of the same spelling', () => {
    // `Patient.identifier[].value` can be the national ID and `Patient.id` can
    // be the same digits. They are different identifier spaces, and collapsing
    // them would assert a link that does not exist. The namespace prefix in
    // tokenForSubject is what keeps them apart.
    const engine = new PHIMaskingEngine();
    const masked = engine.applyMasking(
      { resourceType: 'Patient', id: CANARY, identifier: [{ value: CANARY }] },
      [{ field: 'identifier', maskingType: 'hash' }]
    ) as Record<string, unknown>;

    const idToken = expectToken(masked.id);
    const identifierToken = expectToken(masked.identifier);
    expect(idToken).not.toBe(identifierToken);
    expect(serialise(masked)).not.toContain(CANARY);
  });

  test('tokens do not survive a session-key rotation', () => {
    // The re-identification guarantee rests on this. A token that were stable
    // across sessions would be a durable pseudonym -- joinable to a previous
    // export and, for a small id space, attackable offline.
    const engine = new PHIMaskingEngine();
    const before = engine.tokenForSubject('Patient', REAL_ID);
    engine.rotateSessionKey();
    expect(engine.tokenForSubject('Patient', REAL_ID)).not.toBe(before);
  });

  test('two engines (two sessions) do not agree on a token', () => {
    expect(new PHIMaskingEngine().tokenForSubject('Patient', REAL_ID)).not.toBe(
      new PHIMaskingEngine().tokenForSubject('Patient', REAL_ID)
    );
  });
});

describe('re-identification: the logicalIdPolicy escape hatch', () => {
  test("'remove' drops the id entirely, and the references then dangle", () => {
    // Offered, documented, and NOT the default. This test exists to pin the
    // consequence rather than to endorse it: with `id` gone, the rewritten
    // `Patient/PT_xxx` in the Condition below points at a resource that no
    // longer declares that token -- a handle the reader cannot resolve, in a
    // response that contains the very resource it refers to.
    const engine = new PHIMaskingEngine({ logicalIdPolicy: 'remove' });
    const classifier = new PHIClassifier();

    const patient = maskWith(engine, classifier, { resourceType: 'Patient', id: REAL_ID });
    expect(patient.id).toBeUndefined();

    const condition = maskWith(engine, classifier, resourceReferencingPatient('Condition', REAL_ID));
    // The reference still carries a token...
    const token = expectQualifiedToken(asObject(condition.subject).reference, 'Patient');
    // ...and nothing in the output resolves it. That is the cost of 'remove',
    // and the reason 'tokenize' is the default.
    expect(serialise(patient)).not.toContain(token);
  });

  test('an unrecognised policy value falls through to the documented default', () => {
    const engine = new PHIMaskingEngine({
      logicalIdPolicy: 'whatever' as never
    });
    const masked = engine.applyMasking({ resourceType: 'Patient', id: REAL_ID }, []) as Record<
      string,
      unknown
    >;
    expectToken(masked.id);
  });
});

describe('re-identification: the passes are bounded and non-destructive', () => {
  test('a self-referencing contained structure terminates', () => {
    // Both new passes recurse. deepClone preserves shared references, so a
    // cyclic graph is real here, not hypothetical -- and the id pass did blow
    // the stack before it was given a visited set.
    const engine = new PHIMaskingEngine();
    const outer: Record<string, unknown> = { resourceType: 'Observation', id: 'o1' };
    outer.contained = [outer];
    expect(() => engine.applyMasking(outer, [])).not.toThrow();
  });

  test('a reference cycle terminates', () => {
    const engine = new PHIMaskingEngine();
    const node: Record<string, unknown> = { reference: `Patient/${REAL_ID}` };
    node.self = node;
    const resource = { resourceType: 'Condition', id: 'c1', subject: node };
    expect(() => engine.applyMasking(resource, [])).not.toThrow();
  });

  test('the caller resource is never mutated', () => {
    // The masking engine deep-clones. If either new pass wrote through to the
    // input, the caller's own copy of the record would be silently corrupted --
    // and in this codebase the caller's copy is the real FHIR resource.
    const engine = new PHIMaskingEngine();
    const original = resourceReferencingPatient('Condition', REAL_ID);
    engine.applyMasking(original, [{ field: 'subject', maskingType: 'hash' }]);

    expect(original.id).toBe('condition-1');
    expect((original.subject as Record<string, unknown>).reference).toBe(`Patient/${REAL_ID}`);
    expect((original.subject as Record<string, unknown>).display).toBe('Tamar Cohen');
  });

  test('non-reference strings containing a slash are left alone', () => {
    // The parser anchors on the FHIR resource-name shape so it cannot mistake a
    // mime type, a path or a free-text value for a reference and quietly
    // rewrite it. A de-identifier that corrupts clinical data is its own kind of
    // failure.
    const engine = new PHIMaskingEngine();
    const masked = engine.applyMasking(
      {
        resourceType: 'DocumentReference',
        id: 'd1',
        content: [{ attachment: { contentType: 'application/pdf', title: 'a/b' } }]
      },
      []
    ) as Record<string, unknown>;

    const attachment = asObject(asObject(asArray(masked.content)[0]).attachment);
    expect(attachment.contentType).toBe('application/pdf');
    expect(attachment.title).toBe('a/b');
  });
});

describe('re-identification: interaction with the OPEN id-as-direct-identifier question', () => {
  test('masking a logical id does NOT change how the resource is classified', () => {
    // RECORDED FOR THE USER'S DECISION, NOT DECIDING IT.
    //
    // phi-classifier.ts:89 sets `hasDirectIdentifiers` on `id` OR `identifier`,
    // and determineFinalPHILevel then upgrades MINIMAL -> IDENTIFIABLE. That
    // makes PHILevel.MINIMAL unreachable for any resource carrying an `id`, and
    // it is what keeps three tests quarantined in test-baseline.json. It is the
    // user's open call and was deliberately NOT touched by this lane.
    //
    // The interaction worth knowing: classification runs on the INPUT resource
    // and masking runs after it, so tokenising `id` cannot and does not move
    // the PHI level. The two are independent, and this test pins that -- so
    // whichever way the open question is settled, it will not be settled by
    // accident here.
    const classifier = new PHIClassifier();

    const withRealId = classifier.classifyResource({ resourceType: 'Organization', id: 'org-123' });
    const withTokenId = classifier.classifyResource({
      resourceType: 'Organization',
      id: new PHIMaskingEngine().tokenForSubject('Organization', 'org-123')
    });

    // Same level either way: a token in the `id` slot is still an `id`.
    expect(withTokenId.phiLevel).toBe(withRealId.phiLevel);
    // And the level is the upgraded one, which is the quarantined behaviour --
    // asserted here so that if someone DOES narrow the rule, this test fails and
    // the reviewer is sent to read the note above rather than left guessing.
    expect(withRealId.identifiableFields).toContain('id');
  });

  test('an Organization with NO id still reaches MINIMAL, and its id rule is now dead code', () => {
    // The other half of the interaction, and an argument for the structural
    // approach this lane took: DEFAULT_MASKING_RULES[MINIMAL] contains
    // `{ field: 'id', maskingType: 'hash' }` -- the ONLY `id` rule that existed
    // before this lane -- and because MINIMAL is unreachable for anything
    // carrying an `id`, that rule could never fire on a resource that had one.
    // An `id` guarantee expressed as a PHI-level rule was structurally
    // incapable of firing. pseudonymiseLogicalIds() does not depend on the
    // level at all.
    const classifier = new PHIClassifier();
    const noId = classifier.classifyResource({ resourceType: 'Organization', name: 'Clalit' });
    expect(noId.phiLevel).toBe('minimal');
    expect(noId.requiredMasking.some((rule) => rule.field === 'id')).toBe(true);
  });
});
