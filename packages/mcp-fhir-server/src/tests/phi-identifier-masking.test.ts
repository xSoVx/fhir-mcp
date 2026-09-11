import { describe, test, expect, beforeEach } from '@jest/globals';
import { PHIClassifier } from '../security/phi-classifier.js';
import { PHIAuthorizationEngine } from '../security/phi-authorization-engine.js';
import { MaskingRule, RESOURCE_PHI_MATRIX } from '../types/phi-types.js';
import { CANARY } from './fixtures/canary.js';
import { authorizeAndMask, createAuthEngine, serialize } from './fixtures/phi-harness.js';

const IL_NATIONAL_ID_SYSTEM = 'http://fhir.health.gov.il/identifier/il-national-id';

function hasRule(rules: MaskingRule[], field: string, maskingType: MaskingRule['maskingType']): boolean {
  return rules.some(rule => rule.field === field && rule.maskingType === maskingType);
}

describe('Finding 1 - identifier masking is unconditional', () => {
  let classifier: PHIClassifier;
  let engine: PHIAuthorizationEngine;

  beforeEach(() => {
    classifier = new PHIClassifier();
    engine = createAuthEngine('strict');
  });

  test('hashes Patient.identifier', async () => {
    const patient = {
      resourceType: 'Patient',
      id: 'p1',
      identifier: [{ system: IL_NATIONAL_ID_SYSTEM, value: CANARY }],
      name: [{ family: 'Cohen', given: ['Tamar'] }]
    };

    const outcome = await authorizeAndMask(engine, patient);

    // The three-assertion shape. Without the first two, `not.toContain` passes
    // on an object that never held the value.
    expect(outcome.authorized).toBe(true);
    expect(outcome.maskedResource).toBeDefined();
    expect(serialize(outcome.maskedResource)).not.toContain(CANARY);
  });

  test('hashes identifier on a resource type with NO case in the switch', async () => {
    // Condition is IDENTIFIABLE in the matrix but has no `case` in
    // getResourceSpecificMaskingRules. It must still get the global rule.
    const condition = {
      resourceType: 'Condition',
      id: 'c1',
      identifier: [{ system: IL_NATIONAL_ID_SYSTEM, value: CANARY }],
      subject: { reference: 'Patient/p1' }
    };

    const outcome = await authorizeAndMask(engine, condition);

    expect(outcome.authorized).toBe(true);
    expect(outcome.maskedResource).toBeDefined();
    expect(serialize(outcome.maskedResource)).not.toContain(CANARY);
  });

  test('hashes identifier even when the resource-specific rules are empty', () => {
    // ServiceRequest: IDENTIFIABLE, no `case`, so the per-type rule list is [].
    const classification = classifier.classifyResource({
      resourceType: 'ServiceRequest',
      id: 's1',
      identifier: [{ value: CANARY }]
    });

    expect(hasRule(classification.requiredMasking, 'identifier', 'hash')).toBe(true);
  });

  test('a resource type absent from RESOURCE_PHI_MATRIX still gets the identifier rule', () => {
    const resourceType = 'NutritionOrder';
    expect(RESOURCE_PHI_MATRIX[resourceType]).toBeUndefined();

    const classification = classifier.classifyResource({
      resourceType,
      id: 'n1',
      identifier: [{ value: CANARY }]
    });

    expect(hasRule(classification.requiredMasking, 'identifier', 'hash')).toBe(true);
  });

  test('masks a no-system identifier', async () => {
    // The legacy applySafeguards path filters identifiers by `system` substring
    // only, so an identifier with no `system` at all is its blind spot.
    const patient = {
      resourceType: 'Patient',
      id: 'p2',
      identifier: [{ value: CANARY }]
    };

    const outcome = await authorizeAndMask(engine, patient);

    expect(outcome.authorized).toBe(true);
    expect(outcome.maskedResource).toBeDefined();
    expect(serialize(outcome.maskedResource)).not.toContain(CANARY);
  });

  test.each([
    ['RelatedPerson'],
    ['Practitioner'],
    ['Encounter'],
    ['Coverage']
  ])('%s carries an identifier hash rule', resourceType => {
    const classification = classifier.classifyResource({
      resourceType,
      id: 'x1',
      identifier: [{ system: IL_NATIONAL_ID_SYSTEM, value: CANARY }]
    });

    expect(hasRule(classification.requiredMasking, 'identifier', 'hash')).toBe(true);
  });

  test('Coverage.subscriberId is masked - it is a plain string, not an Identifier', async () => {
    const coverage = {
      resourceType: 'Coverage',
      id: 'cov1',
      status: 'active',
      subscriberId: CANARY,
      beneficiary: { reference: 'Patient/p1' }
    };

    const classification = classifier.classifyResource(coverage);
    expect(hasRule(classification.requiredMasking, 'subscriberId', 'hash')).toBe(true);

    const outcome = await authorizeAndMask(engine, coverage);

    expect(outcome.authorized).toBe(true);
    expect(outcome.maskedResource).toBeDefined();
    expect(serialize(outcome.maskedResource)).not.toContain(CANARY);
  });

  test('the global rules are independent of DEFAULT_MASKING_RULES for the level', () => {
    // ValueSet is PHILevel.NONE, so DEFAULT_MASKING_RULES[NONE] is []. Anything
    // in requiredMasking here therefore came from the global set, proving it is
    // not sourced from the per-level table.
    //
    // (At runtime PHILevel.NONE never reaches the masking engine, so this
    // changes nothing for public resources -- it is a statement about where
    // the rules come from, not about ValueSet.)
    const classification = classifier.classifyResource({
      resourceType: 'ValueSet',
      id: 'v1',
      identifier: [{ value: CANARY }]
    });

    expect(classification.requiredMasking[0]).toEqual({ field: 'identifier', maskingType: 'hash' });
  });
});
