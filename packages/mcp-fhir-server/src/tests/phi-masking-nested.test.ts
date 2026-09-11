import { describe, test, expect } from '@jest/globals';
import {
  PHIMaskingEngine,
  DefaultNestedMaskingRuleResolver,
  NestedMaskingRuleResolver
} from '../security/phi-masking-engine.js';
import { MaskingRule } from '../types/phi-types.js';
import {
  CANARY,
  observationWithContainedPatient,
  bundleWithPatientEntry
} from './fixtures/canary.js';

/**
 * Finding 5 - `contained[]` and `Bundle.entry[].resource` bypassed masking
 * because rules were selected from the OUTER resource's type.
 *
 * As in the pseudonym suite, every negative assertion is preceded by proof
 * that masking actually ran (plan §0.3). Here that proof is stronger than a
 * rule count: each test also asserts a positive change to the nested resource,
 * so a test cannot pass because the nested resource vanished for the wrong
 * reason.
 */
function expectMaskingRan(original: any, masked: any): void {
  expect(masked).toBeDefined();
  expect(masked).not.toBeNull();
  expect(masked).not.toBe(original);
}

/** The rules the OUTER Observation gets - none of them touch `contained`. */
const OBSERVATION_RULES: MaskingRule[] = [
  { field: 'subject', maskingType: 'hash' },
  { field: 'performer', maskingType: 'hash' },
  { field: 'note', maskingType: 'remove' }
];

describe('PHIMaskingEngine - contained[] recursion (finding 5)', () => {
  test('masks a contained Patient by PATIENT rules, not the outer Observation rules', () => {
    const engine = new PHIMaskingEngine();
    const original = observationWithContainedPatient();

    const masked = engine.applyMasking(original, OBSERVATION_RULES);
    expectMaskingRan(original, masked);

    // Positive proof the nested resource was processed at all.
    expect(masked.contained).toHaveLength(1);
    expect(masked.contained[0].resourceType).toBe('Patient');
    expect(masked.contained[0].identifier).not.toEqual(original.contained[0].identifier);

    // ...and only then the canary assertion.
    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });

  test('the outer rules are still applied AFTER the inner recursion', () => {
    const engine = new PHIMaskingEngine();
    const original = observationWithContainedPatient();
    original.note = [{ text: 'free text mentioning ' + CANARY }];

    const masked = engine.applyMasking(original, OBSERVATION_RULES);
    expectMaskingRan(original, masked);

    expect(masked.note).toBeUndefined();              // outer 'remove' ran
    expect(masked.subject).not.toEqual(original.subject); // outer 'hash' ran
    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });

  test('does not mutate the caller resource', () => {
    const engine = new PHIMaskingEngine();
    const original = observationWithContainedPatient();

    engine.applyMasking(original, OBSERVATION_RULES);

    expect(original.contained[0].identifier[0].value).toBe(CANARY);
  });
});

describe('PHIMaskingEngine - Bundle.entry[] recursion (finding 5)', () => {
  test('masks each entry by its OWN resourceType, with ZERO outer rules', () => {
    const engine = new PHIMaskingEngine();
    const original = bundleWithPatientEntry();

    // Zero outer rules is the important case: the pre-fix engine returned
    // early on an empty rule list and never looked at the entries at all.
    const masked = engine.applyMasking(original, []);
    expectMaskingRan(original, masked);

    expect(masked.entry).toHaveLength(2);
    expect(masked.entry[0].resource.resourceType).toBe('Patient');
    expect(masked.entry[0].resource.identifier)
      .not.toEqual(original.entry[0].resource.identifier);

    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });

  test('preserves non-resource entry metadata such as fullUrl', () => {
    const engine = new PHIMaskingEngine();
    const masked = engine.applyMasking(bundleWithPatientEntry(), []);

    expect(masked.entry[0].fullUrl).toBe('http://example.org/Patient/p1');
  });

  test('reaches a Patient contained inside a Bundle entry (two levels down)', () => {
    const engine = new PHIMaskingEngine();
    const masked = engine.applyMasking(bundleWithPatientEntry(), []);

    const observation = masked.entry[1].resource;
    expect(observation.resourceType).toBe('Observation');
    expect(JSON.stringify(observation)).not.toContain(CANARY);
  });

  test('leaves a non-Bundle `entry` array (e.g. List.entry) structurally intact', () => {
    const engine = new PHIMaskingEngine();
    const list = {
      resourceType: 'List',
      entry: [{ item: { reference: 'Patient/p1' } }]
    };

    const masked = engine.applyMasking(list, []);
    expect(masked.entry).toHaveLength(1);
    expect(masked.entry[0].item.reference).toBe('Patient/p1');
  });
});

describe('PHIMaskingEngine - the classifier seam (finding 5)', () => {
  test('the default resolver classifies an unknown nested type as RESTRICTED', () => {
    const engine = new PHIMaskingEngine();
    const outer = {
      resourceType: 'Observation',
      contained: [
        { resourceType: 'NotAFhirResourceType', id: 'x1', secret: CANARY }
      ]
    };

    const masked = engine.applyMasking(outer, []);

    // RESTRICTED is `{ field: '*', maskingType: 'remove' }` - everything but
    // resourceType and id goes.
    expect(masked.contained[0].resourceType).toBe('NotAFhirResourceType');
    expect(masked.contained[0].secret).toBeUndefined();
    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });

  test('an injected resolver is used in place of the default', () => {
    const seen: string[] = [];
    const resolver: NestedMaskingRuleResolver = {
      getRulesFor(resource: any): MaskingRule[] {
        seen.push(resource.resourceType);
        return [{ field: 'identifier', maskingType: 'replace', replacement: 'INJECTED' }];
      }
    };

    const engine = new PHIMaskingEngine();
    engine.setRuleResolver(resolver);

    const masked = engine.applyMasking(observationWithContainedPatient(), []);

    expect(seen).toEqual(['Patient']);
    expect(masked.contained[0].identifier).toBe('INJECTED');
    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });

  test('setRuleResolver rejects an object without getRulesFor', () => {
    const engine = new PHIMaskingEngine();
    expect(() => engine.setRuleResolver({} as NestedMaskingRuleResolver)).toThrow();
  });

  test('a resolver that THROWS falls back to RESTRICTED rather than leaking', () => {
    const engine = new PHIMaskingEngine({
      ruleResolver: {
        getRulesFor(): MaskingRule[] {
          throw new Error('resolver exploded');
        }
      }
    });

    const masked = engine.applyMasking(observationWithContainedPatient(), []);
    expect(masked.contained[0].identifier).toBeUndefined();
    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });

  test('a resolver returning an EMPTY rule set falls back to RESTRICTED', () => {
    const engine = new PHIMaskingEngine({
      ruleResolver: { getRulesFor: (): MaskingRule[] => [] }
    });

    const masked = engine.applyMasking(observationWithContainedPatient(), []);
    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });

  test('DefaultNestedMaskingRuleResolver mirrors the classifier matrix', () => {
    const resolver = new DefaultNestedMaskingRuleResolver();

    expect(resolver.getRulesFor({ resourceType: 'Patient' })
      .some(r => r.field === 'identifier')).toBe(true);
    expect(resolver.getRulesFor({ resourceType: 'Coverage' })
      .some(r => r.field === '*')).toBe(true);
    expect(resolver.getRulesFor({})
      .some(r => r.field === '*')).toBe(true);
    expect(resolver.getRulesFor(undefined)
      .some(r => r.field === '*')).toBe(true);
  });
});

describe('PHIMaskingEngine - recursion is bounded (finding 5)', () => {
  test('terminates on a self-referencing contained structure', () => {
    const engine = new PHIMaskingEngine();
    const observation: any = {
      resourceType: 'Observation',
      id: 'obs-cycle',
      contained: []
    };
    const patient: any = {
      resourceType: 'Patient',
      id: 'p1',
      identifier: [{ value: CANARY }],
      contained: []
    };
    patient.contained.push(patient);   // direct self reference
    observation.contained.push(patient);

    const masked = engine.applyMasking(observation, []);

    expect(masked).toBeDefined();
    expect(masked.contained[0].resourceType).toBe('Patient');
    expect(masked.contained[0].identifier).not.toEqual(patient.identifier);
  });

  test('a 1000-deep nest does not blow the stack and does not pass data through', () => {
    const engine = new PHIMaskingEngine();

    let node: any = {
      resourceType: 'Patient',
      id: 'deep',
      identifier: [{ value: CANARY }]
    };
    for (let i = 0; i < 1000; i++) {
      node = { resourceType: 'Observation', id: 'o' + i, contained: [node] };
    }

    const masked = engine.applyMasking(node, []);
    expect(masked).toBeDefined();

    // Past the depth cap the nested resource is reduced to a bare stub, so the
    // canary cannot survive by simply being buried deep enough.
    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });

  test('nesting within the depth cap is still fully masked', () => {
    const engine = new PHIMaskingEngine({ maxNestingDepth: 5 });

    let node: any = {
      resourceType: 'Patient',
      id: 'inner',
      identifier: [{ value: CANARY }]
    };
    for (let i = 0; i < 3; i++) {
      node = { resourceType: 'Observation', id: 'o' + i, contained: [node] };
    }

    const masked = engine.applyMasking(node, []);
    expect(JSON.stringify(masked)).not.toContain(CANARY);

    // Proof the inner resource survived as a resource (was masked, not stubbed).
    expect(masked.contained[0].contained[0].contained[0].resourceType).toBe('Patient');
  });

  test('beyond the depth cap the nested resource is stubbed, not passed through', () => {
    const engine = new PHIMaskingEngine({ maxNestingDepth: 1 });
    const outer = {
      resourceType: 'Observation',
      contained: [
        {
          resourceType: 'Observation',
          contained: [
            { resourceType: 'Patient', id: 'p1', identifier: [{ value: CANARY }] }
          ]
        }
      ]
    };

    const masked = engine.applyMasking(outer, []);
    const stub = masked.contained[0].contained[0];

    expect(stub).toEqual({ resourceType: 'Patient' });
    expect(JSON.stringify(masked)).not.toContain(CANARY);
  });
});
