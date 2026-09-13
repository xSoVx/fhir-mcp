import { createHash } from 'node:crypto';
/**
 * The PHI canary.
 *
 * One value, planted in every place a FHIR resource can hide an identifier.
 * Mask the resource, serialise it, and the value must appear nowhere. That
 * single assertion catches every finding in the source review -- and, more to
 * the point, every location nobody enumerated.
 *
 * This module is the ONLY place the literal is allowed to appear. Grepping for
 * it anywhere else (outside the golden corpus, which stores it as fixture data)
 * should return nothing.
 */

/**
 * `000000018` is a VALID Israeli national ID (teudat zehut), taken from the
 * IL-Core specification's own Patient example.
 *
 * The leading zeros are the point. An Israeli ID is nine digits including a
 * check digit, and low-numbered IDs are real and in use. Any regex that
 * validates or detects one with a `[1-9]` first character -- or that reaches
 * for `parseInt` and compares numerically -- silently misses this value while
 * appearing to work on every test case someone typed by hand.
 *
 * Do not "fix" this constant to look more realistic.
 */
export const CANARY = '000000018';

/**
 * The canary written as XHTML numeric character references.
 *
 * `text.div` is XHTML, and `&#x30;` is a perfectly legal way to write `0`. A
 * narrative scrubber that regexes the raw string for CANARY sees nothing here,
 * while any browser, any XHTML parser, and any model reading the output sees
 * the digits. This is why the narrative must be ENTITY-DECODED BEFORE it is
 * scanned, not after.
 */
export const CANARY_NUMERIC_ENTITIES = CANARY.split('')
  .map((digit) => `&#x${digit.charCodeAt(0).toString(16)};`)
  .join('');

/**
 * Hebrew, entity-encoded: the family name "Cohen" as it appears in IL-Core's
 * own canonical example narrative. Present for the same reason as above -- a
 * scrubber that only decodes ASCII is not decoding.
 */
export const HEBREW_NAME_ENTITIES = '&#x5DB;&#x5D4;&#x5DF;';

/** The canary base64-encoded, as it would sit in an Attachment.data blob. */
export const CANARY_BASE64 = Buffer.from(CANARY, 'utf8').toString('base64');

/**
 * Every form the canary can take in a serialised resource.
 *
 * Assert against ALL of these, not just the plaintext. A masking pass that
 * strips the literal while leaving the entity-encoded or base64 form behind has
 * not de-identified anything; it has only made the leak harder to grep for.
 */
export const CANARY_FORMS: ReadonlyArray<{ label: string; value: string }> = [
  { label: 'plaintext', value: CANARY },
  { label: 'numeric character references', value: CANARY_NUMERIC_ENTITIES },
  { label: 'base64', value: CANARY_BASE64 },
  { label: 'entity-encoded Hebrew name', value: HEBREW_NAME_ENTITIES }
];

/**
 * Minimal JSON types.
 *
 * These fixtures and the assertions over them deliberately avoid `any`: the
 * repo's lint baseline is 0 errors and a fixed warning count, and a test
 * harness that adds `any` warnings while asserting on type-sensitive masking
 * behaviour is setting a poor example for the code it guards.
 */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

/** Narrow an unknown to a JSON object, failing loudly if it is not one. */
export function asObject(value: unknown): JsonObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(
      `expected a JSON object, got ${Array.isArray(value) ? 'array' : typeof value}`
    );
  }
  return value as JsonObject;
}

/** Narrow an unknown to a JSON array, failing loudly if it is not one. */
export function asArray(value: unknown): JsonValue[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`expected a JSON array, got ${typeof value}`);
  }
  return value as JsonValue[];
}

const IL_NATIONAL_ID_SYSTEM =
  'http://fhir.health.gov.il/identifier/il-national-id';

/**
 * A Patient carrying the canary in every Patient-shaped hiding place at once:
 * structured identifier, narrative (both literal and entity-encoded), a
 * contained Patient, a custom extension, and a self-reference.
 */
export function kitchenSinkPatient(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'Patient',
    id: 'canary-patient',

    // 1. Structured field -- the obvious one.
    identifier: [
      { system: IL_NATIONAL_ID_SYSTEM, value: canary },
      // 2. An identifier with NO system. The legacy applySafeguards() path
      //    filters identifiers by matching 'ssn'/'social'/'government'/
      //    'national' against `system`, so a system-less identifier walks
      //    straight through it.
      { value: canary },
      // 3. Nested one level down, where a top-level field rule does not reach.
      {
        system: IL_NATIONAL_ID_SYSTEM,
        value: 'not-the-canary',
        assigner: { display: `Registered under ${canary}` }
      }
    ],

    name: [{ family: 'Cohen', given: ['Tamar'] }],
    birthDate: '1980-01-01',

    // 4. Narrative, literal form.
    // 5. Narrative, numeric character reference form -- same digits, invisible
    //    to a regex on the raw string.
    text: {
      status: 'generated',
      div:
        '<div xmlns="http://www.w3.org/1999/xhtml">' +
        `Tamar Cohen, ID ${canary}` +
        `<br/>${HEBREW_NAME_ENTITIES} ${CANARY_NUMERIC_ENTITIES}` +
        '</div>'
    },

    // 6. Contained resource -- a full resource with its own resourceType, which
    //    the outer type's rule set never dispatches on.
    contained: [
      {
        resourceType: 'RelatedPerson',
        id: 'rp1',
        identifier: [{ system: IL_NATIONAL_ID_SYSTEM, value: canary }],
        name: [{ family: 'Cohen', given: ['Yossi'] }]
      }
    ],

    // 7. Extension -- arbitrary, schema-free, and not enumerated by any rule.
    extension: [
      {
        url: 'http://example.org/StructureDefinition/legacy-mrn',
        valueString: canary
      },
      {
        url: 'http://example.org/StructureDefinition/nested',
        extension: [
          { url: 'inner', valueString: `mrn:${canary}` }
        ]
      }
    ],

    // 8. Reference -- a literal id embedded in a string.
    link: [
      {
        other: { reference: `Patient/${canary}` },
        type: 'seealso'
      }
    ],

    // 9. meta.security tag -- a surface no finding in the review named.
    meta: {
      versionId: '1',
      security: [
        {
          system: 'http://example.org/labels',
          code: 'restricted',
          display: `subject ${canary}`
        }
      ]
    }
  };
}

/**
 * An Observation whose contained Patient carries the canary, plus the canary in
 * `subject.reference` and in a free-text note.
 */
export function kitchenSinkObservation(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'Observation',
    id: 'canary-observation',
    status: 'final',
    code: { coding: [{ system: 'http://loinc.org', code: '718-7' }] },
    subject: { reference: `Patient/${canary}` },
    contained: [
      {
        resourceType: 'Patient',
        id: 'p1',
        identifier: [{ system: IL_NATIONAL_ID_SYSTEM, value: canary }],
        name: [{ family: 'Cohen' }],
        text: {
          status: 'generated',
          div: `<div xmlns="http://www.w3.org/1999/xhtml">Tamar Cohen ${canary}</div>`
        }
      }
    ],
    note: [{ text: `Patient ID ${canary} reported dizziness.` }],
    valueQuantity: { value: 13.2, unit: 'g/dL' }
  };
}

/** A DocumentReference with the canary base64-encoded inside an attachment. */
export function kitchenSinkDocumentReference(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'DocumentReference',
    id: 'canary-docref',
    status: 'current',
    subject: { reference: `Patient/${canary}` },
    content: [
      {
        attachment: {
          contentType: 'text/plain',
          size: canary.length,
          title: 'Discharge summary',
          data: Buffer.from(canary, 'utf8').toString('base64')
        }
      }
    ]
  };
}

/** A Bundle wrapping the Patient and the Observation. */
export function kitchenSinkBundle(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'Bundle',
    id: 'canary-bundle',
    type: 'searchset',
    entry: [
      { resource: kitchenSinkPatient(canary) },
      { resource: kitchenSinkObservation(canary) }
    ]
  };
}

/**
 * Serialise exactly the way the MCP tool path does.
 *
 * This matters: maskingType 'remove' sets a field to `undefined` rather than
 * deleting the key (phi-masking-engine.ts:116) and relies on the caller
 * serialising it away. Any assertion or golden comparison that inspects the
 * object graph instead of its JSON sees `undefined` keys the real consumer
 * never sees, and drifts from reality in both directions.
 */
export function serialise(value: unknown): string {
  return JSON.stringify(value ?? null);
}
/* ---------------------------------------------------------------------------
 * Lane-C aliases (merged during integration).
 *
 * Lane C created a second `fixtures/canary.ts` with its own names for the same
 * values. The G-CANARY gate requires the literal to live in exactly ONE module,
 * so that file was folded into this one and its names are re-exported here
 * rather than kept as a second copy of the constant.
 * ------------------------------------------------------------------------ */

/** Lane-C name for {@link CANARY_NUMERIC_ENTITIES}. Identical value. */
export const CANARY_ENTITY = CANARY_NUMERIC_ENTITIES;

/**
 * "Tamar Cohen" in Hebrew, from IL-Core's canonical Patient example, written
 * with unicode escapes so the fixture survives any encoding round trip.
 */
export const CANARY_NAME = '\u05EA\u05DE\u05E8 \u05DB\u05D4\u05DF';

/** The same name as XHTML numeric character references. */
export const CANARY_NAME_ENTITY = '&#x5EA;&#x5DE;&#x5E8; &#x5DB;&#x5D4;&#x5DF;';

/**
 * First character of {@link CANARY_NAME} as an entity -- asserted absent from
 * masked output. A scrubber that only decodes ASCII is not decoding.
 */
export const CANARY_NAME_ENTITY_FRAGMENT = '&#x5EA;';

/* ---------------------------------------------------------------------------
 * Lane-D aliases and fixtures (merged during integration), same reason.
 * ------------------------------------------------------------------------ */

/**
 * What the PRE-FIX engine emitted for the canary: an unsalted, unkeyed sha256
 * truncated to 16 hex characters.
 *
 * Computed rather than hard-coded, so the constant tracks the actual attack
 * instead of a copy of it. The Israeli ID space is ~10^8 after the check digit,
 * so a complete rainbow table over these values is minutes of GPU time -- the
 * value below is therefore equivalent to publishing the ID. No masked output
 * may ever contain this string again.
 */
export const LEGACY_UNSALTED_SHA256 = createHash('sha256')
  .update(CANARY)
  .digest('hex')
  .substring(0, 16);

/** An Observation whose `contained[]` Patient carries the canary (finding 5). */
export function observationWithContainedPatient(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'Observation',
    id: 'obs-1',
    status: 'final',
    subject: { reference: '#p1' },
    contained: [
      {
        resourceType: 'Patient',
        id: 'p1',
        identifier: [{ system: 'http://example.org/il-id', value: canary }],
        name: [{ family: 'Cohen', given: ['Dana'] }],
        birthDate: '1980-01-01'
      }
    ]
  };
}

/** A Bundle carrying the canary inside `entry[].resource` (finding 5). */
export function bundleWithPatientEntry(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'Bundle',
    type: 'searchset',
    entry: [
      {
        fullUrl: 'http://example.org/Patient/p1',
        resource: {
          resourceType: 'Patient',
          id: 'p1',
          identifier: [{ system: 'http://example.org/il-id', value: canary }],
          name: [{ family: 'Cohen' }]
        }
      },
      {
        fullUrl: 'http://example.org/Observation/obs-1',
        resource: observationWithContainedPatient(canary)
      }
    ]
  };
}

/* ---------------------------------------------------------------------------
 * Lane-J fixtures: FREE TEXT on the clinical types with no `case` arm.
 *
 * `PHIClassifier.getResourceSpecificMaskingRules()` had no `case` at all for
 * Condition, MedicationRequest, Procedure or CarePlan, so each received only the
 * global layer -- which had no free-text rule. Each fixture below plants the
 * canary in exactly the fields that finding named, and nowhere else, so a
 * failure says which surface regressed rather than only that something did.
 * ------------------------------------------------------------------------ */

/** Condition: `note[].text` and `code.text`. */
export function conditionWithFreeText(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'Condition',
    id: 'cond-1',
    subject: { reference: 'Patient/p1' },
    // A real coding SURVIVES masking; only the free-text `.text` beside it goes.
    // Asserting both in one fixture is what stops the fix from being "delete the
    // whole CodeableConcept".
    code: {
      coding: [{ system: 'http://snomed.info/sct', code: '73211009', display: 'Diabetes mellitus' }],
      text: `Diabetes, per chart for ID ${canary}`
    },
    note: [{ text: `Patient ${canary} reports poor control.` }]
  };
}

/** MedicationRequest: `note[].text` and `dosageInstruction[].text`. */
export function medicationRequestWithFreeText(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'MedicationRequest',
    id: 'medreq-1',
    status: 'active',
    intent: 'order',
    subject: { reference: 'Patient/p1' },
    dosageInstruction: [{ text: `500mg twice daily -- dispense to ${canary}` }],
    note: [{ text: `Called patient ${canary} to confirm.` }]
  };
}

/** Procedure: `note[].text` and `report[].display` (a Reference.display). */
export function procedureWithFreeText(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'Procedure',
    id: 'proc-1',
    status: 'completed',
    subject: { reference: 'Patient/p1' },
    code: {
      coding: [{ system: 'http://snomed.info/sct', code: '80146002', display: 'Appendectomy' }]
    },
    report: [
      {
        reference: 'DiagnosticReport/dr-1',
        // Reference.display -- NOT Coding.display. The masking pass must tell
        // these apart: the Coding.display above has to survive.
        display: `Operative report for ${canary}`
      }
    ],
    note: [{ text: `Uneventful recovery, ${canary}.` }]
  };
}

/** CarePlan: `note[].text` and `description`. */
export function carePlanWithFreeText(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'CarePlan',
    id: 'cp-1',
    status: 'active',
    intent: 'plan',
    subject: { reference: 'Patient/p1' },
    description: `Diabetes management plan for ID ${canary}`,
    note: [{ text: `Reviewed with ${canary} at clinic.` }]
  };
}

/**
 * DiagnosticReport: `presentedForm[].title` and `presentedForm[].url`.
 *
 * `.data` is ALREADY stripped by GLOBAL_ATTACHMENT_MASKING_RULES, and it is
 * present here on purpose: `url` addresses the same blob `data` carried, so a
 * masked report that dropped `data` and kept `url` leaked the identical content
 * behind one redirect.
 */
export function diagnosticReportWithFreeText(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'DiagnosticReport',
    id: 'dr-2',
    status: 'final',
    subject: { reference: 'Patient/p1' },
    code: { coding: [{ system: 'http://loinc.org', code: '58410-2', display: 'CBC panel' }] },
    presentedForm: [
      {
        contentType: 'application/pdf',
        size: 2048,
        title: `Lab report -- ${canary}`,
        url: `https://files.example.org/reports/${canary}.pdf`,
        data: Buffer.from(canary, 'utf8').toString('base64')
      }
    ]
  };
}

/**
 * A resource type with NO `case` arm in getResourceSpecificMaskingRules() that is
 * nevertheless IDENTIFIABLE in RESOURCE_PHI_MATRIX.
 *
 * Finding B is a defect of CLASS, not of list: the four missing `case` arms were
 * symptoms. A fix that enumerates those four passes every per-type test and fails
 * this one, so this is the only fixture here that distinguishes "closed the four
 * holes" from "closed the category".
 *
 * WHY ServiceRequest, AND WHY NOT A MADE-UP TYPE
 * ---------------------------------------------
 * This fixture was first written with an invented type ('NutritionOrder'), and
 * MUTATION TESTING caught that as a FALSE GATE. A type absent from
 * RESOURCE_PHI_MATRIX classifies as RESTRICTED, and
 * DEFAULT_MASKING_RULES[RESTRICTED] is `{ field: '*', maskingType: 'remove' }` --
 * every field is deleted regardless of any free-text rule. The test passed with
 * the free-text fix ripped out entirely, because it had been proving the
 * RESTRICTED wildcard rather than the fix.
 *
 * ServiceRequest is the real analogue of where Condition, MedicationRequest,
 * Procedure and CarePlan stood when they leaked: IDENTIFIABLE, so genuinely
 * rule-masked rather than wiped, and with no `case` arm of its own. Any
 * replacement must satisfy BOTH halves, and the test asserts that non-PHI
 * clinical content survives precisely so a regression to wildcard-wipe behaviour
 * cannot make it pass again.
 *
 * `orderDetail[].text` and `locationReference[].display` are the STRUCTURAL-ONLY
 * probes: neither path appears in GLOBAL_FREE_TEXT_MASKING_RULES, so only
 * PHIMaskingEngine.scrubFreeText() can reach them.
 */
export function unenumeratedTypeWithFreeText(canary: string = CANARY): JsonObject {
  return {
    resourceType: 'ServiceRequest',
    id: 'svcreq-1',
    status: 'active',
    intent: 'order',
    subject: { reference: 'Patient/p1' },

    // A real coding, asserted to SURVIVE. This is the anti-wildcard guard: if
    // this element disappears the resource was wiped rather than masked, and any
    // canary-absence assertion over it is worthless.
    code: {
      coding: [{ system: 'http://loinc.org', code: '24627-2', display: 'Chest CT' }],
      text: `CT chest for ${canary}`
    },

    // Declared-layer surfaces.
    description: `Imaging request for ${canary}`,
    title: `Request ${canary}`,
    comment: `Discussed with ${canary}.`,
    note: [{ text: `Patient ${canary} prefers morning slots.` }],

    // STRUCTURAL-ONLY surfaces: no declared path reaches either of these.
    orderDetail: [{ text: `With contrast -- ID ${canary}` }],
    locationReference: [{ reference: 'Location/l1', display: `Clinic of ${canary}` }]
  };
}

/** Every free-text fixture, with the surfaces each one is guarding. */
export const FREE_TEXT_FIXTURES: ReadonlyArray<{
  resourceType: string;
  surfaces: string[];
  build: (canary?: string) => JsonObject;
}> = [
  {
    resourceType: 'Condition',
    surfaces: ['note[].text', 'code.text'],
    build: conditionWithFreeText
  },
  {
    resourceType: 'MedicationRequest',
    surfaces: ['note[].text', 'dosageInstruction[].text'],
    build: medicationRequestWithFreeText
  },
  {
    resourceType: 'Procedure',
    surfaces: ['note[].text', 'report[].display'],
    build: procedureWithFreeText
  },
  {
    resourceType: 'CarePlan',
    surfaces: ['note[].text', 'description'],
    build: carePlanWithFreeText
  },
  {
    resourceType: 'DiagnosticReport',
    surfaces: ['presentedForm[].title', 'presentedForm[].url'],
    build: diagnosticReportWithFreeText
  },
  {
    resourceType: 'ServiceRequest',
    surfaces: [
      'no case arm, IDENTIFIABLE -- the class test',
      'orderDetail[].text and locationReference[].display are structural-only'
    ],
    build: unenumeratedTypeWithFreeText
  }
];

/**
 * A `resourceType` carrying the canary, for finding C.
 *
 * The value observed in a real audit record. It is attacker-controlled free text
 * that reaches the audit stream with NO credentials -- it only has to fail
 * validation first, and failing validation is exactly what a probe does. Built
 * from CANARY rather than written out, so the literal stays in this module.
 */
export const CANARY_RESOURCE_TYPE = `Patient${CANARY}`;
