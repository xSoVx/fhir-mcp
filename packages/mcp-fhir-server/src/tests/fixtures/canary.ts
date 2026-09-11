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